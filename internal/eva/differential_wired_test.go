package eva

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/GORED/store"
)

// TestRunTargetDifferentialWired drives the Phase-2 deterministic probe end to end against a REAL
// HTTP server with a genuine broken-access-control bug: a real JSON login, the real project-surface
// datastore, the real DifferentialOracle, and the real proof-pooling path. Nothing is stubbed — the
// server's own responses (a low-privilege cookie reading privileged data) are what the oracle
// judges, so a flag means the wiring actually lands a finding without the model in the loop.
func TestRunTargetDifferentialWired(t *testing.T) {
	// A real app: cookie login identifies the caller; /api/tickets/{id} is the bug (any signed-in
	// user reads any ticket); /api/tickets/mine is correctly scoped; /admin is correctly blocked.
	const adminTicket = `{"id":42,"owner":"admin","secret":"NERV-OVERRIDE-7781","project":"evangelion-unit-01"}`
	user := func(r *http.Request) string {
		if c, err := r.Cookie("sid"); err == nil {
			return c.Value
		}
		return ""
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		var sid string
		switch {
		case strings.Contains(string(body), "admin@x"):
			sid = "admin"
		case strings.Contains(string(body), "bob@x"):
			sid = "bob"
		default:
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/"})
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/tickets/42", func(w http.ResponseWriter, r *http.Request) {
		if user(r) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"auth required"}`))
			return
		}
		// BUG: returns the privileged ticket to ANY authenticated caller (broken object-level authz).
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(adminTicket))
	})
	mux.HandleFunc("/api/tickets/mine", func(w http.ResponseWriter, r *http.Request) {
		u := user(r)
		if u == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Correctly scoped: each caller sees only their own record.
		w.Header().Set("Content-Type", "application/json")
		if u == "admin" {
			_, _ = w.Write([]byte(`{"id":1,"owner":"admin","note":"admin-private-note"}`))
		} else {
			_, _ = w.Write([]byte(`{"id":2,"owner":"bob","note":"bob-private-note"}`))
		}
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		switch user(r) {
		case "admin":
			_, _ = w.Write([]byte(`<html><h1>Admin</h1><p>token ADMIN-CONSOLE-9931</p></html>`))
		case "":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusForbidden) // correctly blocks the low identity
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "eva.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	const name = "wiredbac"
	if err := st.SaveTarget(store.Target{
		Name: name, Base: ts.URL, LoginPath: "/api/auth/login", LoginType: "json",
		UserField: "email", PassField: "password",
		PrivCreds: "admin@x:pw", LowCreds: "bob@x:pw",
	}); err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	// The mapped surface recon would have produced (crawl extraction is covered by discover tests).
	for _, p := range []string{"/api/tickets/42", "/api/tickets/mine", "/admin"} {
		if err := st.SaveSurface(name, "GET", p, "recon:priv"); err != nil {
			t.Fatalf("SaveSurface: %v", err)
		}
	}

	s := NewServer(dir, st, 1)
	tg, ok, _ := st.GetTarget(name)
	if !ok {
		t.Fatal("target not found")
	}
	c := &campaign{Name: "wired", Targets: []string{name}}

	s.runTargetDifferential(context.Background(), c, tg)

	// The oracle must flag exactly the BAC endpoint, and only it.
	flags := c.diff[ts.URL]
	if len(flags) != 1 {
		t.Fatalf("expected exactly 1 BAC flag, got %d: %+v", len(flags), flags)
	}
	if flags[0].Path != "/api/tickets/42" {
		t.Fatalf("flagged the wrong endpoint: %q", flags[0].Path)
	}

	// The flag must pool into the pentest report as an object-level authz proof (CWE-639), sourced
	// from the deterministic differential — a finding landed with no model in the loop.
	proofs := s.campaignProofs(c)
	var got bool
	for _, p := range proofs {
		if p.Source == "gored-eva-differential" && strings.Contains(p.Locus, "/api/tickets") {
			got = true
			if p.CWE != "CWE-639" {
				t.Errorf("object (id) path should be CWE-639, got %q", p.CWE)
			}
		}
	}
	if !got {
		t.Fatalf("differential flag did not pool into the report proofs: %+v", proofs)
	}
}
