package probes_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/t0ul/GORED/internal/core"
	probes "github.com/t0ul/GORED/internal/probes"
	"github.com/t0ul/GORED/demotarget"
)

func serveTarget(t *testing.T, s *demotarget.Server) string {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestDifferentialOracleFlagsBACNotScoped runs the canary-free differential oracle
// against the real demo target as two header identities (admin = privileged, alice =
// low-privilege) plus an anonymous baseline. It must flag the BAC list endpoint
// (alice sees admin's confidential memo) and must NOT flag the correctly-scoped
// control (alice sees only her own) or a public page — bounding false positives with
// no planted canary.
func TestDifferentialOracleFlagsBACNotScoped(t *testing.T) {
	_, base := liveTarget(t)

	oracle := &probes.DifferentialOracle{
		Base: base, Egress: core.NewEgress(authority(t, base)), Sessions: core.NewSessions(),
		Priv: core.Identity{Name: "admin", Headers: map[string]string{"X-Session": "admin-session"}},
		Low:  core.Identity{Name: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		Anon: &core.Identity{Name: "anon"},
	}

	findings, err := oracle.Sweep(context.Background(), [][2]string{
		{"GET", "/api/memos"},      // BAC: low-priv sees privileged data
		{"GET", "/api/memos/mine"}, // scoped control: low-priv sees only its own
		{"GET", "/"},               // public page: anon sees it too
	})
	if err != nil {
		t.Fatal(err)
	}

	byPath := map[string]probes.DiffFinding{}
	for _, f := range findings {
		byPath[f.Path] = f
	}

	if got := byPath["/api/memos"]; got.Verdict != probes.VerdictBAC {
		t.Errorf("/api/memos: want bac, got %q (%s)", got.Verdict, got.Evidence)
	} else if got.Marker == "" {
		t.Errorf("/api/memos flagged bac but carries no marker for the repro")
	}
	if got := byPath["/api/memos/mine"]; got.Verdict == probes.VerdictBAC {
		t.Errorf("/api/memos/mine: scoped control must NOT be flagged bac (%s)", got.Evidence)
	}
	if got := byPath["/"]; got.Verdict == probes.VerdictBAC {
		t.Errorf("/: public page must NOT be flagged bac (%s)", got.Evidence)
	}
}

// TestDifferentialOracleHardenedClosesBAC confirms the finding is wired to real
// behavior: with the controls on (per-caller scoping), the same sweep no longer
// flags the list endpoint. A test that could not go from flagged to not-flagged
// would prove nothing.
func TestDifferentialOracleHardenedClosesBAC(t *testing.T) {
	s, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	base := serveTarget(t, s)

	oracle := &probes.DifferentialOracle{
		Base: base, Egress: core.NewEgress(authority(t, base)), Sessions: core.NewSessions(),
		Priv: core.Identity{Name: "admin", Headers: map[string]string{"X-Session": "admin-session"}},
		Low:  core.Identity{Name: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		Anon: &core.Identity{Name: "anon"},
	}
	f, err := oracle.Probe(context.Background(), "GET", "/api/memos")
	if err != nil {
		t.Fatal(err)
	}
	if f.Flagged() {
		t.Errorf("hardened build still flagged /api/memos: %s", f.Evidence)
	}
}

// confidenceFixture serves, to any valid X-Id (anon is refused): three HTML pages
// that are nothing but shared chrome (the same nav/scripts/footer on every page), a
// JSON data endpoint, and an HTML page carrying chrome plus data unique to it. All
// are byte-identical for two identities, so all flag BAC — the point is the oracle's
// confidence should separate the shared shells (low, likely false positives) from
// the real data disclosures (high).
func confidenceFixture() http.Handler {
	const chrome = `<nav>dashboard-navigation-sidebar</nav><script src="analytics-tracking-bundle.js"></script><footer>global-footer-copyright-2026</footer>`
	authed := func(r *http.Request) bool { return r.Header.Get("X-Id") != "" }
	mux := http.NewServeMux()
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !authed(r) {
				http.Error(w, "login required", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(body))
		}
	}
	mux.HandleFunc("/shell1", page(chrome))
	mux.HandleFunc("/shell2", page(chrome))
	mux.HandleFunc("/shell3", page(chrome))
	mux.HandleFunc("/report", page(chrome+`<main>confidential-acquisition-memo megacorp-financials-report board-resolution-draft</main>`))
	mux.HandleFunc("/records", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":1,"holder":"someone-else"}]`))
	})
	return mux
}

func TestDifferentialConfidenceRanksChromeLow(t *testing.T) {
	ts := httptest.NewServer(confidenceFixture())
	t.Cleanup(ts.Close)

	oracle := &probes.DifferentialOracle{
		Base: ts.URL, Egress: core.NewEgress(authority(t, ts.URL)), Sessions: core.NewSessions(),
		Priv: core.Identity{Name: "admin", Headers: map[string]string{"X-Id": "admin"}},
		Low:  core.Identity{Name: "user", Headers: map[string]string{"X-Id": "user"}},
		Anon: &core.Identity{Name: "anon"},
	}
	findings, err := oracle.Sweep(context.Background(), [][2]string{
		{"GET", "/shell1"}, {"GET", "/shell2"}, {"GET", "/shell3"},
		{"GET", "/report"}, {"GET", "/records"},
	})
	if err != nil {
		t.Fatal(err)
	}
	conf := map[string]core.Confidence{}
	for _, f := range findings {
		if !f.Flagged() {
			t.Errorf("%s not flagged (want BAC): %s", f.Path, f.Evidence)
		}
		conf[f.Path] = f.Confidence
	}
	for _, shell := range []string{"/shell1", "/shell2", "/shell3"} {
		if conf[shell] != core.ConfLow {
			t.Errorf("%s: shared chrome should be low confidence, got %q", shell, conf[shell])
		}
	}
	if conf["/records"] != core.ConfHigh {
		t.Errorf("/records: JSON data should be high confidence, got %q", conf["/records"])
	}
	if conf["/report"] != core.ConfMedium {
		t.Errorf("/report: HTML with unique content is ambiguous without a canary, want medium, got %q", conf["/report"])
	}
}

// TestDifferentialCanaryCertain shows a planted canary turns a flag certain: when the
// low-priv response carries a marker the seeder planted, the verdict is BAC at
// "certain" confidence regardless of the heuristic.
func TestDifferentialCanaryCertain(t *testing.T) {
	const marker = "GORED-CANARY-abc123"
	mux := http.NewServeMux()
	mux.HandleFunc("/leak", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Id") == "" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("record owner=admin note=" + marker))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	oracle := &probes.DifferentialOracle{
		Base: ts.URL, Egress: core.NewEgress(authority(t, ts.URL)), Sessions: core.NewSessions(),
		Priv:    core.Identity{Name: "admin", Headers: map[string]string{"X-Id": "admin"}},
		Low:     core.Identity{Name: "user", Headers: map[string]string{"X-Id": "user"}},
		Anon:    &core.Identity{Name: "anon"},
		Markers: []string{marker},
	}
	f, err := oracle.Probe(context.Background(), "GET", "/leak")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Flagged() || f.Confidence != core.ConfCertain {
		t.Fatalf("want BAC/certain, got %s/%s (%s)", f.Verdict, f.Confidence, f.Evidence)
	}
	if f.Marker != marker {
		t.Errorf("want canary marker %q, got %q", marker, f.Marker)
	}
}
