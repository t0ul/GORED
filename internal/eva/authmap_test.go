package eva

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/GORED/internal/tools"
	"github.com/t0ul/GORED/store"
)

// reconAuthMap must record what each identity (anon/low/priv) gets on a GET endpoint and derive the
// promoted reachability columns — the baseline the exploit phase uses to know where BAC is possible
// and which identity reaches it. A role cookie stands in for the recon login's session jar.
func TestReconAuthMap(t *testing.T) {
	mux := http.NewServeMux()
	// /admin: priv-only (anon 401, low 403, priv 200) — needs_auth, NOT reach_low.
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		switch roleCookie(r) {
		case "priv":
			w.WriteHeader(http.StatusOK)
		case "low":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	// /data: any authed identity (anon 401, low 200, priv 200) — needs_auth AND reach_low.
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		if roleCookie(r) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Classify = func(m, p string) string { return classifyEndpoint(m, p).class }
	// seed the two GET endpoints onto the surface so reconAuthMap has something to probe
	_ = st.SaveSurface("app", "", "", "GET", "/admin", "seed")
	_ = st.SaveSurface("app", "", "", "GET", "/data", "seed")

	// stand in for the recon login: seed the shared jar with a role cookie per identity
	sessions := tools.NewSessions()
	u, _ := url.Parse(ts.URL)
	sessions.Client("priv").Jar.SetCookies(u, []*http.Cookie{{Name: "role", Value: "priv"}})
	sessions.Client("low").Jar.SetCookies(u, []*http.Cookie{{Name: "role", Value: "low"}})

	s := &Server{store: st}
	s.reconAuthMap(context.Background(), store.Target{Name: "app", Base: ts.URL}, sessions, tools.NewEgress(strings.TrimPrefix(ts.URL, "http://")))

	rows, _ := st.ListSurface("app")
	byPath := map[string]store.SurfaceRow{}
	for _, r := range rows {
		byPath[r.Path] = r
	}

	admin := byPath["/admin"]
	if admin.Contract == nil || admin.Contract.Auth["anon"] != 401 || admin.Contract.Auth["low"] != 403 || admin.Contract.Auth["priv"] != 200 {
		t.Fatalf("/admin auth map wrong: %+v", admin.Contract)
	}
	if !admin.NeedsAuth || admin.ReachLow {
		t.Errorf("/admin should be needs_auth and NOT reach_low; got needs_auth=%v reach_low=%v", admin.NeedsAuth, admin.ReachLow)
	}
	data := byPath["/data"]
	if !data.NeedsAuth || !data.ReachLow {
		t.Errorf("/data should be needs_auth AND reach_low; got needs_auth=%v reach_low=%v (auth=%+v)", data.NeedsAuth, data.ReachLow, data.Contract.Auth)
	}
}

func roleCookie(r *http.Request) string {
	if c, err := r.Cookie("role"); err == nil {
		return c.Value
	}
	return ""
}
