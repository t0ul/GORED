package probes_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/t0ul/GORED/internal/core"
	probes "github.com/t0ul/GORED/internal/probes"
)

// authFixture is a minimal app whose real API surface is reachable only once logged
// in: "/" is a bare login form that links nothing useful, POST /login sets a session
// cookie, and /app lists the API routes but only to a request carrying that cookie.
// It stands in for RiskRancher's shape (a login page hiding /api/tickets &c.) so the
// authenticated-discovery accept can run offline against a real HTTP server.
func authFixture() http.Handler {
	const loginPage = `<!doctype html><html><body>
<form action="/login" method="post"><input name="user"><input name="pass"></form>
</body></html>`
	// The authenticated page carries the surface a login page never links to.
	const appPage = `<!doctype html><html><body>
<a href="/api/tickets">tickets</a>
<script>
  fetch("/api/reports/view/1");
  const u = "/api/admin/users";
</script>
</body></html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(loginPage))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sess", Value: "ok", Path: "/"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sess"); err != nil || c.Value != "ok" {
			// Unauthenticated: reveal nothing — no API routes leak here.
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(appPage))
	})
	return mux
}

// logoutFixture serves an authenticated page that links both a deeper authenticated
// page and a logout link. The deeper page's API route is only visible while logged
// in. A crawl that follows the logout link (it sorts alphabetically before "/more")
// clears its own cookie and then misses the deep route — so reaching it proves the
// crawl skipped logout.
func logoutFixture() http.Handler {
	authed := func(r *http.Request) bool {
		c, err := r.Cookie("sess")
		return err == nil && c.Value == "ok"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sess", Value: "ok", Path: "/"})
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sess", Value: "", Path: "/", MaxAge: -1})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`<a href="/logout">out</a><a href="/more">more</a>`))
	})
	mux.HandleFunc("/more", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`<a href="/api/deep">deep</a>`))
	})
	return mux
}

func TestAuthenticatedCrawlSkipsLogout(t *testing.T) {
	ts := httptest.NewServer(logoutFixture())
	t.Cleanup(ts.Close)

	httpTool, disc := probes.WebRecon(ts.URL, core.NewEgress(authority(t, ts.URL)), nil)
	ctx := context.Background()
	if _, err := httpTool.Call(ctx, map[string]any{"method": "POST", "path": "/login", "session": "rh"}); err != nil {
		t.Fatal(err)
	}
	out, err := disc.Call(ctx, map[string]any{"path": "/app", "session": "rh"})
	if err != nil {
		t.Fatal(err)
	}
	// /api/deep lives one page past a logout link; reaching it means the crawl did not
	// log itself out on the way.
	if !strings.Contains(out, "/api/deep") {
		t.Errorf("crawl missed /api/deep — it likely followed the logout link and lost the session:\n%s", out)
	}
}

func TestAuthenticatedDiscoveryNeedsLogin(t *testing.T) {
	ts := httptest.NewServer(authFixture())
	t.Cleanup(ts.Close)

	httpTool, disc := probes.WebRecon(ts.URL, core.NewEgress(authority(t, ts.URL)), nil)
	ctx := context.Background()
	authOnly := []string{"/api/tickets", "/api/reports/view/1", "/api/admin/users"}

	// Before login the auth-only page gives up nothing (it 401s), so discovery as the
	// session "rh" must NOT surface the authenticated routes.
	pre, err := disc.Call(ctx, map[string]any{"path": "/app", "session": "rh"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range authOnly {
		if strings.Contains(pre, p) {
			t.Fatalf("authenticated route %s discovered before login:\n%s", p, pre)
		}
	}

	// Log in through the stateful http_request under the same session name.
	loginOut, err := httpTool.Call(ctx, map[string]any{
		"method": "POST", "path": "/login", "session": "rh",
		"body": `{"user":"rh","pass":"pw"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(loginOut), "set-cookie") {
		t.Fatalf("login did not set a session cookie:\n%s", loginOut)
	}

	// Now discovery as "rh" rides that cookie and boards the authenticated surface.
	post, err := disc.Call(ctx, map[string]any{"path": "/app", "session": "rh"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range authOnly {
		if !strings.Contains(post, p) {
			t.Errorf("authenticated discovery missed %s after login:\n%s", p, post)
		}
	}
}
