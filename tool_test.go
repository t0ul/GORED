package gored_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/demotarget"
)

func liveTarget(t *testing.T) (*demotarget.Server, string) {
	t.Helper()
	s, err := demotarget.New()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts.URL
}

func authority(t *testing.T, base string) string {
	t.Helper()
	// base is http://host:port
	return strings.TrimPrefix(base, "http://")
}

func TestEgressAllowsTargetDeniesOthers(t *testing.T) {
	_, base := liveTarget(t)
	e := gored.NewEgress(authority(t, base))
	if !e.Allowed(base + "/") {
		t.Fatal("target authority should be allowed")
	}
	for _, u := range []string{"http://169.254.169.254/latest/meta-data/", "http://example.com/", "https://evil.test/"} {
		if e.Allowed(u) {
			t.Fatalf("off-target host allowed: %s", u)
		}
	}
}

func TestHTTPToolDeniesOffTargetWithBeacon(t *testing.T) {
	_, base := liveTarget(t)
	e := gored.NewEgress(authority(t, base))
	var denied string
	tool := gored.NewHTTPRequestTool(base, e, func(u string) { denied = u })
	_, err := tool.Call(context.Background(), map[string]any{"method": "GET", "url": "http://169.254.169.254/"})
	if !errors.Is(err, gored.ErrEgressDenied) {
		t.Fatalf("want ErrEgressDenied, got %v", err)
	}
	if denied == "" {
		t.Fatal("OnDeny beacon not fired")
	}
}

func TestHTTPToolReachesTargetByPath(t *testing.T) {
	_, base := liveTarget(t)
	e := gored.NewEgress(authority(t, base))
	tool := gored.NewHTTPRequestTool(base, e, nil)
	out, err := tool.Call(context.Background(), map[string]any{
		"method": "GET", "path": "/api/notes/1000", "headers": map[string]any{"X-Session": "alice-session"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "GORED{") {
		t.Fatalf("expected flag in IDOR response, got %q", out)
	}
}

func TestExecAllowlist(t *testing.T) {
	e := gored.NewExecTool()
	out, err := e.Call(context.Background(), map[string]any{"argv": []any{"echo", "hi"}})
	if err != nil || strings.TrimSpace(out) != "hi" {
		t.Fatalf("echo failed: out=%q err=%v", out, err)
	}
	if _, err := e.Call(context.Background(), map[string]any{"argv": []any{"curl", "http://x"}}); err == nil {
		t.Fatal("network command should be refused by the allowlist")
	}
}

func TestBlackboardScrubsAndIsTerse(t *testing.T) {
	b := gored.NewBlackboard()
	b.Add(gored.FindObservation, "contact admin@example.com for the key", 1)
	b.Add(gored.FindEndpoint, "/api/notes/{id}", 1)
	rendered := b.Render()
	if strings.Contains(rendered, "admin@example.com") {
		t.Fatalf("blackboard did not scrub PII: %q", rendered)
	}
	if !strings.Contains(rendered, "/api/notes/{id}") {
		t.Fatal("blackboard dropped the endpoint finding")
	}
}

func TestToolboxResolveTolerant(t *testing.T) {
	tb := gored.NewToolbox(gored.NewHTTPRequestTool("http://127.0.0.1:1", gored.NewEgress("127.0.0.1:1"), nil), gored.NewExecTool())
	// Exact.
	if _, name, ok := tb.Resolve("http_request"); !ok || name != "http_request" {
		t.Fatalf("exact resolve failed: %q %v", name, ok)
	}
	// A weak model echoing the placeholder "http_request|exec" resolves to the first named tool.
	if _, name, ok := tb.Resolve("http_request|exec"); !ok || name != "http_request" {
		t.Fatalf("placeholder resolve failed: %q %v", name, ok)
	}
	if _, _, ok := tb.Resolve("totally_unknown"); ok {
		t.Fatal("unknown tool should not resolve")
	}
}

func TestHTTPToolSessionPersistsAndShowsHeaders(t *testing.T) {
	// A real app: /login sets a session cookie; /secret requires it. No mocks.
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "valid-token", Path: "/"})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("logged in"))
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err != nil || c.Value != "valid-token" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
			return
		}
		_, _ = w.Write([]byte("TOP SECRET"))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	tool := gored.NewHTTPRequestTool(ts.URL, gored.NewEgress(authority(t, ts.URL)), nil)
	ctx := context.Background()

	// Header visibility: the login response's Set-Cookie must surface to the agent.
	login, err := tool.Call(ctx, map[string]any{"method": "GET", "path": "/login", "session": "attacker"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(login), "set-cookie: sid=valid-token") {
		t.Fatalf("login response did not surface Set-Cookie:\n%s", login)
	}

	// Session persistence: the same session reuses the cookie and reaches /secret.
	got, err := tool.Call(ctx, map[string]any{"method": "GET", "path": "/secret", "session": "attacker"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "TOP SECRET") {
		t.Fatalf("session did not persist across calls:\n%s", got)
	}

	// A different session has no cookie and is refused — jars are isolated.
	other, err := tool.Call(ctx, map[string]any{"method": "GET", "path": "/secret", "session": "victim"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(other, "HTTP 403") {
		t.Fatalf("a fresh session should be refused, got:\n%s", other)
	}
}

func TestDiffTool(t *testing.T) {
	d := gored.DiffTool{}
	eq, _ := d.Call(context.Background(), map[string]any{"a": "same", "b": "same"})
	if !strings.Contains(eq, "identical") {
		t.Fatalf("want identical, got %q", eq)
	}
	ne, _ := d.Call(context.Background(), map[string]any{"a": "line1\nX", "b": "line1\nY"})
	if !strings.Contains(ne, "differ") || !strings.Contains(ne, "line 2") {
		t.Fatalf("want a line-2 diff, got %q", ne)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
