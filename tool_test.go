package gored_test

import (
	"context"
	"errors"
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
