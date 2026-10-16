package core

import (
	"context"
	"testing"

	"github.com/t0ul/GORED/internal/tools"
)

// namedTool is a name-only Tool fixture for testing the pure routeByPath/preferTool logic
// (it holds a name and does nothing). It is not a stand-in for a live system — the real
// exploit tools are verified live in internal/probes.
type namedTool struct{ n string }

func (t namedTool) Name() string                                       { return t.n }
func (namedTool) Describe() string                                     { return "" }
func (namedTool) Call(context.Context, map[string]any) (string, error) { return "", nil }

// These are pure-logic tests of the checkpoint's proposal plumbing: no model, no network.
// The live behaviour (the loop actually pausing at a phase boundary and steering on the
// pilot's directive) is exercised by the live sweep, not here.

func TestParseMoves(t *testing.T) {
	reply := `Here are my moves:
[
  {"surface":"html-page","path":"/greeting?name=FUZZ","tool":"xss_scan","why":"reflects the name param"},
  {"surface":"json-api","path":"/api/tickets","tool":"http_request","why":"authz check"}
]`
	got := parseMoves(reply)
	if len(got) != 2 {
		t.Fatalf("want 2 moves, got %d: %+v", len(got), got)
	}
	if got[0].Tool != "xss_scan" || got[0].Path != "/greeting?name=FUZZ" || got[0].Source != "model" {
		t.Errorf("first move wrong: %+v", got[0])
	}
	if got[1].Surface != "json-api" {
		t.Errorf("second move surface wrong: %+v", got[1])
	}
}

func TestParseMovesLooseAndThink(t *testing.T) {
	// No array wrapper, reasoning span, prose around — still salvage the two objects.
	reply := `<think>which first?</think> {"tool":"http_request","path":"/"} and then {"tool":"xss_scan","path":"/s?q=FUZZ"}`
	got := parseMoves(reply)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(got), got)
	}
	// An object with neither path nor tool is dropped.
	if ms := parseMoves(`{"why":"nothing actionable"}`); len(ms) != 0 {
		t.Errorf("want 0 for empty move, got %+v", ms)
	}
}

func TestRouteByPath(t *testing.T) {
	tb := NewToolbox(tools.GetTool{}, tools.XSSScanTool{}) // carries http_request + xss_scan
	cases := []struct {
		path, surface, tool string
	}{
		{"/greeting?name=FUZZ", "html-page", "xss_scan"},
		{"/search?q=x", "html-page", "xss_scan"},
		{"/api/tickets", "json-api", "http_request"}, // no probe_endpoint tool yet -> floor
		{"/data.json", "json-api", "http_request"},
		{"/about", "unknown", "http_request"},
	}
	for _, c := range cases {
		s, tl := routeByPath(c.path, tb)
		if s != c.surface || tl != c.tool {
			t.Errorf("routeByPath(%q) = (%q,%q), want (%q,%q)", c.path, s, tl, c.surface, c.tool)
		}
	}
}

func TestRouteByPathExploitTools(t *testing.T) {
	// A box carrying the Step-7 JSON-API exploit tools: routing should prefer them by surface.
	tb := NewToolbox(
		namedTool{"http_request"}, namedTool{"api_request"},
		namedTool{"mass_assign"}, namedTool{"jwt_forge"}, namedTool{"bola"},
	)
	cases := []struct {
		path, surface, tool string
	}{
		{"/api/token", "json-api", "jwt_forge"},
		{"/api/profile", "json-api", "mass_assign"},
		{"/api/memos", "json-api", "api_request"},
		{"/api/notes/1000", "json-api", "api_request"},
	}
	for _, c := range cases {
		s, tl := routeByPath(c.path, tb)
		if s != c.surface || tl != c.tool {
			t.Errorf("routeByPath(%q) = (%q,%q), want (%q,%q)", c.path, s, tl, c.surface, c.tool)
		}
	}
}

func TestRouteByPathNewTools(t *testing.T) {
	// A box carrying the newer depth tools: routing should prefer them by surface.
	tb := NewToolbox(
		namedTool{"http_request"}, namedTool{"api_request"},
		namedTool{"nosqli"}, namedTool{"dom_xss"}, namedTool{"graphql_introspect"},
	)
	cases := []struct {
		path, surface, tool string
	}{
		{"/graphql", "json-api", "graphql_introspect"},
		{"/api/login", "json-api", "nosqli"},
		{"/auth/signin", "json-api", "nosqli"},
		{"/search?q=x", "html-page", "dom_xss"},   // no xss_scan carried -> dom_xss
		{"/api/token", "json-api", "api_request"}, // no jwt_forge carried -> floor to api_request
	}
	for _, c := range cases {
		s, tl := routeByPath(c.path, tb)
		if s != c.surface || tl != c.tool {
			t.Errorf("routeByPath(%q) = (%q,%q), want (%q,%q)", c.path, s, tl, c.surface, c.tool)
		}
	}
}

func TestPreferToolFallback(t *testing.T) {
	if got := preferTool(nil, "probe_endpoint", "http_request"); got != "http_request" {
		t.Errorf("nil toolbox: want last name http_request, got %q", got)
	}
	tb := NewToolbox(tools.XSSScanTool{})
	if got := preferTool(tb, "xss_scan", "http_request"); got != "xss_scan" {
		t.Errorf("want carried tool xss_scan, got %q", got)
	}
}

func TestDedupeMovesKeepsFirst(t *testing.T) {
	in := []Move{
		{Tool: "xss_scan", Path: "/a", Source: "model"},
		{Tool: "xss_scan", Path: "/a", Source: "router"}, // dup, dropped
		{Tool: "http_request", Path: "/a", Source: "router"},
	}
	got := dedupeMoves(in)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(got), got)
	}
	if got[0].Source != "model" {
		t.Errorf("first should be the model move, got %+v", got[0])
	}
}

func TestPathsIn(t *testing.T) {
	got := pathsIn("GET /greeting?name=x -> 200; see http://127.0.0.1:8088/api/tickets and /health.")
	want := map[string]bool{"/greeting?name=x": true, "/api/tickets": true, "/health": true}
	for _, p := range got {
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("missing paths %v; got %v", want, got)
	}
}

func TestRouterMovesFromBoard(t *testing.T) {
	b := NewUnscrubbedBlackboard()
	b.Add(FindEndpoint, "/greeting?name=x", 1)
	b.Add(FindObservation, "GET /api/tickets -> 200 json", 2)
	r := &Runner{Board: b, Tools: NewToolbox(tools.GetTool{}, tools.XSSScanTool{})}
	moves := r.routerMoves()
	var sawXSS, sawAPI bool
	for _, m := range moves {
		if m.Tool == "xss_scan" && m.Path == "/greeting?name=x" {
			sawXSS = true
		}
		if m.Surface == "json-api" && m.Path == "/api/tickets" {
			sawAPI = true
		}
		if m.Source != "router" {
			t.Errorf("router move has wrong source: %+v", m)
		}
	}
	if !sawXSS || !sawAPI {
		t.Errorf("router floor missed a board path: xss=%v api=%v moves=%+v", sawXSS, sawAPI, moves)
	}
}
