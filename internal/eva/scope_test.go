package eva

import (
	"strings"
	"testing"
)

// toolNames turns a classifyEndpoint tool hint into the exact tool identifiers a focused exploit run
// is scoped to — and, importantly, every class's hint must parse to tools that actually exist, or a
// scoped run would be stranded. This test pins the parse AND that each class maps to real tools.
func TestToolNamesParsesClassHints(t *testing.T) {
	cases := []struct {
		hint string
		want []string
	}{
		{"nosqli / jwt_forge / throttle_probe / password_policy", []string{"nosqli", "jwt_forge", "throttle_probe", "password_policy"}},
		{"mass_assign / body_limit", []string{"mass_assign", "body_limit"}},
		{"api_request / bola", []string{"api_request", "bola"}},
		{"stored_xss / api_request", []string{"stored_xss", "api_request"}},
		{"api_request", []string{"api_request"}},
	}
	for _, c := range cases {
		got := toolNames(c.hint)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("toolNames(%q) = %v, want %v", c.hint, got, c.want)
		}
	}
}

// primaryTool refines the few-shot tool by path within the broad "auth" class (a register/reset
// path is a weak-password target, not an injection target), and examplePath fills a concrete id so
// the example is runnable.
func TestPrimaryToolRefinesAuthSubtype(t *testing.T) {
	const authHint = "nosqli / jwt_forge / throttle_probe / password_policy"
	login := rankedEndpoint{Class: "auth", Path: "/api/auth/login", Tool: authHint}
	if got := primaryTool(login); got != "nosqli" {
		t.Errorf("login few-shot tool = %q, want nosqli", got)
	}
	reg := rankedEndpoint{Class: "auth", Path: "/api/auth/register", Tool: authHint}
	if got := primaryTool(reg); got != "password_policy" {
		t.Errorf("register few-shot tool = %q, want password_policy", got)
	}
	write := rankedEndpoint{Class: "write", Path: "/api/adapters", Tool: "mass_assign / body_limit"}
	if got := primaryTool(write); got != "mass_assign" {
		t.Errorf("write few-shot tool = %q, want mass_assign (class default)", got)
	}
	if examplePath("/api/tickets/{id}") != "/api/tickets/1" {
		t.Errorf("examplePath should fill {id} with a concrete id, got %q", examplePath("/api/tickets/{id}"))
	}
}

// Every class classifyEndpoint can emit must route to a non-empty tool set (otherwise a scoped run
// for that class would have no tools). Walk a representative path per class.
func TestEveryClassHasScopableTools(t *testing.T) {
	paths := map[string][2]string{ // class -> {method, path}
		"auth":   {"POST", "/api/auth/login"},
		"admin":  {"GET", "/api/admin/users"},
		"upload": {"POST", "/api/upload"},
		"ingest": {"POST", "/api/ingest"},
		"export": {"GET", "/api/reports/export"},
		"search": {"GET", "/api/search"},
		"info":   {"GET", "/api/config"},
		"ssrf":   {"GET", "/api/fetch"},
		"write":  {"POST", "/api/adapters"},
		"idor":   {"GET", "/api/tickets/{id}"},
	}
	for class, mp := range paths {
		c := classifyEndpoint(mp[0], mp[1])
		if c.class != class {
			t.Fatalf("path %s %s classified as %q, expected %q (fixture drift)", mp[0], mp[1], c.class, class)
		}
		if len(toolNames(c.tool)) == 0 {
			t.Errorf("class %q routes to no scopable tools (hint %q)", class, c.tool)
		}
	}
}
