package eva

import (
	"strings"
	"testing"

	"github.com/t0ul/GORED/store"
)

// The focused exploit prompt pre-fills the endpoint's reconned contract — typed fields with required
// markers, required headers, and per-identity reachability — so a weak model builds a schema-valid
// request from its own prompt instead of guessing a body that 400s.
func TestExploitInstructionRendersContract(t *testing.T) {
	ep := rankedEndpoint{
		Method: "POST", Path: "/api/auth/login", Class: "auth", Why: "authn bypass",
		Tier: 1, Difficulty: 2,
		Contract: &store.EndpointContract{
			Fields: []store.FieldSpec{
				{Name: "email", Type: "email", Required: true, In: "body"},
				{Name: "password", Type: "string", Required: true, In: "body"},
				{Name: "verbose", Type: "bool", In: "query"},
			},
			Headers: []string{"Content-Type"},
			Auth:    map[string]int{"anon": 401, "low": 200},
		},
	}
	out := exploitInstruction(store.Target{Base: "http://target"}, ep, nil)
	for _, want := range []string{
		"email:email!", "password:string!", // body fields, typed + required
		"verbose:bool", // query field, typed
		"required headers: Content-Type",
		"reachability: anon=401 low=200",
		"EXACTLY these fields",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("instruction missing %q:\n%s", want, out)
		}
	}
}

// The focused prompt few-shots the exact first call for the endpoint's primary class tool, so a
// weak model imitates the right call instead of casting about.
func TestExploitInstructionFewShot(t *testing.T) {
	ep := rankedEndpoint{Method: "POST", Path: "/api/adapters", Class: "write", Tool: "mass_assign / body_limit", Why: "mass assignment", Tier: 2}
	inst := exploitInstruction(store.Target{Base: "http://target"}, ep, nil)
	if !strings.Contains(inst, "Start with this call") || !strings.Contains(inst, `mass_assign {"path":"/api/adapters"}`) {
		t.Errorf("instruction should few-shot the primary class tool's call; got:\n%s", inst)
	}
}

// With no contract it falls back to the legacy flat body-field line, so an un-reconned endpoint
// still gets a usable hint.
func TestExploitInstructionFallsBackToShape(t *testing.T) {
	ep := rankedEndpoint{Method: "PUT", Path: "/api/profile", Class: "write", Why: "mass assignment", Tier: 2, Difficulty: 2, Shape: "name,bio"}
	out := exploitInstruction(store.Target{Base: "http://target"}, ep, nil)
	if !strings.Contains(out, "body fields: name,bio") {
		t.Errorf("no-contract endpoint should fall back to the shape line:\n%s", out)
	}
}
