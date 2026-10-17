package appsweep

import (
	"testing"

	"github.com/t0ul/GORED/internal/tools"
)

// Integration: build the REAL apiexploit toolbox and apply the per-class scoping the exploit phase
// uses (WithAllowedTools -> Toolbox.Restrict). A write endpoint's run must end up with exactly its
// class tools and NONE of the generic/recon escapes (api_request, http_request, discover) — the
// behaviour that forces a weak model onto the right confirmer.
func TestApiExploitToolboxScopesToClass(t *testing.T) {
	st, ok := Stages()["apiexploit"]
	if !ok || st.BuildTools == nil {
		t.Fatal("apiexploit stage missing or has no BuildTools")
	}
	gate := tools.NewGate(tools.DirectTransport{}, tools.NewEgress("127.0.0.1:1"), nil)
	tb := st.BuildTools(gate, "http://127.0.0.1:1")

	// sanity: the full toolbox carries the generic + recon tools we want scoping to drop
	full := map[string]bool{}
	for _, n := range tb.Names() {
		full[n] = true
	}
	for _, want := range []string{"mass_assign", "body_limit", "api_request", "discover"} {
		if !full[want] {
			t.Fatalf("precondition: full apiexploit toolbox should contain %q; got %v", want, tb.Names())
		}
	}

	// scope to the write class's tools (what toolNames("mass_assign / body_limit") yields)
	tb.Restrict([]string{"mass_assign", "body_limit"})
	got := map[string]bool{}
	for _, n := range tb.Names() {
		got[n] = true
	}
	if !got["mass_assign"] || !got["body_limit"] {
		t.Errorf("scoped toolbox must keep the write-class tools; got %v", tb.Names())
	}
	for _, gone := range []string{"api_request", "http_request", "discover", "fingerprint"} {
		if got[gone] {
			t.Errorf("scoped write run must NOT carry %q (the generic/recon escape); got %v", gone, tb.Names())
		}
	}
}
