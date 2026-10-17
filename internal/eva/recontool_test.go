package eva

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/GORED/store"
)

// The recon tool returns a dense, scoped, directly-actionable listing: typed+required fields, the
// per-identity auth map, the attempt count, and only the frontier by default (a found endpoint is
// excluded until exercised=true). This is the format the exploit-phase model reads.
func TestReconToolDenseFrontier(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Classify = func(m, p string) string { return classifyEndpoint(m, p).class }
	const tgt = "app"
	// openapi-grade contract: typed + required + an auth map.
	_ = st.SaveContract(tgt, "POST", "/api/auth/login", "openapi", store.EndpointContract{
		Fields: []store.FieldSpec{
			{Name: "email", Type: "email", Required: true, In: "body"},
			{Name: "password", Type: "string", Required: true, In: "body"},
		},
		Auth: map[string]int{"anon": 401, "low": 200},
	})
	// a second endpoint that we then mark found, so it drops off the frontier.
	_ = st.SaveContract(tgt, "POST", "/api/memos", "static", store.EndpointContract{
		Fields: []store.FieldSpec{{Name: "title", In: "body"}},
	})
	_ = st.MarkAttacked(tgt, "POST", "/api/memos", true)

	tool := reconTool{store: st, target: tgt, attemptCap: 2}

	out, err := tool.Call(context.Background(), map[string]any{}) // default: frontier
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "/api/auth/login") {
		t.Fatalf("frontier should list the login endpoint; got:\n%s", out)
	}
	if !strings.Contains(out, "email:email!") || !strings.Contains(out, "password:string!") {
		t.Errorf("typed + required fields must render as name:type!; got:\n%s", out)
	}
	if !strings.Contains(out, "auth: anon=401 low=200") {
		t.Errorf("per-identity auth map must render in order; got:\n%s", out)
	}
	if strings.Contains(out, "/api/memos") {
		t.Errorf("a found endpoint must be off the frontier; got:\n%s", out)
	}

	all, err := tool.Call(context.Background(), map[string]any{"exercised": true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(all, "/api/memos") || !strings.Contains(all, "[found]") {
		t.Errorf("exercised=true must include the found endpoint marked [found]; got:\n%s", all)
	}
}
