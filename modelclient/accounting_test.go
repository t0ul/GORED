package modelclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/modelclient"
)

// TestAccountingOverRealServer exercises the whole path with no mock: a real HTTP server
// speaking the OpenAI chat-completions API, the real OpenAI client built from a registry
// spec, wrapped in the accounting client. The account must reflect exactly what the server
// returned, call after call.
func TestAccountingOverRealServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	}))
	defer ts.Close()

	spec := gored.ModelSpec{Name: "kimi", Endpoint: ts.URL, Model: "moonshot-v1", ParamsB: 16}
	client := modelclient.FromSpec(spec)
	if client.Name() != "moonshot-v1" {
		t.Fatalf("FromSpec should use the model id, got %q", client.Name())
	}

	acct := gored.NewComputeAccount(spec)
	ac := gored.NewAccountingClient(client, acct)

	for i := 0; i < 2; i++ {
		reply, usage, err := ac.Chat(context.Background(), []gored.Message{{Role: gored.RoleUser, Content: "hi"}}, gored.ChatOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if reply != "ok" || usage.PromptTokens != 10 || usage.CompletionTokens != 5 {
			t.Fatalf("unexpected reply/usage: %q %+v", reply, usage)
		}
	}

	if acct.Calls != 2 || acct.TokensIn != 20 || acct.TokensOut != 10 {
		t.Errorf("account did not accrue the two calls: %+v", acct)
	}
	if acct.Backend != "remote" || acct.Model != "kimi" || acct.ParamsB != 16 {
		t.Errorf("account metadata wrong: %+v", acct)
	}
	if acct.WallMS < 0 {
		t.Errorf("wall time should be non-negative, got %d", acct.WallMS)
	}
}
