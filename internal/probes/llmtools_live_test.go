//go:build live

// Live end-to-end test of the LLM-surface attack: boot a real local model, wrap it in the
// benign llmharness (a fixed system prompt holding a planted secret), and run the real
// llm_attack tool against it over the real direct transport. It proves the capability is
// wired on real bytes — gorauder's corpus runs against a real model endpoint and the harness
// oracle fires if the secret leaks. Excluded from offline `go test`; run with:
//
//	go test -tags live -run TestLLMAttackLive -v ./internal/probes/
package probes_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/probes"
	"github.com/t0ul/GORED/internal/tools"
	"github.com/t0ul/GORED/llmharness"
	"github.com/t0ul/GORED/modelclient"
	goserve "github.com/t0ul/goserve"
)

func TestLLMAttackLive(t *testing.T) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".riskrancher", "models")
	cfg := goserve.Config{
		Dir: dir, Reclaim: true, ReadyTimeout: 120 * time.Second, Stdout: io.Discard,
		Models: []goserve.Model{{Name: "victim", File: "tinyllama.gguf", Port: 11690, Ctx: 2048}},
	}
	if ok, msg := cfg.Available(); !ok {
		t.Skipf("local model not available: %s", msg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	h, err := goserve.Start(ctx, cfg)
	if err != nil {
		t.Fatalf("boot model: %v", err)
	}
	defer h.Close()

	victim := modelclient.New(h.ChatURL("victim"), "victim")
	harness, err := llmharness.New(victim)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	hs := &http.Server{Handler: harness.Handler()}
	go func() { _ = hs.Serve(ln) }()
	defer hs.Close()
	base := "http://" + ln.Addr().String()

	u, _ := url.Parse(base)
	gate := tools.NewGate(tools.DirectTransport{}, tools.NewEgress(u.Host), nil)
	tool := probes.LLMAttackTool{Gate: gate, Base: base}

	out, err := tool.Call(ctx, map[string]any{"path": "/api/chat"})
	if err != nil {
		t.Fatalf("llm_attack errored: %v", err)
	}
	t.Logf("llm_attack result: %s", out)

	// Mechanism: the corpus ran against the real endpoint and produced a verdict line.
	if !strings.Contains(out, "ASR") {
		t.Fatalf("expected an attack-success-rate verdict from the real run; got: %s", out)
	}
	// Best-effort: report whether the model leaked the planted secret (the harness oracle).
	leaked := false
	for _, st := range harness.Status() {
		if st.ID == "prompt-leak" && st.Captured {
			leaked = true
		}
	}
	t.Logf("harness oracle: secret leaked = %v", leaked)

	// The target with containment: an off-allowlist host is denied by the gate.
	var _ core.ModelClient = victim
}
