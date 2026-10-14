//go:build live

// Live end-to-end test: boots the real OSS model via goserve and runs the full
// objective loop against the real demo target. Excluded from offline `go test`
// (GORED is never a CI gate; it is live and stochastic by nature). Run with:
//
//	go test -tags live -run TestLiveRun -v ./...
package core_test

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	core "github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/demotarget"
	"github.com/t0ul/GORED/modelclient"
	"github.com/t0ul/GORED/store"
	gledger "github.com/t0ul/gledger"
	goserve "github.com/t0ul/goserve"
)

func TestLiveRun(t *testing.T) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".riskrancher", "models")
	// A small instruct model that can follow the tool-call protocol. tinyllama-1.1B
	// cannot emit valid tool calls, so it is not a meaningful live gate here.
	const modelFile = "qwen2.5-0.5b-instruct.gguf"
	cfg := goserve.Config{
		Dir: dir, Reclaim: true, ReadyTimeout: 90 * time.Second,
		Models: []goserve.Model{{Name: "attacker", File: modelFile, Port: 11537, Ctx: 2048}},
	}
	if ok, msg := cfg.Available(); !ok {
		t.Fatalf("live lab not set up (%s); do not skip the live gate", msg)
	}

	target, err := demotarget.New()
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = http.Serve(ln, target.Handler()) }()
	base := "http://" + ln.Addr().String()
	host, port, _ := net.SplitHostPort(ln.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	h, err := goserve.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	tracePath := filepath.Join(t.TempDir(), "trace.jsonl")
	audit, _ := gledger.Open(tracePath, "gored")
	st, _ := store.Open(filepath.Join(t.TempDir(), "runs.db"))
	defer st.Close()

	egress := core.NewEgress(host + ":" + port)
	runner := &core.Runner{
		Model:     modelclient.New(h.ChatURL("attacker"), "qwen2.5-0.5b-instruct"),
		Tools:     core.NewToolbox(core.NewHTTPRequestTool(base, egress, nil), core.NewExecTool()),
		Skill:     core.WarmIDORSkill,
		Target:    target,
		Board:     core.NewBlackboard(),
		Audit:     audit,
		Store:     st,
		Bounds:    core.Bounds{MaxSteps: 8, Wall: 120 * time.Second},
		CanaryURL: "http://169.254.169.254/latest/meta-data/",
	}
	res, err := runner.Run(ctx, core.Objective{
		Goal: "Capture the planted flag (GORED{...}).", FlagID: "idor-notes", Base: base,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Deterministic assertions (independent of the stochastic model):
	// 1. The run is persisted.
	row, err := st.GetRun(res.RunID)
	if err != nil || row.ID == 0 {
		t.Fatalf("run not persisted: %+v err=%v", row, err)
	}
	// 2. The containment beacon was denied and recorded in the trace.
	traceBytes, _ := os.ReadFile(tracePath)
	if !strings.Contains(string(traceBytes), "egress_denied") {
		t.Fatal("trace missing the denied egress beacon")
	}
	// 3. The trace hash-chain verifies.
	if ok, _ := audit.Verify(); !ok {
		t.Fatal("trace hash-chain failed to verify")
	}
	// 4. The warm skill drives the IDOR to an oracle-authoritative capture.
	if res.Outcome != "captured" {
		t.Fatalf("warm run did not capture (outcome=%s); the model must drive the IDOR", res.Outcome)
	}
	if res.CapturedVia == "" || !target.Oracle().Captured("idor-notes") {
		t.Fatalf("captured outcome was not oracle-authoritative: via=%q oracle=%v", res.CapturedVia, target.Oracle().Captured("idor-notes"))
	}
	// Anti-forgery: capture must come from the oracle, never a self-report alone.
	if res.ToolCalls == 0 {
		t.Fatal("captured without any tool call — a self-report must never count")
	}
	t.Logf("outcome=%s via=%s steps=%d tool_calls=%d wall_ms=%d tokens_in=%d tokens_out=%d findings=%d",
		res.Outcome, res.CapturedVia, res.Steps, res.ToolCalls, res.WallMS, res.TokensIn, res.TokensOut, len(res.Findings))
}
