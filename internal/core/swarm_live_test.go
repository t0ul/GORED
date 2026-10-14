//go:build live

// Live swarm test: recon (1.5B) enumerates the demo target's surface onto a shared
// board, then the exploit agent (3B) reads the board and captures the flag,
// oracle-authoritative. Excluded from offline `go test`. Run with:
//
//	go test -tags live -run TestLiveSwarm -v ./...
package core_test

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	core "github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/demotarget"
	"github.com/t0ul/GORED/modelclient"
	gledger "github.com/t0ul/gledger"
	goserve "github.com/t0ul/goserve"
)

func TestLiveSwarm(t *testing.T) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".riskrancher", "models")
	cfg := goserve.Config{
		Dir: dir, Reclaim: true, ReadyTimeout: 150 * time.Second,
		Models: []goserve.Model{
			{Name: "recon", File: "qwen2.5-1.5b-instruct.gguf", Port: 11594, Ctx: 4096},
			{Name: "exploit", File: "qwen2.5-3b-instruct.gguf", Port: 11595, Ctx: 4096},
		},
	}
	if ok, msg := cfg.Available(); !ok {
		t.Fatalf("live lab not set up (%s)", msg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Second)
	defer cancel()
	h, err := goserve.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	target, _ := demotarget.New()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: target.Handler()}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	base := "http://" + ln.Addr().String()
	auth := base[len("http://"):]

	board := core.NewBlackboard()
	audit, _ := gledger.Open(filepath.Join(t.TempDir(), "t.jsonl"), "gored")
	egress := core.NewEgress(auth)

	reconTools := core.NewToolbox(core.NewDiscoverTool(base, egress))
	httpTool := core.NewHTTPRequestTool(base, egress, nil)
	httpTool.AllowMethods = map[string]bool{"GET": true, "HEAD": true}
	exploitTools := core.NewToolbox(httpTool, core.DiffTool{})

	sw := &core.Swarm{
		Name: "swarm(recon=qwen1.5b,exploit=qwen3b)", Board: board, Audit: audit, Target: target,
		CanaryURL: "http://169.254.169.254/latest/meta-data/",
		Agents: []core.Agent{
			{Name: "recon", Model: modelclient.New(h.ChatURL("recon"), "qwen1.5b"), Skill: core.ReconSkill, Tools: reconTools, Bounds: core.Bounds{MaxSteps: 4, Wall: 90 * time.Second}},
			{Name: "exploit", Model: modelclient.New(h.ChatURL("exploit"), "qwen3b"), Skill: core.WarmIDORSkill, Tools: exploitTools, Bounds: core.Bounds{MaxSteps: 6, Wall: 120 * time.Second}},
		},
	}
	res, err := sw.Run(ctx, core.Objective{Goal: "Capture the flag.", FlagID: "idor-notes", Base: base})
	if err != nil {
		t.Fatal(err)
	}

	// The recon agent must have handed real endpoints to the board.
	var endpoints int
	for _, f := range board.Findings() {
		if f.Type == core.FindEndpoint {
			endpoints++
		}
	}
	if endpoints == 0 {
		t.Fatal("recon posted no endpoint findings to the board")
	}
	// The exploit agent must have captured, oracle-authoritative.
	if res.Outcome != "captured" || res.CapturedVia == "" || !target.Oracle().Captured("idor-notes") {
		t.Fatalf("swarm did not capture oracle-authoritatively: outcome=%s via=%q", res.Outcome, res.CapturedVia)
	}
	t.Logf("swarm captured via %s; recon boarded %d endpoints; %d tool calls, %dms",
		res.CapturedVia, endpoints, res.ToolCalls, res.WallMS)
}
