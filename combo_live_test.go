//go:build live

// Live combo test: both combos (self-consistency and planner/executor) drive the
// real loop against the real target to an oracle-authoritative capture. Excluded
// from offline `go test`. Run with:
//
//	go test -tags live -run TestLiveCombos -v ./...
package gored_test

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/demotarget"
	"github.com/t0ul/GORED/modelclient"
	gledger "github.com/t0ul/gledger"
	goserve "github.com/t0ul/goserve"
)

func TestLiveCombos(t *testing.T) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".riskrancher", "models")
	const small = "qwen2.5-0.5b-instruct.gguf"
	const big = "qwen2.5-1.5b-instruct.gguf"
	cfg := goserve.Config{
		Dir: dir, Reclaim: true, ReadyTimeout: 150 * time.Second,
		Models: []goserve.Model{
			{Name: "small", File: small, Port: 11560, Ctx: 2048},
			{Name: "big", File: big, Port: 11561, Ctx: 2048},
		},
	}
	if ok, msg := cfg.Available(); !ok {
		t.Fatalf("live lab not set up (%s)", msg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	h, err := goserve.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	smallC := modelclient.New(h.ChatURL("small"), "qwen2.5-0.5b-instruct")
	bigC := modelclient.New(h.ChatURL("big"), "qwen2.5-1.5b-instruct")

	combos := map[string]gored.ModelClient{
		"self-consistency": gored.NewSelfConsistency(smallC, 3, 0.7),
		"planner/executor": gored.NewPlannerExecutor(bigC, smallC),
	}
	for label, client := range combos {
		t.Run(label, func(t *testing.T) {
			target, _ := demotarget.New()
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			srv := &http.Server{Handler: target.Handler()}
			go func() { _ = srv.Serve(ln) }()
			defer srv.Close()
			base := "http://" + ln.Addr().String()
			host, port, _ := net.SplitHostPort(ln.Addr().String())
			audit, _ := gledger.Open(filepath.Join(t.TempDir(), "t.jsonl"), "gored")

			runner := &gored.Runner{
				Model:     client,
				Tools:     gored.NewToolbox(gored.NewHTTPRequestTool(base, gored.NewEgress(host+":"+port), nil), gored.NewExecTool()),
				Skill:     gored.WarmIDORSkill,
				Target:    target,
				Board:     gored.NewBlackboard(),
				Audit:     audit,
				Bounds:    gored.Bounds{MaxSteps: 5, Wall: 90 * time.Second},
				CanaryURL: "http://169.254.169.254/latest/meta-data/",
			}
			res, err := runner.Run(ctx, gored.Objective{Goal: "Capture the flag.", FlagID: "idor-notes", Base: base})
			if err != nil {
				t.Fatal(err)
			}
			if res.Outcome != "captured" || res.CapturedVia == "" || !target.Oracle().Captured("idor-notes") {
				t.Fatalf("%s did not capture oracle-authoritatively: outcome=%s via=%q", label, res.Outcome, res.CapturedVia)
			}
			t.Logf("%s (%s): captured via %s, %d tool calls, %dms", label, client.Name(), res.CapturedVia, res.ToolCalls, res.WallMS)
		})
	}
}
