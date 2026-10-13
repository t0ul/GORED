//go:build live

// Live squad test: a planner's two leads run as two doers IN PARALLEL over one
// shared board, each its own model instance. One lead is the IDOR; the oracle
// confirms that doer's capture and the squad cancels the other. Excluded from
// offline `go test`. Run with:
//
//	go test -tags live -run TestLiveSquad -v ./...
package gored_test

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/demotarget"
	"github.com/t0ul/GORED/modelclient"
	gledger "github.com/t0ul/gledger"
	goserve "github.com/t0ul/goserve"
)

func TestLiveSquad(t *testing.T) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".riskrancher", "models")
	cfg := goserve.Config{
		Dir: dir, Reclaim: true, ReadyTimeout: 150 * time.Second,
		Models: []goserve.Model{
			{Name: "doerA", File: "qwen2.5-3b-instruct.gguf", Port: 11596, Ctx: 4096},
			{Name: "doerB", File: "qwen2.5-3b-instruct.gguf", Port: 11597, Ctx: 4096},
		},
	}
	if ok, msg := cfg.Available(); !ok {
		t.Fatalf("live lab not set up (%s)", msg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 220*time.Second)
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

	board := gored.NewBlackboard()
	audit, _ := gledger.Open(filepath.Join(t.TempDir(), "t.jsonl"), "gored")
	egress := gored.NewEgress(auth)

	// Each doer gets its own http+diff toolbox and its own model instance, so the two
	// leads run genuinely in parallel rather than queueing on one server.
	tools := func() *gored.Toolbox {
		ht := gored.NewHTTPRequestTool(base, egress, nil)
		ht.AllowMethods = map[string]bool{"GET": true, "HEAD": true}
		return gored.NewToolbox(ht, gored.DiffTool{})
	}
	models := map[string]gored.ModelClient{
		"A": modelclient.New(h.ChatURL("doerA"), "qwen3b-A"),
		"B": modelclient.New(h.ChatURL("doerB"), "qwen3b-B"),
	}

	sq := &gored.Squad{
		Name: "squad(planner=static,doers=2xqwen3b)", Board: board, Audit: audit, Target: target,
		CanaryURL: "http://169.254.169.254/latest/meta-data/",
		Workers:   2,
		Planner: gored.StaticPlanner{Label: "static-2", Leads: []gored.Lead{
			{ID: 1, Goal: "Capture the flag via a broken-object-level-authorization (IDOR) bug on the notes API.", Hint: "idor"},
			{ID: 2, Goal: "Capture the flag by reaching an admin-only route as a low-privilege identity.", Hint: "bac"},
		}},
		NewDoer: func(l gored.Lead) gored.Agent {
			skill := gored.SoloColdSkill
			if strings.Contains(l.Hint, "idor") {
				skill = gored.WarmIDORSkill // the lead that can actually land it
			}
			slot := "A"
			if l.ID%2 == 0 {
				slot = "B"
			}
			return gored.Agent{
				Name: "doer" + slot, Model: models[slot], Skill: skill, Tools: tools(),
				Bounds: gored.Bounds{MaxSteps: 6, Wall: 120 * time.Second},
			}
		},
	}

	res, err := sq.Run(ctx, gored.Objective{Goal: "Capture the flag.", FlagID: "idor-notes", Base: base})
	if err != nil {
		t.Fatal(err)
	}

	// Both leads must have been posted to the shared board (the planner ran).
	var leads int
	for _, f := range board.Findings() {
		if f.Type == gored.FindHypothesis && strings.HasPrefix(f.Value, "lead:") {
			leads++
		}
	}
	if leads != 2 {
		t.Fatalf("want 2 leads on the board, got %d", leads)
	}
	if res.Outcome != "captured" || res.CapturedVia == "" || !target.Oracle().Captured("idor-notes") {
		t.Fatalf("squad did not capture oracle-authoritatively: outcome=%s via=%q", res.Outcome, res.CapturedVia)
	}
	t.Logf("squad captured via %s; %d parallel doers; %d tool calls, %dms",
		res.CapturedVia, leads, res.ToolCalls, res.WallMS)
}
