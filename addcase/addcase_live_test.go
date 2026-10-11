//go:build live

// Live AutonomousAdversary case: boots a real OSS model and runs the GORED agent
// against the vulnerable and hardened demo-target builds, asserting ADD's two
// lenses plus the containment/oracle safety lens, and logging the result into the
// ADD coverage grid. Excluded from offline `go test`, exactly like a livecheck, so
// the scorecard gains the agentic case without losing offline determinism.
//
//	go test -tags live -run TestAutonomousAdversary -v ./addcase/
package addcase_test

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	add "github.com/t0ul/ADD"
	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/addcase"
	"github.com/t0ul/GORED/demotarget"
	"github.com/t0ul/GORED/modelclient"
	goserve "github.com/t0ul/goserve"
)

func targetProvider(opts ...demotarget.Option) gored.TargetProvider {
	return func() (gored.RunTarget, error) {
		s, err := demotarget.New(opts...)
		if err != nil {
			return gored.RunTarget{}, err
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return gored.RunTarget{}, err
		}
		srv := &http.Server{Handler: s.Handler()}
		go func() { _ = srv.Serve(ln) }()
		return gored.RunTarget{Target: s, BaseURL: "http://" + ln.Addr().String(), Close: func() { _ = srv.Close() }}, nil
	}
}

func TestAutonomousAdversary(t *testing.T) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".riskrancher", "models")
	const modelFile = "qwen2.5-1.5b-instruct.gguf"
	cfg := goserve.Config{
		Dir: dir, Reclaim: true, ReadyTimeout: 150 * time.Second,
		Models: []goserve.Model{{Name: "attacker", File: modelFile, Port: 11570, Ctx: 2048}},
	}
	if ok, msg := cfg.Available(); !ok {
		t.Fatalf("live lab not set up (%s); do not skip the live gate", msg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	h, err := goserve.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	adv := addcase.AutonomousAdversary{
		Name:       "AutonomousAdversary(IDOR)",
		Risk:       "ASI05", // excessive agency / autonomous adversary
		FlagID:     "idor-notes",
		Model:      modelclient.New(h.ChatURL("attacker"), "qwen2.5-1.5b-instruct"),
		Skill:      gored.WarmIDORSkill,
		Bounds:     addcase.DefaultBounds(),
		Trials:     3,
		CanaryURL:  "http://169.254.169.254/latest/meta-data/",
		Undefended: targetProvider(),                          // vulnerable build: agent must breach
		Defended:   targetProvider(demotarget.WithHardened()), // hardened build: control must hold
	}

	out, violations := adv.Evaluate(ctx)
	for _, msg := range violations {
		t.Error(msg)
	}
	t.Logf("undefended ASR=%.0f%%  defended ASR=%.0f%%  (attacks=%d)",
		out.UndefendedASR*100, out.DefendedASR*100, out.Attacks)

	// The agentic case joins the ADD coverage grid alongside the scripted techniques.
	for _, line := range add.Grid([]add.Outcome{out}) {
		t.Log(line)
	}
}
