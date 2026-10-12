//go:build live

// Live matrix test: a tiny grid (one model, warm, one flag, two trials) that proves
// Matrix.Run boots the model, runs each cell against a fresh target, and persists
// to the store. Excluded from offline `go test`. Run with:
//
//	go test -tags live -run TestLiveMatrix -v ./...
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
	"github.com/t0ul/GORED/store"
	gledger "github.com/t0ul/gledger"
	goserve "github.com/t0ul/goserve"
)

func TestLiveMatrix(t *testing.T) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".riskrancher", "models")
	const modelFile = "qwen2.5-0.5b-instruct.gguf"
	if ok, msg := (goserve.Config{Dir: dir, Models: []goserve.Model{{Name: "a", File: modelFile, Port: 1, Ctx: 1}}}).Available(); !ok {
		t.Fatalf("live lab not set up (%s)", msg)
	}

	st, _ := store.Open(filepath.Join(t.TempDir(), "runs.db"))
	defer st.Close()
	audit, _ := gledger.Open(filepath.Join(t.TempDir(), "trace.jsonl"), "gored")

	mx := &gored.Matrix{
		Spec: gored.MatrixSpec{
			Models: []string{modelFile}, Temps: []gored.SkillTemp{gored.SkillWarm},
			FlagIDs: []string{"idor-notes"}, Trials: 2,
			Bounds: gored.Bounds{MaxSteps: 4, Wall: 60 * time.Second},
		},
		Store: st,
		Audit: audit,
		Model: func(ctx context.Context, model string) (gored.ModelClient, func(), error) {
			cfg := goserve.Config{Dir: dir, Reclaim: true, ReadyTimeout: 90 * time.Second,
				Models: []goserve.Model{{Name: "attacker", File: model, Port: 11552, Ctx: 2048}}}
			h, err := goserve.Start(ctx, cfg)
			if err != nil {
				return nil, nil, err
			}
			return modelclient.New(h.ChatURL("attacker"), "qwen2.5-0.5b-instruct"), h.Close, nil
		},
		Target: func() (gored.RunTarget, error) {
			s, err := demotarget.New()
			if err != nil {
				return gored.RunTarget{}, err
			}
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			srv := &http.Server{Handler: s.Handler()}
			go func() { _ = srv.Serve(ln) }()
			return gored.RunTarget{Target: s, BaseURL: "http://" + ln.Addr().String(), Close: func() { _ = srv.Close() }}, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	ran, err := mx.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ran != 2 {
		t.Fatalf("want 2 runs, got %d", ran)
	}
	rows, err := st.Leaderboard()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range rows {
		if r.SkillTemp == "warm" && r.Difficulty == "easy" {
			found = true
			if r.N != 2 {
				t.Fatalf("warm/easy N=%d want 2", r.N)
			}
			if r.Captured == 0 {
				t.Fatal("warm IDOR should capture at least once with this model")
			}
		}
	}
	if !found {
		t.Fatal("no warm/easy leaderboard row")
	}
}
