// Command gored-matrix runs the experiment grid — models × {cold,warm} × flags × N
// trials — against the benign demo target, persists every run, and prints the
// leaderboard and the cold→warm lift. Each model is booted one at a time via
// goserve. Authorized local testing only; everything talks to loopback.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/demotarget"
	"github.com/t0ul/GORED/modelclient"
	"github.com/t0ul/GORED/store"
	gledger "github.com/t0ul/gledger"
	goserve "github.com/t0ul/goserve"
)

func main() {
	var (
		modelsF  = flag.String("models", "qwen2.5-0.5b-instruct.gguf,qwen2.5-1.5b-instruct.gguf", "comma-separated GGUF files under -modeldir")
		tempsF   = flag.String("temps", "cold,warm", "comma-separated skill temps")
		flagsF   = flag.String("flags", "idor-notes,ssrf-internal", "comma-separated flag ids")
		trials   = flag.Int("trials", 5, "trials per cell")
		steps    = flag.Int("steps", 6, "max objective-loop steps per run")
		modelDir = flag.String("modeldir", defaultModelDir(), "directory holding GGUF files")
		port     = flag.Int("model-port", 11550, "port for the model server (one model at a time)")
		dbPath   = flag.String("db", "gored-matrix.db", "SQLite run store path")
		traceP   = flag.String("trace", "gored-matrix-trace.jsonl", "gledger audit trace path")
	)
	flag.Parse()

	ctx := context.Background()
	spec := gored.MatrixSpec{
		Models:  split(*modelsF),
		Temps:   temps(*tempsF),
		FlagIDs: split(*flagsF),
		Trials:  *trials,
		Bounds:  gored.Bounds{MaxSteps: *steps, Wall: 120 * time.Second},
	}

	audit, err := gledger.Open(*traceP, "gored")
	must(err)
	st, err := store.Open(*dbPath)
	must(err)
	defer st.Close()

	done := 0
	total := len(spec.Cells())
	mx := &gored.Matrix{
		Spec:   spec,
		Model:  gooseProvider(*modelDir, *port),
		Target: targetProvider,
		Store:  st,
		Audit:  audit,
		OnCell: func(c gored.Cell, res gored.RunResult) {
			done++
			log.Printf("[%d/%d] %-26s %-4s %-14s trial %d -> %-8s (%d calls, %dms)",
				done, total, modelName(c.Model), c.Temp, c.Flag, c.Trial, res.Outcome, res.ToolCalls, res.WallMS)
		},
	}
	ran, err := mx.Run(ctx)
	must(err)
	log.Printf("completed %d runs", ran)

	printLeaderboard(st)
	printLift(st)
	ok, n := audit.Verify()
	fmt.Printf("\ntrace: %s (hash-chain verified=%v over %d records)\nstore: %s\n", *traceP, ok, n, *dbPath)
}

func gooseProvider(dir string, port int) gored.ModelProvider {
	return func(ctx context.Context, model string) (gored.ModelClient, func(), error) {
		cfg := goserve.Config{
			Dir: dir, Reclaim: true, ReadyTimeout: 120 * time.Second, Stdout: io.Discard,
			Models: []goserve.Model{{Name: "attacker", File: model, Port: port, Ctx: 2048}},
		}
		if ok, msg := cfg.Available(); !ok {
			return nil, nil, fmt.Errorf("%s", msg)
		}
		bootCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
		h, err := goserve.Start(bootCtx, cfg)
		if err != nil {
			cancel()
			return nil, nil, err
		}
		client := modelclient.New(h.ChatURL("attacker"), modelName(model))
		return client, func() { h.Close(); cancel() }, nil
	}
}

func targetProvider() (gored.RunTarget, error) {
	s, err := demotarget.New()
	if err != nil {
		return gored.RunTarget{}, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return gored.RunTarget{}, err
	}
	srv := &http.Server{Handler: s.Handler()}
	go func() { _ = srv.Serve(ln) }()
	return gored.RunTarget{
		Target:  s,
		BaseURL: "http://" + ln.Addr().String(),
		Close:   func() { _ = srv.Close() },
	}, nil
}

func printLeaderboard(st *store.Store) {
	rows, err := st.Leaderboard()
	must(err)
	fmt.Println("\n==== Leaderboard (per model × skill × difficulty) ====")
	fmt.Println("| model | skill | difficulty | N | captured | capture_rate | ±stderr | med_calls | med_ms |")
	fmt.Println("|---|---|---|--:|--:|--:|--:|--:|--:|")
	for _, r := range rows {
		fmt.Printf("| %s | %s | %s | %d | %d | %.2f | %.2f | %d | %d |\n",
			r.Model, r.SkillTemp, r.Difficulty, r.N, r.Captured, r.CaptureRate, r.StdErr, r.MedianToolCalls, r.MedianWallMS)
	}
}

func printLift(st *store.Store) {
	lifts, err := st.ColdWarmLift()
	must(err)
	fmt.Println("\n==== Cold→warm lift (per model × difficulty) ====")
	fmt.Println("| model | difficulty | cold_rate | warm_rate | lift | N(cold) | N(warm) |")
	fmt.Println("|---|---|--:|--:|--:|--:|--:|")
	for _, l := range lifts {
		fmt.Printf("| %s | %s | %.2f | %.2f | %+.2f | %d | %d |\n",
			l.Model, l.Difficulty, l.ColdRate, l.WarmRate, l.Lift, l.NCold, l.NWarm)
	}
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func temps(s string) []gored.SkillTemp {
	var out []gored.SkillTemp
	for _, p := range split(s) {
		out = append(out, gored.SkillTemp(p))
	}
	return out
}

func modelName(file string) string {
	name := filepath.Base(file)
	return strings.TrimSuffix(name, ".gguf")
}

func defaultModelDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".riskrancher", "models")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
