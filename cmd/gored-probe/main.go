// Command gored-probe points the cold agent at a local app you are building and
// lets it recon and try things on its own, posting findings to the blackboard. It
// is the "continuous in-house pentest" entry point: no planted flags, no hand-fed
// exploit — just a small OSS model, the sandbox primitives, an egress allowlist to
// the target, and a method guard so it cannot mutate a real app unless you let it.
//
// It prints the blackboard the agent built and the outcome; the full per-step
// trace lands in the gledger file for replay.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/probes"
	"github.com/t0ul/GORED/modelclient"
	gledger "github.com/t0ul/gledger"
	goserve "github.com/t0ul/goserve"
)

// externalTarget is a real app GORED does not instrument: it has no server-side
// oracle, so capture is never auto-detected. The point here is to watch the agent
// recon and try things, and read the blackboard it builds.
type externalTarget struct{ name string }

func (e externalTarget) Manifest() core.Manifest {
	return core.Manifest{Name: e.name}
}
func (e externalTarget) Status() []core.FlagStatus { return nil }

func main() {
	var (
		url      = flag.String("url", "http://127.0.0.1:8080", "target base URL (local app under test)")
		modelF   = flag.String("model", "qwen2.5-1.5b-instruct.gguf", "GGUF file under -modeldir")
		modelDir = flag.String("modeldir", defaultModelDir(), "directory holding GGUF files")
		port     = flag.Int("model-port", 11580, "model server port")
		steps    = flag.Int("steps", 10, "max objective-loop steps")
		methods  = flag.String("methods", "GET,HEAD", "allowed HTTP methods (csv); read-only by default")
		goal     = flag.String("goal", "Recon this web app and find a security weakness: an endpoint that returns data without proper authorization, or a way to reach something you should not. Report what you find.", "agent objective")
		traceP   = flag.String("trace", "gored-probe-trace.jsonl", "gledger audit trace path")
	)
	flag.Parse()

	ctx := context.Background()
	cfg := goserve.Config{
		Dir: *modelDir, Reclaim: true, ReadyTimeout: 120 * time.Second, Stdout: io.Discard,
		Models: []goserve.Model{{Name: "attacker", File: *modelF, Port: *port, Ctx: 4096}},
	}
	if ok, msg := cfg.Available(); !ok {
		log.Fatalf("local model not available (%s)", msg)
	}
	h, err := goserve.Start(ctx, cfg)
	must(err)
	defer h.Close()

	egress := core.NewEgress(hostPort(*url))
	httpTool := core.NewHTTPRequestTool(*url, egress, nil)
	httpTool.AllowMethods = methodSet(*methods)

	audit, err := gledger.Open(*traceP, "gored")
	must(err)

	runner := &core.Runner{
		Model:     modelclient.New(h.ChatURL("attacker"), modelName(*modelF)),
		Tools:     core.NewToolbox(httpTool, probes.NewDiscoverTool(*url, egress), core.NewExecTool()),
		Skill:     core.ReconSkill,
		Target:    externalTarget{name: *url},
		Board:     core.NewBlackboard(),
		Audit:     audit,
		Bounds:    core.Bounds{MaxSteps: *steps, Wall: 180 * time.Second},
		CanaryURL: "http://169.254.169.254/latest/meta-data/",
	}
	log.Printf("probing %s with %s (methods=%s, cold skill), watching the blackboard fill",
		*url, modelName(*modelF), *methods)

	res, err := runner.Run(ctx, core.Objective{Goal: *goal, FlagID: "n/a", Base: *url})
	must(err)

	fmt.Println("\n==== blackboard (what the agent posted) ====")
	if len(res.Findings) == 0 {
		fmt.Println("(empty)")
	}
	for _, f := range res.Findings {
		fmt.Printf("  #%d [%s] (step %d) %s\n", f.ID, f.Type, f.SourceStep, f.Value)
	}

	fmt.Println("\n==== run summary ====")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"target": *url, "model": modelName(*modelF), "skill": runner.Skill.Name,
		"outcome": res.Outcome, "steps": res.Steps, "tool_calls": res.ToolCalls,
		"egress_denied_beacon": res.EgressDenied, "tokens_in": res.TokensIn, "tokens_out": res.TokensOut,
	})
	fmt.Printf("\ntrace (full per-step replay): %s\n", *traceP)
}

func methodSet(csv string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(csv, ",") {
		if p = strings.ToUpper(strings.TrimSpace(p)); p != "" {
			m[p] = true
		}
	}
	return m
}

func hostPort(baseURL string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(baseURL, "http://"), "https://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

func modelName(file string) string { return strings.TrimSuffix(filepath.Base(file), ".gguf") }

func defaultModelDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".riskrancher", "models")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
