// Command gored-scout is the planner step: point it at any local web app and it
// uses a LOCAL model to turn the discovered surface into a test plan — which
// endpoints look like authorization boundaries worth testing, what weakness to
// try, and where to plant a canary to prove it. It does the "general idea of what
// to test" half; the swarm/exploit agent then actually tests it. Read-only and
// contained; nothing but discovery runs here.
package main

import (
	"context"
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
	goserve "github.com/t0ul/goserve"
)

func main() {
	var (
		url      = flag.String("url", "http://127.0.0.1:8080", "local app to scout")
		modelF   = flag.String("model", "qwen2.5-3b-instruct.gguf", "local planner model GGUF")
		modelDir = flag.String("modeldir", defaultModelDir(), "GGUF directory")
		port     = flag.Int("model-port", 11620, "model server port")
	)
	flag.Parse()
	ctx := context.Background()

	// 1. Enumerate the real surface (deterministic, read-only).
	egress := core.NewEgress(hostPort(*url))
	disc := probes.NewDiscoverTool(*url, egress)
	out, err := disc.Call(ctx, map[string]any{"path": "/"})
	must(err)
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		if p := strings.TrimSpace(line); strings.HasPrefix(p, "/") {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		log.Fatalf("discover found no paths at %s (is it up?)", *url)
	}
	fmt.Printf("discovered %d endpoint(s) at %s:\n  %s\n\n", len(paths), *url, strings.Join(paths, "\n  "))

	// 2. Local model reasons about WHICH to test and WHERE to plant a canary.
	cfg := goserve.Config{
		Dir: *modelDir, Reclaim: true, ReadyTimeout: 120 * time.Second, Stdout: io.Discard,
		Models: []goserve.Model{{Name: "planner", File: *modelF, Port: *port, Ctx: 4096}},
	}
	if ok, msg := cfg.Available(); !ok {
		log.Fatalf("local model not available (%s)", msg)
	}
	h, err := goserve.Start(ctx, cfg)
	must(err)
	defer h.Close()
	model := modelclient.New(h.ChatURL("planner"), name(*modelF))

	sys := `You are a web-app pentest planner. Given a list of an app's real endpoints, pick the ones that are likely AUTHORIZATION BOUNDARIES — resources owned by a user or role that another user should not reach (think broken access control / IDOR / missing authorization). For each one output ONE line:
- <method path> — <weakness to test> — plant a canary by: <how to create a privileged record to test it>
Only list real candidates from the provided endpoints. Be concise. No preamble.`
	user := "Endpoints:\n" + strings.Join(paths, "\n") + "\n\nTest plan:"
	plan, _, err := model.Chat(ctx, []core.Message{
		{Role: core.RoleSystem, Content: sys},
		{Role: core.RoleUser, Content: user},
	}, core.ChatOpts{Temperature: 0.2, MaxTokens: 400})
	must(err)

	fmt.Printf("==== test plan (by %s, local) ====\n%s\n", model.Name(), strings.TrimSpace(plan))
	fmt.Printf("\nnext: run the swarm against the candidates, then verify each finding with a generated+executed repro.\n")
}

func hostPort(base string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}
func name(file string) string { return strings.TrimSuffix(filepath.Base(file), ".gguf") }
func defaultModelDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".riskrancher", "models")
}
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
