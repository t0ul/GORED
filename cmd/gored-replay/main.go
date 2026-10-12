// Command gored-replay reconstructs a recorded GORED run from its persisted
// gledger trace (and optional run store), so you can see exactly what happened and
// WHO did it — which OSS model emitted each action — without rerunning anything.
// It verifies the trace's hash chain first, so a tampered or hand-edited trace is
// detected: the replay is evidence, not a retelling.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	gledger "github.com/t0ul/gledger"
)

type rec struct {
	TraceID string         `json:"trace_id"`
	Span    string         `json:"span"`
	Event   string         `json:"event"`
	Fields  map[string]any `json:"fields"`
}

func main() {
	var (
		tracePath = flag.String("trace", "gored-swarm-trace.jsonl", "gledger trace file to replay")
		traceID   = flag.String("trace-id", "", "replay only this trace id (default: all in the file)")
	)
	flag.Parse()

	// 1. Integrity: the trace is hash-chained; a replay is only trustworthy if the
	// chain verifies. If it does not, the recording was altered.
	ok, n := gledger.VerifyFile(*tracePath)
	fmt.Printf("trace %s: hash-chain verified=%v over %d records\n", *tracePath, ok, n)
	if !ok {
		fmt.Println("REFUSING to replay: the trace failed integrity verification (tampered or truncated).")
		os.Exit(1)
	}

	f, err := os.Open(*tracePath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var recs []rec
	models := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r rec
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		if *traceID != "" && r.TraceID != *traceID {
			continue
		}
		recs = append(recs, r)
		if m, _ := r.Fields["model"].(string); m != "" {
			models[m] = true
		}
	}

	fmt.Println("\n==== REPLAY ====")
	role := ""
	for _, r := range recs {
		switch r.Event {
		case "swarm_start":
			fmt.Printf("SWARM %s  target=%s  flag=%s\n", str(r.Fields["swarm"]), str(r.Fields["target"]), str(r.Fields["flag_id"]))
		case "run_start":
			fmt.Printf("RUN model=%s skill=%s target=%s\n", str(r.Fields["model"]), str(r.Fields["skill"]), str(r.Fields["target"]))
		case "role_start":
			role = str(r.Fields["role"])
			fmt.Printf("\n--- %s agent  (model=%s, skill=%s) ---\n", strings.ToUpper(role), str(r.Fields["model"]), str(r.Fields["skill"]))
		case "containment":
		case "egress_denied":
			fmt.Printf("  [contained] off-target egress blocked: %s\n", str(r.Fields["beacon"]))
		case "model_call":
			fmt.Printf("  model(%s) says: %s\n", str(r.Fields["model"]), oneLine(str(r.Fields["reply"]), 150))
		case "parse_miss":
			fmt.Printf("  (model produced no valid tool call)\n")
		case "tool_call":
			fmt.Printf("  -> tool %s %s\n", str(r.Fields["tool"]), compactArgs(r.Fields["args"]))
		case "tool_result":
			fmt.Printf("     result: %s\n", oneLine(str(r.Fields["result"]), 110))
		case "capture_detected":
			fmt.Printf("  *** CAPTURE: %s (source=%s) ***\n", str(r.Fields["via"]), str(r.Fields["source"]))
		case "run_end", "swarm_end":
			fmt.Printf("  end: outcome=%s via=%s tool_calls=%v\n", str(r.Fields["outcome"]), str(r.Fields["captured_via"]), r.Fields["tool_calls"])
		}
	}

	ms := make([]string, 0, len(models))
	for m := range models {
		ms = append(ms, m)
	}
	sort.Strings(ms)
	fmt.Printf("\n==== provenance ====\n")
	fmt.Printf("every action above was emitted by these models: %s\n", strings.Join(ms, ", "))
	fmt.Printf("this is a replay of a hash-verified recording; no model ran during replay.\n")
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}
func compactArgs(v any) string {
	b, _ := json.Marshal(v)
	return oneLine(string(b), 160)
}
