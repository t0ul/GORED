// Command gored-replay reconstructs a recorded GORED run from its persisted
// gledger trace, so you can see exactly what happened and WHO did it — which OSS
// model emitted each action — without rerunning anything. It reuses gledger to
// verify the hash chain and read the records (gledger owns the log format), prints
// a text transcript, and with -html delegates to gledger's self-contained HTML
// timeline player. A tampered trace fails verification and is refused.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	gledger "github.com/t0ul/gledger"
)

func main() {
	var (
		tracePath = flag.String("trace", "gored-swarm-trace.jsonl", "gledger trace file to replay")
		traceID   = flag.String("trace-id", "", "replay only this trace id (default: all in the file)")
		htmlOut   = flag.String("html", "", "also write a self-contained HTML player to this path")
	)
	flag.Parse()

	// Integrity first: a replay is only evidence if the chain verifies.
	ok, n := gledger.VerifyFile(*tracePath)
	fmt.Printf("trace %s: hash-chain verified=%v over %d records\n", *tracePath, ok, n)
	if !ok {
		fmt.Println("REFUSING to replay: the trace failed integrity verification (tampered or truncated).")
		os.Exit(1)
	}

	recs, err := gledger.Read(*tracePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *traceID != "" {
		var f []gledger.Record
		for _, r := range recs {
			if r.TraceID == *traceID {
				f = append(f, r)
			}
		}
		recs = f
	}

	models := map[string]bool{}
	fmt.Println("\n==== REPLAY ====")
	for _, r := range recs {
		if m := str(r.Fields["model"]); m != "" {
			models[m] = true
		}
		switch r.Event {
		case "swarm_start":
			fmt.Printf("SWARM %s  target=%s  flag=%s\n", str(r.Fields["swarm"]), str(r.Fields["target"]), str(r.Fields["flag_id"]))
		case "run_start":
			fmt.Printf("RUN model=%s skill=%s target=%s\n", str(r.Fields["model"]), str(r.Fields["skill"]), str(r.Fields["target"]))
		case "role_start":
			fmt.Printf("\n--- %s agent  (model=%s, skill=%s) ---\n", strings.ToUpper(str(r.Fields["role"])), str(r.Fields["model"]), str(r.Fields["skill"]))
		case "egress_denied":
			fmt.Printf("  [contained] off-target egress blocked: %s\n", str(r.Fields["beacon"]))
		case "model_call":
			fmt.Printf("  model(%s) says: %s\n", str(r.Fields["model"]), clip(str(r.Fields["reply"]), 150))
		case "parse_miss":
			fmt.Printf("  (model produced no valid tool call)\n")
		case "repeat_skipped":
			fmt.Printf("  (refused to repeat %s)\n", str(r.Fields["tool"]))
		case "tool_call":
			fmt.Printf("  -> tool %s %s\n", str(r.Fields["tool"]), clip(jsonStr(r.Fields["args"]), 150))
		case "tool_result":
			fmt.Printf("     result: %s\n", clip(str(r.Fields["result"]), 110))
		case "finding":
			fmt.Printf("     board += [%s] %s\n", str(r.Fields["type"]), clip(str(r.Fields["value"]), 90))
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
	fmt.Printf("\n==== provenance ====\nevery action above was emitted by these models: %s\n", strings.Join(ms, ", "))
	fmt.Printf("this is a replay of a hash-verified recording; no model ran during replay.\n")

	if *htmlOut != "" {
		title := "GORED replay"
		if len(ms) > 0 {
			title = "GORED replay — " + strings.Join(ms, " + ")
		}
		pageHTML, err := gledger.RenderHTML(title, recs, ok)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(*htmlOut, pageHTML, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("\nHTML player written: %s\n", *htmlOut)
	}
}

func str(v any) string { s, _ := v.(string); return s }
func clip(s string, n int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
func jsonStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
