package eva

import (
	"github.com/t0ul/GORED/internal/core"
	gledger "github.com/t0ul/gledger"
	"os"
	"strings"
)

// parseRunTrace reads a run's trace once and builds all three lenses: the event feed, the
// blackboard findings, the discovered surface (map), the capture repro, and whether a capture
// landed. One pass, so the page seeds live and finished runs the same way.
func parseRunTrace(path string) (events []traceEvt, findings []core.Finding, targets []targetNode, repro string, breached bool) {
	recs, err := gledger.Read(path)
	if err != nil {
		return
	}
	seen := map[string]int{} // tool key -> index in targets
	lastKey := ""
	for _, rec := range recs {
		ev := traceEvt{Span: rec.Span, Event: rec.Event, Detail: eventDetail(rec.Fields)}
		switch {
		case strings.Contains(rec.Event, "capture"), strings.Contains(rec.Event, "breach"):
			ev.Cls = "hit"
			breached = true
		case strings.Contains(rec.Event, "denied"), strings.Contains(rec.Event, "egress"):
			ev.Cls = "contain"
		case strings.Contains(rec.Event, "error"):
			ev.Cls = "warn"
		}
		events = append(events, ev)

		if rec.Span == "board" && rec.Event == "finding" {
			f := core.Finding{}
			if v, ok := rec.Fields["type"].(string); ok {
				f.Type = core.FindingType(v)
			}
			if v, ok := rec.Fields["value"].(string); ok {
				f.Value = v
			}
			findings = append(findings, f)
		}
		if rec.Span == "tool" && rec.Event == "tool_call" {
			if args, ok := rec.Fields["args"].(map[string]any); ok {
				method := strings.ToUpper(asStr(args["method"]))
				if method == "" {
					method = "GET"
				}
				p := asStr(args["path"])
				if p == "" {
					p = urlPath(asStr(args["url"]))
				}
				if p != "" && strings.HasPrefix(p, "/") {
					if len(p) > 80 {
						p = p[:80] + "…"
					}
					k := method + " " + p
					if _, ok := seen[k]; !ok {
						seen[k] = len(targets)
						targets = append(targets, targetNode{Method: method, Path: p})
					}
					lastKey = k
				}
			}
		}
		if rec.Span == "tool" && rec.Event == "tool_result" {
			// A discover result lists the paths the crawl FOUND (not just what the agent requested):
			// fold them into the surface map, so it reflects the enumerated surface and project memory
			// persists it for later passes.
			for _, p := range discoveredPaths(asStr(rec.Fields["result"])) {
				k := "GET " + p
				if _, ok := seen[k]; !ok {
					seen[k] = len(targets)
					targets = append(targets, targetNode{Method: "GET", Path: p, Last: "(discovered by crawl)"})
				}
			}
		}
		if rec.Span == "tool" && rec.Event == "tool_result" && lastKey != "" {
			if idx, ok := seen[lastKey]; ok {
				if res := asStr(rec.Fields["result"]); res != "" {
					if len(res) > 300 {
						res = res[:300] + "…"
					}
					targets[idx].Last = res
				}
			}
		}
		if rec.Span == "verify" && rec.Event == "repro" {
			if v, ok := rec.Fields["curl"].(string); ok && v != "" {
				repro = v
			}
		}
	}
	return
}

// eventDetail picks the most informative field for a trace line, truncated.
func eventDetail(f map[string]any) string {
	for _, k := range []string{"tool", "via", "phase", "hint", "value", "result", "error", "reply", "curl", "beacon"} {
		if s := asStr(f[k]); s != "" {
			s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
			if len(s) > 160 {
				s = s[:160] + "…"
			}
			return s
		}
	}
	return ""
}

// traceTriage reads a run's trace and returns its blackboard findings and the capture repro
// command. It parses the already-written trace, so it reflects exactly what happened.
func traceTriage(path string) ([]core.Finding, string) {
	recs, err := gledger.Read(path)
	if err != nil {
		return nil, ""
	}
	var findings []core.Finding
	var repro string
	for _, rec := range recs {
		switch {
		case rec.Span == "board" && rec.Event == "finding":
			f := core.Finding{}
			if v, ok := rec.Fields["type"].(string); ok {
				f.Type = core.FindingType(v)
			}
			if v, ok := rec.Fields["value"].(string); ok {
				f.Value = v
			}
			if v, ok := rec.Fields["id"].(float64); ok {
				f.ID = int(v)
			}
			findings = append(findings, f)
		case rec.Span == "verify" && rec.Event == "repro":
			if v, ok := rec.Fields["curl"].(string); ok && v != "" {
				repro = v
			}
		}
	}
	return findings, repro
}

// traceSitemap reads a run's trace and returns the distinct requests the agent made on the
// target — the surface map the target "Angel" panel draws. It parses the already-written
// tool-call events, so it reflects exactly what was touched, and fills live as the run goes.
func traceSitemap(path string) []targetNode {
	recs, err := gledger.Read(path)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var nodes []targetNode
	for _, rec := range recs {
		if rec.Span != "tool" {
			continue
		}
		// A discover result enumerated paths the crawl FOUND — draw them on the map too, not just
		// the paths the agent then requested (so the map fills as discovery happens, live).
		if rec.Event == "tool_result" {
			for _, p := range discoveredPaths(asStr(rec.Fields["result"])) {
				if key := "GET " + p; !seen[key] {
					seen[key] = true
					nodes = append(nodes, targetNode{Method: "GET", Path: p, Last: "(discovered by crawl)"})
				}
			}
			continue
		}
		if rec.Event != "tool_call" {
			continue
		}
		args, ok := rec.Fields["args"].(map[string]any)
		if !ok {
			continue
		}
		method := strings.ToUpper(asStr(args["method"]))
		if method == "" {
			method = "GET"
		}
		p := asStr(args["path"])
		if p == "" {
			p = urlPath(asStr(args["url"]))
		}
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		if len(p) > 80 {
			p = p[:80] + "…"
		}
		if key := method + " " + p; !seen[key] {
			seen[key] = true
			nodes = append(nodes, targetNode{Method: method, Path: p})
		}
	}
	if len(nodes) > 50 {
		nodes = nodes[:50]
	}
	return nodes
}

func asStr(v any) string { s, _ := v.(string); return s }

// discoveredPaths extracts the paths a discover (crawl) tool result enumerated, so the surface map
// and project memory reflect what the crawl FOUND, not only what the agent went on to request. It
// only parses a discover result (prefix "discovered "), so it never scrapes "/..." tokens out of an
// ordinary HTTP response body.
func discoveredPaths(result string) []string {
	if !strings.HasPrefix(result, "discovered ") {
		return nil
	}
	var out []string
	for _, tok := range strings.Fields(result) {
		if strings.HasPrefix(tok, "/") {
			if len(tok) > 80 {
				tok = tok[:80] + "…"
			}
			out = append(out, tok)
		}
	}
	return out
}

// urlPath returns the path portion of a full URL, or "" if it has no path.
func urlPath(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		if j := strings.IndexByte(u[i+3:], '/'); j >= 0 {
			return u[i+3+j:]
		}
		return ""
	}
	return u
}

// readTraceLines returns the trace file's complete (newline-terminated) lines and their
// count. A trailing partial line mid-write is excluded, so a reader never sees half a
// record. A missing file yields none — the stream just waits for it to appear.
func readTraceLines(path string) ([]string, int) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil, 0
	}
	nl := strings.LastIndexByte(string(b), '\n')
	if nl < 0 {
		return nil, 0
	}
	raw := strings.Split(string(b[:nl]), "\n")
	out := raw[:0]
	for _, ln := range raw {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out, len(out)
}
