package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	gledger "github.com/t0ul/gledger"
)

// Move is one proposed next action at a checkpoint: a concrete (surface, path, tool,
// why) the model ranked, or a deterministic router suggestion. The pilot picks a subset
// of these at the gate; the chosen moves plus a free-text hint become the directive the
// next phase runs within. A Move is a SUGGESTION the pilot judges — it never decides
// capture (only the oracle does), and its Source records whether the model or the
// deterministic router floor produced it.
type Move struct {
	Surface string `json:"surface"` // "html-page" | "json-api" | "spa-shell" | "unknown"
	Path    string `json:"path"`    // e.g. "/greeting?name=FUZZ"
	Tool    string `json:"tool"`    // e.g. "xss_scan"
	Why     string `json:"why"`     // one-line rationale
	Source  string `json:"source"`  // "model" | "router" (provenance, never trusted as truth)
}

// Checkpoint is the human-in-the-loop seam consulted at a phase boundary, BEFORE the
// loop spends tokens on the next phase. It is the type form of the autonomy dial:
//
//   - A nil Checkpoint means fully autonomous — the loop never pauses, byte-for-byte
//     the behaviour the headless CLI and the continuous ADD/CI gate depend on.
//   - A non-nil Checkpoint receives the phase just entered, the live board, and the
//     ranked proposals, and returns the chosen moves, a hint to steer the next phase,
//     and whether to proceed. proceed=false ends the run cleanly (outcome "aborted").
//
// A Checkpoint changes only WHICH move the loop spends tokens on; it never confirms a
// finding. Capture stays the oracle's call on the target's real bytes.
//
// It is named Checkpoint, not Gate, to keep it distinct from the egress gate
// (internal/tools.Gate) that contains every outbound request — a different concern.
type Checkpoint interface {
	Decide(ctx context.Context, phase string, board *Blackboard, proposals []Move) (chosen []Move, hint string, proceed bool)
}

// consultCheckpoint proposes moves, asks the Checkpoint to decide, and records the
// pilot's directive on the board so the next phase's prompt carries it. It returns false
// when the pilot aborts, so the caller stops the run. It is only reached when a
// Checkpoint is installed, so the autonomous path is untouched.
func (r *Runner) consultCheckpoint(ctx context.Context, traceID, phase string, msgs []Message, res *RunResult) bool {
	proposals := r.proposeMoves(ctx, traceID, phase, msgs, res)
	chosen, hint, proceed := r.Checkpoint.Decide(ctx, phase, r.Board, proposals)
	if !proceed {
		return false
	}
	r.applyDirective(chosen, hint, res.Steps)
	r.emit(traceID, "checkpoint", "decide", gledger.F{"phase": phase, "proposals": len(proposals), "chosen": len(chosen), "hint": hint})
	return true
}

// proposeMoves asks the model for ranked next moves given the board (one extra call,
// wired to the live model), then always appends the deterministic router's moves as the
// floor — so the pilot sees real options even when a small model flubs the JSON. Both
// kinds are suggestions; neither is authoritative.
func (r *Runner) proposeMoves(ctx context.Context, traceID, phase string, msgs []Message, res *RunResult) []Move {
	var moves []Move
	ask := Message{Role: RoleUser, Content: fmt.Sprintf(
		"Checkpoint for the %q phase. Based ONLY on the blackboard below, propose up to 4 ranked next moves. "+
			"Reply with a JSON array; each item {\"surface\":\"html-page|json-api|spa-shell\",\"path\":\"/<path>\",\"tool\":\"<one of: %s>\",\"why\":\"<one line>\"}. No prose.\n\nBlackboard:\n%s",
		phase, strings.Join(r.Tools.Names(), ", "), r.Board.Render())}
	if reply, usage, err := r.Model.Chat(ctx, append(append([]Message{}, msgs...), ask), ChatOpts{Temperature: 0.2, MaxTokens: 384}); err == nil {
		res.TokensIn += usage.PromptTokens
		res.TokensOut += usage.CompletionTokens
		r.emit(traceID, "checkpoint", "propose", gledger.F{"phase": phase, "reply": reply, "tokens_out": usage.CompletionTokens})
		moves = append(moves, parseMoves(reply)...)
	} else {
		r.emit(traceID, "checkpoint", "propose_error", gledger.F{"phase": phase, "error": err.Error()})
	}
	moves = append(moves, r.routerMoves()...)
	return dedupeMoves(moves)
}

// applyDirective writes the pilot's choice onto the board as a labelled note. The board
// is rendered into every subsequent prompt, so this is how a human decision steers the
// model — without touching the loop's control flow or the oracle.
func (r *Runner) applyDirective(chosen []Move, hint string, step int) {
	var parts []string
	for _, m := range chosen {
		s := strings.TrimSpace(m.Tool + " " + m.Path)
		if s != "" {
			parts = append(parts, s)
		}
	}
	dir := "PILOT DIRECTIVE"
	if len(parts) > 0 {
		dir += " — focus: " + strings.Join(parts, "; ")
	}
	if h := strings.TrimSpace(hint); h != "" {
		dir += " — hint: " + h
	}
	if dir == "PILOT DIRECTIVE" {
		dir += " — proceed"
	}
	r.Board.Add(FindHypothesis, dir, step)
}

// routerMoves is the deterministic floor: it routes each path already on the board to a
// tool by its class (json-api -> probe; a reflecting html-page -> xss_scan; else a plain
// GET). It reads only paths the run actually discovered, so the floor is grounded in real
// recon, never a baked-in answer.
func (r *Runner) routerMoves() []Move {
	seen := map[string]bool{}
	var out []Move
	for _, f := range r.Board.Findings() {
		for _, p := range pathsIn(f.Value) {
			if seen[p] {
				continue
			}
			seen[p] = true
			surface, tool := routeByPath(p, r.Tools)
			out = append(out, Move{Surface: surface, Path: p, Tool: tool, Why: "router floor: discovered path", Source: "router"})
		}
	}
	return out
}

// parseMoves pulls Move objects out of a model reply. It tolerates a bare array, loose
// objects, or prose around them: it extracts every balanced {...} and keeps the ones that
// name a path or a tool.
func parseMoves(reply string) []Move {
	reply = stripThink(reply)
	var out []Move
	for _, raw := range extractAllJSON(reply) {
		var m struct {
			Surface string `json:"surface"`
			Path    string `json:"path"`
			Tool    string `json:"tool"`
			Why     string `json:"why"`
		}
		if json.Unmarshal([]byte(raw), &m) == nil && (strings.TrimSpace(m.Path) != "" || strings.TrimSpace(m.Tool) != "") {
			out = append(out, Move{Surface: m.Surface, Path: m.Path, Tool: m.Tool, Why: m.Why, Source: "model"})
		}
	}
	return out
}

// routeByPath classifies a discovered path and names the tool to exercise it with,
// preferring a tool the current toolbox actually carries.
func routeByPath(p string, tb *Toolbox) (surface, tool string) {
	lp := strings.ToLower(p)
	switch {
	case strings.Contains(lp, "token") || strings.Contains(lp, "jwt") || strings.Contains(lp, "/auth") || strings.Contains(lp, "login"):
		// an auth/token surface: forge a token if the box carries the tool
		return "json-api", preferTool(tb, "jwt_forge", "api_request", "http_request")
	case strings.Contains(lp, "profile") || strings.Contains(lp, "account") || strings.Contains(lp, "/users") || strings.Contains(lp, "settings"):
		// a write surface for your own record: try mass assignment
		return "json-api", preferTool(tb, "mass_assign", "api_request", "http_request")
	case strings.Contains(lp, "/api") || strings.HasSuffix(lp, ".json"):
		// a JSON resource: an authenticated/id-swapped request, or a differential BAC check
		return "json-api", preferTool(tb, "api_request", "bola", "probe_endpoint", "http_request")
	case strings.Contains(lp, "?") || strings.Contains(lp, "search") || strings.Contains(lp, "greet") ||
		strings.Contains(lp, "echo") || strings.Contains(lp, "q=") || strings.Contains(lp, "name="):
		return "html-page", preferTool(tb, "xss_scan", "http_request")
	default:
		return "unknown", preferTool(tb, "http_request")
	}
}

// preferTool returns the first named tool the toolbox carries, else the last name given.
func preferTool(tb *Toolbox, names ...string) string {
	have := map[string]bool{}
	if tb != nil {
		for _, n := range tb.Names() {
			have[n] = true
		}
	}
	for _, n := range names {
		if have[n] {
			return n
		}
	}
	if len(names) > 0 {
		return names[len(names)-1]
	}
	return "http_request"
}

// dedupeMoves drops repeats keyed by (tool,path), keeping first-seen order so model
// proposals rank above the router floor.
func dedupeMoves(in []Move) []Move {
	seen := map[string]bool{}
	var out []Move
	for _, m := range in {
		k := m.Tool + " " + m.Path
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, m)
	}
	return out
}

// pathsIn extracts path-like tokens ("/..." or the path of a full URL) from a board
// value, so the router floor can route them.
func pathsIn(s string) []string {
	var out []string
	for _, tok := range strings.Fields(s) {
		tok = strings.Trim(tok, ".,;:)(\"'")
		if i := strings.Index(tok, "://"); i >= 0 {
			if j := strings.IndexByte(tok[i+3:], '/'); j >= 0 {
				out = append(out, tok[i+3+j:])
				continue
			}
		}
		if strings.HasPrefix(tok, "/") && len(tok) > 1 {
			out = append(out, tok)
		}
	}
	return out
}
