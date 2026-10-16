package eva

import (
	"context"
	"github.com/t0ul/GORED/internal/bench"
	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/store"
	"sort"
	"strings"
	"time"
)

const assistBeat = 15 * time.Second

// run is one launched sweep's live state, kept in memory for this process.
type run struct {
	ID       string
	Stage    string
	Base     string
	Model    string
	Models   string // researcher-matrix model set (CSV); empty = single-model run on Model
	Trials   int
	Autonomy string // "piloted" | "assisted" | "autonomous"
	Status   string // "running" | "waiting" | "done" | "error" | "aborted"
	Err      string
	Started  time.Time
	Elapsed  string
	Sums     []core.ContenderSummary
	Trace    string
	Prompt   string // skill-instruction override for this run, empty = stage default

	// Pending is the open checkpoint awaiting the pilot, nil when none. cp relays the
	// pilot's decision back to the blocked Runner goroutine. Both are guarded by the
	// Server mutex.
	Pending    *pending
	cp         *pilotCheckpoint
	cancel     context.CancelFunc // cancels the run's context for a hard ABORT; nil until execute runs
	queuedHint string             // a mid-run directive, merged into the next checkpoint's hint
	slot       int                // the concurrency bay / port offset this run holds
	campaignID string             // the campaign that scheduled this run, empty for an interactive sortie
	targetName string             // the store target name, so the model's save_surface tool can attribute its map
	flags      *bench.Flags       // the run's bench flags, carried so a campaign can execute it after building
}

// mergeHints joins two non-empty directive hints, so a mid-run directive rides alongside the
// pilot's gate hint rather than replacing it.
func mergeHints(a, b string) string {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}

// IsMatrix reports whether this is a researcher-matrix sortie (several models on one stage).
func (r *run) IsMatrix() bool { return r.Models != "" }

// ModelLabel is the model(s) to show for this run: the matrix set when it is a matrix sortie,
// otherwise the single model. Centralizing it keeps the data columns honest (Model holds a
// single model, Models the set) while every render reads one label.
func (r *run) ModelLabel() string {
	if r.Models != "" {
		return "matrix: " + r.Models
	}
	return r.Model
}

// pending is a checkpoint surfaced to the pilot: the phase about to run, the ranked
// proposals to pick from, and a board snapshot for context.
type pending struct {
	Phase     string
	Proposals []core.Move
	Board     []core.Finding
}

// decision is the pilot's answer, relayed from the HTTP handler to the Runner.
type decision struct {
	chosen  []core.Move
	hint    string
	proceed bool
}

// pilotCheckpoint implements core.Checkpoint. Decide publishes the pending checkpoint to
// the run, then blocks until the pilot submits (piloted) or a short beat elapses
// (assisted). It is installed only for the piloted/assisted dial; autonomous runs carry
// no checkpoint at all, so they stay byte-for-byte the headless loop.
type pilotCheckpoint struct {
	srv      *Server
	run      *run
	autonomy string
	decided  chan decision
}

func (c *pilotCheckpoint) Decide(ctx context.Context, phase string, board *core.Blackboard, proposals []core.Move) ([]core.Move, string, bool) {
	c.srv.mu.Lock()
	c.run.Status = "waiting"
	c.run.Pending = &pending{Phase: phase, Proposals: proposals, Board: board.Findings()}
	c.srv.mu.Unlock()
	c.srv.persist(c.run)

	defer func() {
		c.srv.mu.Lock()
		c.run.Pending = nil
		if c.run.Status == "waiting" {
			c.run.Status = "running"
		}
		c.srv.mu.Unlock()
		c.srv.persist(c.run)
	}()

	if c.autonomy == "assisted" {
		select {
		case d := <-c.decided:
			return d.chosen, mergeHints(d.hint, c.takeQueuedHint()), d.proceed
		case <-time.After(assistBeat):
			var def []core.Move
			if len(proposals) > 0 {
				def = proposals[:1] // the model's top-ranked move
			}
			return def, c.takeQueuedHint(), true // a queued directive steers the auto-proceed
		case <-ctx.Done():
			return nil, "", false
		}
	}
	// piloted: block until the pilot decides (or the context is cancelled).
	select {
	case d := <-c.decided:
		return d.chosen, mergeHints(d.hint, c.takeQueuedHint()), d.proceed
	case <-ctx.Done():
		return nil, "", false
	}
}

// takeQueuedHint reads and clears any mid-run directive queued on the run.
func (c *pilotCheckpoint) takeQueuedHint() string {
	c.srv.mu.Lock()
	defer c.srv.mu.Unlock()
	h := c.run.queuedHint
	c.run.queuedHint = ""
	return h
}

func toEVARun(rn *run) store.EVARun {
	return store.EVARun{
		ID: rn.ID, Stage: rn.Stage, Base: rn.Base, Model: rn.Model, Models: rn.Models, Trials: rn.Trials,
		Autonomy: rn.Autonomy, Status: rn.Status, Err: rn.Err, Started: rn.Started,
		Elapsed: rn.Elapsed, Trace: rn.Trace, Prompt: rn.Prompt, Sums: rn.Sums,
	}
}

func fromEVARun(er store.EVARun) *run {
	return &run{
		ID: er.ID, Stage: er.Stage, Base: er.Base, Model: er.Model, Models: er.Models, Trials: er.Trials,
		Autonomy: er.Autonomy, Status: er.Status, Err: er.Err, Started: er.Started,
		Elapsed: er.Elapsed, Trace: er.Trace, Prompt: er.Prompt, Sums: er.Sums,
	}
}

// runView is the run plus render-time triage read from its trace (findings, repro). The
// triage is derived from the trace, never recomputed, so it stays an honest account of what
// the run actually did.
type runView struct {
	*run
	Events   []traceEvt     // the FEED lens: the event stream so far
	Findings []core.Finding // the FINDINGS lens
	Repro    string
	Targets  []targetNode // the MAP lens: the discovered surface
	Breached bool         // a capture landed — the Angel's pattern goes red
}

// targetNode is one discovered request on the target surface (the MAP lens). Last is the most
// recent tool_result bytes for that path, so clicking the node on the map can show what it returned.
type targetNode struct {
	Method string
	Path   string
	Last   string
}

// traceEvt is one trace record themed for the EVA timeline.
type traceEvt struct{ Span, Event, Detail, Cls string }

// sortedSums orders contenders by capture rate, then capture-per-Mtoken, then fewest tokens —
// the leaderboard's own ranking, so the themed table matches the research renderer.
func sortedSums(in []core.ContenderSummary) []core.ContenderSummary {
	out := make([]core.ContenderSummary, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CaptureRate != out[j].CaptureRate {
			return out[i].CaptureRate > out[j].CaptureRate
		}
		if out[i].CapturePerMTok != out[j].CapturePerMTok {
			return out[i].CapturePerMTok > out[j].CapturePerMTok
		}
		return out[i].MeanTokens < out[j].MeanTokens
	})
	return out
}

// normalizeModelsCSV cleans the matrix "models" form field: trim each entry, drop empties,
// rejoin with ", ". Empty in → empty out, which the launch handler reads as a single-model run.
func normalizeModelsCSV(s string) string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ", ")
}

// aborted reports whether every trial ended because the pilot aborted at a checkpoint.
func aborted(results []core.SweepResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, r := range results {
		if r.Outcome != "aborted" {
			return false
		}
	}
	return true
}
