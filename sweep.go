package gored

import (
	"context"
	"fmt"
	"sort"
	"time"

	gledger "github.com/t0ul/gledger"
)

// Shape is one experiment configuration — how models and planning are arranged for
// a contender. The sweep compares the three the experiment turns on (plan
// GORED-SWARM-EXPERIMENT.md): a single model doing everything with tools, a model
// planner dividing work among small doers, and a deterministic planner doing the
// same so the planning compute is taken off a model entirely.
type Shape string

const (
	ShapeSolo    Shape = "A-solo"    // one model + tools does recon and exploit (the baseline to beat)
	ShapePlanner Shape = "B-planner" // a model planner + N small doers over a shared board (Squad + ModelPlanner)
	ShapeStatic  Shape = "E-static"  // a deterministic finding-graph planner + N doers (Squad + StaticPlanner)
)

// Runnable is anything the sweep runs for one trial. Runner (solo), Swarm
// (sequential roles), and Squad (planner + parallel doers) all already have this
// method, so a contender of any shape plugs into the same sweep.
type Runnable interface {
	Run(ctx context.Context, obj Objective) (RunResult, error)
}

// Contender is one fully-specified entry in the sweep: a name and shape, plus a
// Build that wires its runnable for a single fresh target. Build also returns the
// compute accounts to read afterward, so the sweep can report each shape's cost at
// iso-budget rather than on raw score — wrap each model client in an
// AccountingClient and hand back its account here. The host-specific wiring (boot a
// model, build tools, egress) lives in Build, in the cmd, so the library stays pure.
type Contender struct {
	Name  string
	Shape Shape
	Temp  SkillTemp // cold|warm scaffolding level this contender uses; "" if unset
	Build func(rt RunTarget) (Runnable, []*ComputeAccount, error)
	// TraceFilter, if set, is a function the sweep calls with each trial's RunResult so
	// the caller can remember a trace id per contender (used to link a blackboard
	// replay from the leaderboard). Optional.
	TraceFilter func(res RunResult)
}

// SweepResult is one trial of one contender: its outcome, the compute it spent, and
// (when a ruler and a verdict mapping are set) how it scored against ground truth.
type SweepResult struct {
	Contender   string           `json:"contender"`
	Shape       Shape            `json:"shape"`
	Temp        SkillTemp        `json:"temp,omitempty"`
	Trial       int              `json:"trial"`
	TraceID     string           `json:"trace_id,omitempty"`
	Outcome     string           `json:"outcome"`
	CapturedVia string           `json:"captured_via,omitempty"`
	Steps       int              `json:"steps"`
	ToolCalls   int              `json:"tool_calls"`
	TokensIn    int              `json:"tokens_in"`
	TokensOut   int              `json:"tokens_out"`
	WallMS      int64            `json:"wall_ms"`
	ParamsB     float64          `json:"params_b"` // summed declared footprint of the models used
	Compute     []ComputeAccount `json:"compute,omitempty"`
	Score       *Score           `json:"score,omitempty"`
}

// Scorer maps a trial's verdicts to a Score against the frozen ground truth. The sweep
// depends on this interface, not on the concrete *Ruler, so the scoring implementation (the
// evidence-ladder Ruler) can live in its own package without the sweep importing it — a
// one-way dependency (the scorer's package imports the sweep's vocabulary, not the reverse).
type Scorer interface {
	Score(verdicts []Verdict, minRung Ladder) Score
}

// Sweep runs a set of contenders over a fresh target for a number of trials each,
// so A/B/E are measured on identical, unforgeable flags. Capture is oracle- (or
// detector-) authoritative inside each runnable; the sweep only records and scores.
type Sweep struct {
	Contenders []Contender
	Target     TargetProvider
	FlagID     string
	Goal       string
	Trials     int
	Audit      *gledger.AuditLog
	// Ruler and Verdicts are optional. When both are set, each trial's capture is
	// mapped to verdicts (e.g. via EscapeProofs + Validator) and scored against the
	// frozen ground truth, so the comparison is recall/precision, not just capture.
	// Ruler is a Scorer (the *Ruler satisfies it), so the sweep stays decoupled from the
	// concrete scoring package.
	Ruler    Scorer
	Verdicts func(res RunResult, rt RunTarget) []Verdict
	MinRung  Ladder // scoring threshold; empty => reachable
	OnTrial  func(SweepResult)
}

// Run executes every contender for every trial and returns one SweepResult per
// trial. A contender that simply fails to capture is a normal result; only a wiring
// error (target build, Build, runnable error) aborts.
func (s *Sweep) Run(ctx context.Context) ([]SweepResult, error) {
	trials := s.Trials
	if trials < 1 {
		trials = 1
	}
	var out []SweepResult
	for _, c := range s.Contenders {
		for tr := 1; tr <= trials; tr++ {
			rt, err := s.Target()
			if err != nil {
				return out, fmt.Errorf("sweep %q trial %d: build target: %w", c.Name, tr, err)
			}
			runnable, accts, berr := c.Build(rt)
			if berr != nil {
				rt.Close()
				return out, fmt.Errorf("sweep %q trial %d: build contender: %w", c.Name, tr, berr)
			}
			start := time.Now()
			res, rerr := runnable.Run(ctx, Objective{Goal: s.Goal, FlagID: s.FlagID, Base: rt.BaseURL})
			wall := time.Since(start)
			if rerr != nil {
				rt.Close()
				return out, fmt.Errorf("sweep %q trial %d: run: %w", c.Name, tr, rerr)
			}

			if c.TraceFilter != nil {
				c.TraceFilter(res)
			}
			sr := SweepResult{
				Contender: c.Name, Shape: c.Shape, Temp: c.Temp, Trial: tr, TraceID: res.TraceID,
				Outcome: res.Outcome, CapturedVia: res.CapturedVia,
				Steps: res.Steps, ToolCalls: res.ToolCalls,
				TokensIn: res.TokensIn, TokensOut: res.TokensOut,
				WallMS: wall.Milliseconds(),
			}
			for _, a := range accts {
				if a == nil {
					continue
				}
				sr.Compute = append(sr.Compute, *a)
				sr.ParamsB += a.ParamsB
			}
			if s.Ruler != nil && s.Verdicts != nil {
				sc := s.Ruler.Score(s.Verdicts(res, rt), s.MinRung)
				sr.Score = &sc
			}
			rt.Close()

			if s.OnTrial != nil {
				s.OnTrial(sr)
			}
			out = append(out, sr)
		}
	}
	return out, nil
}

// ContenderSummary rolls a contender's trials into the comparison row: capture
// rate, mean compute, and (when scored) mean recall/precision. This is the
// leaderboard row keyed by {shape, models, budget}.
type ContenderSummary struct {
	Contender    string    `json:"contender"`
	Shape        Shape     `json:"shape"`
	Temp         SkillTemp `json:"temp,omitempty"` // cold|warm scaffolding level
	Trials       int       `json:"trials"`
	Captured     int       `json:"captured"`
	CaptureRate  float64   `json:"capture_rate"`
	MeanToolCall float64   `json:"mean_tool_calls"`
	MeanTokens   float64   `json:"mean_tokens"` // in+out
	MeanWallMS   float64   `json:"mean_wall_ms"`
	ParamsB      float64   `json:"params_b"` // footprint (constant across a contender's trials)
	// CapturePerMTok is capture rate per million tokens spent — the iso-budget
	// headline: which shape captures most for the compute it burns. Zero when no
	// tokens were spent (e.g. a deterministic planner that never calls a model).
	CapturePerMTok float64  `json:"capture_per_mtok"`
	MeanRecall     *float64 `json:"mean_recall,omitempty"`
	MeanPrecision  *float64 `json:"mean_precision,omitempty"`
	// TraceID is a representative trial's trace (a captured one is preferred), so the
	// leaderboard can offer a blackboard replay of that run. ReplayHref, when set by
	// the renderer's caller, is the link the row points at.
	TraceID    string `json:"trace_id,omitempty"`
	ReplayHref string `json:"replay_href,omitempty"`
	// MemPct is the model's contamination score for this target (0..1): how much it
	// recalled the real target unprompted. nil when not probed. A high value means the
	// discovery numbers may reflect memorization rather than reasoning.
	MemPct *float64 `json:"mem_pct,omitempty"`
}

// Summarize rolls trial results into one row per contender, in input order of first
// appearance, so the table reads A, B, E. It is pure: it does no I/O and can be
// tested on hand-built results.
func Summarize(results []SweepResult) []ContenderSummary {
	type acc struct {
		sum           ContenderSummary
		tok           float64
		tc            float64
		wall          float64
		rec           float64
		prec          float64
		rn            int // trials that carried a score
		capturedTrace bool
	}
	accs := map[string]*acc{}
	var order []string
	for _, r := range results {
		a, ok := accs[r.Contender]
		if !ok {
			a = &acc{sum: ContenderSummary{Contender: r.Contender, Shape: r.Shape, Temp: r.Temp}}
			accs[r.Contender] = a
			order = append(order, r.Contender)
		}
		a.sum.Trials++
		if r.Outcome == "captured" {
			a.sum.Captured++
		}
		// Keep a representative trace for the replay link: prefer a captured trial's,
		// otherwise the first seen, so every row can link to an actual run.
		if r.TraceID != "" && (a.sum.TraceID == "" || (r.Outcome == "captured" && !a.capturedTrace)) {
			a.sum.TraceID = r.TraceID
			if r.Outcome == "captured" {
				a.capturedTrace = true
			}
		}
		a.tc += float64(r.ToolCalls)
		a.tok += float64(r.TokensIn + r.TokensOut)
		a.wall += float64(r.WallMS)
		a.sum.ParamsB = r.ParamsB // constant across a contender's trials
		if r.Score != nil {
			a.rec += r.Score.Recall
			a.prec += r.Score.Precision
			a.rn++
		}
	}
	var out []ContenderSummary
	for _, name := range order {
		a := accs[name]
		n := float64(a.sum.Trials)
		a.sum.CaptureRate = float64(a.sum.Captured) / n
		a.sum.MeanToolCall = a.tc / n
		a.sum.MeanTokens = a.tok / n
		a.sum.MeanWallMS = a.wall / n
		if a.tok > 0 {
			meanTok := a.tok / n
			a.sum.CapturePerMTok = a.sum.CaptureRate / (meanTok / 1e6)
		}
		if a.rn > 0 {
			rec := a.rec / float64(a.rn)
			prec := a.prec / float64(a.rn)
			a.sum.MeanRecall = &rec
			a.sum.MeanPrecision = &prec
		}
		out = append(out, a.sum)
	}
	return out
}

// Table renders the summaries as a fixed-width comparison table for a terminal.
func Table(sums []ContenderSummary) string {
	rows := make([]ContenderSummary, len(sums))
	copy(rows, sums)
	// Stable, informative order: by capture rate desc, then fewer tokens.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].CaptureRate != rows[j].CaptureRate {
			return rows[i].CaptureRate > rows[j].CaptureRate
		}
		return rows[i].MeanTokens < rows[j].MeanTokens
	})
	out := fmt.Sprintf("%-28s %-10s %-5s %7s %8s %9s %5s %11s  %s\n",
		"contender", "shape", "skill", "cap%", "tools", "tokens", "mem%", "cap/Mtok", "recall/prec")
	for _, r := range rows {
		rp := "-"
		if r.MeanRecall != nil {
			rp = fmt.Sprintf("%.2f/%.2f", *r.MeanRecall, *r.MeanPrecision)
		}
		temp := string(r.Temp)
		if temp == "" {
			temp = "-"
		}
		mem := "-"
		if r.MemPct != nil {
			mem = fmt.Sprintf("%.0f%%", *r.MemPct*100)
		}
		out += fmt.Sprintf("%-28s %-10s %-5s %6.0f%% %8.1f %9.0f %5s %11.2f  %s\n",
			trunc(r.Contender, 28), string(r.Shape), temp, r.CaptureRate*100,
			r.MeanToolCall, r.MeanTokens, mem, r.CapturePerMTok, rp)
	}
	return out
}
