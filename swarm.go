package gored

import (
	"context"
	"fmt"
	"time"

	gledger "github.com/t0ul/gledger"
)

// Agent is one role in a swarm: its own model, skill, tools, context window, and
// bounds. Roles share the blackboard and the trace but not their transcripts — the
// board is the only channel between them, which is what keeps each context sharp
// (plan §5). The recon role distils findings; the exploit role reads them.
type Agent struct {
	Name   string
	Model  ModelClient
	Skill  Skill
	Tools  *Toolbox
	Bounds Bounds
}

// Swarm runs several roles against one target over a shared blackboard. v1 is
// sequential: each role runs its objective loop in order (recon, then exploit),
// and because the loop is board-driven (not transcript-driven), the exploit role's
// prompt carries the board the recon role built, never recon's raw scan output.
type Swarm struct {
	Board     *Blackboard
	Audit     *gledger.AuditLog
	Target    Target
	Agents    []Agent
	Store     RunStore
	CanaryURL string
	// Name identifies the swarm as a contestant on the leaderboard, e.g.
	// "swarm(recon=qwen0.5b,exploit=qwen3b)".
	Name string
	// SkillTemp labels the swarm's run (cold|warm, by the exploit agent's skill) so
	// it groups on the leaderboard like a solo. Empty records "swarm".
	SkillTemp string
}

// Run executes the roles in order, stopping as soon as the oracle reports the flag
// captured. It returns one aggregate RunResult across all roles.
func (s *Swarm) Run(ctx context.Context, obj Objective) (RunResult, error) {
	traceID := gledger.NewTraceID()
	start := time.Now()
	res := RunResult{TraceID: traceID, Outcome: "failed"}

	s.emit(traceID, "swarm", "swarm_start", gledger.F{
		"swarm": s.Name, "roles": s.roleNames(), "flag_id": obj.FlagID, "target": obj.Base,
	})

	var runID int64
	if s.Store != nil {
		temp := s.SkillTemp
		if temp == "" {
			temp = "swarm"
		}
		id, err := s.Store.StartRun(traceID, RunMeta{
			SuiteVersion: "phase5", Model: s.Name, Skill: "recon+exploit", SkillTemp: temp,
			Target: obj.Base, FlagID: obj.FlagID, Difficulty: s.difficultyOf(obj.FlagID),
		})
		if err != nil {
			return res, fmt.Errorf("swarm store start: %w", err)
		}
		runID = id
		res.RunID = id
	}

	for _, role := range s.Agents {
		r := &Runner{
			Model: role.Model, Tools: role.Tools, Skill: role.Skill,
			Target: s.Target, Board: s.Board, Audit: s.Audit,
			Bounds: role.Bounds, CanaryURL: s.CanaryURL,
		}
		s.emit(traceID, "swarm", "role_start", gledger.F{"role": role.Name, "skill": role.Skill.Name})
		rr, err := r.Run(ctx, obj)
		if err != nil {
			return res, fmt.Errorf("swarm role %q: %w", role.Name, err)
		}
		// Aggregate across roles.
		res.Steps += rr.Steps
		res.ToolCalls += rr.ToolCalls
		res.TokensIn += rr.TokensIn
		res.TokensOut += rr.TokensOut
		if rr.EgressDenied {
			res.EgressDenied = true
		}
		if rr.ModelClaim != "" {
			res.ModelClaim = rr.ModelClaim
		}
		s.emit(traceID, "swarm", "role_end", gledger.F{
			"role": role.Name, "outcome": rr.Outcome, "tool_calls": rr.ToolCalls,
			"board_findings": len(s.Board.Findings()),
		})
		if rr.Outcome == "captured" {
			res.Outcome, res.CapturedVia = "captured", rr.CapturedVia
			break
		}
	}

	res.WallMS = time.Since(start).Milliseconds()
	res.Findings = s.Board.Findings()
	s.emit(traceID, "swarm", "swarm_end", gledger.F{
		"swarm": s.Name, "outcome": res.Outcome, "captured_via": res.CapturedVia,
		"steps": res.Steps, "tool_calls": res.ToolCalls, "wall_ms": res.WallMS,
		"tokens_in": res.TokensIn, "tokens_out": res.TokensOut,
	})

	if s.Store != nil {
		for _, f := range res.Findings {
			_ = s.Store.AddFinding(runID, f)
		}
		_ = s.Store.FinishRun(runID, RunStats{
			Outcome: res.Outcome, ToolCalls: res.ToolCalls, WallMS: res.WallMS,
			TokensIn: res.TokensIn, TokensOut: res.TokensOut,
		})
	}
	return res, nil
}

func (s *Swarm) roleNames() string {
	out := ""
	for i, r := range s.Agents {
		if i > 0 {
			out += "->"
		}
		out += r.Name
	}
	return out
}

func (s *Swarm) difficultyOf(flagID string) Difficulty {
	for _, f := range s.Target.Manifest().Flags {
		if f.ID == flagID {
			return f.Difficulty
		}
	}
	return ""
}

func (s *Swarm) emit(traceID, span, event string, f gledger.F) {
	if s.Audit != nil {
		s.Audit.Emit(traceID, span, event, f)
	}
}
