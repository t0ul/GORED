package gored

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// Combos are ModelClients composed of base models, so the matrix and leaderboard
// score a combo as just another contestant (plan §8). Two are built here:
// planner/executor (a stronger model plans the next step, a cheaper one formats the
// tool call) and self-consistency (sample the next step K times, take the majority).

// PlannerExecutor runs a two-model step: the planner states the next action in one
// sentence, then the executor turns that into the tool-call JSON. The idea is that
// planning (reasoning) and execution (format compliance) stress different skills,
// and splitting them can beat either model alone.
type PlannerExecutor struct {
	Planner  ModelClient
	Executor ModelClient
}

func NewPlannerExecutor(planner, executor ModelClient) *PlannerExecutor {
	return &PlannerExecutor{Planner: planner, Executor: executor}
}

func (p *PlannerExecutor) Name() string {
	return fmt.Sprintf("planexec(%s->%s)", p.Planner.Name(), p.Executor.Name())
}

func (p *PlannerExecutor) Chat(ctx context.Context, msgs []Message, opts ChatOpts) (string, Usage, error) {
	planMsgs := append(cloneMsgs(msgs), Message{
		Role:    RoleUser,
		Content: "Think step by step, then state in ONE short sentence the single next action to take against the target. Do not output JSON yet.",
	})
	plan, pu, err := p.Planner.Chat(ctx, planMsgs, ChatOpts{Temperature: 0.2, MaxTokens: 120})
	if err != nil {
		return "", Usage{}, fmt.Errorf("planner: %w", err)
	}
	execMsgs := append(cloneMsgs(msgs), Message{
		Role:    RoleUser,
		Content: "Planned next action: " + plan + "\nNow output exactly one JSON object for that action and nothing else.",
	})
	reply, eu, err := p.Executor.Chat(ctx, execMsgs, ChatOpts{Temperature: opts.Temperature, MaxTokens: opts.MaxTokens})
	if err != nil {
		return "", Usage{}, fmt.Errorf("executor: %w", err)
	}
	return reply, Usage{
		PromptTokens:     pu.PromptTokens + eu.PromptTokens,
		CompletionTokens: pu.CompletionTokens + eu.CompletionTokens,
	}, nil
}

// SelfConsistency samples the next step K times from one model at a diversifying
// temperature and returns the majority action. A forged or malformed sample loses
// to the consensus, which tends to stabilize a small model's tool use.
type SelfConsistency struct {
	Inner ModelClient
	K     int
	Temp  float64
}

func NewSelfConsistency(inner ModelClient, k int, temp float64) *SelfConsistency {
	if k < 1 {
		k = 1
	}
	return &SelfConsistency{Inner: inner, K: k, Temp: temp}
}

func (s *SelfConsistency) Name() string {
	return fmt.Sprintf("selfcons(%s,k=%d)", s.Inner.Name(), s.K)
}

func (s *SelfConsistency) Chat(ctx context.Context, msgs []Message, opts ChatOpts) (string, Usage, error) {
	maxTok := opts.MaxTokens
	if maxTok == 0 {
		maxTok = 256
	}
	type sample struct {
		reply string
		key   string
	}
	counts := map[string]int{}
	repByKey := map[string]string{}
	var total Usage
	var firstReply string
	var lastErr error
	valid := 0
	for i := 0; i < s.K; i++ {
		reply, u, err := s.Inner.Chat(ctx, msgs, ChatOpts{Temperature: s.Temp, MaxTokens: maxTok})
		total.PromptTokens += u.PromptTokens
		total.CompletionTokens += u.CompletionTokens
		if err != nil {
			lastErr = err
			continue
		}
		if firstReply == "" {
			firstReply = reply
		}
		act, ok := parseAction(reply)
		if !ok {
			continue // malformed samples do not get a vote
		}
		valid++
		k := actionKey(act)
		counts[k]++
		if _, seen := repByKey[k]; !seen {
			repByKey[k] = reply
		}
	}
	if valid == 0 {
		if firstReply != "" {
			return firstReply, total, nil // no consensus; let the loop record a parse miss
		}
		if lastErr != nil {
			return "", total, lastErr
		}
		return "", total, nil
	}
	// Winner: highest vote; ties broken by the lexicographically smallest key for
	// determinism.
	var winners []string
	best := 0
	for k, c := range counts {
		if c > best {
			best = c
			winners = []string{k}
		} else if c == best {
			winners = append(winners, k)
		}
	}
	sort.Strings(winners)
	return repByKey[winners[0]], total, nil
}

// actionKey canonicalizes an action for voting: "done" groups all finish claims;
// a tool call is keyed by tool name plus its JSON-marshaled args (map keys are
// sorted by encoding/json, so the key is stable).
func actionKey(a action) string {
	if a.Done {
		return "done"
	}
	b, _ := json.Marshal(a.Args)
	return "tool:" + a.Tool + ":" + string(b)
}

func cloneMsgs(msgs []Message) []Message {
	out := make([]Message, len(msgs))
	copy(out, msgs)
	return out
}
