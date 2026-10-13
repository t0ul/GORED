package gored

import (
	"math"
	"strings"
	"testing"
)

func TestSummarizeRollup(t *testing.T) {
	f := func(x float64) *float64 { return &x }
	results := []SweepResult{
		// A-solo: 2 trials, 1 capture, 1000 tokens each.
		{Contender: "A", Shape: ShapeSolo, Trial: 1, Outcome: "captured", ToolCalls: 4, TokensIn: 600, TokensOut: 400, ParamsB: 7, Score: &Score{Recall: 1.0, Precision: 1.0}},
		{Contender: "A", Shape: ShapeSolo, Trial: 2, Outcome: "failed", ToolCalls: 6, TokensIn: 600, TokensOut: 400, ParamsB: 7, Score: &Score{Recall: 0.0, Precision: 0.0}},
		// E-static: 1 trial, captured, zero tokens (deterministic planner, no model calls here).
		{Contender: "E", Shape: ShapeStatic, Trial: 1, Outcome: "captured", ToolCalls: 3, TokensIn: 0, TokensOut: 0, ParamsB: 1.5},
	}
	sums := Summarize(results)
	if len(sums) != 2 {
		t.Fatalf("want 2 rows, got %d", len(sums))
	}
	// Order preserved: A first, E second.
	if sums[0].Contender != "A" || sums[1].Contender != "E" {
		t.Fatalf("order not preserved: %+v", sums)
	}
	a := sums[0]
	if a.Trials != 2 || a.Captured != 1 || a.CaptureRate != 0.5 {
		t.Errorf("A rollup wrong: %+v", a)
	}
	if a.MeanTokens != 1000 || a.MeanToolCall != 5 {
		t.Errorf("A means wrong: tokens=%v tools=%v", a.MeanTokens, a.MeanToolCall)
	}
	// cap/Mtok = 0.5 / (1000/1e6) = 500.
	if math.Abs(a.CapturePerMTok-500) > 1e-6 {
		t.Errorf("A cap/Mtok = %v, want 500", a.CapturePerMTok)
	}
	if a.MeanRecall == nil || math.Abs(*a.MeanRecall-0.5) > 1e-9 {
		t.Errorf("A mean recall wrong: %v", a.MeanRecall)
	}
	e := sums[1]
	// Zero tokens => cap/Mtok stays 0 (no divide-by-zero), score absent.
	if e.CaptureRate != 1.0 || e.CapturePerMTok != 0 || e.MeanRecall != nil {
		t.Errorf("E rollup wrong: %+v", e)
	}
	_ = f
}

func TestTableRendersAndOrders(t *testing.T) {
	sums := []ContenderSummary{
		{Contender: "lowcap", Shape: ShapePlanner, Trials: 2, Captured: 0, CaptureRate: 0.0, MeanTokens: 500},
		{Contender: "hicap", Shape: ShapeSolo, Trials: 2, Captured: 2, CaptureRate: 1.0, MeanTokens: 900},
	}
	out := Table(sums)
	if !strings.Contains(out, "contender") || !strings.Contains(out, "cap/Mtok") {
		t.Fatalf("header missing:\n%s", out)
	}
	// hicap (rate 1.0) must sort above lowcap (rate 0.0).
	if strings.Index(out, "hicap") > strings.Index(out, "lowcap") {
		t.Errorf("table not sorted by capture rate:\n%s", out)
	}
}
