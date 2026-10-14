package validate_test

import (
	"testing"

	"github.com/t0ul/GORED/internal/core"
	validate "github.com/t0ul/GORED/internal/validate"
)

// TestRulerScore checks recall/precision/confirmed against a small ground-truth ruler that
// mirrors the RR shape: two authz true-positives, one known-good endpoint, one false-
// positive dependency. The verdicts find one TP at the exploitable rung, miss the other,
// correctly leave the known-good unflagged, and wrongly flag the fp — exercising every path.
func TestRulerScore(t *testing.T) {
	ruler := &validate.Ruler{App: "rr", Entries: []validate.RulerEntry{
		{App: "rr", Locus: "/api/tickets", Class: "authz", Label: validate.LabelTruePositive},
		{App: "rr", Locus: "/api/drafts/report/{id}", Class: "idor", Label: validate.LabelTruePositive},
		{App: "rr", Locus: "/api/admin", Class: "authz", Label: validate.LabelKnownGood},
		{App: "rr", Locus: "golang.org/x/crypto", Class: "sca", Label: validate.LabelFalsePositive},
	}}

	verdicts := []core.Verdict{
		{App: "rr", Locus: "/api/tickets", Rung: core.LadderExploitable},  // TP, confirmed
		{App: "rr", Locus: "/api/admin", Rung: core.LadderReported},       // known-good, only reported -> not flagged (good)
		{App: "rr", Locus: "golang.org/x/crypto", Rung: core.LadderReachable}, // fp flagged -> false positive
		// /api/drafts/report/{id} absent -> a miss
	}

	s := ruler.Score(verdicts, core.LadderReachable)

	if s.TPTotal != 2 || s.TPFound != 1 || s.FN != 1 {
		t.Errorf("want 2 TP / 1 found / 1 missed, got %+v", s)
	}
	if s.FP != 1 || len(s.FalsePositives) != 1 {
		t.Errorf("x/crypto flagged should count as 1 false positive, got FP=%d %v", s.FP, s.FalsePositives)
	}
	if len(s.Confirmed) != 1 || s.Confirmed[0] != "rr:/api/tickets" {
		t.Errorf("the exploitable TP should be confirmed, got %v", s.Confirmed)
	}
	if s.Recall != 0.5 {
		t.Errorf("recall should be 0.5, got %v", s.Recall)
	}
	if s.Precision != 0.5 {
		t.Errorf("precision should be 1 TP / (1 TP + 1 FP) = 0.5, got %v", s.Precision)
	}
}

// TestRulerLocusNormalization confirms a ruler entry and a verdict on the same instance
// route match through the shared locus reducer: /api/drafts/report/5 matches {id}.
func TestRulerLocusNormalization(t *testing.T) {
	ruler := &validate.Ruler{Entries: []validate.RulerEntry{
		{App: "rr", Locus: "/api/drafts/report/{id}", Label: validate.LabelTruePositive},
	}}
	verdicts := []core.Verdict{{App: "rr", Locus: "/api/drafts/report/5", Rung: core.LadderTriggerable}}
	s := ruler.Score(verdicts, core.LadderReachable)
	if s.TPFound != 1 {
		t.Errorf("an instance route should match the {id} ruler entry, got %+v", s)
	}
}
