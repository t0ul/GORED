package gored

import (
	"strings"
	"testing"
)

func TestRenderLeaderboardHTML(t *testing.T) {
	rec := 0.5
	prec := 1.0
	sums := []ContenderSummary{
		{Contender: "solo(qwen3b)", Shape: ShapeSolo, Temp: SkillWarm, Trials: 2, Captured: 2, CaptureRate: 1.0, MeanToolCall: 2, MeanTokens: 1000, ParamsB: 3, CapturePerMTok: 1000, MeanRecall: &rec, MeanPrecision: &prec, ReplayHref: "replay-abc.html"},
		{Contender: "static+2doers", Shape: ShapeStatic, Temp: SkillCold, Trials: 2, Captured: 1, CaptureRate: 0.5, MeanToolCall: 3, MeanTokens: 2000, ParamsB: 6, CapturePerMTok: 250},
		{Contender: "planner(qwen1.5b)+2doers", Shape: ShapePlanner, Temp: SkillCold, Trials: 2, Captured: 0, CaptureRate: 0.0, MeanToolCall: 6, MeanTokens: 4000, ParamsB: 4.5},
	}
	html := string(RenderLeaderboardHTML(LeaderboardMeta{Title: "test board", Target: "demo", Trials: 2}, sums))

	for _, want := range []string{
		"<title>test board</title>", "solo(qwen3b)", "cap / Mtok", "A-solo", "100%", "2/2",
		">skill<",                                // the new column header
		`chip t-warm">warm`, `chip t-cold">cold`, // temp chips
		`href="replay-abc.html"`, // the BB replay link
	} {
		if !strings.Contains(html, want) {
			t.Errorf("leaderboard missing %q", want)
		}
	}
	// Highest capture rate (solo 100%) must render before the 0% planner row.
	if strings.Index(html, "solo(qwen3b)") > strings.Index(html, "planner(qwen1.5b)+2doers") {
		t.Error("rows not sorted by capture rate")
	}
	// Theme-aware: defines dark tokens behind both guards, with an explicit body bg.
	for _, want := range []string{`prefers-color-scheme:dark`, `:root[data-theme="dark"]`, "background:var(--bg)"} {
		if !strings.Contains(html, want) {
			t.Errorf("not theme-complete: missing %q", want)
		}
	}
	// No scripts embedded (safe to publish/open anywhere).
	if strings.Contains(strings.ToLower(html), "<script") {
		t.Error("leaderboard must not embed scripts")
	}
}

func TestCommaInt(t *testing.T) {
	cases := map[float64]string{0: "0", 999: "999", 1000: "1,000", 12345: "12,345", 1000000: "1,000,000"}
	for in, want := range cases {
		if got := commaInt(in); got != want {
			t.Errorf("commaInt(%v)=%q want %q", in, got, want)
		}
	}
}
