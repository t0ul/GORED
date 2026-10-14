package store_test

import (
	"math"
	"path/filepath"
	"testing"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/store"
)

// seed writes one finished run with the given shape to a real SQLite store.
func seed(t *testing.T, st *store.Store, model, temp, diff, outcome string, toolCalls, wallMS int) {
	t.Helper()
	id, err := st.StartRun("trace", core.RunMeta{
		Model: model, SkillTemp: temp, Difficulty: core.Difficulty(diff), FlagID: "f",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishRun(id, core.RunStats{Outcome: outcome, ToolCalls: toolCalls, WallMS: int64(wallMS)}); err != nil {
		t.Fatal(err)
	}
}

func TestLeaderboardAggregates(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// qwenA warm/easy: 3 of 4 captured, with tool-call counts 1,2,3 among captures.
	seed(t, st, "qwenA", "warm", "easy", "captured", 1, 100)
	seed(t, st, "qwenA", "warm", "easy", "captured", 2, 200)
	seed(t, st, "qwenA", "warm", "easy", "captured", 3, 300)
	seed(t, st, "qwenA", "warm", "easy", "failed", 0, 50)
	// qwenA cold/easy: 1 of 2 captured.
	seed(t, st, "qwenA", "cold", "easy", "captured", 1, 120)
	seed(t, st, "qwenA", "cold", "easy", "failed", 0, 40)

	rows, err := st.Leaderboard()
	if err != nil {
		t.Fatal(err)
	}
	var warm *store.LeaderboardRow
	for i := range rows {
		if rows[i].Model == "qwenA" && rows[i].SkillTemp == "warm" {
			warm = &rows[i]
		}
	}
	if warm == nil {
		t.Fatal("no warm row")
	}
	if warm.N != 4 || warm.Captured != 3 {
		t.Fatalf("warm N/captured wrong: %+v", warm)
	}
	if math.Abs(warm.CaptureRate-0.75) > 1e-9 {
		t.Fatalf("warm capture_rate = %v want 0.75", warm.CaptureRate)
	}
	if warm.MedianToolCalls != 2 { // median of 1,2,3 among captures
		t.Fatalf("median tool calls = %d want 2", warm.MedianToolCalls)
	}
	if warm.MedianWallMS != 200 {
		t.Fatalf("median wall = %d want 200", warm.MedianWallMS)
	}
	// Leaderboard sorts by capture rate desc: warm (0.75) before cold (0.5).
	if rows[0].SkillTemp != "warm" {
		t.Fatalf("expected warm first by capture rate, got %+v", rows[0])
	}
}

func TestColdWarmLift(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// easy: cold 1/2 = 0.5, warm 2/2 = 1.0 -> lift +0.5
	seed(t, st, "qwenA", "cold", "easy", "captured", 1, 100)
	seed(t, st, "qwenA", "cold", "easy", "failed", 0, 100)
	seed(t, st, "qwenA", "warm", "easy", "captured", 1, 100)
	seed(t, st, "qwenA", "warm", "easy", "captured", 1, 100)
	// medium: only cold present -> no lift row (needs both arms)
	seed(t, st, "qwenA", "cold", "medium", "failed", 0, 100)

	lifts, err := st.ColdWarmLift()
	if err != nil {
		t.Fatal(err)
	}
	if len(lifts) != 1 {
		t.Fatalf("want exactly one lift row (easy), got %d: %+v", len(lifts), lifts)
	}
	l := lifts[0]
	if l.Difficulty != "easy" || math.Abs(l.Lift-0.5) > 1e-9 || math.Abs(l.ColdRate-0.5) > 1e-9 || math.Abs(l.WarmRate-1.0) > 1e-9 {
		t.Fatalf("lift wrong: %+v", l)
	}
}

func TestComboComparison(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// warm/medium: best solo 0.80 (bigsolo), a combo that ties/below (0.60) and one that beats (1.00).
	for i := 0; i < 4; i++ {
		seed(t, st, "bigsolo", "warm", "medium", "captured", 1, 100)
	}
	seed(t, st, "bigsolo", "warm", "medium", "failed", 0, 100) // 4/5 = 0.80
	for i := 0; i < 3; i++ {
		seed(t, st, "planexec(a->b)", "warm", "medium", "captured", 1, 100)
	}
	seed(t, st, "planexec(a->b)", "warm", "medium", "failed", 0, 100)
	seed(t, st, "planexec(a->b)", "warm", "medium", "failed", 0, 100) // 3/5 = 0.60 -> drop
	for i := 0; i < 5; i++ {
		seed(t, st, "selfcons(a,k=3)", "warm", "medium", "captured", 1, 100) // 5/5 = 1.00 -> KEEP
	}

	cmp, err := st.ComboComparison()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.ComboVsSolo{}
	for _, c := range cmp {
		got[c.Combo] = c
	}
	pe, ok := got["planexec(a->b)"]
	if !ok || pe.Beats || pe.BestSolo != "bigsolo" {
		t.Fatalf("planexec should not beat best solo: %+v", pe)
	}
	sc, ok := got["selfcons(a,k=3)"]
	if !ok || !sc.Beats {
		t.Fatalf("selfcons should beat best solo: %+v", sc)
	}
}
