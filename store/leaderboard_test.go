package store_test

import (
	"math"
	"path/filepath"
	"testing"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/store"
)

// seed writes one finished run with the given shape to a real SQLite store.
func seed(t *testing.T, st *store.Store, model, temp, diff, outcome string, toolCalls, wallMS int) {
	t.Helper()
	id, err := st.StartRun("trace", gored.RunMeta{
		Model: model, SkillTemp: temp, Difficulty: gored.Difficulty(diff), FlagID: "f",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishRun(id, gored.RunStats{Outcome: outcome, ToolCalls: toolCalls, WallMS: int64(wallMS)}); err != nil {
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
