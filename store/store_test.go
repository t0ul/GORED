package store_test

import (
	"path/filepath"
	"testing"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/store"
)

func TestRunRoundTrip(t *testing.T) {
	// Real SQLite on disk — no mocks.
	st, err := store.Open(filepath.Join(t.TempDir(), "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	id, err := st.StartRun("trace-abc", gored.RunMeta{
		SuiteVersion: "phase1", Model: "tinyllama", Skill: "cold-web-recon-exploit",
		SkillTemp: "cold", Target: "http://127.0.0.1:1", FlagID: "idor-notes", Difficulty: gored.DiffEasy,
	})
	if err != nil {
		t.Fatal(err)
	}
	f := gored.Finding{Type: gored.FindEndpoint, Value: "/api/notes/{id}", SourceStep: 1, Refs: []int{}}
	if err := st.AddFinding(id, f); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishRun(id, gored.RunStats{Outcome: "captured", ToolCalls: 3, WallMS: 1200, TokensIn: 500, TokensOut: 80, Notes: ""}); err != nil {
		t.Fatal(err)
	}
	r, err := st.GetRun(id)
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != "captured" || r.ToolCalls != 3 || r.Model != "tinyllama" || r.TraceID != "trace-abc" {
		t.Fatalf("round-trip mismatch: %+v", r)
	}
	if r.Findings != 1 {
		t.Fatalf("want 1 finding, got %d", r.Findings)
	}
}
