package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/t0ul/GORED/internal/core"
)

// Real SQLite, no mocks: open a temp DB, round-trip an EVA run through save/update/list/get.
func TestEVARunRoundTrip(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "eva.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	r := EVARun{
		ID: "abc123", Stage: "exploit", Base: "http://127.0.0.1:8088",
		Model: "qwen2.5-3b-instruct.gguf", Trials: 1, Autonomy: "piloted",
		Status: "running", Started: time.Now(), Trace: "/tmp/t.jsonl", Prompt: "custom",
	}
	if err := st.SaveEVARun(r); err != nil {
		t.Fatal(err)
	}

	// Update: same id, now done with a summary.
	r.Status = "done"
	r.Elapsed = "47s"
	r.Sums = []core.ContenderSummary{{Contender: "solo(qwen) {xss}", Captured: 1, Trials: 1, CaptureRate: 1}}
	if err := st.SaveEVARun(r); err != nil {
		t.Fatal(err)
	}

	got, ok, err := st.GetEVARun("abc123")
	if err != nil || !ok {
		t.Fatalf("GetEVARun: ok=%v err=%v", ok, err)
	}
	if got.Status != "done" || got.Elapsed != "47s" || got.Prompt != "custom" {
		t.Errorf("round-trip fields wrong: %+v", got)
	}
	if got.Models != "" {
		t.Errorf("single-model run should have empty Models, got %q", got.Models)
	}
	if len(got.Sums) != 1 || got.Sums[0].Captured != 1 {
		t.Errorf("sums not persisted: %+v", got.Sums)
	}

	list, err := st.ListEVARuns()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListEVARuns: n=%d err=%v", len(list), err)
	}

	// Missing id.
	if _, ok, _ := st.GetEVARun("nope"); ok {
		t.Error("expected ok=false for missing id")
	}
}

// A researcher-matrix sortie persists its model set in the Models column, and a per-model
// summary row for each contender. Real SQLite, no mocks.
func TestEVARunMatrixModels(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "eva.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	r := EVARun{
		ID: "mtx1", Stage: "apiexploit", Base: "http://127.0.0.1:8088",
		Models: "qwen2.5-0.5b-instruct.gguf, qwen2.5-1.5b-instruct.gguf",
		Trials: 2, Autonomy: "autonomous", Status: "done", Started: time.Now(),
		Trace: "/tmp/m.jsonl",
		Sums: []core.ContenderSummary{
			{Contender: "solo(qwen2.5-0.5b-instruct.gguf) {api-idor}", Captured: 0, Trials: 2},
			{Contender: "solo(qwen2.5-1.5b-instruct.gguf) {api-idor}", Captured: 1, Trials: 2, CaptureRate: 0.5},
		},
	}
	if err := st.SaveEVARun(r); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.GetEVARun("mtx1")
	if err != nil || !ok {
		t.Fatalf("GetEVARun: ok=%v err=%v", ok, err)
	}
	if got.Models != r.Models {
		t.Errorf("Models not persisted: got %q want %q", got.Models, r.Models)
	}
	if len(got.Sums) != 2 {
		t.Fatalf("expected 2 contender rows, got %d", len(got.Sums))
	}
}
