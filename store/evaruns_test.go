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
