package eva

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/t0ul/GORED/store"
)

// The model's save_surface tool must persist a reported endpoint to project memory, attributed to
// the run's model, normalizing a missing leading slash and defaulting the method — and reject a
// call with no path (it cannot invent surface).
func TestSurfaceSaveTool(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tool := surfaceSaveTool{store: st, target: "emaildrop", model: "ministral-8b", runID: "run-7"}

	if _, err := tool.Call(context.Background(), map[string]any{"path": "api/drops/{id}", "note": "drop by id"}); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	// It lands on the target's map...
	if n := st.CountSurface("emaildrop"); n != 1 {
		t.Fatalf("expected 1 map endpoint, got %d", n)
	}
	// ...and is attributed to this run's model.
	rows, err := st.ListSurfaceByModel("emaildrop", "ministral-8b")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 attributed sighting, got %d: %+v", len(rows), rows)
	}
	if rows[0].Path != "/api/drops/{id}" { // leading slash normalized
		t.Errorf("path not normalized: %q", rows[0].Path)
	}
	if rows[0].Method != "GET" { // method defaulted
		t.Errorf("method should default to GET, got %q", rows[0].Method)
	}
	if rows[0].RunID != "run-7" {
		t.Errorf("run not attributed: %q", rows[0].RunID)
	}

	if _, err := tool.Call(context.Background(), map[string]any{"note": "no path"}); err == nil {
		t.Error("a call with no path must error, not persist empty surface")
	}
}
