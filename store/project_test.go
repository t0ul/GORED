package store_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/t0ul/GORED/store"
)

// Surface rows are attributed per model: the same path found by two models is kept as two distinct
// rows, and "" is the shared deterministic-recon surface — so a researcher can compare what each
// model mapped on the same target instead of them overwriting one another.
func TestSurfacePerModel(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const tgt = "krabber"
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(st.SaveSurface(tgt, "qwen", "GET", "/api/molts/{id}", "qwen found it"))
	must(st.SaveSurface(tgt, "granite", "GET", "/api/molts/{id}", "granite found it too"))
	must(st.SaveSurface(tgt, "", "GET", "/login", "recon"))

	all, err := st.ListSurface(tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rows across models, got %d: %+v", len(all), all)
	}

	qwen, err := st.ListSurfaceByModel(tgt, "qwen")
	if err != nil {
		t.Fatal(err)
	}
	if len(qwen) != 1 || qwen[0].Path != "/api/molts/{id}" || qwen[0].Model != "qwen" {
		t.Fatalf("qwen view wrong: %+v", qwen)
	}
	shared, err := st.ListSurfaceByModel(tgt, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(shared) != 1 || shared[0].Path != "/login" {
		t.Fatalf("shared recon view wrong: %+v", shared)
	}

	// Re-saving the same (target, model, path) refreshes, not duplicates.
	must(st.SaveSurface(tgt, "qwen", "GET", "/api/molts/{id}", "refreshed"))
	if n := st.CountSurface(tgt); n != 3 {
		t.Fatalf("refresh should not duplicate; count=%d", n)
	}
}

// A legacy project_surface (no model column) is blown away and rebuilt with the new schema on Open,
// per the research-scratch brief — Open must succeed and the new column must work.
func TestSurfaceLegacyRebuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE project_surface (target TEXT, method TEXT, path TEXT, last TEXT, ts TEXT, PRIMARY KEY (target, method, path))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO project_surface VALUES ('t','GET','/old','recon','now')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open must rebuild a legacy surface table, got: %v", err)
	}
	defer st.Close()
	// The rebuild dropped the old row (research scratch, not migrated) and the model column works.
	if err := st.SaveSurface("t", "qwen", "GET", "/new", "note"); err != nil {
		t.Fatalf("new schema broken after rebuild: %v", err)
	}
	rows, _ := st.ListSurfaceByModel("t", "qwen")
	if len(rows) != 1 || rows[0].Path != "/new" {
		t.Fatalf("expected the new model-attributed row, got %+v", rows)
	}
}
