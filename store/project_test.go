package store_test

import (
	"path/filepath"
	"testing"

	"github.com/t0ul/GORED/store"
)

// The target is the unit of memory: the same endpoint found by two models is ONE row on the
// canonical map (so any later run seeds from the whole map and never starts over), while who found
// it is recorded per model in the attribution ledger — the point of the tweak.
func TestSurfaceMapAndAttribution(t *testing.T) {
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
	// Two models find the same endpoint; recon finds another.
	must(st.SaveSurface(tgt, "qwen", "run1", "GET", "/api/molts/{id}", "qwen found it"))
	must(st.SaveSurface(tgt, "granite", "run2", "GET", "/api/molts/{id}", "granite found it too"))
	must(st.SaveSurface(tgt, "", "", "GET", "/login", "recon"))

	// The MAP is by target: one row per endpoint (not one per model) — this is what seeds a run.
	all, err := st.ListSurface(tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("map should have 2 endpoints (deduped across models), got %d: %+v", len(all), all)
	}
	if st.CountSurface(tgt) != 2 {
		t.Fatalf("map count should be 2, got %d", st.CountSurface(tgt))
	}

	// Attribution is per model: both models' sighting of /api/molts/{id} is recorded distinctly.
	qwen, err := st.ListSurfaceByModel(tgt, "qwen")
	if err != nil {
		t.Fatal(err)
	}
	if len(qwen) != 1 || qwen[0].Path != "/api/molts/{id}" || qwen[0].RunID != "run1" {
		t.Fatalf("qwen attribution wrong: %+v", qwen)
	}
	granite, _ := st.ListSurfaceByModel(tgt, "granite")
	if len(granite) != 1 || granite[0].RunID != "run2" {
		t.Fatalf("granite attribution wrong: %+v", granite)
	}
	finds, _ := st.ListSurfaceFinds(tgt)
	if len(finds) != 3 { // qwen+granite on /api/molts/{id}, recon "" on /login
		t.Fatalf("ledger should have 3 sightings, got %d: %+v", len(finds), finds)
	}

	// Re-saving refreshes the same sighting, never duplicates it.
	must(st.SaveSurface(tgt, "qwen", "run3", "GET", "/api/molts/{id}", "again"))
	if q, _ := st.ListSurfaceByModel(tgt, "qwen"); len(q) != 1 || q[0].RunID != "run3" {
		t.Fatalf("refresh should update not duplicate: %+v", q)
	}
}

// A row created ONLY by SaveShape (shape-discovery, no prior crawl) has a NULL last — ListSurface
// must still return it, not error out. This is the bug that silently emptied the surface and stalled
// the exploit phase on the live RR rerun.
func TestSaveShapeOnlyRowListable(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// no SaveSurface first — only a shape, so last stays NULL
	if err := st.SaveShape("app", "POST", "/api/ingest/{id}", "source,asset,title"); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListSurface("app")
	if err != nil {
		t.Fatalf("ListSurface must tolerate a NULL last from a shape-only row, got: %v", err)
	}
	if len(rows) != 1 || rows[0].Path != "/api/ingest/{id}" || rows[0].Shape != "source,asset,title" {
		t.Fatalf("shape-only row not returned correctly: %+v", rows)
	}
}

// The reverse-engineered shape lives in its own column (a later crawl/ffuf label must NOT clobber
// it), and attack state accumulates so a later pass can skip what's done and work the frontier.
func TestShapeAndAttackState(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const tgt = "app"
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(st.SaveSurface(tgt, "", "", "POST", "/api/x", "recon:priv")) // mapped by the crawl
	must(st.SaveShape(tgt, "POST", "/api/x", "email,note"))           // shape reverse-engineered
	must(st.SaveSurface(tgt, "", "", "POST", "/api/x", "ffuf"))       // a LATER label write to the same row

	get := func() store.SurfaceRow {
		rows, _ := st.ListSurface(tgt)
		for _, r := range rows {
			if r.Path == "/api/x" {
				return r
			}
		}
		t.Fatal("row missing")
		return store.SurfaceRow{}
	}
	if r := get(); r.Shape != "email,note" {
		t.Fatalf("shape was clobbered by a later label write: %q", r.Shape) // the fragility fix
	}

	// Attack progress accumulates and sticks captured once a finding lands.
	must(st.MarkAttacked(tgt, "POST", "/api/x", false))
	if r := get(); r.Attempts != 1 || r.Captured {
		t.Fatalf("after 1 miss: attempts=%d captured=%v", r.Attempts, r.Captured)
	}
	must(st.MarkAttacked(tgt, "POST", "/api/x", true))
	if r := get(); r.Attempts != 2 || !r.Captured {
		t.Fatalf("after a capture: attempts=%d captured=%v", r.Attempts, r.Captured)
	}
	if r := get(); r.Shape != "email,note" { // shape untouched by attack marking
		t.Fatalf("shape lost after MarkAttacked: %q", r.Shape)
	}
}

// Findings mirror surface: the target is the unit of memory (one canonical finding per
// target+type+value), and which model reported it is a per-model attribution — so models can be
// compared on the same target without duplicating the finding.
func TestFindingMapAndAttribution(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const tgt = "riskrancher"
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	// Two models independently report the same finding; one model finds a second one.
	must(st.SaveFinding(tgt, "qwen", "run1", "idor", "GET /api/tickets/{id} leaks other owners"))
	must(st.SaveFinding(tgt, "granite", "run2", "idor", "GET /api/tickets/{id} leaks other owners"))
	must(st.SaveFinding(tgt, "qwen", "run1", "bac", "/admin reachable as low-priv"))

	// Canonical ledger is by target: the shared finding is ONE row, not one per model.
	all, err := st.ListFindings(tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("ledger should have 2 findings (deduped across models), got %d: %+v", len(all), all)
	}

	// Attribution is per model.
	if q, _ := st.ListFindingsByModel(tgt, "qwen"); len(q) != 2 {
		t.Fatalf("qwen should have 2 attributed findings, got %d", len(q))
	}
	if g, _ := st.ListFindingsByModel(tgt, "granite"); len(g) != 1 || g[0].RunID != "run2" {
		t.Fatalf("granite attribution wrong: %+v", g)
	}
	if attr, _ := st.ListFindingAttrib(tgt); len(attr) != 3 { // qwen×2 + granite×1
		t.Fatalf("attribution ledger should have 3 rows, got %d", len(attr))
	}

	// A non-model source ("") lands on the canonical ledger but is not attributed to any model.
	must(st.SaveFinding(tgt, "", "", "misconfig", "missing security headers"))
	if n := st.CountFindings(tgt); n != 3 {
		t.Fatalf("ledger count should be 3, got %d", n)
	}
	if attr, _ := st.ListFindingAttrib(tgt); len(attr) != 3 {
		t.Fatalf("a non-model finding must not add a model attribution: %d", len(attr))
	}
}
