package store_test

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/t0ul/GORED/store"
)

// SaveContract's read-merge-write must not lose an update under concurrency: many writers folding
// a distinct field into the same endpoint must all survive (run with -race).
func TestSaveContractConcurrent(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const tgt, n = "app", 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = st.SaveContract(tgt, "POST", "/api/x", "static", store.EndpointContract{
				Fields: []store.FieldSpec{{Name: fmt.Sprintf("f%d", i), In: "body"}},
			})
		}(i)
	}
	wg.Wait()
	rows, _ := st.ListSurface(tgt)
	if len(rows) != 1 || rows[0].Contract == nil {
		t.Fatalf("want one merged row with a contract, got %+v", rows)
	}
	if got := len(rows[0].Contract.Fields); got != n {
		t.Fatalf("concurrent merges lost fields: got %d want %d", got, n)
	}
}

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

// A row created ONLY by SaveContract (shape-discovery, no prior crawl) has a NULL last —
// ListSurface must still return it, not error out. This is the bug that silently emptied the
// surface and stalled the exploit phase on the live RR rerun.
func TestSaveContractOnlyRowListable(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// no SaveSurface first — only a contract, so last stays NULL
	if err := st.SaveContract("app", "POST", "/api/ingest/{id}", "static", store.EndpointContract{
		Fields: []store.FieldSpec{{Name: "source", In: "body"}, {Name: "asset", In: "body"}, {Name: "title", In: "body"}},
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListSurface("app")
	if err != nil {
		t.Fatalf("ListSurface must tolerate a NULL last from a contract-only row, got: %v", err)
	}
	if len(rows) != 1 || rows[0].Path != "/api/ingest/{id}" || rows[0].Shape() != "source,asset,title" {
		t.Fatalf("contract-only row not returned correctly: %+v", rows)
	}
	if !rows[0].HasBody {
		t.Errorf("row with body fields should have has_body set")
	}
}

// The structured contract survives a later crawl/ffuf label write (it must NOT clobber the shape),
// and attack state accumulates so a later pass can skip what's done and work the frontier.
func TestContractAndAttackState(t *testing.T) {
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
	must(st.SaveContract(tgt, "POST", "/api/x", "static", store.EndpointContract{
		Fields: []store.FieldSpec{{Name: "email", In: "body"}, {Name: "note", In: "body"}}})) // contract reverse-engineered
	must(st.SaveSurface(tgt, "", "", "POST", "/api/x", "ffuf")) // a LATER label write to the same row

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
	if r := get(); r.Shape() != "email,note" {
		t.Fatalf("contract was clobbered by a later label write: %q", r.Shape()) // the fragility fix
	}

	// Attack progress accumulates and sticks found once a finding lands.
	must(st.MarkAttacked(tgt, "POST", "/api/x", false))
	if r := get(); r.Attempts != 1 || r.Found {
		t.Fatalf("after 1 miss: attempts=%d found=%v", r.Attempts, r.Found)
	}
	must(st.MarkAttacked(tgt, "POST", "/api/x", true))
	if r := get(); r.Attempts != 2 || !r.Found {
		t.Fatalf("after a finding: attempts=%d found=%v", r.Attempts, r.Found)
	}
	if r := get(); r.Shape() != "email,note" { // contract untouched by attack marking
		t.Fatalf("contract lost after MarkAttacked: %q", r.Shape())
	}
}

// SaveContract MERGES by source precedence: a stronger source (openapi) sets a field's type, and a
// later weaker source (static) must not downgrade it to unknown; headers and auth union; a new field
// from either source is added.
func TestContractMergePrecedence(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const tgt = "app"
	// static sees the field name with no type; openapi then declares its type + required + a header.
	_ = st.SaveContract(tgt, "POST", "/api/users", "static", store.EndpointContract{
		Fields: []store.FieldSpec{{Name: "email", In: "body"}}})
	_ = st.SaveContract(tgt, "POST", "/api/users", "openapi", store.EndpointContract{
		Fields:  []store.FieldSpec{{Name: "email", Type: "email", Required: true, In: "body"}, {Name: "role", Type: "string", In: "body"}},
		Headers: []string{"Content-Type"},
		Auth:    map[string]int{"anon": 401, "low": 200},
	})
	// a LATER static pass re-sees email with no type — must NOT erase the openapi type.
	_ = st.SaveContract(tgt, "POST", "/api/users", "static", store.EndpointContract{
		Fields: []store.FieldSpec{{Name: "email", In: "body"}}})

	rows, _ := st.ListSurface(tgt)
	if len(rows) != 1 || rows[0].Contract == nil {
		t.Fatalf("want one row with a contract, got %+v", rows)
	}
	c := rows[0].Contract
	byName := map[string]store.FieldSpec{}
	for _, f := range c.Fields {
		byName[f.Name] = f
	}
	if byName["email"].Type != "email" || !byName["email"].Required {
		t.Errorf("openapi type/required must survive a later static pass; got %+v", byName["email"])
	}
	if byName["role"].Type != "string" {
		t.Errorf("openapi-only field role missing/typeless: %+v", byName["role"])
	}
	if rows[0].Source != "openapi" {
		t.Errorf("best source should be openapi, got %q", rows[0].Source)
	}
	if !rows[0].NeedsAuth || !rows[0].ReachLow {
		t.Errorf("auth map should set needs_auth (anon 401) and reach_low (low 200): %+v", rows[0])
	}
}

// QueryEndpoints returns the scoped frontier the recon tool reads: not-yet-exercised by default,
// class-filterable, capped — so the model pulls a slice, never the whole map.
func TestQueryEndpointsFrontier(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const tgt = "app"
	st.Classify = func(method, path string) string {
		if method == "POST" {
			return "write"
		}
		return "info"
	}
	_ = st.SaveContract(tgt, "POST", "/api/a", "static", store.EndpointContract{Fields: []store.FieldSpec{{Name: "x"}}})
	_ = st.SaveContract(tgt, "GET", "/api/b", "static", store.EndpointContract{})
	_ = st.SaveContract(tgt, "POST", "/api/c", "static", store.EndpointContract{Fields: []store.FieldSpec{{Name: "y"}}})
	_ = st.MarkAttacked(tgt, "POST", "/api/c", true) // c is found -> off the frontier

	front, err := st.QueryEndpoints(tgt, store.QueryOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(front) != 2 {
		t.Fatalf("frontier should exclude the found endpoint; got %d: %+v", len(front), front)
	}
	writes, _ := st.QueryEndpoints(tgt, store.QueryOpts{Class: "write"})
	if len(writes) != 1 || writes[0].Path != "/api/a" {
		t.Fatalf("class filter should return only the unexercised write /api/a; got %+v", writes)
	}
	all, _ := st.QueryEndpoints(tgt, store.QueryOpts{Exercised: true})
	if len(all) != 3 {
		t.Fatalf("exercised=true should include the found endpoint; got %d", len(all))
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
