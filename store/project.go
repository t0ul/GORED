package store

import (
	"database/sql"
	"time"
)

// SurfaceRow is one endpoint on a target's canonical map, accumulated across every pass and every
// model. The target is the unit of memory: one row per endpoint, so any later run (any model) seeds
// from the whole map and never starts over. Who found it is recorded separately in SurfaceFind.
type SurfaceRow struct {
	Target   string
	Method   string
	Path     string
	Last     string
	TS       time.Time
	Shape    string // reverse-engineered request body shape (fields=…); "" when unknown
	Attempts int    // times the exploit phase has worked this endpoint
	Captured bool   // a finding landed here; never re-attack
}

// SurfaceFind attributes a map endpoint to a model that reported it (and the run it was in), so a
// researcher can compare what each model discovered on the same target. Model "" is deterministic
// recon (crawl/ffuf/graphql), shared across models.
type SurfaceFind struct {
	Target string
	Method string
	Path   string
	Model  string
	RunID  string
	Note   string
	TS     time.Time
}

// FindingRow is one finding a campaign has recorded on a target, accumulated across passes
// (deduped by target+type+value, so re-finding the same thing does not bloat the memory).
type FindingRow struct {
	Target string
	Type   string
	Value  string
	RunID  string
	TS     time.Time
}

// SaveSurface records a discovered endpoint on a target's canonical map AND, when a model found it
// (model != "", "" = deterministic recon), a per-model attribution in surface_find. The map is the
// cross-run memory a later pass seeds from (one row per endpoint, so no run restarts from scratch);
// the attribution keeps "who found what" without fragmenting the map.
func (s *Store) SaveSurface(target, model, runID, method, path, last string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(
		`INSERT INTO project_surface (target, method, path, last, ts) VALUES (?,?,?,?,?)
		 ON CONFLICT(target, method, path) DO UPDATE SET last=excluded.last, ts=excluded.ts`,
		target, method, path, last, now); err != nil {
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO surface_find (target, method, path, model, run_id, note, ts) VALUES (?,?,?,?,?,?,?)
		 ON CONFLICT(target, method, path, model) DO UPDATE SET run_id=excluded.run_id, note=excluded.note, ts=excluded.ts`,
		target, method, path, model, runID, last, now)
	return err
}

// ListSurface returns a target's canonical map — one row per endpoint, every model's discoveries
// folded in, with the reverse-engineered shape and the exploit-progress counters — which is what a
// run seeds from (so it can skip what is done and work the frontier).
func (s *Store) ListSurface(target string) ([]SurfaceRow, error) {
	rows, err := s.db.Query(`SELECT target, method, path, last, ts, COALESCE(shape,''), COALESCE(attempts,0), COALESCE(captured,0) FROM project_surface WHERE target=? ORDER BY path, method`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SurfaceRow
	for rows.Next() {
		var r SurfaceRow
		var ts string
		var cap int
		if err := rows.Scan(&r.Target, &r.Method, &r.Path, &r.Last, &ts, &r.Shape, &r.Attempts, &cap); err != nil {
			return nil, err
		}
		r.TS, _ = time.Parse(time.RFC3339Nano, ts)
		r.Captured = cap != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveShape records the reverse-engineered request body shape for an endpoint on the canonical map,
// in its own column so a later crawl/ffuf write to the same row cannot clobber it. Upserts the row
// if the endpoint is not yet present. Does not touch the attempt counters.
func (s *Store) SaveShape(target, method, path, shape string) error {
	_, err := s.db.Exec(
		`INSERT INTO project_surface (target, method, path, shape, ts) VALUES (?,?,?,?,?)
		 ON CONFLICT(target, method, path) DO UPDATE SET shape=excluded.shape`,
		target, method, path, shape, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// MarkAttacked records that the exploit phase worked an endpoint: it bumps the attempt count, sets
// captured if a finding landed, and stamps the time — so a later run (or pass) advances the frontier
// instead of re-attacking the same endpoints from the start.
func (s *Store) MarkAttacked(target, method, path string, captured bool) error {
	cap := 0
	if captured {
		cap = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO project_surface (target, method, path, attempts, captured, last_attacked) VALUES (?,?,?,1,?,?)
		 ON CONFLICT(target, method, path) DO UPDATE SET attempts=COALESCE(attempts,0)+1, captured=MAX(COALESCE(captured,0), excluded.captured), last_attacked=excluded.last_attacked`,
		target, method, path, cap, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// ListSurfaceByModel returns the endpoints one model found on a target (pass "" for deterministic
// recon), so a researcher can compare models' discovery against the same target.
func (s *Store) ListSurfaceByModel(target, model string) ([]SurfaceFind, error) {
	return s.findQuery(`SELECT target, method, path, model, run_id, note, ts FROM surface_find WHERE target=? AND model=? ORDER BY path, method`, target, model)
}

// ListSurfaceFinds returns the whole attribution ledger for a target (every model's sightings),
// the join behind a per-model comparison.
func (s *Store) ListSurfaceFinds(target string) ([]SurfaceFind, error) {
	return s.findQuery(`SELECT target, method, path, model, run_id, note, ts FROM surface_find WHERE target=? ORDER BY model, path, method`, target)
}

func (s *Store) findQuery(q string, args ...any) ([]SurfaceFind, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SurfaceFind
	for rows.Next() {
		var f SurfaceFind
		var runID, note sql.NullString
		var ts string
		if err := rows.Scan(&f.Target, &f.Method, &f.Path, &f.Model, &runID, &note, &ts); err != nil {
			return nil, err
		}
		f.RunID, f.Note = runID.String, note.String
		f.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, f)
	}
	return out, rows.Err()
}

// SaveFinding records a finding on a target's canonical ledger (deduped by target+type+value, so
// re-finding the same thing does not bloat memory) AND, when a model reported it (model != ""), a
// per-model attribution in finding_find — so a researcher can compare which model found which
// finding on the same target, exactly as the surface map and its attribution do.
func (s *Store) SaveFinding(target, model, runID, typ, value string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(
		`INSERT OR IGNORE INTO project_findings (target, type, value, run_id, ts) VALUES (?,?,?,?,?)`,
		target, typ, value, runID, now); err != nil {
		return err
	}
	if model == "" {
		return nil // no model attribution for a non-model source
	}
	_, err := s.db.Exec(
		`INSERT INTO finding_find (target, type, value, model, run_id, ts) VALUES (?,?,?,?,?,?)
		 ON CONFLICT(target, type, value, model) DO UPDATE SET run_id=excluded.run_id, ts=excluded.ts`,
		target, typ, value, model, runID, now)
	return err
}

// ListFindings returns a target's canonical findings (every model folded in), most recent first.
func (s *Store) ListFindings(target string) ([]FindingRow, error) {
	rows, err := s.db.Query(`SELECT target, type, value, run_id, ts FROM project_findings WHERE target=? ORDER BY ts DESC`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var r FindingRow
		var ts string
		if err := rows.Scan(&r.Target, &r.Type, &r.Value, &r.RunID, &ts); err != nil {
			return nil, err
		}
		r.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListFindingsByModel returns the findings one model reported on a target, so models can be
// compared against the same target (the finding-side mirror of ListSurfaceByModel).
func (s *Store) ListFindingsByModel(target, model string) ([]FindingRow, error) {
	return s.findingAttrQuery(`SELECT target, type, value, run_id, ts FROM finding_find WHERE target=? AND model=? ORDER BY ts DESC`, target, model)
}

// ListFindingAttrib returns the whole per-model finding ledger for a target.
func (s *Store) ListFindingAttrib(target string) ([]FindingRow, error) {
	return s.findingAttrQuery(`SELECT target, type, value, run_id, ts FROM finding_find WHERE target=? ORDER BY model, ts DESC`, target)
}

func (s *Store) findingAttrQuery(q string, args ...any) ([]FindingRow, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var r FindingRow
		var runID sql.NullString
		var ts string
		if err := rows.Scan(&r.Target, &r.Type, &r.Value, &runID, &ts); err != nil {
			return nil, err
		}
		r.RunID = runID.String
		r.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountSurface / CountFindings are best-effort counts for the console badges.
func (s *Store) CountSurface(target string) int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM project_surface WHERE target=?`, target).Scan(&n)
	return n
}

func (s *Store) CountFindings(target string) int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM project_findings WHERE target=?`, target).Scan(&n)
	return n
}
