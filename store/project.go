package store

import (
	"database/sql"
	"time"
)

// SurfaceRow is one endpoint on a target's canonical map, accumulated across every pass and every
// model. The target is the unit of memory: one row per endpoint, so any later run (any model) seeds
// from the whole map and never starts over. Who found it is recorded separately in SurfaceFind.
type SurfaceRow struct {
	Target string
	Method string
	Path   string
	Last   string
	TS     time.Time
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
// folded in — which is what a run seeds from.
func (s *Store) ListSurface(target string) ([]SurfaceRow, error) {
	rows, err := s.db.Query(`SELECT target, method, path, last, ts FROM project_surface WHERE target=? ORDER BY path, method`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SurfaceRow
	for rows.Next() {
		var r SurfaceRow
		var ts string
		if err := rows.Scan(&r.Target, &r.Method, &r.Path, &r.Last, &ts); err != nil {
			return nil, err
		}
		r.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, r)
	}
	return out, rows.Err()
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

// SaveFinding records a finding for a target, ignoring an exact repeat (target+type+value).
func (s *Store) SaveFinding(target, typ, value, runID string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO project_findings (target, type, value, run_id, ts) VALUES (?,?,?,?,?)`,
		target, typ, value, runID, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// ListFindings returns a target's accumulated findings, most recent first.
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
