package store

import "time"

// SurfaceRow is one endpoint a campaign has discovered on a target, accumulated across passes.
type SurfaceRow struct {
	Target string
	Method string
	Path   string
	Last   string
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

// SaveSurface records (or refreshes) a discovered endpoint for a target. The project surface is
// the cross-run memory a later pass seeds from, so it skips rediscovery.
func (s *Store) SaveSurface(target, method, path, last string) error {
	_, err := s.db.Exec(
		`INSERT INTO project_surface (target, method, path, last, ts) VALUES (?,?,?,?,?)
		 ON CONFLICT(target, method, path) DO UPDATE SET last=excluded.last, ts=excluded.ts`,
		target, method, path, last, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// ListSurface returns a target's accumulated surface, by method+path.
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
