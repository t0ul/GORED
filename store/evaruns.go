package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/t0ul/GORED/internal/core"
)

// EVARun is the cockpit-level record of one piloted/autonomous sortie: the durable copy
// of the EVA server's in-memory run, so the sortie log survives a restart. The per-step
// detail still lives in the gledger trace at Trace; this is only the launch config and the
// final summary.
type EVARun struct {
	ID       string
	Stage    string
	Base     string
	Model    string
	Trials   int
	Autonomy string
	Status   string
	Err      string
	Started  time.Time
	Elapsed  string
	Trace    string
	Prompt   string
	Sums     []core.ContenderSummary
}

// SaveEVARun upserts a cockpit run. EVA calls it on launch and on each status change, so
// the latest state is always on disk.
func (s *Store) SaveEVARun(r EVARun) error {
	sums, _ := json.Marshal(r.Sums)
	_, err := s.db.Exec(
		`INSERT INTO eva_runs (id, stage, base, model, trials, autonomy, status, err, started, elapsed, trace, prompt, sums_json)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   stage=excluded.stage, base=excluded.base, model=excluded.model, trials=excluded.trials,
		   autonomy=excluded.autonomy, status=excluded.status, err=excluded.err, started=excluded.started,
		   elapsed=excluded.elapsed, trace=excluded.trace, prompt=excluded.prompt, sums_json=excluded.sums_json`,
		r.ID, r.Stage, r.Base, r.Model, r.Trials, r.Autonomy, r.Status, r.Err,
		r.Started.UTC().Format(time.RFC3339Nano), r.Elapsed, r.Trace, r.Prompt, string(sums),
	)
	return err
}

// ListEVARuns returns the cockpit runs, most recent first.
func (s *Store) ListEVARuns() ([]EVARun, error) {
	rows, err := s.db.Query(
		`SELECT id, stage, base, model, trials, autonomy, status, err, started, elapsed, trace, prompt, sums_json
		 FROM eva_runs ORDER BY started DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EVARun
	for rows.Next() {
		r, err := scanEVARun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetEVARun reads one cockpit run; ok is false when none exists.
func (s *Store) GetEVARun(id string) (EVARun, bool, error) {
	row := s.db.QueryRow(
		`SELECT id, stage, base, model, trials, autonomy, status, err, started, elapsed, trace, prompt, sums_json
		 FROM eva_runs WHERE id=?`, id)
	r, err := scanEVARun(row)
	if err == sql.ErrNoRows {
		return EVARun{}, false, nil
	}
	if err != nil {
		return EVARun{}, false, err
	}
	return r, true, nil
}

// scanRow is satisfied by both *sql.Row and *sql.Rows.
type scanRow interface {
	Scan(dest ...any) error
}

func scanEVARun(sc scanRow) (EVARun, error) {
	var r EVARun
	var started, sums string
	if err := sc.Scan(&r.ID, &r.Stage, &r.Base, &r.Model, &r.Trials, &r.Autonomy, &r.Status,
		&r.Err, &started, &r.Elapsed, &r.Trace, &r.Prompt, &sums); err != nil {
		return r, err
	}
	r.Started, _ = time.Parse(time.RFC3339Nano, started)
	if sums != "" {
		_ = json.Unmarshal([]byte(sums), &r.Sums)
	}
	return r, nil
}
