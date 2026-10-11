// Package store persists GORED runs to SQLite: the per-run aggregate
// (redteam_runs) and the blackboard (redteam_findings), per plan §7. The per-step
// trace is NOT duplicated here — it lives in the gledger audit keyed by trace_id.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	gored "github.com/t0ul/GORED"
	_ "modernc.org/sqlite"
)

// Store is a SQLite-backed gored.RunStore.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS redteam_runs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            TEXT NOT NULL,
  suite_version TEXT,
  model         TEXT NOT NULL,
  model_params  TEXT,
  skill         TEXT,
  skill_temp    TEXT,
  target        TEXT,
  flag_id       TEXT,
  difficulty    TEXT,
  outcome       TEXT,
  tool_calls    INTEGER,
  wall_ms       INTEGER,
  tokens_in     INTEGER,
  tokens_out    INTEGER,
  trace_id      TEXT,
  notes         TEXT
);
CREATE TABLE IF NOT EXISTS redteam_findings (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id      INTEGER NOT NULL REFERENCES redteam_runs(id),
  ts          TEXT NOT NULL,
  type        TEXT,
  value       TEXT,
  source_step INTEGER,
  refs_json   TEXT,
  scrubbed    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON redteam_findings(run_id);
`

// Open opens (creating if needed) a run store at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// StartRun inserts the run row and returns its id.
func (s *Store) StartRun(traceID string, m gored.RunMeta) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO redteam_runs (ts, suite_version, model, model_params, skill, skill_temp, target, flag_id, difficulty, outcome, trace_id)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339Nano), m.SuiteVersion, m.Model, m.ModelParams,
		m.Skill, m.SkillTemp, m.Target, m.FlagID, string(m.Difficulty), "running", traceID,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// AddFinding persists one blackboard finding under a run.
func (s *Store) AddFinding(runID int64, f gored.Finding) error {
	refs := make([]string, len(f.Refs))
	for i, r := range f.Refs {
		refs[i] = fmt.Sprintf("%d", r)
	}
	scrubbed := 0
	if f.Scrubbed {
		scrubbed = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO redteam_findings (run_id, ts, type, value, source_step, refs_json, scrubbed) VALUES (?,?,?,?,?,?,?)`,
		runID, time.Now().UTC().Format(time.RFC3339Nano), string(f.Type), f.Value, f.SourceStep,
		"["+strings.Join(refs, ",")+"]", scrubbed,
	)
	return err
}

// FinishRun writes the final aggregate.
func (s *Store) FinishRun(runID int64, st gored.RunStats) error {
	_, err := s.db.Exec(
		`UPDATE redteam_runs SET outcome=?, tool_calls=?, wall_ms=?, tokens_in=?, tokens_out=?, notes=? WHERE id=?`,
		st.Outcome, st.ToolCalls, st.WallMS, st.TokensIn, st.TokensOut, st.Notes, runID,
	)
	return err
}

// Run is a read-back of a persisted run (for inspection/tests).
type Run struct {
	ID        int64
	Model     string
	Skill     string
	SkillTemp string
	FlagID    string
	Outcome   string
	ToolCalls int
	WallMS    int64
	TraceID   string
	Findings  int
}

// GetRun reads a run and its finding count.
func (s *Store) GetRun(id int64) (Run, error) {
	var r Run
	err := s.db.QueryRow(
		`SELECT id, model, skill, skill_temp, flag_id, outcome, COALESCE(tool_calls,0), COALESCE(wall_ms,0), trace_id
		 FROM redteam_runs WHERE id=?`, id,
	).Scan(&r.ID, &r.Model, &r.Skill, &r.SkillTemp, &r.FlagID, &r.Outcome, &r.ToolCalls, &r.WallMS, &r.TraceID)
	if err != nil {
		return r, err
	}
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM redteam_findings WHERE run_id=?`, id).Scan(&r.Findings)
	return r, nil
}
