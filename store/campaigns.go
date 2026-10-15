package store

import (
	"database/sql"
	"time"
)

// Campaign is a durable record of an overnight blind campaign: a named set of targets run
// autonomously, one model, with its child runs linked by id. The per-target/per-stage detail
// lives in the child eva_runs + their gledger traces; this is the campaign-level envelope so a
// campaign survives a restart and the morning report can find its runs.
type Campaign struct {
	ID      string // PK
	Name    string
	Targets string // CSV of target names
	Model   string
	Status  string // "running" | "done" | "aborted" | "error"
	Started time.Time
	Elapsed string
	RunIDs  string // CSV of child run ids (eva_runs.id)
	Cur     string // the current "target · stage" in flight, for live status
	Note    string
}

// SaveCampaign upserts a campaign. Called on launch and on each state change.
func (s *Store) SaveCampaign(c Campaign) error {
	_, err := s.db.Exec(
		`INSERT INTO campaigns (id, name, targets, model, status, started, elapsed, run_ids, cur, note)
		 VALUES (?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   name=excluded.name, targets=excluded.targets, model=excluded.model, status=excluded.status,
		   started=excluded.started, elapsed=excluded.elapsed, run_ids=excluded.run_ids, cur=excluded.cur, note=excluded.note`,
		c.ID, c.Name, c.Targets, c.Model, c.Status, c.Started.UTC().Format(time.RFC3339Nano),
		c.Elapsed, c.RunIDs, c.Cur, c.Note,
	)
	return err
}

// ListCampaigns returns campaigns, most recent first.
func (s *Store) ListCampaigns() ([]Campaign, error) {
	rows, err := s.db.Query(
		`SELECT id, name, targets, model, status, started, elapsed, run_ids, cur, note
		 FROM campaigns ORDER BY started DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Campaign
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCampaign reads one campaign; ok is false when none exists.
func (s *Store) GetCampaign(id string) (Campaign, bool, error) {
	row := s.db.QueryRow(
		`SELECT id, name, targets, model, status, started, elapsed, run_ids, cur, note
		 FROM campaigns WHERE id=?`, id)
	c, err := scanCampaign(row)
	if err == sql.ErrNoRows {
		return Campaign{}, false, nil
	}
	if err != nil {
		return Campaign{}, false, err
	}
	return c, true, nil
}

func scanCampaign(sc scanRow) (Campaign, error) {
	var c Campaign
	var started string
	if err := sc.Scan(&c.ID, &c.Name, &c.Targets, &c.Model, &c.Status, &started, &c.Elapsed,
		&c.RunIDs, &c.Cur, &c.Note); err != nil {
		return c, err
	}
	c.Started, _ = time.Parse(time.RFC3339Nano, started)
	return c, nil
}
