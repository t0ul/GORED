package store

import "database/sql"

// Target is a registered app the campaign can point at: a base URL, which stages to run,
// the transport, and an auth recipe so the model can authenticate. The campaign names
// targets; this is the durable config for each. Secrets are stored in plaintext — this is
// a local-lab DB for the owner's own apps (per the campaign plan's locked decision).
//
// Two identity shapes are supported, matching the engine's tooling:
//   - creds login: PrivCreds/LowCreds are "user:password"; the model POSTs them to LoginPath
//     (JSON or form, with UserField/PassField) under a "session" name and reuses that session.
//   - static header: PrivHeader/LowHeader are "Name: value" headers the model carries per request.
type Target struct {
	Name       string // PK
	Base       string // base URL, e.g. http://127.0.0.1:8080
	Transport  string // "direct" | "brig"
	Stages     string // CSV of stage names to run, e.g. "recon,apiexploit,llmattack"
	Ensure     bool   // auto-(re)launch the bundled vulnapp before the run (demotarget)
	LoginPath  string // login endpoint for creds identities, e.g. /api/auth/login
	LoginType  string // "json" | "form"
	UserField  string // login body field for the username/email (default "email")
	PassField  string // login body field for the password (default "password")
	PrivCreds  string // privileged identity "user:password" (creds login)
	LowCreds   string // low-privilege identity "user:password" (creds login)
	PrivHeader string // privileged identity static header "Name: value"
	LowHeader  string // low-privilege identity static header "Name: value"
	Notes      string
}

// SaveTarget upserts a target by name.
func (s *Store) SaveTarget(t Target) error {
	ensure := 0
	if t.Ensure {
		ensure = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO targets (name, base, transport, stages, ensure_app, login_path, login_type, user_field, pass_field, priv_creds, low_creds, priv_header, low_header, notes)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(name) DO UPDATE SET
		   base=excluded.base, transport=excluded.transport, stages=excluded.stages, ensure_app=excluded.ensure_app,
		   login_path=excluded.login_path, login_type=excluded.login_type, user_field=excluded.user_field,
		   pass_field=excluded.pass_field, priv_creds=excluded.priv_creds, low_creds=excluded.low_creds,
		   priv_header=excluded.priv_header, low_header=excluded.low_header, notes=excluded.notes`,
		t.Name, t.Base, t.Transport, t.Stages, ensure, t.LoginPath, t.LoginType, t.UserField, t.PassField,
		t.PrivCreds, t.LowCreds, t.PrivHeader, t.LowHeader, t.Notes,
	)
	return err
}

// SeedTarget inserts a target only if one of that name does not already exist, so a default
// target set can be seeded on boot without clobbering the user's edits (mirrors SeedSkills).
func (s *Store) SeedTarget(t Target) error {
	ensure := 0
	if t.Ensure {
		ensure = 1
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO targets (name, base, transport, stages, ensure_app, login_path, login_type, user_field, pass_field, priv_creds, low_creds, priv_header, low_header, notes)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.Name, t.Base, t.Transport, t.Stages, ensure, t.LoginPath, t.LoginType, t.UserField, t.PassField,
		t.PrivCreds, t.LowCreds, t.PrivHeader, t.LowHeader, t.Notes,
	)
	return err
}

// ListTargets returns the registered targets, by name.
func (s *Store) ListTargets() ([]Target, error) {
	rows, err := s.db.Query(
		`SELECT name, base, transport, stages, ensure_app, login_path, login_type, user_field, pass_field, priv_creds, low_creds, priv_header, low_header, notes
		 FROM targets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTarget reads one target; ok is false when none exists.
func (s *Store) GetTarget(name string) (Target, bool, error) {
	row := s.db.QueryRow(
		`SELECT name, base, transport, stages, ensure_app, login_path, login_type, user_field, pass_field, priv_creds, low_creds, priv_header, low_header, notes
		 FROM targets WHERE name=?`, name)
	t, err := scanTarget(row)
	if err == sql.ErrNoRows {
		return Target{}, false, nil
	}
	if err != nil {
		return Target{}, false, err
	}
	return t, true, nil
}

// DeleteTarget removes a target by name.
func (s *Store) DeleteTarget(name string) error {
	_, err := s.db.Exec(`DELETE FROM targets WHERE name=?`, name)
	return err
}

func scanTarget(sc scanRow) (Target, error) {
	var t Target
	var ensure int
	if err := sc.Scan(&t.Name, &t.Base, &t.Transport, &t.Stages, &ensure, &t.LoginPath, &t.LoginType,
		&t.UserField, &t.PassField, &t.PrivCreds, &t.LowCreds, &t.PrivHeader, &t.LowHeader, &t.Notes); err != nil {
		return t, err
	}
	t.Ensure = ensure != 0
	return t, nil
}
