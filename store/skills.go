package store

import "github.com/t0ul/GORED/internal/core"

// The skills table is the first step of the Studio migration: the agent's skills become
// DATA in the datastore instead of hardcoded Go vars, so a surface can list (and later
// edit) them. The run path still uses the in-code skills until the registry is wired to the
// stages; this table is the data milestone, seeded from core.Catalog.

// SeedSkills inserts the built-in skills if they are not already present. It never
// overwrites an existing row, so a future edited skill survives re-seeding.
func (s *Store) SeedSkills(skills []core.Skill) error {
	for _, sk := range skills {
		if _, err := s.db.Exec(
			`INSERT OR IGNORE INTO skills (name, temp, instruction, builtin) VALUES (?,?,?,1)`,
			sk.Name, string(sk.Temp), sk.Instruction,
		); err != nil {
			return err
		}
	}
	return nil
}

// SkillRow is a skill plus whether it is a built-in (seeded) or a user-authored one.
type SkillRow struct {
	core.Skill
	BuiltIn bool
}

// ListSkills returns the skills in the registry, built-ins first then by name.
func (s *Store) ListSkills() ([]SkillRow, error) {
	rows, err := s.db.Query(`SELECT name, temp, instruction, builtin FROM skills ORDER BY builtin DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SkillRow
	for rows.Next() {
		var r SkillRow
		var temp string
		var builtin int
		if err := rows.Scan(&r.Name, &temp, &r.Instruction, &builtin); err != nil {
			return nil, err
		}
		r.Temp = core.SkillTemp(temp)
		r.BuiltIn = builtin != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertSkill writes a user-authored (or edited) skill. The authoring surface is deferred;
// this is the write half the registry will use once Studio gains an editor.
func (s *Store) UpsertSkill(sk core.Skill) error {
	_, err := s.db.Exec(
		`INSERT INTO skills (name, temp, instruction, builtin) VALUES (?,?,?,0)
		 ON CONFLICT(name) DO UPDATE SET temp=excluded.temp, instruction=excluded.instruction`,
		sk.Name, string(sk.Temp), sk.Instruction,
	)
	return err
}
