package store

import (
	"path/filepath"
	"testing"

	"github.com/t0ul/GORED/internal/core"
)

func TestSkillsSeedAndList(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.SeedSkills(core.Catalog()); err != nil {
		t.Fatal(err)
	}
	// Idempotent: seeding again adds nothing.
	if err := st.SeedSkills(core.Catalog()); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListSkills()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(core.Catalog()) {
		t.Fatalf("want %d skills, got %d", len(core.Catalog()), len(rows))
	}
	for _, r := range rows {
		if !r.BuiltIn || r.Name == "" || r.Instruction == "" {
			t.Errorf("bad seeded skill: %+v", r)
		}
	}

	// A user-authored skill is not a built-in.
	if err := st.UpsertSkill(core.Skill{Name: "mine", Temp: core.SkillWarm, Instruction: "do x"}); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.ListSkills()
	var found bool
	for _, r := range rows {
		if r.Name == "mine" {
			found = true
			if r.BuiltIn {
				t.Error("authored skill marked builtin")
			}
		}
	}
	if !found {
		t.Error("authored skill not listed")
	}
}
