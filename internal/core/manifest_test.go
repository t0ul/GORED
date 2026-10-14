package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDemoManifestIsValid(t *testing.T) {
	// The tracked demo manifest must load and validate.
	m, err := LoadManifest(filepath.Join("..", "..", "demotarget", "demo.target.json"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "demotarget" || len(m.Flags) != 2 {
		t.Fatalf("unexpected manifest: %+v", m)
	}
}

func TestManifestValidateCatchesProblems(t *testing.T) {
	cases := map[string]Manifest{
		"no name":   {Flags: []FlagSpec{{ID: "a", Class: ClassIDOR, Difficulty: DiffEasy}}},
		"no flags":  {Name: "x"},
		"empty id":  {Name: "x", Flags: []FlagSpec{{Class: ClassIDOR, Difficulty: DiffEasy}}},
		"bad class": {Name: "x", Flags: []FlagSpec{{ID: "a", Class: "nope", Difficulty: DiffEasy}}},
		"bad diff":  {Name: "x", Flags: []FlagSpec{{ID: "a", Class: ClassIDOR, Difficulty: "nope"}}},
		"dup id": {Name: "x", Flags: []FlagSpec{
			{ID: "a", Class: ClassIDOR, Difficulty: DiffEasy},
			{ID: "a", Class: ClassSSRF, Difficulty: DiffMedium},
		}},
	}
	for name, m := range cases {
		if err := m.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestLoadManifestRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte(`{"name":"x","flags":[{"id":"a","class":"idor","difficulty":"easy"}],"surprise":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(p); err == nil {
		t.Fatal("unknown field accepted")
	}
}
