package core

import "testing"

func TestMatrixCellsModelMajor(t *testing.T) {
	spec := MatrixSpec{
		Models:  []string{"m1", "m2"},
		Temps:   []SkillTemp{SkillCold, SkillWarm},
		FlagIDs: []string{"f1", "f2"},
		Trials:  3,
	}
	cells := spec.Cells()
	if len(cells) != 2*2*2*3 {
		t.Fatalf("want 24 cells, got %d", len(cells))
	}
	// Model-major: the first 12 cells are all m1.
	for i := 0; i < 12; i++ {
		if cells[i].Model != "m1" {
			t.Fatalf("cell %d not model-major: %+v", i, cells[i])
		}
	}
	if cells[0] != (Cell{Model: "m1", Temp: SkillCold, Flag: "f1", Trial: 1}) {
		t.Fatalf("first cell wrong: %+v", cells[0])
	}
}

func TestSkillForSelection(t *testing.T) {
	if s, ok := SkillFor(ClassSSRF, SkillCold); !ok || s.Temp != SkillCold {
		t.Fatalf("cold should always resolve: %+v %v", s, ok)
	}
	if s, ok := SkillFor(ClassIDOR, SkillWarm); !ok || s.Name != "warm-idor" {
		t.Fatalf("warm idor wrong: %+v %v", s, ok)
	}
	if s, ok := SkillFor(ClassSSRF, SkillWarm); !ok || s.Name != "warm-ssrf" {
		t.Fatalf("warm ssrf wrong: %+v %v", s, ok)
	}
	if _, ok := SkillFor(ClassInjection, SkillWarm); ok {
		t.Fatal("no warm skill exists for injection yet; should report false")
	}
}

func TestHostPort(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:18080":           "127.0.0.1:18080",
		"http://127.0.0.1:18080/api/notes": "127.0.0.1:18080",
		"https://localhost:443/x":          "localhost:443",
	}
	for in, want := range cases {
		if got := hostPort(in); got != want {
			t.Errorf("hostPort(%q)=%q want %q", in, got, want)
		}
	}
}
