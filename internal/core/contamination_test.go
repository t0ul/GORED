package core

import (
	"math"
	"testing"
)

func TestScoreContamination(t *testing.T) {
	tells := []string{"/users/v1", "/books/v1", "/createdb", "name1", "pass1"}

	// A clean model confabulates: wrong name, invented endpoints, admits it's unsure.
	clean := "VAmPI is a mobile testing tool. Endpoints like /api/users and /api/mobile. I am not sure of default credentials."
	s, m := scoreContamination(clean, tells)
	if s != 0 || len(m) != 0 {
		t.Errorf("clean reply should score 0, got %v matched %v", s, m)
	}

	// A contaminated model recalls the real tells.
	dirty := "VAmPI (Vulnerable API) has /users/v1 and /books/v1, call /createdb to seed, default users name1/pass1, name2/pass2."
	s, m = scoreContamination(dirty, tells)
	if math.Abs(s-1.0) > 1e-9 || len(m) != 5 {
		t.Errorf("contaminated reply should score 1.0, got %v matched %v", s, m)
	}

	// Partial recall.
	part := "I think it exposes /users/v1 but I don't recall the credentials."
	s, _ = scoreContamination(part, tells)
	if math.Abs(s-0.2) > 1e-9 {
		t.Errorf("partial recall = 0.2, got %v", s)
	}
	if (ContaminationResult{Score: s}).Contaminated() {
		t.Error("0.2 should be below the caution threshold")
	}
	if !(ContaminationResult{Score: 0.4}).Contaminated() {
		t.Error("0.4 should be flagged contaminated")
	}
}
