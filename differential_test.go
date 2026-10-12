package gored_test

import (
	"context"
	"net/http/httptest"
	"testing"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/demotarget"
)

func serveTarget(t *testing.T, s *demotarget.Server) string {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestDifferentialOracleFlagsBACNotScoped runs the canary-free differential oracle
// against the real demo target as two header identities (admin = privileged, alice =
// low-privilege) plus an anonymous baseline. It must flag the BAC list endpoint
// (alice sees admin's confidential memo) and must NOT flag the correctly-scoped
// control (alice sees only her own) or a public page — bounding false positives with
// no planted canary.
func TestDifferentialOracleFlagsBACNotScoped(t *testing.T) {
	_, base := liveTarget(t)

	oracle := &gored.DifferentialOracle{
		Base: base, Egress: gored.NewEgress(authority(t, base)), Sessions: gored.NewSessions(),
		Priv: gored.Identity{Name: "admin", Headers: map[string]string{"X-Session": "admin-session"}},
		Low:  gored.Identity{Name: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		Anon: &gored.Identity{Name: "anon"},
	}

	findings, err := oracle.Sweep(context.Background(), [][2]string{
		{"GET", "/api/memos"},      // BAC: low-priv sees privileged data
		{"GET", "/api/memos/mine"}, // scoped control: low-priv sees only its own
		{"GET", "/"},               // public page: anon sees it too
	})
	if err != nil {
		t.Fatal(err)
	}

	byPath := map[string]gored.DiffFinding{}
	for _, f := range findings {
		byPath[f.Path] = f
	}

	if got := byPath["/api/memos"]; got.Verdict != gored.VerdictBAC {
		t.Errorf("/api/memos: want bac, got %q (%s)", got.Verdict, got.Evidence)
	} else if got.Marker == "" {
		t.Errorf("/api/memos flagged bac but carries no marker for the repro")
	}
	if got := byPath["/api/memos/mine"]; got.Verdict == gored.VerdictBAC {
		t.Errorf("/api/memos/mine: scoped control must NOT be flagged bac (%s)", got.Evidence)
	}
	if got := byPath["/"]; got.Verdict == gored.VerdictBAC {
		t.Errorf("/: public page must NOT be flagged bac (%s)", got.Evidence)
	}
}

// TestDifferentialOracleHardenedClosesBAC confirms the finding is wired to real
// behavior: with the controls on (per-caller scoping), the same sweep no longer
// flags the list endpoint. A test that could not go from flagged to not-flagged
// would prove nothing.
func TestDifferentialOracleHardenedClosesBAC(t *testing.T) {
	s, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	base := serveTarget(t, s)

	oracle := &gored.DifferentialOracle{
		Base: base, Egress: gored.NewEgress(authority(t, base)), Sessions: gored.NewSessions(),
		Priv: gored.Identity{Name: "admin", Headers: map[string]string{"X-Session": "admin-session"}},
		Low:  gored.Identity{Name: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		Anon: &gored.Identity{Name: "anon"},
	}
	f, err := oracle.Probe(context.Background(), "GET", "/api/memos")
	if err != nil {
		t.Fatal(err)
	}
	if f.Flagged() {
		t.Errorf("hardened build still flagged /api/memos: %s", f.Evidence)
	}
}
