package gored_test

import (
	"context"
	"strings"
	"testing"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/demotarget"
)

func idorHunt(t *testing.T, base string) gored.HuntReport {
	t.Helper()
	sessions := gored.NewSessions()
	eg := gored.NewEgress(authority(t, base))
	priv := gored.Identity{Name: "admin", Session: "admin", Headers: map[string]string{"X-Session": "admin-session"}}
	h := &gored.Hunt{
		Base: base, Egress: eg, Sessions: sessions,
		Priv: priv,
		Low:  gored.Identity{Name: "alice", Session: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		Anon: &gored.Identity{Name: "anon", Session: "anon"},
		// Seeder plants a memo as admin, then the id-swap reads /api/memos/{id} as
		// alice. No model: the canary overlay confirms certainty without one.
		Seeder: &gored.CanarySeeder{Base: base, Egress: eg, Sessions: sessions, Priv: priv},
	}
	rep, err := h.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// TestHuntObjectLevelIDOR proves phase 7a: the seeder plants a memo as admin and the
// id-swap reads it by id as the low-privilege alice, so the object-level IDOR on
// GET /api/memos/{id} is found (CWE-639, certain via the canary) — a class the
// collection-only differential missed.
func TestHuntObjectLevelIDOR(t *testing.T) {
	_, base := liveTarget(t)
	rep := idorHunt(t, base)

	var idor *gored.HuntFinding
	for i := range rep.Findings {
		if rep.Findings[i].CWE == "CWE-639" && strings.HasPrefix(rep.Findings[i].Path, "/api/memos/") {
			idor = &rep.Findings[i]
		}
	}
	if idor == nil {
		t.Fatalf("expected a CWE-639 object-level IDOR on /api/memos/{id}; findings=%+v", rep.Findings)
	}
	if idor.Confidence != gored.ConfCertain {
		t.Errorf("object IDOR should be certain (canary disclosed), got %q", idor.Confidence)
	}
}

// TestHuntObjectLevelIDORHardenedClosed confirms the finding is wired to real
// behavior: with per-record ownership on, the id-swap no longer discloses the memo,
// so no CWE-639 is reported.
func TestHuntObjectLevelIDORHardenedClosed(t *testing.T) {
	s, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	rep := idorHunt(t, serveTarget(t, s))
	for _, f := range rep.Findings {
		if f.CWE == "CWE-639" {
			t.Errorf("hardened build still reported an object IDOR: %s (%s)", f.Path, f.Evidence)
		}
	}
}
