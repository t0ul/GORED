package gored_test

import (
	"context"
	"testing"

	gored "github.com/t0ul/GORED"
)

// TestHuntOnDemotargetGeneric runs the whole generic hunt pipeline (discover ->
// differential -> report) against the demo target with no model. It proves the
// pipeline is app-agnostic: the same Hunt that finds CWE-862 in RiskRancher maps
// this different app's surface and flags its identity-based broken access control
// (GET /api/memos), while leaving the correctly scoped control unflagged. Without a
// model the flag is reported UNVERIFIED, never CONFIRMED — trust comes from a repro.
func TestHuntOnDemotargetGeneric(t *testing.T) {
	_, base := liveTarget(t)

	h := &gored.Hunt{
		Base: base, Egress: gored.NewEgress(authority(t, base)), Sessions: gored.NewSessions(),
		Priv: gored.Identity{Name: "admin", Headers: map[string]string{"X-Session": "admin-session"}},
		Low:  gored.Identity{Name: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		Anon: &gored.Identity{Name: "anon"},
		// Model nil: the model-dependent confirmation is exercised live; here we prove
		// the generic discover+differential pipeline runs on a second app.
	}
	rep, err := h.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if !contains(rep.Discovered, "/api/memos") || !contains(rep.Discovered, "/api/memos/mine") {
		t.Fatalf("discovery did not map the memo surface: %v", rep.Discovered)
	}

	var memos *gored.HuntFinding
	for i := range rep.Findings {
		if rep.Findings[i].Path == "/api/memos/mine" {
			t.Errorf("scoped control /api/memos/mine must not be a finding")
		}
		if rep.Findings[i].Path == "/api/memos" {
			memos = &rep.Findings[i]
		}
	}
	if memos == nil {
		t.Fatalf("expected /api/memos flagged as BAC; findings=%+v", rep.Findings)
	}
	if memos.CWE != "CWE-862" {
		t.Errorf("/api/memos: want CWE-862, got %q", memos.CWE)
	}
	if memos.Confirmed || memos.Verified {
		t.Errorf("/api/memos should be UNVERIFIED with no model, got verified=%v confirmed=%v", memos.Verified, memos.Confirmed)
	}
	if rep.Unverified != 1 || rep.Confirmed != 0 {
		t.Errorf("counts off: confirmed=%d unconfirmed=%d unverified=%d", rep.Confirmed, rep.Unconfirmed, rep.Unverified)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
