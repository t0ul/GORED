package probes_test

import (
	"context"
	"strings"
	"testing"

	"github.com/t0ul/GORED/internal/core"
	probes "github.com/t0ul/GORED/internal/probes"
)

// TestHuntOnDemotargetGeneric runs the whole generic hunt pipeline (discover ->
// differential -> report) against the demo target with no model. It proves the
// pipeline is app-agnostic: the same Hunt that finds CWE-862 in RiskRancher maps
// this different app's surface and flags its identity-based broken access control
// (GET /api/memos), while leaving the correctly scoped control unflagged. Without a
// model the flag is reported UNVERIFIED, never CONFIRMED — trust comes from a repro.
func TestHuntOnDemotargetGeneric(t *testing.T) {
	_, base := liveTarget(t)

	h := &probes.Hunt{
		Base: base, Egress: core.NewEgress(authority(t, base)), Sessions: core.NewSessions(),
		Priv: core.Identity{Name: "admin", Headers: map[string]string{"X-Session": "admin-session"}},
		Low:  core.Identity{Name: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		Anon: &core.Identity{Name: "anon"},
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

	var memos *probes.HuntFinding
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

// TestHuntMergesSeedPaths proves the ajax-spider-as-discovery path: URLs from an
// external crawler are reduced to same-origin paths and merged into the testable
// surface (closing the SPA-depth gap), while off-origin URLs are dropped.
func TestHuntMergesSeedPaths(t *testing.T) {
	_, base := liveTarget(t)
	h := &probes.Hunt{
		Base: base, Egress: core.NewEgress(authority(t, base)), Sessions: core.NewSessions(),
		Priv: core.Identity{Name: "admin", Headers: map[string]string{"X-Session": "admin-session"}},
		Low:  core.Identity{Name: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		Anon: &core.Identity{Name: "anon"},
		SeedPaths: []string{
			base + "/api/spa-route",      // full same-origin URL from a crawler
			"/api/xhr-endpoint",          // a bare path
			"https://evil.example/pwn",   // off-origin: must be dropped
		},
	}
	rep, err := h.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/api/spa-route", "/api/xhr-endpoint"} {
		if !contains(rep.Discovered, want) {
			t.Errorf("seeded path %s not merged into the surface: %v", want, rep.Discovered)
		}
	}
	for _, p := range rep.Discovered {
		if strings.Contains(p, "evil.example") {
			t.Errorf("off-origin seed leaked into the surface: %s", p)
		}
	}
}
