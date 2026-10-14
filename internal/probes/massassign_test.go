package probes_test

import (
	"context"
	"testing"

	"github.com/t0ul/GORED/internal/core"
	probes "github.com/t0ul/GORED/internal/probes"
	"github.com/t0ul/GORED/demotarget"
)

func aliceProbe(t *testing.T, base string) *probes.MassAssignProbe {
	t.Helper()
	return &probes.MassAssignProbe{
		Base:     base,
		Egress:   core.NewEgress(authority(t, base)),
		Sessions: core.NewSessions(),
		Low:      core.Identity{Name: "alice", Session: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
	}
}

// TestMassAssignVulnerableHonorsRole proves the discovery: the vulnerable PUT /api/profile
// binds the whole body onto the model, so the low-privilege alice sets her own role to
// admin. The independent read-back makes it a certain finding with no model involved.
func TestMassAssignVulnerableHonorsRole(t *testing.T) {
	_, base := liveTarget(t) // vulnerable build
	f, err := aliceProbe(t, base).Probe(context.Background(), "PUT", "/api/profile", "/api/profile")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Flagged() {
		t.Fatalf("vulnerable endpoint should be flagged; got %+v", f)
	}
	if f.Field != "role" {
		t.Errorf("want honored field role, got %q", f.Field)
	}
	if f.Confidence != core.ConfCertain {
		t.Errorf("read-back confirmed persistence, want certain, got %q", f.Confidence)
	}
	if f.WasValue != "user" || f.SentValue != "admin" {
		t.Errorf("want role user -> admin, got was=%v sent=%v", f.WasValue, f.SentValue)
	}
	if f.CWE != "CWE-915" {
		t.Errorf("want CWE-915, got %q", f.CWE)
	}
}

// TestMassAssignHardenedIgnoresRole confirms the finding is wired to real behavior: with
// the name/bio whitelist on, a client-set role is dropped, so nothing is flagged — no
// false positive on a properly built endpoint.
func TestMassAssignHardenedIgnoresRole(t *testing.T) {
	s, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	base := serveTarget(t, s)
	f, err := aliceProbe(t, base).Probe(context.Background(), "PUT", "/api/profile", "/api/profile")
	if err != nil {
		t.Fatal(err)
	}
	if f.Flagged() {
		t.Errorf("hardened endpoint ignores client-set role; should not flag, got field=%q conf=%q", f.Field, f.Confidence)
	}
}

// TestMassAssignUpdatesStillWork is the control's own sanity: the hardened endpoint must
// still accept the legitimate name/bio change it whitelists, so the fix is not "reject
// everything". A read-back shows the new name and the unchanged role.
func TestMassAssignUpdatesStillWork(t *testing.T) {
	s, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	base := serveTarget(t, s)
	p := &probes.MassAssignProbe{
		Base: base, Egress: core.NewEgress(authority(t, base)), Sessions: core.NewSessions(),
		Low:    core.Identity{Name: "alice", Session: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		Fields: []probes.MassAssignField{{Name: "name", Value: "Alice Updated"}},
	}
	f, err := p.Probe(context.Background(), "PUT", "/api/profile", "/api/profile")
	if err != nil {
		t.Fatal(err)
	}
	// name is whitelisted, so the probe sees it change — that is expected and benign,
	// not a privilege bug. The test just confirms the write path works end to end.
	if !f.Flagged() || f.Field != "name" {
		t.Errorf("whitelisted name change should round-trip, got %+v", f)
	}
}
