package probes_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/t0ul/GORED/demotarget"
	"github.com/t0ul/GORED/internal/core"
	probes "github.com/t0ul/GORED/internal/probes"
)

func pwPolicyProbe(t *testing.T, base string) *probes.PasswordPolicyProbe {
	t.Helper()
	return &probes.PasswordPolicyProbe{
		Base:   base,
		Egress: core.NewEgress(authority(t, base)),
	}
}

// TestPasswordPolicyMissingOnVulnRegister proves the discovery: the vulnerable register accepts a
// trivially weak password for a new account (2xx) — a certain weak-password finding (CWE-521).
func TestPasswordPolicyMissingOnVulnRegister(t *testing.T) {
	_, base := liveTarget(t) // vulnerable build
	f, err := pwPolicyProbe(t, base).Probe(context.Background(), "/api/register")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Flagged() {
		t.Fatalf("vulnerable register has no password policy; want flagged, got %+v", f)
	}
	if f.Status < 200 || f.Status >= 300 {
		t.Errorf("want a 2xx acceptance of the weak password, got %d", f.Status)
	}
	if f.CWE != "CWE-521" {
		t.Errorf("want CWE-521, got %q", f.CWE)
	}
}

// TestPasswordPolicyPresentOnHardenedRegister confirms the finding is wired to real behaviour: the
// hardened build rejects a weak password with 400, so nothing is flagged — no false positive.
func TestPasswordPolicyPresentOnHardenedRegister(t *testing.T) {
	s, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	base := serveTarget(t, s)
	f, err := pwPolicyProbe(t, base).Probe(context.Background(), "/api/register")
	if err != nil {
		t.Fatal(err)
	}
	if f.Flagged() {
		t.Fatalf("hardened register enforces a policy; want not flagged, got %+v", f)
	}
	if f.Status != http.StatusBadRequest {
		t.Errorf("want 400 rejecting the weak password, got %d", f.Status)
	}
}
