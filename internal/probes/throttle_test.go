package probes_test

import (
	"context"
	"testing"

	"github.com/t0ul/GORED/demotarget"
	"github.com/t0ul/GORED/internal/core"
	probes "github.com/t0ul/GORED/internal/probes"
)

func throttleProbe(t *testing.T, base string) *probes.ThrottleProbe {
	t.Helper()
	return &probes.ThrottleProbe{
		Base:     base,
		Egress:   core.NewEgress(authority(t, base)),
		Attempts: 12,
		Workers:  6,
	}
}

// TestThrottleMissingOnVulnLogin proves the discovery on real behaviour: the vulnerable login
// counts nothing, so a concurrent burst of wrong-credential attempts is never blocked — a
// certain missing-throttle finding (CWE-307), decided on the server's own statuses.
func TestThrottleMissingOnVulnLogin(t *testing.T) {
	_, base := liveTarget(t) // vulnerable build
	f, err := throttleProbe(t, base).Probe(context.Background(), "/api/login", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Flagged() {
		t.Fatalf("vulnerable login has no rate limit; want flagged, got %+v", f)
	}
	if f.Blocked {
		t.Errorf("vulnerable login must never block the burst; got blocked=%v hist=%v", f.Blocked, f.StatusHist)
	}
	if f.CWE != "CWE-307" {
		t.Errorf("want CWE-307, got %q", f.CWE)
	}
}

// TestThrottlePresentOnHardenedLogin confirms the finding is wired to real behaviour: the
// hardened build rate-limits per client, so the burst is blocked with 429 and nothing is
// flagged — no false positive on a properly throttled endpoint.
func TestThrottlePresentOnHardenedLogin(t *testing.T) {
	s, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	base := serveTarget(t, s)
	f, err := throttleProbe(t, base).Probe(context.Background(), "/api/login", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if f.Flagged() {
		t.Fatalf("hardened login throttles; want not flagged, got %+v", f)
	}
	if !f.Blocked {
		t.Errorf("hardened login should block the burst with 429; got hist=%v", f.StatusHist)
	}
}
