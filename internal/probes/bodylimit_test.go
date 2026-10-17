package probes_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/t0ul/GORED/demotarget"
	"github.com/t0ul/GORED/internal/core"
	probes "github.com/t0ul/GORED/internal/probes"
)

func bodyLimitProbe(t *testing.T, base string) *probes.BodyLimitProbe {
	t.Helper()
	return &probes.BodyLimitProbe{
		Base:     base,
		Egress:   core.NewEgress(authority(t, base)),
		Sessions: core.NewSessions(),
		Identity: core.Identity{Name: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		// a small oversized body keeps the test fast while still exceeding the hardened cap (1 MiB)
		SizeBytes: 2 << 20,
	}
}

// TestBodyLimitMissingOnVulnWrite proves the discovery: the vulnerable write reads an unbounded
// body, so a multi-megabyte request is accepted (2xx) — a certain unbounded-body finding (CWE-770).
func TestBodyLimitMissingOnVulnWrite(t *testing.T) {
	_, base := liveTarget(t) // vulnerable build
	f, err := bodyLimitProbe(t, base).Probe(context.Background(), "POST", "/api/memos")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Flagged() {
		t.Fatalf("vulnerable write has no body limit; want flagged, got %+v", f)
	}
	if f.Status < 200 || f.Status >= 300 {
		t.Errorf("want a 2xx acceptance of the oversized body, got %d", f.Status)
	}
	if f.CWE != "CWE-770" {
		t.Errorf("want CWE-770, got %q", f.CWE)
	}
}

// TestBodyLimitPresentOnHardenedWrite confirms the finding is wired to real behaviour: the
// hardened build caps the body with http.MaxBytesReader, so the oversized request is rejected
// with 413 and nothing is flagged — no false positive on a bounded endpoint.
func TestBodyLimitPresentOnHardenedWrite(t *testing.T) {
	s, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	base := serveTarget(t, s)
	f, err := bodyLimitProbe(t, base).Probe(context.Background(), "POST", "/api/memos")
	if err != nil {
		t.Fatal(err)
	}
	if f.Flagged() {
		t.Fatalf("hardened write caps the body; want not flagged, got %+v", f)
	}
	if f.Status != http.StatusRequestEntityTooLarge {
		t.Errorf("want 413 on the oversized body, got %d", f.Status)
	}
}
