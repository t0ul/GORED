package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/t0ul/GORED/internal/core"
	validate "github.com/t0ul/GORED/internal/validate"
	"github.com/t0ul/gobrig"
)

// TestBuildProofsAndValidate: a confirmed RCE + confirmed escape become an exploitable
// CWE-78 verdict carrying the host-compromise chain, with the executed exploit as repro.
func TestBuildProofsAndValidate(t *testing.T) {
	f := gobrig.RCEFinding{Endpoint: "/exec", Param: "cmd", CWE: "CWE-78", Confirmed: true,
		Evidence: "param \"cmd\" on /exec echoed the nonce"}
	ps := buildProofs("brig-target", "http://127.0.0.1:8088", f, true, true)
	if len(ps) != 2 {
		t.Fatalf("want 2 proofs (RCE + container), got %d", len(ps))
	}

	verdicts := (&validate.Validator{}).Validate(nil, ps)

	var rce *core.Verdict
	for i := range verdicts {
		if verdicts[i].Locus == "/exec" {
			rce = &verdicts[i]
		}
	}
	if rce == nil || !rce.Exploitable || rce.Rung != core.LadderExploitable {
		t.Fatalf("expected an exploitable /exec verdict, got %+v", rce)
	}
	if !slices.Contains(rce.CWEs, "CWE-78") {
		t.Errorf("RCE verdict should carry CWE-78, got %v", rce.CWEs)
	}
	if rce.Repro == "" {
		t.Error("exploitable verdict must carry its repro")
	}
	if len(rce.Chain) == 0 || !strings.Contains(rce.Chain[0], "host-compromise") {
		t.Errorf("confirmed escape should raise the host-compromise chain, got %v", rce.Chain)
	}
}

// TestBuildProofsRCEOnly: an RCE with no confirmed escape yields the exploitable RCE
// verdict but no host chain.
func TestBuildProofsRCEOnly(t *testing.T) {
	f := gobrig.RCEFinding{Endpoint: "/exec", Param: "cmd", CWE: "CWE-78", Confirmed: true}
	ps := buildProofs("t", "http://x", f, true, false)
	if len(ps) != 1 {
		t.Fatalf("want 1 proof, got %d", len(ps))
	}
	v := (&validate.Validator{}).Validate(nil, ps)
	if len(v) != 1 || !v[0].Exploitable {
		t.Fatalf("want 1 exploitable verdict, got %+v", v)
	}
	if len(v[0].Chain) != 0 {
		t.Errorf("no escape confirmed -> no host chain, got %v", v[0].Chain)
	}
}
