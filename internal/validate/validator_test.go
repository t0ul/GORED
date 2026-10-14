package validate_test

import (
	"testing"

	"github.com/t0ul/GORED/internal/core"
	validate "github.com/t0ul/GORED/internal/validate"
)

func findVerdict(vs []core.Verdict, app, locus string) *core.Verdict {
	for i := range vs {
		if vs[i].App == app && vs[i].Locus == locus {
			return &vs[i]
		}
	}
	return nil
}

// TestValidatorFusionAndChain locks the pure logic: a scanner finding and a GORED proof
// on the same locus fuse into one exploitable verdict (the scanner reported it, GORED
// proved it); a proof with no scanner match stands alone as a GORED discovery; an
// exploitable app verdict plus a root-container proof earns the host-compromise chain;
// and the ranking puts the exploitable verdicts on top and a ruled-out one at the bottom.
func TestValidatorFusionAndChain(t *testing.T) {
	scanners := []core.ScannerFinding{
		// a SAST claim on /api/profile — present, but unproven
		{Source: "Semgrep", App: "demo", Location: "/api/profile", Severity: "Medium", CWE: "CWE-862", Title: "missing authorization check"},
		// a dependency CVE the reachability scanner ruled out — must sink to the bottom
		{Source: "govulncheck", App: "demo", Location: "golang.org/x/crypto", Severity: "Low", Title: "GO-x in x/crypto", Reachable: boolPtr(false)},
	}
	proofs := []core.Proof{
		// GORED proved the /api/profile issue exploitable (fuses with the Semgrep claim)
		{App: "demo", Locus: "/api/profile", Kind: "route", CWE: "CWE-915", Rung: core.LadderExploitable, Confidence: core.ConfCertain, Exploitable: true, Repro: "PUT /api/profile {role:admin}", Source: "gored-massassign", Evidence: "role user->admin, read back"},
		// GORED discovered a JWT bypass no scanner reported (stands alone)
		{App: "demo", Locus: "/api/whoami", Kind: "route", CWE: "CWE-347", Rung: core.LadderExploitable, Confidence: core.ConfCertain, Exploitable: true, Repro: "forge token, replay", Source: "gored-jwt", Evidence: "forged token accepted"},
		// the container runs as root (feeds the chain, not exploitable itself)
		{App: "demo", Locus: "Dockerfile", Kind: "container", CWE: "CWE-250", Rung: core.LadderPresent, Confidence: core.ConfHigh, Source: "gored-runtime", Evidence: "runs as root"},
	}

	vs := (&validate.Validator{}).Validate(scanners, proofs)

	prof := findVerdict(vs, "demo", "/api/profile")
	if prof == nil || !prof.Exploitable || prof.Rung != core.LadderExploitable {
		t.Fatalf("/api/profile should fuse to an exploitable verdict, got %+v", prof)
	}
	if !contains(prof.Sources, "Semgrep") || !contains(prof.Sources, "gored-massassign") {
		t.Errorf("fused verdict should list both the scanner and GORED, got %v", prof.Sources)
	}
	if prof.Repro == "" {
		t.Errorf("an exploitable verdict must carry its repro")
	}
	if len(prof.Chain) == 0 {
		t.Errorf("exploitable app + root container should earn the host-compromise chain, got none")
	}

	who := findVerdict(vs, "demo", "/api/whoami")
	if who == nil || !who.Exploitable {
		t.Fatalf("/api/whoami should be an exploitable GORED-only verdict, got %+v", who)
	}
	if !contains(who.Sources, "gored-jwt") {
		t.Errorf("GORED-only verdict should credit gored-jwt, got %v", who.Sources)
	}

	// Ranking: exploitable on top, the ruled-out dependency at the very bottom.
	if vs[0].Rung != core.LadderExploitable {
		t.Errorf("an exploitable verdict should rank first, got %s %s:%s", vs[0].Rung, vs[0].App, vs[0].Locus)
	}
	if last := vs[len(vs)-1]; last.Rung != core.LadderRuledOut {
		t.Errorf("the ruled-out dependency should rank last, got %s %s:%s", last.Rung, last.App, last.Locus)
	}
}

