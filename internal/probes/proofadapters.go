package probes

import (
	"fmt"

	gored "github.com/t0ul/GORED"
)

// Adapters: a probe's own finding -> a normalized core Proof. They live with the probes
// (they read probe-specific finding fields) and produce the shared gored.Proof vocabulary,
// so the validate layer consumes Proofs without knowing any probe's finding shape.

// ProofFromHunt normalizes a gored-hunt access-control finding. A confirmed finding (the
// model-written repro reproduced the disclosure) is exploitable and carries that repro;
// a certain-but-unconfirmed one is triggerable; a high one is reachable.
func ProofFromHunt(f HuntFinding, app string) (gored.Proof, bool) {
	if f.Verdict != VerdictBAC {
		return gored.Proof{}, false
	}
	locus, kind := gored.NormLocus(f.Path)
	p := gored.Proof{App: app, Locus: locus, Kind: kind, CWE: f.CWE, Confidence: f.Confidence,
		Source: "gored-hunt", Evidence: f.Evidence}
	switch {
	case f.Confirmed:
		p.Rung, p.Exploitable, p.Repro = gored.LadderExploitable, true, f.ReproGo
	case f.Confidence == gored.ConfCertain:
		p.Rung = gored.LadderTriggerable
	case f.Confidence == gored.ConfHigh:
		p.Rung = gored.LadderReachable
	default:
		p.Rung = gored.LadderReported
	}
	return p, true
}

// ProofFromMassAssign normalizes a mass-assignment finding. Certain means the probe wrote
// a privileged field and read it back changed — an executed privilege escalation, so
// exploitable; high (reflected only) is triggerable.
func ProofFromMassAssign(f MassAssignFinding, app string) (gored.Proof, bool) {
	if !f.Flagged() {
		return gored.Proof{}, false
	}
	locus, kind := gored.NormLocus(f.WritePath)
	p := gored.Proof{App: app, Locus: locus, Kind: kind, CWE: f.CWE, Confidence: f.Confidence,
		Source: "gored-massassign", Evidence: f.Evidence}
	if f.Confidence == gored.ConfCertain {
		p.Rung, p.Exploitable = gored.LadderExploitable, true
		p.Repro = fmt.Sprintf("%s %s with {\"%s\":%v} as the low-priv identity; read it back changed", f.Method, f.WritePath, f.Field, f.SentValue)
	} else {
		p.Rung = gored.LadderTriggerable
	}
	return p, true
}

// ProofFromJWT normalizes a JWT finding. Certain means a forged token was accepted on
// replay — an executed authentication bypass, so exploitable; high (forgeable, replay
// not confirmed) is triggerable. locus is the protected path the token unlocks.
func ProofFromJWT(f JWTFinding, app, locus string) (gored.Proof, bool) {
	if !f.Flagged() {
		return gored.Proof{}, false
	}
	l, kind := gored.NormLocus(locus)
	p := gored.Proof{App: app, Locus: l, Kind: kind, CWE: f.CWE, Confidence: f.Confidence,
		Source: "gored-jwt", Evidence: f.Evidence}
	if f.Confidence == gored.ConfCertain {
		p.Rung, p.Exploitable = gored.LadderExploitable, true
		p.Repro = fmt.Sprintf("forge a %s token (vector %s) and replay it on %s", f.Alg, f.Vector, locus)
	} else {
		p.Rung = gored.LadderTriggerable
	}
	return p, true
}
