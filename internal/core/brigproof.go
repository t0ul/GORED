package core

// EscapeProofs turns a confirmed container RCE (and, when it happened, the escape) into
// proofs for the Validator. It is the shared seam both the scripted agent (gored-brigagent)
// and the model-driven agent (gored-brigswarm) use, so a Brig capture always lands the same
// verdict shape. It takes plain strings, not any Brig type, so the GORED core stays
// decoupled from the chamber module.
//
// The RCE is an exploitable app finding (CWE-78) with the executed exploit as its repro.
// When the escape was confirmed (a host-only canary was read from inside the container), a
// second proof records the privileged/root container (CWE-250); the Validator fuses the two
// on the same app into the host-compromise chain on the exploitable verdict.
func EscapeProofs(app, locus, rceRepro, escapeRepro, source string, escapeConfirmed bool) []Proof {
	ps := []Proof{{
		App: app, Locus: locus, Kind: "route", CWE: "CWE-78",
		Rung: LadderExploitable, Confidence: ConfCertain, Exploitable: true,
		Repro: rceRepro, Source: source, Evidence: "confirmed OS command injection (RCE) on the container app",
	}}
	if escapeConfirmed {
		ps = append(ps, Proof{
			App: app, Locus: "container", Kind: "container", CWE: "CWE-250",
			Rung: LadderExploitable, Confidence: ConfCertain, Exploitable: true,
			Repro: escapeRepro, Source: source,
			Evidence: "privileged container with a writable host bind; the RCE read a host-only canary = escape to the VM host",
		})
	}
	return ps
}
