package main

import (
	"fmt"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/gobrig"
)

// buildProofs turns a confirmed Brig escape into GORED proofs for the Validator. A
// discovered+confirmed RCE is an exploitable app finding (CWE-78) with the executed
// exploit as its repro. When the exploit also read the host canary through the
// misconfigured container, a second proof records the privileged/root container
// (CWE-250); the Validator fuses the two on the same app into a host-compromise chain on
// the exploitable verdict. Everything here is proven by canary, so the rungs are earned.
func buildProofs(app, base string, f gobrig.RCEFinding, rceConfirmed, escapeConfirmed bool) []core.Proof {
	if !f.Confirmed || !rceConfirmed {
		if !escapeConfirmed {
			return nil
		}
	}
	rceRepro := f.Exploit(base, "cat /flag-in-container") + "  (read the in-container canary)"
	escRepro := f.Exploit(base, "cat /host/root/brig-canary") + "  (read a host-only canary from inside the container)"
	return core.EscapeProofs(app, f.Endpoint, rceRepro, escRepro, "gored-brigagent", escapeConfirmed)
}

// summarize renders the verdicts for the agent's report.
func summarize(verdicts []core.Verdict) string {
	out := ""
	for _, v := range verdicts {
		mark := ""
		if v.Exploitable {
			mark = " EXPLOITABLE"
		}
		out += fmt.Sprintf("[%s %s%s] %s:%s %v\n", v.Rung, v.Confidence, mark, v.App, v.Locus, v.CWEs)
		if v.Repro != "" {
			out += "    repro: " + v.Repro + "\n"
		}
		for _, c := range v.Chain {
			out += "    chain: " + c + "\n"
		}
	}
	return out
}
