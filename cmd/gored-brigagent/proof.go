package main

import (
	"fmt"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/gobrig"
)

// buildProofs turns a confirmed Brig escape into GORED proofs for the Validator. A
// discovered+confirmed RCE is an exploitable app finding (CWE-78) with the executed
// exploit as its repro. When the exploit also read the host canary through the
// misconfigured container, a second proof records the privileged/root container
// (CWE-250); the Validator fuses the two on the same app into a host-compromise chain on
// the exploitable verdict. Everything here is proven by canary, so the rungs are earned.
func buildProofs(app, base string, f gobrig.RCEFinding, rceConfirmed, escapeConfirmed bool) []gored.Proof {
	var ps []gored.Proof
	if f.Confirmed && rceConfirmed {
		ps = append(ps, gored.Proof{
			App: app, Locus: f.Endpoint, Kind: "route", CWE: f.CWE,
			Rung: gored.LadderExploitable, Confidence: gored.ConfCertain, Exploitable: true,
			Repro:    f.Exploit(base, "cat /flag-in-container") + "  (read the in-container canary)",
			Source:   "gored-brigagent",
			Evidence: f.Evidence + "; RCE confirmed by reading the in-container canary",
		})
	}
	if escapeConfirmed {
		// The container the RCE landed in is privileged with a writable host bind; the
		// exploit read a host-only canary through it. Record the misconfig so the Validator
		// raises the host-compromise chain on the exploitable verdict.
		ps = append(ps, gored.Proof{
			App: app, Locus: "container", Kind: "container", CWE: "CWE-250",
			Rung: gored.LadderExploitable, Confidence: gored.ConfCertain, Exploitable: true,
			Repro:    f.Exploit(base, "cat /host/root/brig-canary") + "  (read a host-only canary from inside the container)",
			Source:   "gored-brigagent",
			Evidence: "privileged container with a writable host bind; the RCE read a host-only canary = container escape to the VM host",
		})
	}
	return ps
}

// summarize renders the verdicts for the agent's report.
func summarize(verdicts []gored.Verdict) string {
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
