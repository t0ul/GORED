package eva

import (
	"net/http"
	"strings"
	"time"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/probes"
	"github.com/t0ul/GORED/internal/report"
	"github.com/t0ul/GORED/internal/tools"
	"github.com/t0ul/GORED/internal/validate"
	gledger "github.com/t0ul/gledger"
)

// sentinelProof maps a probe-tool CONFIRMED sentinel (emitted on real-byte confirmation) to the
// CWE and human name of the exploit it proves. These are the model-loop's self-evidencing
// confirmations — the oracle, not the model's claim, decided them.
var sentinelProof = []struct{ sentinel, cwe, kind string }{
	{"MASSASSIGN-CONFIRMED", "CWE-915", "mass assignment (client set a privileged field)"},
	{"JWT-FORGE-CONFIRMED", "CWE-347", "JWT forgery (a forged token was accepted)"},
	{"BOLA-CONFIRMED", "CWE-639", "broken object-level authorization"},
	{"NOSQLI-CONFIRMED", "CWE-943", "NoSQL injection (operator-injection auth bypass)"},
}

// campaignProofs builds core.Proofs from the campaign's child-run traces: every probe-tool
// confirmation (a CONFIRMED sentinel on real bytes) and every flag-candidate disclosure becomes
// an exploitable-rung, certain-confidence Proof keyed by target (App), so the Validator groups
// and chains them. Proofs are pooled across the campaign's runs — cross-run chaining comes free.
func (s *Server) campaignProofs(c *campaign) []core.Proof {
	baseName := map[string]string{}
	if s.store != nil {
		for _, tn := range c.Targets {
			if tg, ok, _ := s.store.GetTarget(tn); ok {
				baseName[tg.Base] = tn
			}
		}
	}
	s.mu.Lock()
	type rr struct{ trace, base string }
	var runs []rr
	for _, rid := range c.RunIDs {
		if rn := s.runs[rid]; rn != nil {
			runs = append(runs, rr{rn.Trace, rn.Base})
		}
	}
	nuc := map[string][]tools.NucleiFinding{} // snapshot the breadth findings under the lock
	for base, fs := range c.nuclei {
		nuc[base] = fs
	}
	ffz := map[string][]tools.FfufFinding{} // snapshot the content-discovery hits
	for base, fs := range c.ffuf {
		ffz[base] = fs
	}
	s.mu.Unlock()

	var proofs []core.Proof
	for _, r := range runs {
		app := baseName[r.base]
		if app == "" {
			app = r.base
		}
		recs, err := gledger.Read(r.trace)
		if err != nil {
			continue
		}
		var repro string
		for _, rec := range recs {
			if rec.Span == "verify" && rec.Event == "repro" {
				if v, ok := rec.Fields["curl"].(string); ok && v != "" {
					repro = v
				}
			}
		}
		lastPath := ""
		for _, rec := range recs {
			if rec.Span == "tool" && rec.Event == "tool_call" {
				if args, ok := rec.Fields["args"].(map[string]any); ok {
					p := asStr(args["path"])
					if p == "" {
						p = urlPath(asStr(args["url"]))
					}
					if p != "" {
						lastPath = p
					}
				}
			}
			if rec.Span == "tool" && rec.Event == "tool_result" {
				res := asStr(rec.Fields["result"])
				for _, sp := range sentinelProof {
					if strings.Contains(res, sp.sentinel) {
						proofs = append(proofs, core.Proof{
							App: app, Locus: lastPath, Kind: sp.kind, CWE: sp.cwe,
							Rung: core.LadderExploitable, Confidence: core.ConfCertain, Exploitable: true,
							Evidence: clip(res, 240), Repro: repro, Source: "gored-eva-campaign",
						})
					}
				}
			}
			if rec.Span == "board" && rec.Event == "finding" {
				if t, _ := rec.Fields["type"].(string); t == "flag-candidate" {
					proofs = append(proofs, core.Proof{
						App: app, Locus: lastPath, Kind: "sensitive data disclosure (flag read via id access)", CWE: "CWE-639",
						Rung: core.LadderExploitable, Confidence: core.ConfCertain, Exploitable: true,
						Evidence: clip(asStr(rec.Fields["value"]), 240), Repro: repro, Source: "gored-eva-campaign",
					})
				}
			}
		}
	}
	// Pool the nuclei breadth findings (web-hygiene / misconfig / exposure / CVE) alongside the
	// model-loop depth proofs, so the one pentest report covers both halves.
	for base, fs := range nuc {
		app := baseName[base]
		if app == "" {
			app = base
		}
		for _, f := range fs {
			if p, ok := probes.ProofFromNuclei(f, app); ok {
				proofs = append(proofs, p)
			}
		}
	}
	// Pool the ffuf content-discovery hits (unlinked endpoints, leftover backups, exposed config /
	// VCS files) so the report covers the forced-browsing surface the model-loop and nuclei miss.
	for base, fs := range ffz {
		app := baseName[base]
		if app == "" {
			app = base
		}
		for _, f := range fs {
			if p, ok := probes.ProofFromFfuf(f, app); ok {
				proofs = append(proofs, p)
			}
		}
	}
	return proofs
}

// campaignPentest serves the formal pentest report (CWE, confidence, remediation, chain) for a
// campaign, rendered by report.RenderReportHTML from the campaign's pooled proofs. It is the
// hand-off artifact — a self-contained, script-free HTML page.
func (s *Server) campaignPentest(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	c := s.campaigns[r.PathValue("id")]
	s.mu.Unlock()
	if c == nil {
		http.NotFound(w, r)
		return
	}
	proofs := s.campaignProofs(c)
	verdicts := (&validate.Validator{}).Validate(nil, proofs)
	meta := report.ReportMeta{
		Title:  "GORED Campaign — " + c.Name,
		Target: strings.Join(c.Targets, ", "),
		Scope:  "Authorized local testing. Egress allowlisted to each target; writes self-scoped; blind (nothing planted).",
		Date:   time.Now(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(report.RenderReportHTML(meta, verdicts))
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
