package validate

import (
	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/ingest"
	"fmt"
	"sort"
	"strings"
)

// core.Ladder is the unified evidence ladder GORED reports a finding on. It runs from a bare
// scanner claim up to a proven exploit, with ruled-out as the side exit for a finding
// shown not to apply. The whole tool exists to move findings up this ladder honestly and
// claim only the rung it proved: the top rung, exploitable, is reserved for a finding an
// executed repro actually reproduced — the thing scanners cannot do.
// core.Ladder, core.LadderRank, core.Proof and core.Verdict are core evidence vocabulary (see evidence.go).

func higherLadder(a, b core.Ladder) core.Ladder {
	if core.LadderRank(a) >= core.LadderRank(b) {
		return a
	}
	return b
}

// Validator turns the finding graph into ranked verdicts. It is the capstone: it reads
// the scanner aggregate (correlated and whitebox-rated), fuses GORED's own proofs onto
// the matching issues, forms the honest cross-issue chains, and ranks everything so the
// confirmed-exploitable findings with repros sit at the top. An optional core.SourceAnalyzer
// raises scanner issues onto the static rungs; without it they rest on reachability.
type Validator struct {
	Analyzer core.SourceAnalyzer  // language lane: raises a code/dependency finding onto the static rungs
	Runtime  core.RuntimeAnalyzer // runtime lane: raises a Dockerfile/container finding onto the rungs
}

// Validate fuses scanner findings and GORED proofs into one ranked list of verdicts.
func (v *Validator) Validate(scanners []core.ScannerFinding, proofs []core.Proof) []core.Verdict {
	byKey := map[string]*core.Verdict{}
	var order []string
	key := func(app, locus string) string { return app + "\x00" + locus }

	// Scanner issues first: each correlated issue becomes a verdict at its static rung.
	for _, is := range Correlate(scanners) {
		k := key(is.App, is.Locus)
		vd := &core.Verdict{
			App: is.App, Locus: is.Locus, Kind: is.Kind,
			Rung: v.issueLadder(is), Confidence: core.ConfLow, Severity: is.Severity,
			CWEs: append([]string{}, is.CWEs...), Sources: append([]string{}, is.Sources...),
		}
		vd.Evidence = append(vd.Evidence, fmt.Sprintf("scanners (%s) reported it; static rung %s",
			strings.Join(is.Sources, "+"), vd.Rung))
		byKey[k] = vd
		order = append(order, k)
	}

	// GORED proofs: fuse onto the matching issue, or stand alone (what scanners missed).
	for _, p := range proofs {
		k := key(p.App, p.Locus)
		vd := byKey[k]
		if vd == nil {
			vd = &core.Verdict{App: p.App, Locus: p.Locus, Kind: p.Kind, Rung: core.LadderReported}
			byKey[k] = vd
			order = append(order, k)
			vd.Evidence = append(vd.Evidence, "not reported by any scanner — discovered by GORED")
		}
		vd.Rung = higherLadder(vd.Rung, p.Rung)
		if confRank(p.Confidence) > confRank(vd.Confidence) {
			vd.Confidence = p.Confidence
		}
		if p.Exploitable {
			vd.Exploitable = true
			if p.Repro != "" {
				vd.Repro = p.Repro
			}
		}
		vd.Sources = addUnique(vd.Sources, p.Source)
		vd.CWEs = addUnique(vd.CWEs, p.CWE)
		vd.Evidence = append(vd.Evidence, fmt.Sprintf("%s proved %s (%s): %s", p.Source, p.Rung, p.Confidence, p.Evidence))
	}

	verdicts := make([]core.Verdict, 0, len(order))
	for _, k := range order {
		verdicts = append(verdicts, *byKey[k])
	}
	chainHostCompromise(verdicts)
	sort.SliceStable(verdicts, func(i, j int) bool { return moreUrgent(verdicts[i], verdicts[j]) })
	return verdicts
}

// issueLadder places a correlated scanner issue on the ladder from the whitebox analyzer's
// rungs, else the merged reachability. The combine precedence is reachable > ruled-out >
// present: a reachability determination (even a negative one) is more information than
// bare presence, so a dependency one scanner flagged present and another ruled not
// reachable is ruled out, not present. It never claims past present for a scanner issue —
// reaching live or exploiting is a proof's job, not a scanner's.
func (v *Validator) issueLadder(is CorrelatedIssue) core.Ladder {
	if v.Analyzer != nil || v.Runtime != nil {
		reach, ruled, present := false, false, false
		for _, f := range is.Findings {
			r := v.rateFinding(f)
			switch r {
			case core.RungReachable:
				reach = true
			case core.RungRuledOut: // == core.RungAbsent
				ruled = true
			case core.RungPresent:
				present = true
			}
		}
		switch {
		case reach:
			return core.LadderReachable
		case ruled:
			return core.LadderRuledOut
		case present:
			return core.LadderPresent
		}
	}
	switch {
	case is.Reachable != nil && *is.Reachable:
		return core.LadderReachable
	case is.Reachable != nil && !*is.Reachable:
		return core.LadderRuledOut
	default:
		return core.LadderReported
	}
}

// rateFinding routes a finding to the analyzer that understands it: a Dockerfile/container
// finding to the runtime analyzer, everything else to the language analyzer. A finding no
// analyzer claims stays unknown — it is never falsely ruled out by the wrong analyzer.
func (v *Validator) rateFinding(f core.ScannerFinding) core.Rung {
	if ingest.IsDockerfileFinding(f) {
		if v.Runtime != nil {
			r, _ := v.Runtime.Analyze(f)
			return r
		}
		return core.RungUnknown
	}
	if v.Analyzer != nil {
		r, _ := v.Analyzer.Analyze(f)
		return r
	}
	return core.RungUnknown
}

// chainHostCompromise adds the one runtime chain GORED asserts in v1: an exploitable
// app-level issue plus a container that runs as root is a host-compromise path. It is
// flagged on the exploitable verdict, never exploited — GORED does not run an escape.
func chainHostCompromise(verdicts []core.Verdict) {
	rootFlagged, rootConfirmed := map[string]bool{}, map[string]bool{}
	for _, vd := range verdicts {
		if hasStr(vd.CWEs, "CWE-250") || (vd.Locus == "Dockerfile" && containsSub(vd.Evidence, "root")) {
			rootFlagged[vd.App] = true
			if vd.Exploitable { // the escape was actually executed (e.g. a host canary was read)
				rootConfirmed[vd.App] = true
			}
		}
	}
	for i := range verdicts {
		// Tag the exploitable app issue, not the container verdict itself.
		if !verdicts[i].Exploitable || !rootFlagged[verdicts[i].App] || hasStr(verdicts[i].CWEs, "CWE-250") {
			continue
		}
		note := "exploitable app issue + container runs as root (CWE-250) = host-compromise path (flagged, not exploited)"
		if rootConfirmed[verdicts[i].App] {
			note = "exploitable app RCE + root container with host access = host-compromise CONFIRMED (escape executed to the VM host)"
		}
		verdicts[i].Chain = append(verdicts[i].Chain, note)
	}
}

// moreUrgent orders verdicts for triage: highest ladder, then confidence, then severity,
// then a proven exploit, then app/locus for stability.
func moreUrgent(a, b core.Verdict) bool {
	if ra, rb := core.LadderRank(a.Rung), core.LadderRank(b.Rung); ra != rb {
		return ra > rb
	}
	if ca, cb := confRank(a.Confidence), confRank(b.Confidence); ca != cb {
		return ca > cb
	}
	if sa, sb := sevRank(a.Severity), sevRank(b.Severity); sa != sb {
		return sa > sb
	}
	if a.Exploitable != b.Exploitable {
		return a.Exploitable
	}
	if a.App != b.App {
		return a.App < b.App
	}
	return a.Locus < b.Locus
}

// ---- adapters: GORED's own findings -> normalized proofs ----

// ProofFromHunt/ProofFromMassAssign/ProofFromJWT moved to internal/probes (they adapt probe
// findings into a core core.Proof). ProofFromContainerIssue stays here — core.ContainerIssue is an
// ingest type, not a probe.

// ProofFromContainerIssue normalizes a discovered container misconfiguration. It is
// present/confirmed (read straight from the Dockerfile), never exploitable on its own —
// its force comes from the host-compromise chain when the app is also exploitable.
func ProofFromContainerIssue(ci core.ContainerIssue, app string) core.Proof {
	return core.Proof{
		App: app, Locus: "Dockerfile", Kind: "container", CWE: ci.CWE,
		Rung: core.LadderPresent, Confidence: core.ConfHigh, Source: "gored-runtime",
		Evidence: ci.Title + " — " + ci.Why,
	}
}

func confRank(c core.Confidence) int {
	switch c {
	case core.ConfCertain:
		return 4
	case core.ConfHigh:
		return 3
	case core.ConfMedium:
		return 2
	case core.ConfLow:
		return 1
	default:
		return 0
	}
}

func addUnique(ss []string, s string) []string {
	if s == "" {
		return ss
	}
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}

func hasStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func containsSub(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
