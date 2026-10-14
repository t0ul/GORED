package gored

import (
	"fmt"
	"sort"
	"strings"
)

// Ladder is the unified evidence ladder GORED reports a finding on. It runs from a bare
// scanner claim up to a proven exploit, with ruled-out as the side exit for a finding
// shown not to apply. The whole tool exists to move findings up this ladder honestly and
// claim only the rung it proved: the top rung, exploitable, is reserved for a finding an
// executed repro actually reproduced — the thing scanners cannot do.
type Ladder string

const (
	LadderReported    Ladder = "reported"    // a scanner claimed it; nothing independently proven
	LadderPresent     Ladder = "present"     // the vulnerable code/config is in the app
	LadderReachable   Ladder = "reachable"   // it is on a path from an entry point
	LadderTriggerable Ladder = "triggerable" // GORED reached it live but did not confirm the impact
	LadderExploitable Ladder = "exploitable" // an executed repro reproduced the security impact
	LadderRuledOut    Ladder = "ruled-out"   // shown not to apply (not present, or not reachable)
)

func LadderRank(l Ladder) int {
	switch l {
	case LadderExploitable:
		return 5
	case LadderTriggerable:
		return 4
	case LadderReachable:
		return 3
	case LadderPresent:
		return 2
	case LadderReported:
		return 1
	default: // ruled-out
		return 0
	}
}

func higherLadder(a, b Ladder) Ladder {
	if LadderRank(a) >= LadderRank(b) {
		return a
	}
	return b
}

// Proof is a normalized GORED discovery/verification result: a finding GORED produced
// itself (an access-control hunt, a mass-assignment or JWT probe, a container analysis),
// carrying how far up the ladder it proved the issue and the repro when it proved an
// exploit. Proofs are the evidence the validator fuses onto the scanner aggregate.
type Proof struct {
	App, Locus, Kind string
	CWE              string
	Rung             Ladder
	Confidence       Confidence
	Exploitable      bool
	Repro            string
	Evidence         string
	Source           string // gored-hunt | gored-massassign | gored-jwt | gored-runtime
}

// Verdict is the finding graph's conclusion about one issue: the highest rung proven
// across every source, whether an executed repro exists, the evidence ladder that got it
// there, and any multi-issue chain it participates in. It is the triage unit a person
// acts on — one ranked row, carrying its proof.
type Verdict struct {
	App, Locus, Kind string
	Rung             Ladder
	Confidence       Confidence
	Exploitable      bool
	Repro            string
	Severity         string
	CWEs             []string
	Sources          []string
	Evidence         []string // what proved each step, most recent last
	Chain            []string // multi-issue chain notes (e.g. app exploit + root container)
}

// Validator turns the finding graph into ranked verdicts. It is the capstone: it reads
// the scanner aggregate (correlated and whitebox-rated), fuses GORED's own proofs onto
// the matching issues, forms the honest cross-issue chains, and ranks everything so the
// confirmed-exploitable findings with repros sit at the top. An optional SourceAnalyzer
// raises scanner issues onto the static rungs; without it they rest on reachability.
type Validator struct {
	Analyzer SourceAnalyzer  // language lane: raises a code/dependency finding onto the static rungs
	Runtime  RuntimeAnalyzer // runtime lane: raises a Dockerfile/container finding onto the rungs
}

// Validate fuses scanner findings and GORED proofs into one ranked list of verdicts.
func (v *Validator) Validate(scanners []ScannerFinding, proofs []Proof) []Verdict {
	byKey := map[string]*Verdict{}
	var order []string
	key := func(app, locus string) string { return app + "\x00" + locus }

	// Scanner issues first: each correlated issue becomes a verdict at its static rung.
	for _, is := range Correlate(scanners) {
		k := key(is.App, is.Locus)
		vd := &Verdict{
			App: is.App, Locus: is.Locus, Kind: is.Kind,
			Rung: v.issueLadder(is), Confidence: ConfLow, Severity: is.Severity,
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
			vd = &Verdict{App: p.App, Locus: p.Locus, Kind: p.Kind, Rung: LadderReported}
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

	verdicts := make([]Verdict, 0, len(order))
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
func (v *Validator) issueLadder(is CorrelatedIssue) Ladder {
	if v.Analyzer != nil || v.Runtime != nil {
		reach, ruled, present := false, false, false
		for _, f := range is.Findings {
			r := v.rateFinding(f)
			switch r {
			case RungReachable:
				reach = true
			case RungRuledOut: // == RungAbsent
				ruled = true
			case RungPresent:
				present = true
			}
		}
		switch {
		case reach:
			return LadderReachable
		case ruled:
			return LadderRuledOut
		case present:
			return LadderPresent
		}
	}
	switch {
	case is.Reachable != nil && *is.Reachable:
		return LadderReachable
	case is.Reachable != nil && !*is.Reachable:
		return LadderRuledOut
	default:
		return LadderReported
	}
}

// rateFinding routes a finding to the analyzer that understands it: a Dockerfile/container
// finding to the runtime analyzer, everything else to the language analyzer. A finding no
// analyzer claims stays unknown — it is never falsely ruled out by the wrong analyzer.
func (v *Validator) rateFinding(f ScannerFinding) Rung {
	if isDockerfileFinding(f) {
		if v.Runtime != nil {
			r, _ := v.Runtime.Analyze(f)
			return r
		}
		return RungUnknown
	}
	if v.Analyzer != nil {
		r, _ := v.Analyzer.Analyze(f)
		return r
	}
	return RungUnknown
}

// chainHostCompromise adds the one runtime chain GORED asserts in v1: an exploitable
// app-level issue plus a container that runs as root is a host-compromise path. It is
// flagged on the exploitable verdict, never exploited — GORED does not run an escape.
func chainHostCompromise(verdicts []Verdict) {
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
func moreUrgent(a, b Verdict) bool {
	if ra, rb := LadderRank(a.Rung), LadderRank(b.Rung); ra != rb {
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

// ProofFromHunt normalizes a gored-hunt access-control finding. A confirmed finding (the
// model-written repro reproduced the disclosure) is exploitable and carries that repro;
// a certain-but-unconfirmed one is triggerable; a high one is reachable.
func ProofFromHunt(f HuntFinding, app string) (Proof, bool) {
	if f.Verdict != VerdictBAC {
		return Proof{}, false
	}
	locus, kind := NormLocus(f.Path)
	p := Proof{App: app, Locus: locus, Kind: kind, CWE: f.CWE, Confidence: f.Confidence,
		Source: "gored-hunt", Evidence: f.Evidence}
	switch {
	case f.Confirmed:
		p.Rung, p.Exploitable, p.Repro = LadderExploitable, true, f.ReproGo
	case f.Confidence == ConfCertain:
		p.Rung = LadderTriggerable
	case f.Confidence == ConfHigh:
		p.Rung = LadderReachable
	default:
		p.Rung = LadderReported
	}
	return p, true
}

// ProofFromMassAssign normalizes a mass-assignment finding. Certain means the probe wrote
// a privileged field and read it back changed — an executed privilege escalation, so
// exploitable; high (reflected only) is triggerable.
func ProofFromMassAssign(f MassAssignFinding, app string) (Proof, bool) {
	if !f.Flagged() {
		return Proof{}, false
	}
	locus, kind := NormLocus(f.WritePath)
	p := Proof{App: app, Locus: locus, Kind: kind, CWE: f.CWE, Confidence: f.Confidence,
		Source: "gored-massassign", Evidence: f.Evidence}
	if f.Confidence == ConfCertain {
		p.Rung, p.Exploitable = LadderExploitable, true
		p.Repro = fmt.Sprintf("%s %s with {\"%s\":%v} as the low-priv identity; read it back changed", f.Method, f.WritePath, f.Field, f.SentValue)
	} else {
		p.Rung = LadderTriggerable
	}
	return p, true
}

// ProofFromJWT normalizes a JWT finding. Certain means a forged token was accepted on
// replay — an executed authentication bypass, so exploitable; high (forgeable, replay
// not confirmed) is triggerable. locus is the protected path the token unlocks.
func ProofFromJWT(f JWTFinding, app, locus string) (Proof, bool) {
	if !f.Flagged() {
		return Proof{}, false
	}
	l, kind := NormLocus(locus)
	p := Proof{App: app, Locus: l, Kind: kind, CWE: f.CWE, Confidence: f.Confidence,
		Source: "gored-jwt", Evidence: f.Evidence}
	if f.Confidence == ConfCertain {
		p.Rung, p.Exploitable = LadderExploitable, true
		p.Repro = fmt.Sprintf("forge a %s token (vector %s) and replay it on %s", f.Alg, f.Vector, locus)
	} else {
		p.Rung = LadderTriggerable
	}
	return p, true
}

// ProofFromContainerIssue normalizes a discovered container misconfiguration. It is
// present/confirmed (read straight from the Dockerfile), never exploitable on its own —
// its force comes from the host-compromise chain when the app is also exploitable.
func ProofFromContainerIssue(ci ContainerIssue, app string) Proof {
	return Proof{
		App: app, Locus: "Dockerfile", Kind: "container", CWE: ci.CWE,
		Rung: LadderPresent, Confidence: ConfHigh, Source: "gored-runtime",
		Evidence: ci.Title + " — " + ci.Why,
	}
}

func confRank(c Confidence) int {
	switch c {
	case ConfCertain:
		return 4
	case ConfHigh:
		return 3
	case ConfMedium:
		return 2
	case ConfLow:
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
