package validate

import (
	"github.com/t0ul/GORED/internal/core"
	"sort"
	"strings"
)

// CorrelatedIssue is one logical problem, formed by collapsing every finding that shares
// a normalized locus — the same route, source file, or dependency module within one app.
// It is the triage unit the thesis turns on: scanners emit many disjoint rows about one
// thing (Trivy and govulncheck both flag the same CVE; ZAP reports seven missing headers
// on one route; one dependency carries five CVEs), and a person wants one ranked row per
// real problem, not five. The rollup is honest: Severity is the worst in the group, and
// Reachable is merged so a reachability-aware scanner's verdict dominates a presence-only
// one's — if any source proved it reachable the issue is reachable; if none did but one
// ruled it out, it is ruled out; otherwise unknown. Every raw finding is kept in Findings
// so no detail is lost by the collapse.
type CorrelatedIssue struct {
	App       string           // the app the locus belongs to
	Locus     string           // the normalized key: a route, a file, or a module
	Kind      string           // how the locus was keyed: "route" | "file" | "module" | "other"
	Findings  []core.ScannerFinding // every finding that collapsed into this issue, in input order
	Sources   []string         // the distinct scanners that reported it, sorted
	Severity  string           // the worst severity in the group, normalized lower-case
	Reachable *bool            // merged reachability (see type doc); nil = unknown
	CWEs      []string         // the union of CWEs across the group, sorted
}

// Count is how many raw findings collapsed into this issue.
func (c CorrelatedIssue) Count() int { return len(c.Findings) }

// Correlate groups findings into issues by (app, normalized locus), collapsing the
// disjoint rows scanners emit about one thing into one ranked triage unit. It is pure —
// no source tree, no network — so it runs on whatever an aggregator already holds. The
// result is sorted by priority: worst severity first, then reachable before unknown
// before ruled-out, then the larger pile-up, then app and locus for a stable order.
func Correlate(findings []core.ScannerFinding) []CorrelatedIssue {
	groups := map[string]*CorrelatedIssue{}
	order := []string{} // preserve first-seen order for determinism before the final sort
	for _, f := range findings {
		locus, kind := locusOf(f)
		key := f.App + "\x00" + locus
		ci := groups[key]
		if ci == nil {
			ci = &CorrelatedIssue{App: f.App, Locus: locus, Kind: kind}
			groups[key] = ci
			order = append(order, key)
		}
		ci.Findings = append(ci.Findings, f)
	}

	out := make([]CorrelatedIssue, 0, len(order))
	for _, key := range order {
		ci := groups[key]
		rollup(ci)
		out = append(out, *ci)
	}
	sort.SliceStable(out, func(i, j int) bool { return morePriority(out[i], out[j]) })
	return out
}

// rollup fills an issue's Sources, Severity, Reachable, and CWEs from its findings.
func rollup(ci *CorrelatedIssue) {
	srcSet, cweSet := map[string]bool{}, map[string]bool{}
	worst := 0
	ci.Severity = "unknown"
	anyTrue, anyFalse := false, false
	for _, f := range ci.Findings {
		if s := strings.TrimSpace(f.Source); s != "" {
			srcSet[s] = true
		}
		if f.CWE != "" {
			cweSet[f.CWE] = true
		}
		if r := sevRank(f.Severity); r > worst {
			worst = r
			ci.Severity = sevLabel(f.Severity)
		}
		if f.Reachable != nil {
			if *f.Reachable {
				anyTrue = true
			} else {
				anyFalse = true
			}
		}
	}
	ci.Sources = sortedKeys(srcSet)
	ci.CWEs = sortedKeys(cweSet)
	switch {
	case anyTrue:
		t := true
		ci.Reachable = &t
	case anyFalse:
		f := false
		ci.Reachable = &f
	default:
		ci.Reachable = nil
	}
}

// locusOf reduces a finding's location to the key that identifies the one thing it is
// about, so different scanners' locators collapse onto a shared row: a URL path becomes
// its route template (instance ids folded to {id}), a dependency/package becomes its
// module (so sub-packages and many CVEs on one dep group), and a source file keeps its
// path but drops the line (so many rules in one file group). Classification is by shape,
// not by language: a leading "/" is a route, a domain-like first segment (or "stdlib") is
// a module, a trailing file extension is a file. Anything else keys on itself.
func locusOf(f core.ScannerFinding) (locus, kind string) {
	return core.NormLocus(f.Location)
}

// normLocus reduces any location string (a scanner's or a GORED proof's) to the shared
// (locus, kind) key, so a scanner finding and a GORED proof about the same surface collapse
// onto one issue regardless of which produced them.
// core.NormLocus and its helpers (looksLikeModule/looksLikeFile/stripLineSuffix/normalizeRoute)
// are core evidence vocabulary (see evidence.go).

// sevRank orders severities so the worst in a group wins. Unknown/empty ranks lowest —
// GORED does not inflate an issue past what a scanner actually claimed.
func sevRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium", "moderate":
		return 3
	case "low":
		return 2
	case "info", "informational", "negligible":
		return 1
	default:
		return 0
	}
}

func sevLabel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "moderate":
		return "medium"
	case "informational":
		return "info"
	case "negligible":
		return "info"
	case "":
		return "unknown"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

// reachRank orders merged reachability for the priority sort: reachable outranks unknown
// outranks ruled-out.
func reachRank(r *bool) int {
	switch {
	case r == nil:
		return 1
	case *r:
		return 2
	default:
		return 0
	}
}

// morePriority reports whether a should sort before b in the triage order.
func morePriority(a, b CorrelatedIssue) bool {
	if ra, rb := sevRank(a.Severity), sevRank(b.Severity); ra != rb {
		return ra > rb
	}
	if ra, rb := reachRank(a.Reachable), reachRank(b.Reachable); ra != rb {
		return ra > rb
	}
	if a.Count() != b.Count() {
		return a.Count() > b.Count()
	}
	if a.App != b.App {
		return a.App < b.App
	}
	return a.Locus < b.Locus
}

func sortedKeys(m map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
