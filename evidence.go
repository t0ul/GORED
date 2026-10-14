package gored

import (
	"regexp"
	"strings"
)

// evidence.go holds the shared "evidence" vocabulary of the red-team loop: the small types
// every subsystem speaks in, and the pure locus/ladder helpers that operate on them. Keeping
// them here, in the core package, lets the probe and validate subsystems live in their own
// packages (internal/probes, internal/validate) and still agree on the same
// Confidence/Identity/Proof/Verdict/Ladder/Score terms without importing each other. Logic
// lives with each subsystem; this file is vocabulary and the helpers that are vocabulary.

// Confidence ranks how likely a BAC flag is a real authorization bug rather than a shared
// authenticated page both identities legitimately see. It is a canary-free triage signal:
// without a planted marker the oracle cannot be certain, so it says how much to trust the
// flag instead of hiding the uncertainty.
type Confidence string

const (
	ConfCertain Confidence = "certain" // a planted canary was disclosed — ground truth, no false positive
	ConfHigh    Confidence = "high"    // structured data, or page content unique to this resource, disclosed cross-identity
	ConfMedium  Confidence = "medium"  // some unique content disclosed, mixed with shared chrome
	ConfLow     Confidence = "low"     // response is mostly shared page chrome; high false-positive likelihood
)

// Identity is a caller a probe or oracle tests a resource as. Session names a cookie jar in a
// shared Sessions registry (filled by an earlier http_request login); Headers carries any
// static per-identity header (an X-Session or Authorization token) an app uses instead of
// cookies. An anonymous identity has neither a logged-in jar nor headers. LoginPath/LoginBody,
// when set, say how to authenticate this identity from scratch (a POST login) so a finding can
// be reproduced without reusing the live cookie jar.
type Identity struct {
	Name             string
	Session          string
	Headers          map[string]string
	LoginPath        string
	LoginBody        string
	LoginContentType string // e.g. application/json or application/x-www-form-urlencoded
}

// ok2xx reports whether an HTTP status is a 2xx success. A trivial shared predicate used by
// both the core seed code and the differential probe.
func ok2xx(status int) bool { return status >= 200 && status < 300 }

// Ladder is the evidence ladder: how far a finding has been proven, from a bare scanner
// report up to an executed exploit.
type Ladder string

const (
	LadderReported    Ladder = "reported"    // a scanner claimed it; nothing independently proven
	LadderPresent     Ladder = "present"     // the vulnerable code/config is in the app
	LadderReachable   Ladder = "reachable"   // it is on a path from an entry point
	LadderTriggerable Ladder = "triggerable" // GORED reached it live but did not confirm the impact
	LadderExploitable Ladder = "exploitable" // an executed repro reproduced the security impact
	LadderRuledOut    Ladder = "ruled-out"   // shown not to apply (not present, or not reachable)
)

// LadderRank orders the ladder so the strongest evidence sorts first.
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

// Proof is a normalized GORED discovery/verification result: a finding GORED produced itself
// (an access-control hunt, a mass-assignment or JWT probe, a container analysis), carrying how
// far up the ladder it proved the issue and the repro when it proved an exploit. Proofs are
// the evidence the validator fuses onto the scanner aggregate.
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

// Verdict is the finding graph's conclusion about one issue: the highest rung proven across
// every source, whether an executed repro exists, the evidence ladder that got it there, and
// any multi-issue chain it participates in. It is the triage unit a person acts on — one
// ranked row, carrying its proof.
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

// Score is a run's result against a ruler: recall over the real bugs, precision against the
// known-good/false-positive set, and the loci confirmed with an executed repro.
type Score struct {
	TPTotal        int      `json:"tp_total"`
	TPFound        int      `json:"tp_found"`
	FN             int      `json:"fn"`
	FP             int      `json:"fp"`
	Recall         float64  `json:"recall"`
	Precision      float64  `json:"precision"`
	Missed         []string `json:"missed,omitempty"`          // TP loci no verdict reached
	FalsePositives []string `json:"false_positives,omitempty"` // known-good/fp loci the run flagged
	Confirmed      []string `json:"confirmed,omitempty"`       // TP loci reached at the exploitable rung (with a repro)
}

// NormLocus reduces any location string (a scanner's or a GORED proof's) to the shared
// (locus, kind) key, so a scanner finding and a GORED proof about the same surface collapse
// onto one issue regardless of which produced them. It is core vocabulary: the probes and the
// validate/correlate code must key loci identically.
func NormLocus(location string) (locus, kind string) {
	loc := strings.TrimSpace(location)
	switch {
	case loc == "":
		return "(unknown)", "other"
	case strings.HasPrefix(loc, "/"):
		return normalizeRoute(loc), "route"
	case looksLikeModule(loc):
		return modulePath(loc), "module"
	case looksLikeFile(loc):
		return stripLineSuffix(loc), "file"
	default:
		return loc, "other"
	}
}

// looksLikeModule is true for a dependency path whose first segment is a registry domain
// (golang.org/x/net, github.com/org/repo, gopkg.in/yaml.v2) or the Go stdlib marker.
func looksLikeModule(loc string) bool {
	if loc == "stdlib" {
		return true
	}
	first := loc
	if i := strings.IndexByte(loc, '/'); i >= 0 {
		first = loc[:i]
	}
	return strings.Contains(first, ".")
}

var reFileExt = regexp.MustCompile(`\.[A-Za-z][A-Za-z0-9]*(?::\d+)?$`)

// looksLikeFile is true for a source path ending in an extension, optionally with a :line
// suffix (pkg/auth/auth_handlers.go:111, src/app.ts).
func looksLikeFile(loc string) bool { return reFileExt.MatchString(loc) }

var reLineSuffix = regexp.MustCompile(`:\d+$`)

// stripLineSuffix drops a trailing :line so findings at different lines of one file group.
func stripLineSuffix(loc string) string { return reLineSuffix.ReplaceAllString(loc, "") }

var (
	reNumSeg  = regexp.MustCompile(`^\d+$`)
	reUUIDSeg = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reHexSeg  = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
)

// normalizeRoute folds instance identifiers in a URL path to {id} so findings on, say,
// /api/drafts/5 and /api/drafts/9 collapse onto one route. It uses the same {id} convention as
// the OpenAPI ingestion so a correlated route lines up with a hunt target.
func normalizeRoute(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if reNumSeg.MatchString(s) || reUUIDSeg.MatchString(s) || reHexSeg.MatchString(s) {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
}
