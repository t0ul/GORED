package gored

// Identity is a caller a probe or oracle tests a resource as. Session names a cookie jar in a
// shared Sessions registry (filled by an earlier http_request login); Headers carries any
// static per-identity header (an X-Session or Authorization token) an app uses instead of
// cookies. An anonymous identity has neither a logged-in jar nor headers. LoginPath/LoginBody,
// when set, say how to authenticate this identity from scratch (a POST login) so a finding can
// be reproduced without reusing the live cookie jar. It is core vocabulary: the probes produce
// it and the core canary/seed code consumes it, so it lives here, shared by both.
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

// evidence.go holds the shared "evidence" vocabulary of the red-team loop: the small types
// every subsystem speaks in. Keeping them here, in the core package, lets the probe and
// validate subsystems move to their own packages (internal/probes, internal/validate) and
// still agree on the same Confidence/Proof/Verdict/Ladder/Score terms without importing each
// other. Logic lives with each subsystem; this file is vocabulary only.

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
