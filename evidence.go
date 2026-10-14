package gored

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
