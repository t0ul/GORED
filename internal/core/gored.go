// Package gored is the app-layer red-team framework: it drives a model (the
// weapon) to capture planted flags in a controlled local build of your own web
// app (the target), then scores and persists how each model did.
//
// This root package defines the taxonomy and the small interfaces the runtime is
// built from. Concrete implementations (the demo target, the objective loop, the
// model client, the sandbox tools, the run store) live in subpackages and in the
// app that wires GORED to real fleet components, so nothing app-specific leaks
// into the library.
//
// Authorized use only: GORED is for testing the author's own applications on
// local hosts, with flags the author planted. The capture oracle is the single
// source of truth for success; everything the target says back is untrusted data.
package core

import "time"

// VulnClass is a planted vulnerability category. The demo target plants IDOR and
// a loopback-scoped SSRF; the taxonomy leaves room for the other classes the plan
// names (auth bypass, injection) without committing the demo to them.
type VulnClass string

const (
	ClassIDOR       VulnClass = "idor"
	ClassSSRF       VulnClass = "ssrf"
	ClassAuthBypass VulnClass = "auth-bypass"
	ClassInjection  VulnClass = "injection"
)

// Difficulty is a coarse tier used to bucket the leaderboard.
type Difficulty string

const (
	DiffEasy   Difficulty = "easy"
	DiffMedium Difficulty = "medium"
	DiffHard   Difficulty = "hard"
)

// FlagSpec describes one planted vulnerability: a stable id, its class and tier,
// where the flag lives (for the human reading the manifest), and how the oracle
// detects capture. The flag's secret value is never in the spec — it is generated
// fresh per run by the Oracle and kept server-side, which is what makes a flag
// unforgeable.
type FlagSpec struct {
	ID         string     `json:"id"`
	Class      VulnClass  `json:"class"`
	Difficulty Difficulty `json:"difficulty"`
	Where      string     `json:"where"`
	Detect     string     `json:"detect"`
}

// FlagStatus is the public capture state of one flag, as the oracle reports it to
// a harness. It deliberately omits the secret value: a harness learns whether a
// flag was captured and by what path, never the secret, so it cannot flip its own
// result by reading the status.
type FlagStatus struct {
	ID         string     `json:"id"`
	Class      VulnClass  `json:"class"`
	Difficulty Difficulty `json:"difficulty"`
	Captured   bool       `json:"captured"`
	Via        string     `json:"via,omitempty"`
	At         time.Time  `json:"at,omitempty"`
}

// Target is a running app under test: its manifest of planted flags and the
// current, oracle-authoritative capture state. A harness detects success only
// through Status — never by reading the model's self-report.
type Target interface {
	Manifest() Manifest
	Status() []FlagStatus
}
