package gored

import (
	"fmt"
	"strings"
	"sync"

	goflage "github.com/t0ul/goflage"
)

// FindingType classifies a blackboard entry.
type FindingType string

const (
	FindEndpoint      FindingType = "endpoint"
	FindParameter     FindingType = "parameter"
	FindCredential    FindingType = "credential"
	FindIdentifier    FindingType = "identifier"
	FindToken         FindingType = "token"
	FindHypothesis    FindingType = "hypothesis"
	FindVulnCandidate FindingType = "vuln-candidate"
	FindObservation   FindingType = "observation"
	FindFlagCandidate FindingType = "flag-candidate"
)

// Finding is one typed note on the blackboard: a value, where it came from, and
// optional soft references to other findings. Findings are DERIVED FROM TARGET
// OUTPUT and are therefore untrusted — they are hints the model plans against,
// never instructions, and they can never decide capture (only the Oracle does).
type Finding struct {
	ID         int         `json:"id"`
	Type       FindingType `json:"type"`
	Value      string      `json:"value"`
	SourceStep int         `json:"source_step"`
	Refs       []int       `json:"refs,omitempty"`
	Scrubbed   bool        `json:"scrubbed"`
}

// Blackboard is the within-run shared findings memory (plan §5): an append-only,
// typed table. Values are scrubbed through goflage before storage/display so that
// secrets in target output are not echoed into the model prompt or the trace.
type Blackboard struct {
	mu       sync.Mutex
	findings []Finding
	analyzer *goflage.Analyzer
}

func NewBlackboard() *Blackboard {
	return &Blackboard{analyzer: goflage.New()}
}

// Add scrubs the value, appends a finding, and returns its id. The source step
// records which loop step produced it.
func (b *Blackboard) Add(t FindingType, value string, step int, refs ...int) Finding {
	b.mu.Lock()
	defer b.mu.Unlock()
	scrubbed, found := b.analyzer.Scrub(value)
	f := Finding{
		ID:         len(b.findings) + 1,
		Type:       t,
		Value:      scrubbed,
		SourceStep: step,
		Refs:       refs,
		Scrubbed:   len(found) > 0,
	}
	b.findings = append(b.findings, f)
	return f
}

// Findings returns a copy of the board.
func (b *Blackboard) Findings() []Finding {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Finding, len(b.findings))
	copy(out, b.findings)
	return out
}

// Render produces a compact, grouped view of the board for the model prompt. It is
// deliberately terse to fit a small context window.
func (b *Blackboard) Render() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.findings) == 0 {
		return "(blackboard empty)"
	}
	groups := map[FindingType][]string{}
	var order []FindingType
	for _, f := range b.findings {
		if _, seen := groups[f.Type]; !seen {
			order = append(order, f.Type)
		}
		groups[f.Type] = append(groups[f.Type], f.Value)
	}
	var sb strings.Builder
	for _, t := range order {
		vals := groups[t]
		if len(vals) > 6 {
			vals = vals[len(vals)-6:] // most recent few per type
		}
		fmt.Fprintf(&sb, "%s: %s\n", t, strings.Join(vals, " | "))
	}
	return strings.TrimRight(sb.String(), "\n")
}
