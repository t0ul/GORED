package gored

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// RulerLabel is the ground-truth verdict for one entry in a ruler: a real bug the setup
// should find, a correctly-gated endpoint it must not flag, or a scanner claim that is a
// false positive and should be ruled out.
type RulerLabel string

const (
	LabelTruePositive  RulerLabel = "tp"         // a real bug; the setup should flag it (recall)
	LabelKnownGood     RulerLabel = "known-good" // correctly gated; flagging it is a false positive (precision)
	LabelFalsePositive RulerLabel = "fp"         // a scanner claim that is not real; the setup should rule it out
)

// RulerEntry is one ground-truth datum, keyed by the same (app, normalized locus) a verdict
// uses so the two line up. Class partitions the two rulers: an authz/idor entry belongs to
// the DISCOVER ruler (what the swarm should find), an sca/dast/config entry to the VALIDATE
// ruler (what the triage should confirm or reject).
type RulerEntry struct {
	App   string     `json:"app"`
	Locus string     `json:"locus"`
	Class string     `json:"class,omitempty"` // authz | idor | sca | dast | config | ...
	CWE   string     `json:"cwe,omitempty"`
	Label RulerLabel `json:"label"`
	Note  string     `json:"note,omitempty"`
}

// Ruler is a frozen ground-truth label set for one app, the measuring stick a run is scored
// against. It is independent of GORED (written from a manual review or a one-off triage),
// so scoring a run against it is not GORED grading its own work.
type Ruler struct {
	App     string       `json:"app"`
	Source  string       `json:"source,omitempty"` // how it was derived (manual review, frozen scanner triage, ...)
	Entries []RulerEntry `json:"entries"`
}

// LoadRuler reads a ruler from a JSON file.
func LoadRuler(path string) (*Ruler, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Ruler
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("ruler %s: %w", path, err)
	}
	return &r, nil
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

// Score grades verdicts against the ruler. A verdict "flags" a locus when its rung reaches
// at least minRung (default reachable) — i.e. the run actively considers it a real or
// likely bug, as opposed to a bare scanner report or a ruled-out finding. Recall is over
// the ruler's true positives; precision counts a flag on a known-good/fp locus as a false
// positive; flagged loci absent from the ruler are left unscored, since the ruler is not
// exhaustive.
func (r *Ruler) Score(verdicts []Verdict, minRung Ladder) Score {
	if minRung == "" {
		minRung = LadderReachable
	}
	threshold := ladderRank(minRung)

	// Highest rung the run reached per (app, normalized locus).
	best := map[string]Ladder{}
	for _, v := range verdicts {
		k := v.App + "\x00" + normLocusKey(v.Locus)
		if cur, ok := best[k]; !ok || ladderRank(v.Rung) > ladderRank(cur) {
			best[k] = v.Rung
		}
	}
	flagged := func(app, locus string) (Ladder, bool) {
		rung, ok := best[app+"\x00"+normLocusKey(locus)]
		if !ok || ladderRank(rung) < threshold {
			return rung, false
		}
		return rung, true
	}

	var s Score
	labelByKey := map[string]RulerLabel{}
	for _, e := range r.Entries {
		labelByKey[e.App+"\x00"+normLocusKey(e.Locus)] = e.Label
		if e.Label != LabelTruePositive {
			continue
		}
		s.TPTotal++
		rung, hit := flagged(e.App, e.Locus)
		if hit {
			s.TPFound++
			if rung == LadderExploitable {
				s.Confirmed = append(s.Confirmed, e.App+":"+e.Locus)
			}
		} else {
			s.FN++
			s.Missed = append(s.Missed, e.App+":"+e.Locus)
		}
	}
	// Precision: flags landing on a known-good / fp entry are false positives.
	for k, rung := range best {
		if ladderRank(rung) < threshold {
			continue
		}
		if lbl, ok := labelByKey[k]; ok && lbl != LabelTruePositive {
			s.FP++
			s.FalsePositives = append(s.FalsePositives, prettyKey(k))
		}
	}

	if s.TPTotal > 0 {
		s.Recall = float64(s.TPFound) / float64(s.TPTotal)
	}
	if s.TPFound+s.FP > 0 {
		s.Precision = float64(s.TPFound) / float64(s.TPFound+s.FP)
	}
	sort.Strings(s.Missed)
	sort.Strings(s.FalsePositives)
	sort.Strings(s.Confirmed)
	return s
}

// normLocusKey normalizes a ruler/verdict locus so both sides key identically. A locus is
// stored already-shaped (a route, module, or file), so this reuses the same reducer that
// correlation and the validator use.
func normLocusKey(locus string) string {
	k, _ := normLocus(locus)
	return k
}

func prettyKey(k string) string {
	for i := 0; i < len(k); i++ {
		if k[i] == 0 {
			return k[:i] + ":" + k[i+1:]
		}
	}
	return k
}
