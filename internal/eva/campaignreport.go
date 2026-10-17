package eva

import (
	"net/http"
	"time"

	"github.com/t0ul/GORED/internal/core"
)

// reportChild is one child run's account, recovered from its trace: coverage (tool calls +
// distinct tools + discovered paths), evidence (candidate findings + repro), and whether a finding
// was oracle-confirmed.
type reportChild struct {
	ID        string
	Stage     string
	Status    string
	Found     bool
	Breached  bool
	ToolCalls int
	Tools     []string
	Paths     []targetNode
	Findings  []core.Finding
	Repro     string
	HasSums   bool
}

// reportTarget rolls up a target's child runs for the morning report.
type reportTarget struct {
	Name      string
	Base      string
	Children  []reportChild
	Stages    []string
	PathCount int
	FindCount int
	Findings  int
}

// campaignReport is the whole morning report: the campaign envelope plus per-target coverage.
type campaignReport struct {
	ID            string
	Name          string
	Model         string
	Status        string
	Started       time.Time
	Elapsed       string
	Targets       []reportTarget
	TotalFindings int
	TotalFinds    int
	TotalPaths    int
}

// buildReport assembles the morning report for a campaign from its child runs' traces. Coverage
// and evidence are read from the gledger trace (parseRunTrace), never recomputed — so the report
// is an honest account of what each sortie actually did.
func (s *Server) buildReport(c *campaign) campaignReport {
	// Resolve each campaign target's base URL so child runs (which carry only a base) group
	// under the target's name.
	baseName := map[string]string{}
	for _, tn := range c.Targets {
		if s.store != nil {
			if tg, ok, _ := s.store.GetTarget(tn); ok {
				baseName[tg.Base] = tn
			}
		}
	}

	s.mu.Lock()
	rep := campaignReport{ID: c.ID, Name: c.Name, Model: c.Model, Status: c.Status, Started: c.Started, Elapsed: c.Elapsed}
	type runRef struct {
		id, stage, status, base, trace string
		sums                           []core.ContenderSummary
	}
	var refs []runRef
	for _, rid := range c.RunIDs {
		if rn := s.runs[rid]; rn != nil {
			refs = append(refs, runRef{rn.ID, rn.Stage, rn.Status, rn.Base, rn.Trace, rn.Sums})
		}
	}
	s.mu.Unlock()

	byBase := map[string]*reportTarget{}
	var order []string // bases, in first-seen order
	for _, r := range refs {
		rt := byBase[r.base]
		if rt == nil {
			name := baseName[r.base]
			if name == "" {
				name = r.base
			}
			rt = &reportTarget{Name: name, Base: r.base}
			byBase[r.base] = rt
			order = append(order, r.base)
		}
		child := childReport(r.id, r.stage, r.status, r.trace, captured(r.sums), len(r.sums) > 0)
		rt.Children = append(rt.Children, child)
		rt.Stages = addDistinct(rt.Stages, r.stage)
		rt.PathCount += len(child.Paths)
		rt.FindCount += len(child.Findings)
		if child.Found {
			rt.Findings++
		}
	}
	for _, base := range order {
		rt := byBase[base]
		rep.Targets = append(rep.Targets, *rt)
		rep.TotalFindings += rt.Findings
		rep.TotalFinds += rt.FindCount
		rep.TotalPaths += rt.PathCount
	}
	return rep
}

// childReport reads one run's trace into a reportChild.
func childReport(id, stage, status, tracePath string, isFound, hasSums bool) reportChild {
	// Found is the oracle's aggregated verdict (captured(Sums)), same as the live counter.
	// We deliberately do NOT fold in parseRunTrace's breached flag: that also matches
	// egress_breach (a containment failure), which is not an oracle-confirmed finding.
	events, findings, targets, repro, breached := parseRunTrace(tracePath)
	ch := reportChild{
		ID: id, Stage: phaseLabel(stage), Status: status, Found: isFound, Breached: breached,
		Paths: targets, Findings: findings, Repro: repro, HasSums: hasSums,
	}
	for _, ev := range events {
		if ev.Span == "tool" && ev.Event == "tool_call" {
			ch.ToolCalls++
			ch.Tools = addDistinct(ch.Tools, ev.Detail)
		}
	}
	return ch
}

func addDistinct(xs []string, x string) []string {
	if x == "" {
		return xs
	}
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}

// campaignReportHandler renders a campaign's morning report.
func (s *Server) campaignReportHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	c := s.campaigns[r.PathValue("id")]
	s.mu.Unlock()
	if c == nil {
		http.NotFound(w, r)
		return
	}
	render(w, campaignReportTmpl, s.buildReport(c))
}
