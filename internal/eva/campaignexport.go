package eva

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
)

// campaignReportMD serves the morning report as Markdown — the same coverage/evidence as the
// themed report, in a form you can paste into an issue or a handoff doc.
func (s *Server) campaignReportMD(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	c := s.campaigns[r.PathValue("id")]
	s.mu.Unlock()
	if c == nil {
		http.NotFound(w, r)
		return
	}
	rep := s.buildReport(c)
	var b strings.Builder
	fmt.Fprintf(&b, "# GORED Campaign — %s\n\n", rep.Name)
	fmt.Fprintf(&b, "Model: %s · Status: %s", rep.Model, rep.Status)
	if rep.Elapsed != "" {
		fmt.Fprintf(&b, " · %s", rep.Elapsed)
	}
	fmt.Fprintf(&b, "\n\nTargets: %d · Findings: %d · Candidates: %d · Paths touched: %d\n\n",
		len(rep.Targets), rep.TotalFindings, rep.TotalFinds, rep.TotalPaths)
	for _, t := range rep.Targets {
		verdict := "nothing found"
		if t.Findings > 0 {
			verdict = fmt.Sprintf("%d FOUND", t.Findings)
		}
		fmt.Fprintf(&b, "## %s (%s) — %s\n\n", t.Name, t.Base, verdict)
		fmt.Fprintf(&b, "Stages: %s · Paths: %d · Candidates: %d · Sorties: %d\n\n",
			strings.Join(t.Stages, ", "), t.PathCount, t.FindCount, len(t.Children))
		for _, ch := range t.Children {
			foundTag := ""
			if ch.Found {
				foundTag = " — FOUND"
			}
			fmt.Fprintf(&b, "### %s [%s]%s\n\n", ch.Stage, ch.Status, foundTag)
			fmt.Fprintf(&b, "%d tool calls", ch.ToolCalls)
			if len(ch.Tools) > 0 {
				fmt.Fprintf(&b, " (%s)", strings.Join(ch.Tools, ", "))
			}
			b.WriteString("\n\n")
			if len(ch.Paths) > 0 {
				b.WriteString("Discovered surface:\n\n")
				for _, p := range ch.Paths {
					fmt.Fprintf(&b, "- `%s %s`\n", p.Method, p.Path)
				}
				b.WriteString("\n")
			}
			if len(ch.Findings) > 0 {
				b.WriteString("Findings:\n\n")
				for _, f := range ch.Findings {
					fmt.Fprintf(&b, "- **%s** %s\n", f.Type, clip(f.Value, 220))
				}
				b.WriteString("\n")
			}
			if ch.Repro != "" {
				fmt.Fprintf(&b, "Repro:\n\n```\n%s\n```\n\n", ch.Repro)
			}
		}
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", "campaign-"+c.ID+".md"))
	_, _ = w.Write([]byte(b.String()))
}

// campaignSurfaceCSV serves the discovered surface as CSV (target, stage, method, path, last) —
// the endpoint inventory the campaign touched, for a spreadsheet or another tool.
func (s *Server) campaignSurfaceCSV(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	c := s.campaigns[r.PathValue("id")]
	s.mu.Unlock()
	if c == nil {
		http.NotFound(w, r)
		return
	}
	rep := s.buildReport(c)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "campaign-"+c.ID+"-surface.csv"))
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"target", "base", "stage", "method", "path", "last_response"})
	for _, t := range rep.Targets {
		for _, ch := range t.Children {
			for _, p := range ch.Paths {
				_ = cw.Write([]string{t.Name, t.Base, ch.Stage, p.Method, p.Path, clip(p.Last, 200)})
			}
		}
	}
}
