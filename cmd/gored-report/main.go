// Command gored-report is the Documentation & Reporting stage (HTB stage 8): it reads
// a JSON array of GORED verdicts (as gored-validate -json or a sweep emits) and renders
// a self-contained pentest report — executive summary, severity-ranked findings with
// executed reproductions, evidence, attack chains, and per-CWE remediation. It runs no
// model and touches no target; it only assembles what the Validator already proved.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/report"
)

func main() {
	var (
		verdictsF = flag.String("verdicts", "", "JSON file: a []Verdict array, or an object with a \"verdicts\" field")
		htmlOut   = flag.String("html", "report.html", "output path for the HTML report")
		title     = flag.String("title", "GORED penetration test report", "report title")
		target    = flag.String("target", "", "target name shown in the report")
		scope     = flag.String("scope", "", "one-line scope/authorization note")
	)
	flag.Parse()
	if *verdictsF == "" {
		log.Fatal("gored-report: -verdicts <file.json> is required")
	}
	b, err := os.ReadFile(*verdictsF)
	must(err)

	verdicts, err := parseVerdicts(b)
	must(err)
	if len(verdicts) == 0 {
		log.Fatal("gored-report: no verdicts found in the input")
	}

	page := report.RenderReportHTML(report.ReportMeta{Title: *title, Target: *target, Scope: *scope}, verdicts)
	must(os.WriteFile(*htmlOut, page, 0o644))
	fmt.Printf("report: %s (%d findings)\n", *htmlOut, len(verdicts))
}

// parseVerdicts accepts either a bare array or an object that wraps the array under a
// "verdicts" key (what gored-validate -json emits), so either output feeds the report.
func parseVerdicts(b []byte) ([]core.Verdict, error) {
	var arr []core.Verdict
	if json.Unmarshal(b, &arr) == nil && len(arr) > 0 {
		return arr, nil
	}
	var wrap struct {
		Verdicts []core.Verdict `json:"verdicts"`
	}
	if err := json.Unmarshal(b, &wrap); err != nil {
		return nil, err
	}
	return wrap.Verdicts, nil
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
