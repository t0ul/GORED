// Command gored-findings reads the scanner findings an aggregator holds (RiskRancher's
// tickets store by default) through a FindingSource and prints what GORED now has to
// work with: counts by scanner, by app, the reachability split, and the CWEs. It is
// the read side of the validation pipeline — scanners feed the aggregator, this reads
// the aggregate back for validation and prioritization. Read-only.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sort"
	"strings"

	gored "github.com/t0ul/GORED"
	validate "github.com/t0ul/GORED/internal/validate"
)

func main() {
	var (
		dbPath = flag.String("db", "", "path to the findings SQLite DB (e.g. RiskRancher's data/riskrancher.db)")
		table  = flag.String("table", "tickets", "findings table")
		where  = flag.String("where", "", "optional SQL filter (without WHERE)")
		app       = flag.String("app", "", "only findings whose asset app == this")
		list      = flag.Bool("list", false, "print each finding line")
		source    = flag.String("source", "", "path to the app's source tree; whitebox-analyses each finding to a rung (present/reachable/ruled-out)")
		runtime   = flag.String("runtime", "", "path to a dir with a Dockerfile; discovers container misconfigs and validates runtime findings to rungs")
		correlate = flag.Bool("correlate", false, "collapse findings that share a route/file/module into one ranked issue (dedup + triage)")
	)
	flag.Parse()
	if *dbPath == "" {
		log.Fatal("need -db <findings sqlite path>")
	}

	src := gored.SQLFindingSource{DBPath: *dbPath, Table: *table, Where: *where}
	findings, err := src.Findings(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// Optional whitebox analysis: pick an analyzer by detecting the source language.
	var analyzer gored.SourceAnalyzer
	if *source != "" {
		analyzer = gored.DetectAnalyzer(*source)
		if analyzer == nil {
			log.Printf("note: -source %s: unsupported language (no analyzer); skipping whitebox rungs", *source)
		}
	}

	bySource, byApp, byCWE, byRung := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	reach, ruledOut, unknown := 0, 0, 0
	kept := 0
	keptFindings := make([]gored.ScannerFinding, 0, len(findings))
	for _, f := range findings {
		if *app != "" && f.App != *app {
			continue
		}
		kept++
		keptFindings = append(keptFindings, f)
		bySource[f.Source]++
		byApp[f.App]++
		if f.CWE != "" {
			byCWE[f.CWE]++
		}
		switch {
		case f.Reachable == nil:
			unknown++
		case *f.Reachable:
			reach++
		default:
			ruledOut++
		}
		rungLine := ""
		if analyzer != nil {
			rung, why := analyzer.Analyze(f)
			byRung[string(rung)]++
			rungLine = "  [" + string(rung) + "] " + why
		}
		if *list {
			fmt.Println("  " + f.Line() + rungLine)
		}
	}

	fmt.Printf("\n==== findings in %s ====\n", *dbPath)
	fmt.Printf("total: %d\n", kept)
	fmt.Printf("by scanner: %s\n", sortedCounts(bySource))
	fmt.Printf("by app:     %s\n", sortedCounts(byApp))
	fmt.Printf("reachability: reachable=%d ruled-out=%d unknown=%d\n", reach, ruledOut, unknown)
	if len(byCWE) > 0 {
		fmt.Printf("CWEs: %s\n", sortedCounts(byCWE))
	}
	if analyzer != nil {
		fmt.Printf("whitebox (%s source): %s\n", analyzer.Lang(), sortedCounts(byRung))
	}
	fmt.Printf("\nruled-out (not reachable / not present) are deprioritized; reachable + access-control findings go to the validator next.\n")

	if *correlate {
		printCorrelated(keptFindings, analyzer)
	}

	if *runtime != "" {
		printRuntime(*runtime, keptFindings)
	}
}

// printRuntime reports the container runtime: the misconfigurations GORED discovers in
// the Dockerfile (the discover lane) and, for any runtime finding a scanner reported, the
// rung it reaches when validated against the file (confirmed vs ruled-out).
func printRuntime(dir string, findings []gored.ScannerFinding) {
	ra := gored.DetectRuntimeAnalyzer(dir)
	if ra == nil {
		fmt.Printf("\n==== runtime (%s) ====\nno runtime artifact found (no Dockerfile); skipping\n", dir)
		return
	}
	fmt.Printf("\n==== runtime: %s container (%s) ====\n", ra.Runtime(), dir)
	issues := ra.Issues()
	fmt.Printf("discovered %d misconfiguration(s) in the Dockerfile:\n", len(issues))
	for _, is := range issues {
		fmt.Printf("  %s\n", is.LineStr())
	}
	// Validate any runtime-shaped scanner findings (e.g. trivy config) against the file.
	for _, f := range findings {
		if rung, why := ra.Analyze(f); rung != gored.RungUnknown {
			fmt.Printf("  validate [%s] %s @ %s -> %s (%s)\n", f.Source, f.Title, f.Asset, rung, why)
		}
	}
}

// printCorrelated collapses the findings into ranked issues and prints them, showing how
// many raw rows became how many issues — the triage reduction. When a source analyzer is
// available each issue also shows the best (most advanced) static rung across its members.
func printCorrelated(findings []gored.ScannerFinding, analyzer gored.SourceAnalyzer) {
	issues := validate.Correlate(findings)
	fmt.Printf("\n==== correlated issues (dedup + triage) ====\n")
	fmt.Printf("%d findings -> %d issues\n\n", len(findings), len(issues))
	for _, c := range issues {
		reach := "reach=unknown"
		if c.Reachable != nil {
			if *c.Reachable {
				reach = "reachable"
			} else {
				reach = "ruled-out"
			}
		}
		rung := ""
		if analyzer != nil {
			rung = " rung=" + string(bestRung(c, analyzer))
		}
		cwe := ""
		if len(c.CWEs) > 0 {
			cwe = "  cwe=" + strings.Join(c.CWEs, ",")
		}
		fmt.Printf("  [%s %s%s] %s:%s  x%d  sources=%s%s\n",
			c.Severity, reach, rung, c.App, c.Locus, c.Count(), strings.Join(c.Sources, "+"), cwe)
	}
}

// bestRung combines the static rungs of an issue's findings into one. Precedence is
// reachable > ruled-out > present > unknown: a proven-reachable path wins, but a proven
// not-reachable verdict (ruled-out) outranks a bare "present" from a presence-only
// scanner — determining reachability is strictly more information than noting presence,
// so present + ruled-out on the same dependency is ruled-out, not present.
func bestRung(c validate.CorrelatedIssue, analyzer gored.SourceAnalyzer) gored.Rung {
	// RungAbsent and RungRuledOut share the string "ruled-out", so one key covers both.
	order := map[gored.Rung]int{
		gored.RungUnknown: 0, gored.RungPresent: 1,
		gored.RungRuledOut: 2, gored.RungReachable: 3,
	}
	best := gored.RungUnknown
	for _, f := range c.Findings {
		r, _ := analyzer.Analyze(f)
		if order[r] > order[best] {
			best = r
		}
	}
	return best
}

func sortedCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s=%d", k, m[k])
	}
	return out
}
