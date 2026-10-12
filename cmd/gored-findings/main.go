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

	gored "github.com/t0ul/GORED"
)

func main() {
	var (
		dbPath = flag.String("db", "", "path to the findings SQLite DB (e.g. RiskRancher's data/riskrancher.db)")
		table  = flag.String("table", "tickets", "findings table")
		where  = flag.String("where", "", "optional SQL filter (without WHERE)")
		app    = flag.String("app", "", "only findings whose asset app == this")
		list   = flag.Bool("list", false, "print each finding line")
		source = flag.String("source", "", "path to the app's source tree; whitebox-analyses each finding to a rung (present/reachable/ruled-out)")
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
	for _, f := range findings {
		if *app != "" && f.App != *app {
			continue
		}
		kept++
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
