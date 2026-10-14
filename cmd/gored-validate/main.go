// Command gored-validate is the capstone of the validation pipeline: it reads the scanner
// aggregate an aggregator holds (RiskRancher's tickets by default), fuses GORED's own
// proofs onto the matching issues, and prints one ranked list of verdicts on the unified
// evidence ladder — with the confirmed-exploitable findings, and their repros, on top.
//
// Proofs come from a gored-hunt report (-hunt report.json): each access-control finding
// becomes a proof, and a confirmed one (its executed repro reproduced the disclosure) is
// exploitable. An optional -source tree raises the scanner issues onto the static rungs.
// Read-only against the aggregator; it runs no probes itself.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/t0ul/GORED/internal/core"
	validate "github.com/t0ul/GORED/internal/validate"
	"github.com/t0ul/GORED/internal/probes"
)

func main() {
	var (
		dbPath = flag.String("db", "", "path to the findings SQLite DB (RiskRancher's data/riskrancher.db)")
		table  = flag.String("table", "tickets", "findings table")
		where  = flag.String("where", "", "optional SQL filter (without WHERE)")
		app    = flag.String("app", "", "app name: filters scanner findings and labels the hunt proofs")
		source = flag.String("source", "", "app source tree; raises scanner issues onto the static rungs (code + Dockerfile)")
		huntP  = flag.String("hunt", "", "a gored-hunt report JSON; its access-control findings become proofs")
		jsonP  = flag.String("json", "", "also write the verdicts as JSON here (for the blackboard view)")
		rulerP = flag.String("ruler", "", "score the verdicts against a ground-truth ruler JSON (recall/precision)")
		minR   = flag.String("ruler-min", "reachable", "min rung that counts as 'flagged' when scoring (reported|present|reachable|triggerable|exploitable)")
	)
	flag.Parse()
	if *dbPath == "" {
		log.Fatal("need -db <findings sqlite path>")
	}

	src := core.SQLFindingSource{DBPath: *dbPath, Table: *table, Where: *where}
	findings, err := src.Findings(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	scanners := make([]core.ScannerFinding, 0, len(findings))
	for _, f := range findings {
		if *app == "" || f.App == *app {
			scanners = append(scanners, f)
		}
	}

	v := &validate.Validator{}
	if *source != "" {
		if a := core.DetectAnalyzer(*source); a != nil {
			v.Analyzer = a
		} else {
			log.Printf("note: -source %s: unsupported language; scanner issues rest on reachability", *source)
		}
		v.Runtime = core.DetectRuntimeAnalyzer(*source) // rates any Dockerfile findings
	}

	proofs := huntProofs(*huntP, *app)
	verdicts := v.Validate(scanners, proofs)
	if *jsonP != "" {
		if b, err := json.MarshalIndent(verdicts, "", "  "); err == nil {
			_ = os.WriteFile(*jsonP, b, 0o644)
		}
	}

	fmt.Printf("\n==== GORED verdicts: %s ====\n", *dbPath)
	fmt.Printf("%d scanner finding(s) + %d proof(s) -> %d verdict(s)\n\n", len(scanners), len(proofs), len(verdicts))
	exploitable := 0
	for _, vd := range verdicts {
		mark := ""
		if vd.Exploitable {
			mark, exploitable = " EXPLOITABLE", exploitable+1
		}
		cwe := ""
		if len(vd.CWEs) > 0 {
			cwe = "  " + strings.Join(vd.CWEs, ",")
		}
		fmt.Printf("[%s %s%s] %s:%s%s  sources=%s\n", vd.Rung, vd.Confidence, mark, vd.App, vd.Locus, cwe, strings.Join(vd.Sources, "+"))
		if len(vd.Evidence) > 0 {
			fmt.Printf("    ladder: %s\n", strings.Join(vd.Evidence, " | "))
		}
		if vd.Repro != "" {
			fmt.Printf("    repro: %s\n", firstLine(vd.Repro))
		}
		for _, c := range vd.Chain {
			fmt.Printf("    chain: %s\n", c)
		}
	}
	fmt.Printf("\n%d confirmed-exploitable (with a repro) out of %d verdicts\n", exploitable, len(verdicts))

	if *rulerP != "" {
		ruler, err := validate.LoadRuler(*rulerP)
		if err != nil {
			log.Fatal(err)
		}
		s := ruler.Score(verdicts, core.Ladder(*minR))
		fmt.Printf("\n==== scored against %s (ruler: %s) ====\n", ruler.App, *rulerP)
		fmt.Printf("recall: %.0f%% (%d/%d real bugs flagged)   precision: %.0f%% (%d false positive(s))\n",
			100*s.Recall, s.TPFound, s.TPTotal, 100*s.Precision, s.FP)
		if len(s.Confirmed) > 0 {
			fmt.Printf("confirmed-exploitable: %s\n", strings.Join(s.Confirmed, ", "))
		}
		if len(s.Missed) > 0 {
			fmt.Printf("missed: %s\n", strings.Join(s.Missed, ", "))
		}
		if len(s.FalsePositives) > 0 {
			fmt.Printf("false positives: %s\n", strings.Join(s.FalsePositives, ", "))
		}
	}
}

// huntProofs loads a gored-hunt report and turns each access-control finding into a proof.
func huntProofs(path, app string) []core.Proof {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read -hunt %s: %v", path, err)
	}
	var rep probes.HuntReport
	if err := json.Unmarshal(b, &rep); err != nil {
		log.Fatalf("-hunt %s is not a gored-hunt report: %v", path, err)
	}
	name := app
	if name == "" {
		name = rep.Target
	}
	var proofs []core.Proof
	for _, f := range rep.Findings {
		if p, ok := probes.ProofFromHunt(f, name); ok {
			proofs = append(proofs, p)
		}
	}
	return proofs
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}
