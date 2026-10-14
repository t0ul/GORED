// Command gored-appsweep runs one loop stage (recon | map | plan | exploit) against a local
// app and prints the leaderboard. It is a thin CLI over internal/appsweep — the run library
// the EVA web cockpit drives in-process too, so the CLI and the cockpit share one code path.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/t0ul/GORED/internal/appsweep"
	"github.com/t0ul/GORED/internal/bench"
)

func main() {
	f := bench.DefaultFlags()
	f.Trace = "gored-appsweep-trace.jsonl"
	stageF := flag.String("stage", "recon", "loop stage: "+appsweep.StageNames())
	f.Register(flag.CommandLine)
	flag.Parse()
	if _, err := appsweep.Run(context.Background(), f, *stageF); err != nil {
		log.Fatal(err)
	}
}
