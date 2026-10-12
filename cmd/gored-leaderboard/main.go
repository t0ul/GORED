// Command gored-leaderboard reads a GORED run store and prints the leaderboard,
// the cold→warm lift, and the combo-vs-solo verdict as JSON. It is the read seam
// the agent factory's model-select consumes to rank contestants by attack success;
// it is read-only and starts nothing.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/t0ul/GORED/store"
)

func main() {
	dbPath := flag.String("db", "gored-matrix.db", "SQLite run store path")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	board, err := st.Leaderboard()
	if err != nil {
		log.Fatal(err)
	}
	lift, err := st.ColdWarmLift()
	if err != nil {
		log.Fatal(err)
	}
	combos, err := st.ComboComparison()
	if err != nil {
		log.Fatal(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"leaderboard":    board,
		"cold_warm_lift": lift,
		"combo_vs_solo":  combos,
	})
}
