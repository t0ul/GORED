// Command gored-eva serves the EVA web cockpit: the surface you pilot GORED runs from.
package main

import (
	"flag"
	"log"
	"net/http"
	"path/filepath"

	"github.com/t0ul/GORED/internal/eva"
	"github.com/t0ul/GORED/store"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4100", "listen address")
	traces := flag.String("traces", ".", "directory for per-run trace files")
	storePath := flag.String("store", "", "SQLite run registry (default <traces>/eva.db; '-' disables persistence)")
	maxConc := flag.Int("max-concurrent", 1, "runs allowed in flight at once (>1 only with small models; each boots its own model)")
	flag.Parse()

	var st *store.Store
	switch *storePath {
	case "-":
		// persistence disabled
	default:
		path := *storePath
		if path == "" {
			path = filepath.Join(*traces, "eva.db")
		}
		s, err := store.Open(path)
		if err != nil {
			log.Fatalf("open store %s: %v", path, err)
		}
		defer s.Close()
		st = s
		log.Printf("run registry: %s", path)
	}

	srv := eva.NewServer(*traces, st, *maxConc)
	log.Printf("EVA cockpit on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
