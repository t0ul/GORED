// Command gored-eva serves the EVA web cockpit: the surface you pilot GORED runs from.
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/t0ul/GORED/internal/eva"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4100", "listen address")
	traces := flag.String("traces", ".", "directory for per-run trace files")
	flag.Parse()
	srv := eva.NewServer(*traces)
	log.Printf("EVA cockpit on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
