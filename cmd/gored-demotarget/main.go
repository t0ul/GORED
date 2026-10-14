// Command gored-demotarget runs the benign demotarget JSON-API CTF app for local testing:
// a self-contained app with planted IDOR and loopback-SSRF flags (and a JWT / mass-assign
// surface) that GORED's JSON-API exploit stage points at. It is the tracked, benign target —
// no real data, safe to run on loopback. Use -hardened to serve the defended build.
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/t0ul/GORED/demotarget"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "listen address")
	hardened := flag.Bool("hardened", false, "serve the defended build (controls wired; flags unreachable)")
	flag.Parse()

	var opts []demotarget.Option
	if *hardened {
		opts = append(opts, demotarget.WithHardened())
	}
	srv, err := demotarget.New(opts...)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("demotarget on http://%s (hardened=%v)", *addr, *hardened)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
