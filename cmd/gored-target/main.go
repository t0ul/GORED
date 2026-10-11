// Command gored-target runs the benign demo CTF target on a local host. It binds
// loopback only. Flag secrets are never printed; read capture state from
// GET /oracle/status. Authorized local testing only.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/t0ul/GORED/demotarget"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "loopback address to bind (host:port; port 0 picks a free port)")
	flag.Parse()

	if host, _, err := net.SplitHostPort(*addr); err == nil {
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() && host != "localhost" {
			log.Fatalf("gored-target binds loopback only; refusing %s", *addr)
		}
	}

	srv, err := demotarget.New()
	if err != nil {
		log.Fatalf("build target: %v", err)
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	base := "http://" + ln.Addr().String()

	m := srv.Manifest()
	m.BaseURL = base
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	log.Printf("gored demo target listening on %s", base)
	_ = enc.Encode(m)

	log.Fatal(http.Serve(ln, srv.Handler()))
}
