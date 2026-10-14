// Package brig adapts gobrig (the contained-detonation chamber) to the tools.Transport
// interface, isolating the gobrig import to one place. A brig.Transport is always wrapped
// in a tools.Gate by the caller, so every fetch and every scanner detonation it performs
// is authorized against the Egress allowlist first — the Brig tools stop bypassing
// containment, and a denied call emits the loop's beacon.
package brig

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/t0ul/GORED/internal/tools"
	"github.com/t0ul/gobrig"
)

// Transport routes outbound through a running Brig's control bridge. Fetch is a GET over
// the guest loopback; Detonate runs a scanner (dalfox, webanalyze) inside the chamber. It
// keeps reconsweep's timeout split: a short client for fetches, a long one for scans, which
// fire many payloads and run for tens of seconds.
type Transport struct {
	Bridge    string        // host bridge address, e.g. 127.0.0.1:5050
	FetchHTTP *http.Client  // nil uses a 30s client
	ScanHTTP  *http.Client  // nil uses a 120s client
	TraceID   string        // detonation trace label; default "gored-tool"
}

func (t Transport) fetchClient() *http.Client {
	if t.FetchHTTP != nil {
		return t.FetchHTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (t Transport) scanClient() *http.Client {
	if t.ScanHTTP != nil {
		return t.ScanHTTP
	}
	return &http.Client{Timeout: 120 * time.Second}
}

func (t Transport) traceID() string {
	if t.TraceID != "" {
		return t.TraceID
	}
	return "gored-tool"
}

// Fetch performs an HTTP GET through the Brig bridge and returns the response body.
func (t Transport) Fetch(ctx context.Context, rawurl string) (string, error) {
	c := gobrig.Client{Bridge: t.Bridge, HTTP: t.fetchClient()}
	return gobrig.HTTPGet(ctx, c, rawurl)
}

// Detonate runs the scanner invocation argv inside the chamber and returns its output.
// targetURL is the host the scanner reaches; the tools.Gate has already authorized it.
func (t Transport) Detonate(ctx context.Context, _ string, argv []string) (string, error) {
	c := gobrig.Client{Bridge: t.Bridge, HTTP: t.scanClient()}
	r, err := c.Detonate(ctx, gobrig.Detonation{Argv: argv, TraceID: t.traceID()})
	if err != nil {
		return "", err
	}
	return r.Output, nil
}

// Request performs an arbitrary HTTP request through the chamber. The guest's HTTP client
// is wget-only (GET), so arbitrary method/header/body requests are not yet carried over the
// Brig transport — the JSON-API exploit stages run over the direct transport against a local
// app for now. Wiring this through a curl argv in the chamber is the follow-up; until then it
// fails closed rather than silently degrading to a GET.
func (t Transport) Request(_ context.Context, method, _ string, _ map[string]string, _ string) (int, string, error) {
	return 0, "", fmt.Errorf("brig transport does not yet support arbitrary %s requests; use the direct transport for JSON-API exploit stages", method)
}

// Describe labels the transport for traces.
func (t Transport) Describe() string { return "brig(" + t.Bridge + ")" }

// Transport satisfies the tools outbound interface.
var _ tools.Transport = Transport{}
