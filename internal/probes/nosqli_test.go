package probes

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/t0ul/GORED/demotarget"
)

// Real system, no model: the vulnerable demotarget login honors operator objects, so the probe's
// operator payload authenticates where wrong credentials do not — the server's real auth decision
// is the oracle, and the sentinel asserts it.
func TestNoSQLiToolLive(t *testing.T) {
	base, done := startDemotarget(t)
	defer done()
	out, err := NoSQLiTool{Gate: demoGate(t, base), Base: base}.Call(context.Background(), map[string]any{
		"path": "/api/login", "user_field": "username", "pass_field": "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, NoSQLiSentinel) {
		t.Fatalf("nosqli should confirm operator-injection auth bypass on the vulnerable build; got: %s", out)
	}
}

// The hardened build rejects operator objects, so nothing bypasses and the probe must not flag —
// a properly neutralizing login produces no false positive.
func TestNoSQLiToolHardenedNoFP(t *testing.T) {
	srv, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(ln) }()
	defer hs.Close()
	base := "http://" + ln.Addr().String()
	out, err := NoSQLiTool{Gate: demoGate(t, base), Base: base}.Call(context.Background(), map[string]any{"path": "/api/login"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, NoSQLiSentinel) {
		t.Fatalf("nosqli must not flag the hardened build (operators rejected); got: %s", out)
	}
}
