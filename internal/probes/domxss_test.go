package probes

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/t0ul/GORED/demotarget"
)

// Real system, real browser: the vulnerable demotarget reflects the q parameter into HTML unescaped,
// so an injected payload actually executes in a headless Chrome and writes its nonce back — the
// browser's execution is the oracle, and the sentinel asserts it. Skips if no Chrome is installed.
func chromeOrSkip(t *testing.T) {
	t.Helper()
	if chromePath() == "" {
		t.Skip("no Chrome/Chromium found; skipping live DOM-XSS browser test")
	}
}

func TestDOMXSSToolLive(t *testing.T) {
	chromeOrSkip(t)
	base, done := startDemotarget(t)
	defer done()
	out, err := DOMXSSTool{Gate: demoGate(t, base), Base: base}.Call(
		ctxWithTimeout(t), map[string]any{"url": base + "/search?q=FUZZ"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, DOMXSSSentinel) {
		t.Fatalf("dom_xss should confirm execution on the unescaped reflection; got: %s", out)
	}
}

// The hardened build HTML-escapes the reflection, so no payload executes and the probe must not flag
// — a properly escaped reflection produces no false positive.
func TestDOMXSSToolHardenedNoFP(t *testing.T) {
	chromeOrSkip(t)
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
	out, err := DOMXSSTool{Gate: demoGate(t, base), Base: base}.Call(
		ctxWithTimeout(t), map[string]any{"url": base + "/search?q=FUZZ"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, DOMXSSSentinel) {
		t.Fatalf("dom_xss must not flag the hardened build (reflection escaped); got: %s", out)
	}
}

// Containment decision (pure logic): the browser interceptor allows only the target host and
// browser-internal schemes; an off-target beacon is denied. This is the rule the live interceptor
// enforces (and counts) during a scan.
func TestReqAllowed(t *testing.T) {
	const target = "127.0.0.1:8099"
	allow := []string{"http://127.0.0.1:8099/x", "https://127.0.0.1:8099/a?b=c", "about:blank", "data:text/html,x"}
	deny := []string{"http://evil.example/beacon", "http://169.254.169.254/latest", "https://attacker.test/x.png", "http://127.0.0.1:9999/other"}
	for _, u := range allow {
		if !reqAllowed(u, target) {
			t.Errorf("should allow same-host/internal request: %s", u)
		}
	}
	for _, u := range deny {
		if reqAllowed(u, target) {
			t.Errorf("should deny off-target beacon: %s", u)
		}
	}
}

// ctxWithTimeout bounds the live browser test so a stuck Chrome cannot hang the suite.
func ctxWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}
