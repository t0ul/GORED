package probes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/tools"
)

// DOM/reflected XSS that actually EXECUTES is the class dalfox (xss_scan) under-reports and a static
// reflection check cannot see: a payload that only runs once the browser builds the DOM, or is
// written into a client-side sink. This probe drives a real headless Chrome, injects a payload that
// writes a unique nonce to window.__gored, and reads it back — so the browser's own execution is the
// oracle (a reflected-but-escaped value never fires, so there is no false positive). It is generic
// (payloads carry no app-specific values; the probe only ever gets the target URL + a param to fuzz)
// and contained (navigation is egress-gated and every browser request is intercepted so only the
// target host is reachable; an off-target beacon is failed and counted).

// domxssPayloads are generic execution payloads; %[1]s is the nonce. They cover the common reflection
// contexts (HTML text, broken-out attribute, raw script, and a JS-string break-out).
var domxssPayloads = []string{
	`"><img src=x onerror="window.__gored='%[1]s'">`,
	`'><img src=x onerror="window.__gored='%[1]s'">`,
	`<img src=x onerror="window.__gored='%[1]s'">`,
	`<svg onload="window.__gored='%[1]s'">`,
	`<script>window.__gored='%[1]s'</script>`,
	`';window.__gored='%[1]s';//`,
}

// DOMXSSFinding is a browser-confirmed XSS; Payload is empty when nothing executed.
type DOMXSSFinding struct {
	URL        string
	Payload    string
	CWE        string // CWE-79
	Confidence core.Confidence
	Evidence   string
	Denied     int // off-target browser requests blocked during the probe (containment proof)
}

// Flagged reports whether a payload executed in the browser.
func (f DOMXSSFinding) Flagged() bool { return f.Payload != "" }

// DOMXSSProbe tests a URL for XSS that executes in a real browser.
type DOMXSSProbe struct {
	Base    string
	Egress  *core.Egress
	Param   string // query param to inject when the template has no FUZZ marker (default "q")
	Timeout time.Duration
}

// chromePath returns a host Chrome/Chromium binary, or "" to let chromedp auto-detect.
func chromePath() string {
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/usr/bin/google-chrome",
		"/usr/bin/chromium",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Probe navigates a headless browser to the target with each payload and returns the first that
// executes. tmpl is a URL containing the literal marker FUZZ where the payload goes.
func (p *DOMXSSProbe) Probe(ctx context.Context, tmpl string) (DOMXSSFinding, error) {
	to := p.Timeout
	if to == 0 {
		to = 30 * time.Second
	}
	baseCtx, cancelT := context.WithTimeout(ctx, to)
	defer cancelT()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
	)
	if cp := chromePath(); cp != "" {
		opts = append(opts, chromedp.ExecPath(cp))
	}
	allocCtx, cancelA := chromedp.NewExecAllocator(baseCtx, opts...)
	defer cancelA()
	// Silence chromedp's async event logger: a current Chrome emits a newer Network IPAddressSpace
	// enum (e.g. "Loopback") than this cdproto knows, so it logs an unmarshal error for every
	// request event. That noise is cosmetic — the oracle is the window.__gored read-back, and real
	// failures still surface through chromedp.Run — so drop it rather than spam the campaign log.
	bctx, cancelB := chromedp.NewContext(allocCtx, chromedp.WithErrorf(func(string, ...interface{}) {}))
	defer cancelB()

	// Containment: intercept every browser request and allow only the target host (plus
	// about:/data:/blob: internals). An off-target request — a payload beaconing out — is failed
	// and counted, the browser-level analog of the egress allowlist denying a scanner beacon.
	allowHost := hostOf(p.Base)
	var denied int64
	chromedp.ListenTarget(bctx, func(ev interface{}) {
		e, ok := ev.(*fetch.EventRequestPaused)
		if !ok {
			return
		}
		go func() {
			c := chromedp.FromContext(bctx)
			ectx := cdp.WithExecutor(bctx, c.Target)
			if reqAllowed(e.Request.URL, allowHost) {
				_ = fetch.ContinueRequest(e.RequestID).Do(ectx)
				return
			}
			atomic.AddInt64(&denied, 1)
			_ = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(ectx)
		}()
	})
	if err := chromedp.Run(bctx, fetch.Enable()); err != nil {
		return DOMXSSFinding{}, fmt.Errorf("dom_xss: start browser: %w", err)
	}

	for _, pl := range domxssPayloads {
		nonce := "gored" + nonceHex()
		inj := url.QueryEscape(fmt.Sprintf(pl, nonce))
		u := strings.ReplaceAll(tmpl, "FUZZ", inj)
		if p.Egress == nil || !p.Egress.Allowed(u) {
			continue // navigation is egress-gated to the target
		}
		var got string
		// Each navigation is a fresh document, so window.__gored is undefined unless THIS payload
		// executed and set it to the nonce.
		err := chromedp.Run(bctx,
			chromedp.Navigate(u),
			chromedp.Sleep(250*time.Millisecond),
			chromedp.Evaluate(`window.__gored || ""`, &got),
		)
		if err != nil {
			continue
		}
		if got == nonce {
			return DOMXSSFinding{
				URL: u, Payload: fmt.Sprintf(pl, nonce), CWE: "CWE-79", Confidence: core.ConfCertain,
				Evidence: fmt.Sprintf("payload executed in a real browser (nonce %s written to window.__gored) at %s", nonce, u),
				Denied:   int(atomic.LoadInt64(&denied)),
			}, nil
		}
	}
	return DOMXSSFinding{Denied: int(atomic.LoadInt64(&denied))}, nil
}

// nonceHex returns a short random hex token used to prove a payload executed (the browser writes it
// to window.__gored and the probe reads it back), so a stale or reflected value cannot be mistaken
// for execution.
func nonceHex() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("gored: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// hostOf returns the host[:port] of a base URL for the containment allow-check.
func hostOf(base string) string {
	if u, err := url.Parse(base); err == nil {
		return u.Host
	}
	return ""
}

// reqAllowed permits a browser request only to the target host or to a browser-internal scheme.
func reqAllowed(raw, allowHost string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "about", "data", "blob", "chrome", "devtools":
		return true
	}
	return u.Host == allowHost
}

// DOMXSSTool (dom_xss) exposes the probe to the agent loop. The sentinel is emitted only when the
// browser actually executed the payload, read by ExploitDetector — the model cannot assert a capture.
type DOMXSSTool struct {
	Gate *tools.Gate
	Base string
}

func (DOMXSSTool) Name() string { return "dom_xss" }
func (DOMXSSTool) Describe() string {
	return `Test a URL for cross-site scripting that EXECUTES in a real headless browser (DOM/reflected, CWE-79). ` +
		`args: {"url":"http://host/search?q=FUZZ"} (put the marker FUZZ where a parameter's value goes) ` +
		`or {"path":"/search","param":"q"}. It injects payloads and confirms a finding only when one runs in the browser.`
}

func (t DOMXSSTool) Call(ctx context.Context, args map[string]any) (string, error) {
	tmpl, err := domxssTemplate(args, t.Base)
	if err != nil {
		return "", fmt.Errorf("dom_xss: %w", err)
	}
	p := &DOMXSSProbe{Base: t.Base, Egress: t.Gate.Egress(), Param: tools.AsString(args["param"])}
	f, err := p.Probe(ctx, tmpl)
	if err != nil {
		return "", err
	}
	if f.Flagged() {
		return DOMXSSSentinel + " " + f.Evidence, nil
	}
	return "no dom xss: injected payloads did not execute in the browser", nil
}

// domxssTemplate resolves the args into a URL containing the FUZZ marker. If the caller already put
// FUZZ in the url it is used as-is; otherwise the chosen param's value is set to FUZZ.
func domxssTemplate(args map[string]any, base string) (string, error) {
	raw := tools.AsString(args["url"])
	if raw == "" {
		path := tools.AsString(args["path"])
		if path == "" {
			return "", fmt.Errorf("need a url or path")
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		raw = strings.TrimRight(base, "/") + path
	}
	if strings.Contains(raw, "FUZZ") {
		return raw, nil
	}
	param := tools.AsString(args["param"])
	if param == "" {
		param = "q"
	}
	sep := "?"
	if strings.Contains(raw, "?") {
		sep = "&"
	}
	return raw + sep + param + "=FUZZ", nil
}
