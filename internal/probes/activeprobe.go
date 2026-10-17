package probes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/tools"
)

// ActiveProbe reverse-engineers an app's API by DRIVING it in a real browser and recording the
// requests it actually fires — the framework-agnostic way a pentester reverse-engineers an app from
// its traffic (what jp3g did to Beli). Parsing source only ever covers one stack at a time (fetch,
// then axios, then htmx, …); watching real requests covers them all, because fetch, axios, htmx
// attributes and plain <form> submits every one surfaces as a network request. It fills benign
// values, submits forms and fires hx/click triggers, and captures each request's method, path and
// body shape. It runs in the contained browser (off-target requests blocked) as the authenticated
// identity. It SUBMITS (so it mutates — intended for throwaway local test instances).
type ActiveProbe struct {
	Base     string
	Egress   *core.Egress
	Sessions *core.Sessions
	Session  string
	Timeout  time.Duration
}

// driveJS fills every field with a benign, type-appropriate value, then submits every form and
// clicks every htmx/trigger element, so the app fires its real requests. It is generic: it reads the
// page's own inputs and controls, nothing app-specific.
const driveJS = `(() => {
  const v = (el) => { const t=(el.type||el.tagName||'').toLowerCase();
    if(t==='email') return 'probe@example.test';
    if(t==='password') return 'Probe!23456';
    if(t==='number'||t==='range') return '1';
    if(t==='url') return 'http://example.test';
    if(t==='tel') return '5555550123';
    if(t==='checkbox'||t==='radio'){ el.checked=true; return null; }
    if(t==='select'){ if(el.options&&el.options.length) el.selectedIndex=el.options.length-1; return null; }
    return 'probe'; };
  document.querySelectorAll('input,textarea,select').forEach(el=>{ try{ const x=v(el); if(x!==null&&x!==undefined) el.value=x; }catch(e){} });
  document.querySelectorAll('[hx-get],[hx-post],[hx-put],[hx-patch],[hx-delete]').forEach(el=>{ try{ el.click(); }catch(e){} });
  document.querySelectorAll('form').forEach(f=>{ try{ f.requestSubmit ? f.requestSubmit() : f.submit(); }catch(e){} });
})();`

// Probe drives each page and returns the API shapes it observed the app fire. Best-effort: a page
// that fails to load is skipped; the browser's own requests are the source of truth.
func (p *ActiveProbe) Probe(ctx context.Context, pages []string) ([]APIShape, error) {
	bctx, _, cleanup, err := browserSession(ctx, p.Base, p.Timeout)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Authenticate the browser so it drives the signed-in surface (same session cookie as recon).
	if p.Sessions != nil && p.Session != "" {
		if u, e := url.Parse(p.Base); e == nil {
			if cookies := p.Sessions.Client(p.Session).Jar.Cookies(u); len(cookies) > 0 {
				host := u.Hostname()
				_ = chromedp.Run(bctx, chromedp.ActionFunc(func(cx context.Context) error {
					exp := cdp.TimeSinceEpoch(time.Now().Add(24 * time.Hour))
					for _, c := range cookies {
						_ = network.SetCookie(c.Name, c.Value).WithDomain(host).WithPath("/").WithExpires(&exp).Do(cx)
					}
					return nil
				}))
			}
		}
	}

	allowHost := hostOf(p.Base)
	var mu sync.Mutex
	var caps []capturedReq
	chromedp.ListenTarget(bctx, func(ev interface{}) {
		e, ok := ev.(*network.EventRequestWillBeSent)
		if !ok {
			return
		}
		if u, err := url.Parse(e.Request.URL); err == nil && u.Host == allowHost {
			mu.Lock()
			caps = append(caps, capturedReq{e.Request.Method, e.Request.URL, postDataOf(e.Request), interestingHeaders(e.Request.Headers)})
			mu.Unlock()
		}
	})
	if err := chromedp.Run(bctx, network.Enable()); err != nil {
		return nil, err
	}

	for _, pg := range pages {
		u := strings.TrimRight(p.Base, "/") + ensureLeadingSlash(pg)
		if p.Egress == nil || !p.Egress.Allowed(u) {
			continue
		}
		// Navigate, let it settle, drive the controls, let the fired requests land.
		_ = chromedp.Run(bctx,
			chromedp.Navigate(u),
			chromedp.Sleep(400*time.Millisecond),
			chromedp.Evaluate(driveJS, nil),
			chromedp.Sleep(700*time.Millisecond),
		)
	}

	mu.Lock()
	defer mu.Unlock()
	return shapesFromCaptures(caps), nil
}

// capturedReq is one request the browser fired while being driven (method, full URL, body, and the
// security-relevant request header names).
type capturedReq struct {
	method, url, body string
	headers           []string
}

// interestingHeaders pulls the security-relevant request header NAMES (never values) out of a
// captured request: the content type the endpoint expects, and any auth/CSRF header the app sends —
// so a probe knows it must carry them or be rejected with a 400/403.
func interestingHeaders(h network.Headers) []string {
	var out []string
	for k := range h {
		lk := strings.ToLower(k)
		if lk == "content-type" || lk == "authorization" || strings.Contains(lk, "csrf") || strings.Contains(lk, "xsrf") {
			out = append(out, k)
		}
	}
	return out
}

// postDataOf reconstructs a request body from the CDP post-data entries (each a base64 chunk). The
// network.Request has no flat PostData field in this cdproto; the body is split into entries.
func postDataOf(req *network.Request) string {
	if req == nil || !req.HasPostData {
		return ""
	}
	var b strings.Builder
	for _, e := range req.PostDataEntries {
		if dec, err := base64.StdEncoding.DecodeString(e.Bytes); err == nil {
			b.Write(dec)
		} else {
			b.WriteString(e.Bytes)
		}
	}
	return b.String()
}

// shapesFromCaptures turns observed requests into deduped API shapes: method, normalized path, and
// the body field names parsed from a form-encoded or JSON body (and query keys for a GET with a
// query). It drops the asset/navigation noise a page load makes.
func shapesFromCaptures(caps []capturedReq) []APIShape {
	type key struct{ m, p string }
	idx := map[key]int{}
	var out []APIShape
	for _, c := range caps {
		u, err := url.Parse(c.url)
		if err != nil {
			continue
		}
		path := normalizeAPIPath(u.Path)
		if path == "" || isStaticAssetPath(path) {
			continue
		}
		method := strings.ToUpper(c.method)
		if method == "" {
			method = "GET"
		}
		fields := bodyFieldNames(c.body)
		var query []string
		for k := range u.Query() {
			query = append(query, k)
		}
		k := key{method, path}
		if i, ok := idx[k]; ok {
			out[i].Fields = mergeStrings(out[i].Fields, fields)
			out[i].Query = mergeStrings(out[i].Query, query)
			out[i].Headers = mergeStrings(out[i].Headers, c.headers)
			continue
		}
		idx[k] = len(out)
		out = append(out, APIShape{Method: method, Path: path, Fields: fields, Query: query, Headers: c.headers})
	}
	return out
}

// bodyFieldNames extracts field names from a request body, whether form-encoded (a=1&b=2) or JSON
// (an object's keys, or the keys of the first element of an array).
func bodyFieldNames(body string) []string {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	if body[0] == '{' || body[0] == '[' {
		var obj map[string]any
		if json.Unmarshal([]byte(body), &obj) == nil {
			return sortedKeys(obj)
		}
		var arr []map[string]any
		if json.Unmarshal([]byte(body), &arr) == nil && len(arr) > 0 {
			return sortedKeys(arr[0])
		}
		return nil
	}
	if vals, err := url.ParseQuery(body); err == nil {
		var out []string
		for k := range vals {
			out = append(out, k)
		}
		return out
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// isStaticAssetPath mirrors the eva-side asset filter so page-load noise (scripts, styles, images)
// is not recorded as an API endpoint.
func isStaticAssetPath(p string) bool {
	lp := strings.ToLower(p)
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".map", ".gif", ".webp"} {
		if strings.HasSuffix(lp, ext) {
			return true
		}
	}
	return false
}

// ActiveProbeTool (active_probe) exposes dynamic reverse-engineering to the agent loop.
type ActiveProbeTool struct {
	Gate     *tools.Gate
	Base     string
	Sessions *core.Sessions
	Session  string
}

func (ActiveProbeTool) Name() string { return "active_probe" }
func (ActiveProbeTool) Describe() string {
	return `Reverse-engineer the app's API by DRIVING it in a real browser: it fills benign values and submits the forms / fires the htmx & fetch triggers on the pages you give it, then reports the real requests (method, path, body fields) the app sent. args: {"pages":["/","/login","/dashboard"]}. Works for any stack (fetch, axios, htmx, plain forms) because it watches real traffic, not source. It SUBMITS, so use it on the authorized local target.`
}

func (t ActiveProbeTool) Call(ctx context.Context, args map[string]any) (string, error) {
	pages := asStringSlice(args["pages"])
	if len(pages) == 0 {
		pages = []string{"/"}
	}
	session := tools.AsString(args["session"])
	if session == "" {
		session = t.Session
	}
	p := &ActiveProbe{Base: t.Base, Egress: t.Gate.Egress(), Sessions: t.Sessions, Session: session}
	shapes, err := p.Probe(ctx, pages)
	if err != nil {
		return "", err
	}
	if len(shapes) == 0 {
		return "active_probe: drove the pages but observed no API requests", nil
	}
	var b strings.Builder
	b.WriteString("active_probe: observed the app fire these requests:\n")
	for _, s := range shapes {
		if len(s.Fields) > 0 {
			b.WriteString("- " + s.Method + " " + s.Path + " body fields: " + strings.Join(s.Fields, ",") + "\n")
		} else {
			b.WriteString("- " + s.Method + " " + s.Path + "\n")
		}
	}
	return b.String(), nil
}
