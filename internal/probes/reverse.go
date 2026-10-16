package probes

import (
	"regexp"
	"strings"
)

// Reverse-engineer the app's API from its OWN client code. A web app's JavaScript spells out the
// private API contract the same way a mobile app's traffic does (the technique jp3g used on Beli):
// each fetch/XHR call names the method, the path, and the request body's shape. Reading that back is
// pure recon of the app's own code — no hardcoding, no app-specific strings — and it hands the
// exploit phase the request SHAPE so the model does not have to guess the body (object vs array,
// which fields). It is a best-effort heuristic over readable client JS, not a JS parser: it extracts
// what it can (always method+path; body field names when the call uses an inline object literal).

// APIShape is one reverse-engineered client→API call: how the app itself calls the endpoint.
type APIShape struct {
	Method string   // GET/POST/PUT/PATCH/DELETE (GET when the call omits method)
	Path   string   // same-origin path, with a ${...} template segment normalized to {id}
	Fields []string // request-body field names, when the body is an inline object literal
}

var (
	// a fetch("…"/'…'/`…`) call; the captured group is the URL/path literal.
	reFetchURL = regexp.MustCompile("fetch\\(\\s*[\"'`]([^\"'`]+)[\"'`]")
	reMethodJS = regexp.MustCompile(`(?i)method\s*:\s*["'` + "`" + `]?([A-Za-z]+)`)
	// the request body's inline object literal: JSON.stringify({...}) or body: {...}. [^{}]* keeps it
	// to a flat object (a nested value just yields no fields, which is fine — we still get method+path).
	reBodyObj = regexp.MustCompile(`(?s)(?:JSON\.stringify\(\s*|body\s*:\s*)\{([^{}]*)\}`)
	reFieldJS = regexp.MustCompile(`["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*:`)
	reTplSeg  = regexp.MustCompile(`\$\{[^}]*\}`)
)

// skipField drops obvious non-field tokens that the flat-object regex can pick up (scheme words,
// nested-call noise) so the hint stays clean.
var skipField = map[string]bool{"http": true, "https": true, "headers": true, "method": true}

// reverseAPIShapes extracts the API calls a chunk of client JS makes. Each fetch(...) yields a shape:
// its method, its path (template ids normalized to {id}, query stripped), and the body field names
// when the call passes an inline object literal.
func ReverseAPIShapes(js string) []APIShape {
	var out []APIShape
	for _, loc := range reFetchURL.FindAllStringSubmatchIndex(js, -1) {
		raw := js[loc[2]:loc[3]]
		path := normalizeAPIPath(raw)
		if !strings.HasPrefix(path, "/") { // same-origin paths only, not absolute URLs
			continue
		}
		end := loc[1] + 400
		if end > len(js) {
			end = len(js)
		}
		win := js[loc[1]:end] // the options object follows the url within a small window
		method := "GET"
		if m := reMethodJS.FindStringSubmatch(win); m != nil {
			method = strings.ToUpper(m[1])
		}
		var fields []string
		seen := map[string]bool{}
		if b := reBodyObj.FindStringSubmatch(win); b != nil {
			for _, fm := range reFieldJS.FindAllStringSubmatch(b[1], -1) {
				f := fm[1]
				if skipField[strings.ToLower(f)] || seen[f] {
					continue
				}
				seen[f] = true
				fields = append(fields, f)
			}
		}
		out = append(out, APIShape{Method: method, Path: path, Fields: fields})
	}
	return out
}

// normalizeAPIPath turns a JS URL literal into a stable surface path: a ${...} template segment
// becomes {id}, and any query string is dropped.
func normalizeAPIPath(u string) string {
	u = reTplSeg.ReplaceAllString(u, "{id}")
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	return strings.TrimSpace(u)
}
