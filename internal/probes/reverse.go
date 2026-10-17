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

const bt = "`"

var (
	// fetch("…"/'…'/`…`, { … }) — the captured group is the URL/path literal.
	reFetchURL = regexp.MustCompile("fetch\\(\\s*[\"'" + bt + "]([^\"'" + bt + "]+)[\"'" + bt + "]")
	// a method-verb call on any client: fetch is above; axios.post / $.post / api.put / http.delete /
	// client.get(…) all read as `.verb("/path"`, so the verb IS the method. Covers axios, jQuery's
	// $.post/$.get, and any wrapped HTTP client — not just raw fetch.
	reVerbCall = regexp.MustCompile(`(?i)\.(get|post|put|patch|delete)\(\s*["'` + bt + `](/[^"'` + bt + `]*)`)
	// a config-object call: axios({url:"/path", method:…, data:{…}}) or $.ajax({url:"/path", type:…,
	// data:{…}}) — the path rides a url: key.
	reConfigURL = regexp.MustCompile(`(?i)\burl\s*:\s*["'` + bt + `](/[^"'` + bt + `]*)`)
	// method/type key (jQuery uses type), for fetch-options and config-object forms.
	reMethodJS = regexp.MustCompile(`(?i)(?:method|type)\s*:\s*["'` + bt + `]?([A-Za-z]+)`)
	// a body object under JSON.stringify(...) / body: / data: (the wrapper forms).
	reBodyObj = regexp.MustCompile(`(?s)(?:JSON\.stringify\(\s*|(?:body|data)\s*:\s*)\{([^{}]*)\}`)
	// the first flat object literal in a window — the positional data arg of a verb call like .post(url,{…}).
	reFirstObj = regexp.MustCompile(`(?s)\{([^{}]*)\}`)
	reFieldJS  = regexp.MustCompile(`["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*:`)
	reTplSeg   = regexp.MustCompile(`\$\{[^}]*\}`)
)

// skipField drops obvious non-field tokens that the flat-object regex can pick up (scheme words,
// nested-call noise) so the hint stays clean.
var skipField = map[string]bool{"http": true, "https": true, "headers": true, "method": true}

// reverseAPIShapes extracts the API calls a chunk of client JS makes. Each fetch(...) yields a shape:
// its method, its path (template ids normalized to {id}, query stripped), and the body field names
// when the call passes an inline object literal.
func ReverseAPIShapes(js string) []APIShape {
	type key struct{ m, p string }
	idx := map[key]int{}
	var out []APIShape
	add := func(method, rawURL, win string, positional bool) {
		path := normalizeAPIPath(rawURL)
		if !strings.HasPrefix(path, "/") { // same-origin paths only, not absolute URLs
			return
		}
		method = strings.ToUpper(method)
		if method == "" {
			method = "GET"
		}
		fields := bodyFields(win, positional)
		k := key{method, path}
		if i, ok := idx[k]; ok {
			out[i].Fields = mergeStrings(out[i].Fields, fields)
			return
		}
		idx[k] = len(out)
		out = append(out, APIShape{Method: method, Path: path, Fields: fields})
	}
	// fetch(url, { method, headers, body }) — method is in the options object.
	for _, loc := range reFetchURL.FindAllStringSubmatchIndex(js, -1) {
		win := windowAt(js, loc[1], 400)
		add(methodIn(win), js[loc[2]:loc[3]], win, false)
	}
	// client.verb("/path", {data}) — axios / $.post / wrapped clients. The verb is the method and the
	// body is the positional object arg.
	for _, loc := range reVerbCall.FindAllStringSubmatchIndex(js, -1) {
		win := windowAt(js, loc[1], 220)
		add(js[loc[2]:loc[3]], js[loc[4]:loc[5]], win, true)
	}
	// axios({url, method, data}) / $.ajax({url, type, data}) — path on a url: key, body under data:.
	for _, loc := range reConfigURL.FindAllStringSubmatchIndex(js, -1) {
		win := windowAt(js, loc[0], 400) // include the surrounding config object
		add(methodIn(win), js[loc[2]:loc[3]], win, false)
	}
	return out
}

// windowAt returns the text of the current statement following start: up to n chars, but cut at the
// first ';' so one call's window never bleeds into the next statement (which would mis-attribute a
// neighbouring call's method/body to this one).
func windowAt(s string, start, n int) string {
	if start < 0 {
		start = 0
	}
	end := start + n
	if end > len(s) {
		end = len(s)
	}
	w := s[start:end]
	if i := strings.IndexByte(w, ';'); i >= 0 {
		w = w[:i]
	}
	return w
}

func methodIn(win string) string {
	if m := reMethodJS.FindStringSubmatch(win); m != nil {
		return m[1]
	}
	return ""
}

// bodyFields extracts the request-body field names from a window. positional=true reads the first
// object literal (a verb call's data arg); otherwise it reads the body:/data:/JSON.stringify object
// (so a fetch options wrapper's method/headers/body keys are not mistaken for body fields).
func bodyFields(win string, positional bool) []string {
	re := reBodyObj
	if positional {
		re = reFirstObj
	}
	m := re.FindStringSubmatch(win)
	if m == nil {
		return nil
	}
	var fields []string
	seen := map[string]bool{}
	for _, fm := range reFieldJS.FindAllStringSubmatch(m[1], -1) {
		f := fm[1]
		if skipField[strings.ToLower(f)] || seen[f] {
			continue
		}
		seen[f] = true
		fields = append(fields, f)
	}
	return fields
}

func mergeStrings(a, b []string) []string {
	seen := map[string]bool{}
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			a = append(a, s)
		}
	}
	return a
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
