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
	Method  string            // GET/POST/PUT/PATCH/DELETE (GET when the call omits method)
	Path    string            // same-origin path, with a ${...} template segment normalized to {id}
	Fields  []string          // request-body field names, when the body is an inline object literal
	Query   []string          // query-string parameter keys observed on the URL
	Types   map[string]string // best-effort inferred type per field (string|number|bool); absent when unknown
	Headers []string          // security-relevant request header names the app sends (Content-Type, CSRF, Authorization)
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
	// a key: value pair in a flat object literal — group 1 is the field name, group 2 the value up to
	// the next comma/brace/newline (enough to sniff a string/number/bool literal).
	reFieldKV = regexp.MustCompile(`["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*:\s*([^,}\n]*)`)
	reTplSeg  = regexp.MustCompile(`\$\{[^}]*\}`)
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
		fields, types := bodyFields(win, positional)
		query := queryKeysOf(rawURL)
		k := key{method, path}
		if i, ok := idx[k]; ok {
			out[i].Fields = mergeStrings(out[i].Fields, fields)
			out[i].Query = mergeStrings(out[i].Query, query)
			out[i].Types = mergeTypes(out[i].Types, types)
			return
		}
		idx[k] = len(out)
		out = append(out, APIShape{Method: method, Path: path, Fields: fields, Query: query, Types: types})
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

// bodyFields extracts the request-body field names (and a best-effort inferred type per field) from
// a window. positional=true reads the first object literal (a verb call's data arg); otherwise it
// reads the body:/data:/JSON.stringify object (so a fetch options wrapper's method/headers/body keys
// are not mistaken for body fields). A field whose value is a literal (string/number/bool) is typed;
// a field whose value is a variable or expression stays untyped (OpenAPI, when present, fills it).
func bodyFields(win string, positional bool) ([]string, map[string]string) {
	re := reBodyObj
	if positional {
		re = reFirstObj
	}
	m := re.FindStringSubmatch(win)
	if m == nil {
		return nil, nil
	}
	var fields []string
	seen := map[string]bool{}
	types := map[string]string{}
	for _, fm := range reFieldKV.FindAllStringSubmatch(m[1], -1) {
		f := fm[1]
		if skipField[strings.ToLower(f)] || seen[f] {
			continue
		}
		seen[f] = true
		fields = append(fields, f)
		if t := jsValueType(fm[2]); t != "" {
			types[f] = t
		}
	}
	if len(types) == 0 {
		types = nil
	}
	return fields, types
}

// jsValueType classifies a JS literal value into the probe type vocabulary; "" for a variable or
// expression (which the static parser cannot type).
func jsValueType(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	switch v[0] {
	case '"', '\'', '`':
		return "string"
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return "number"
	}
	if v == "true" || v == "false" {
		return "bool"
	}
	return ""
}

// queryKeysOf extracts the query-string parameter keys from a raw URL literal (before the path is
// normalized and the query stripped), so search/filter params become part of the contract.
func queryKeysOf(raw string) []string {
	i := strings.IndexByte(raw, '?')
	if i < 0 {
		return nil
	}
	var keys []string
	seen := map[string]bool{}
	for _, pair := range strings.Split(raw[i+1:], "&") {
		k := pair
		if j := strings.IndexByte(pair, '='); j >= 0 {
			k = pair[:j]
		}
		if k = strings.TrimSpace(k); k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}

// mergeTypes unions two field→type maps; existing (a) wins so a stronger earlier inference is kept.
func mergeTypes(a, b map[string]string) map[string]string {
	if len(b) == 0 {
		return a
	}
	if a == nil {
		a = map[string]string{}
	}
	for k, v := range b {
		if _, ok := a[k]; !ok {
			a[k] = v
		}
	}
	return a
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
