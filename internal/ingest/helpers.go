package ingest

import "strings"

// testablePath and looksLikeModule are small pure predicates the ingest parsers share with
// the root hunt/correlate code. They are duplicated here (rather than imported) so internal/
// ingest stays free of any dependency on the root package — the import edge runs one way,
// root -> ingest, with no cycle. They are trivial and stable; the security-critical parsers
// (the kind the architecture plan keeps to one copy) live in internal/tools, not here.

func testablePath(p string) bool {
	if strings.ContainsAny(p, "{}") {
		return false // a route template, not a concrete resource
	}
	if strings.HasPrefix(p, "/static/") || strings.HasPrefix(p, "/assets/") {
		return false
	}
	for _, skip := range []string{"/api/auth/", "/login", "/register", "/logout", "/signout"} {
		if strings.HasPrefix(p, skip) || p == strings.TrimSuffix(skip, "/") {
			return false
		}
	}
	last := p[strings.LastIndex(p, "/")+1:]
	if strings.Contains(last, ".") {
		return false // a static asset (has a file extension)
	}
	return true
}

func looksLikeModule(loc string) bool {
	if loc == "stdlib" {
		return true
	}
	first := loc
	if i := strings.IndexByte(loc, '/'); i >= 0 {
		first = loc[:i]
	}
	return strings.Contains(first, ".")
}
