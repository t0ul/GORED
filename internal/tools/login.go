package tools

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// LoginSpec is a target's login recipe: the endpoint, the body shape, and the credential field names.
type LoginSpec struct {
	Type      string // "json" | "form" (default json)
	Path      string // login endpoint, e.g. /api/auth/login or /krab/login
	UserField string // default "email"
	PassField string // default "password"
	User      string
	Pass      string
}

var (
	// a hidden CSRF input, either name-then-value or value-then-name, single or double quotes.
	reCSRFInputNV = regexp.MustCompile(`(?is)<input[^>]*\bname=['"]([^'"]*(?:csrf|xsrf|authenticity)[^'"]*)['"][^>]*\bvalue=['"]([^'"]*)['"]`)
	reCSRFInputVN = regexp.MustCompile(`(?is)<input[^>]*\bvalue=['"]([^'"]*)['"][^>]*\bname=['"]([^'"]*(?:csrf|xsrf|authenticity)[^'"]*)['"]`)
	reCSRFMeta    = regexp.MustCompile(`(?is)<meta[^>]*\bname=['"]([^'"]*(?:csrf|xsrf)[^'"]*)['"][^>]*\bcontent=['"]([^'"]*)['"]`)
)

// extractCSRF pulls a CSRF field name + token out of a login page's HTML (a hidden form input or a
// meta tag). Generic across frameworks (nosurf's csrf_token, Rails authenticity_token, meta csrf-token).
// Returns ("","") when the page carries no CSRF token (e.g. a JSON API or a token-less form).
func extractCSRF(html string) (field, token string) {
	if m := reCSRFInputNV.FindStringSubmatch(html); m != nil {
		return m[1], m[2]
	}
	if m := reCSRFInputVN.FindStringSubmatch(html); m != nil {
		return m[2], m[1]
	}
	if m := reCSRFMeta.FindStringSubmatch(html); m != nil {
		return m[1], m[2]
	}
	return "", ""
}

// Authenticate logs the session in, handling CSRF. For a form login it first GETs the login page
// (which sets the CSRF cookie in this session's jar and carries the token), extracts the token, and
// submits it alongside the credentials — the GET-then-POST dance a real browser does. For a JSON
// login it posts the credentials directly. The cookie(s) the server sets land in the named session
// jar, so later calls under that session are authenticated.
func (t *HTTPRequestTool) Authenticate(ctx context.Context, session string, s LoginSpec) (string, error) {
	uf, pf := s.UserField, s.PassField
	if uf == "" {
		uf = "email"
	}
	if pf == "" {
		pf = "password"
	}
	var body, ct string
	headers := map[string]any{}
	if strings.EqualFold(s.Type, "form") {
		// GET the login page under this session to obtain the CSRF token + cookie.
		field, token := "", ""
		if page, err := t.Call(ctx, map[string]any{"method": "GET", "path": s.Path, "session": session}); err == nil {
			field, token = extractCSRF(page)
		}
		v := url.Values{}
		v.Set(uf, s.User)
		v.Set(pf, s.Pass)
		if field != "" {
			v.Set(field, token)
		}
		body, ct = v.Encode(), "application/x-www-form-urlencoded"
		if token != "" {
			headers["X-CSRF-Token"] = token // many frameworks also accept the token via header
		}
	} else {
		body, ct = fmt.Sprintf("{%q:%q,%q:%q}", uf, s.User, pf, s.Pass), "application/json"
	}
	headers["Content-Type"] = ct
	return t.Call(ctx, map[string]any{"method": "POST", "path": s.Path, "body": body, "session": session, "headers": headers})
}
