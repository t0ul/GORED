package tools

import "testing"

// extractCSRF must pull the field name + token from the common patterns: nosurf's single-quoted
// hidden input, a double-quoted one, Rails authenticity_token, and a meta tag; and nothing from
// a page with no token.
func TestExtractCSRF(t *testing.T) {
	cases := []struct{ name, html, field, token string }{
		{"nosurf single-quote", `<input type='hidden' name='csrf_token' value='AbC123=='>`, "csrf_token", "AbC123=="},
		{"double-quote", `<input type="hidden" name="csrf_token" value="xyz">`, "csrf_token", "xyz"},
		{"value-then-name", `<input value="tok9" name="authenticity_token" type="hidden">`, "authenticity_token", "tok9"},
		{"meta tag", `<meta name="csrf-token" content="MetaTok">`, "csrf-token", "MetaTok"},
		{"none", `<form><input name="email"></form>`, "", ""},
	}
	for _, c := range cases {
		f, tok := extractCSRF(c.html)
		if f != c.field || tok != c.token {
			t.Errorf("%s: got (%q,%q), want (%q,%q)", c.name, f, tok, c.field, c.token)
		}
	}
}
