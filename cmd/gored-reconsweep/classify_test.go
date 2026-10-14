package main

import "testing"

// TestClassifySurface uses response-body shapes captured from the real targets (vulnapp and
// OWASP Juice Shop, both in the Brig) so the classifier is checked against actual bytes, not
// a contrived fixture. It is pure logic: no network, no model.
func TestClassifySurface(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"vulnapp-html", `<!doctype html><html><head><title>Acme Portal — Home</title><script src="/static/react.js"></script></head><body><h1>Acme Portal</h1></body></html>`, "html-page"},
		{"vulnapp-json", `{"greeting":"Hello, x"}`, "json-api"},
		{"juice-spa-shell", "<!--\n ~ Copyright\n-->\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head><title>OWASP Juice Shop</title></head><body><app-root></app-root></body></html>", "spa-shell"},
		{"juice-rest-json", `{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)"}]}`, "json-api"},
		{"json-array", `[{"id":1}]`, "json-api"},
		{"empty", "", "unknown"},
		{"plain-text", "ok", "non-html"},
		{"react-div-root", `<!doctype html><html><body><div id="root"></div><script type="module" src="/main.js"></script></body></html>`, "spa-shell"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, note := classifySurface(c.body)
			if got != c.want {
				t.Fatalf("classifySurface(%s) class = %q, want %q", c.name, got, c.want)
			}
			if note == "" {
				t.Fatalf("classifySurface(%s) returned an empty routing note", c.name)
			}
		})
	}
}
