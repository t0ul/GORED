package main

import (
	"strings"
	"testing"

	"github.com/t0ul/GORED/internal/tools"
)

// TestRouteClass pins the stack-aware routing: XSS belongs on a server-rendered HTML page,
// NEVER on a JSON API; a SPA shell is DOM XSS (browser-only). Pure logic, no network.
func TestRouteClass(t *testing.T) {
	// html-page -> XSS with the xss_scan tool.
	if vc, tool, _ := routeClass("html-page"); !strings.Contains(vc, "XSS") || tool != "xss_scan" {
		t.Errorf("html-page should route reflected XSS to xss_scan, got (%q,%q)", vc, tool)
	}
	// json-api -> authz/JWT/mass-assignment, and explicitly NOT xss_scan.
	vc, tool, note := routeClass("json-api")
	if tool == "xss_scan" {
		t.Errorf("json-api must NOT route to xss_scan, got tool=%q", tool)
	}
	if !strings.Contains(strings.ToLower(vc), "author") && !strings.Contains(strings.ToLower(vc), "jwt") {
		t.Errorf("json-api should route the authz/JWT path, got %q", vc)
	}
	if !strings.Contains(strings.ToLower(note), "do not run an xss") {
		t.Errorf("json-api note should warn off XSS, got %q", note)
	}
	// spa-shell -> DOM XSS, needs a browser, not xss_scan.
	if vc, tool, _ := routeClass("spa-shell"); tool == "xss_scan" || !strings.Contains(strings.ToLower(vc), "dom") {
		t.Errorf("spa-shell should route DOM XSS away from xss_scan, got (%q,%q)", vc, tool)
	}
}

func TestClassifySurfacePlan(t *testing.T) {
	cases := map[string]string{
		`<!doctype html><html><head><script src="/static/react.js"></script></head><body><h1>hi</h1></body></html>`: "html-page",
		`<!doctype html><html><body><app-root></app-root></body></html>`:                                            "spa-shell",
		`{"greeting":"Hello, x"}`:                                                                                    "json-api",
		`ok`:                                                                                                         "non-html",
		``:                                                                                                          "unknown",
	}
	for body, want := range cases {
		if got, _ := tools.ClassifySurface(body); got != want {
			t.Errorf("ClassifySurface(%.24q) = %q, want %q", body, got, want)
		}
	}
}
