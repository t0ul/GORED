package main

import (
	"testing"

	"github.com/t0ul/GORED/internal/tools"
)

// TestMineEndpoints checks the JS-bundle miner against literal shapes taken from real
// bundles (Juice Shop's main.js carries /api/* and /rest/* route strings; static assets and
// fragments must be dropped). Pure logic: no network, no model.
func TestMineEndpoints(t *testing.T) {
	src := "fetch('/rest/products/search?q='+q);const u=\"/api/Challenges\";" +
		"import('/main.js');a.src='/assets/logo.png';x=`/rest/admin/application-version`;" +
		"bad='/foo//bar';dots='/a/../b';css=\"/styles.css\""
	got := map[string]bool{}
	mineEndpoints(src, got)
	want := []string{"/rest/products/search", "/api/Challenges", "/rest/admin/application-version"}
	for _, w := range want {
		if !got[w] {
			t.Errorf("miner missed %q", w)
		}
	}
	for _, bad := range []string{"/main.js", "/assets/logo.png", "/styles.css", "/foo//bar", "/a/../b"} {
		if got[bad] {
			t.Errorf("miner wrongly kept %q (asset or malformed)", bad)
		}
	}
}

func TestScriptSrcs(t *testing.T) {
	html := `<head><script src="polyfills.js"></script><script defer src='/main.js'></script>` +
		`<script type="module" src="rolldown-runtime-abc.js"></script></head>`
	got := scriptSrcs(html)
	if len(got) != 3 {
		t.Fatalf("scriptSrcs = %v, want 3", got)
	}
}

func TestLinkedPaths(t *testing.T) {
	// vulnapp's index links several paths; Juice Shop's shell links none.
	vuln := `<a href=/search?q=>s</a><a href="/greeting?name=guest">g</a><a href=/api/status>a</a>`
	lp := linkedPaths(vuln)
	for _, p := range []string{"/search", "/greeting", "/api/status"} {
		if !lp[p] {
			t.Errorf("linkedPaths missed %q", p)
		}
	}
	juice := `<!doctype html><html><body><app-root></app-root></body></html>`
	if len(linkedPaths(juice)) != 0 {
		t.Errorf("SPA shell should link nothing, got %v", linkedPaths(juice))
	}
}

func TestClassifySurfaceMap(t *testing.T) {
	cases := map[string]string{
		`{"status":"success"}`:                                "json-api",
		`<!doctype html><html><body><app-root></app-root>`:    "spa-shell",
		`<!doctype html><html><body><h1>hi</h1></body></html>`: "html-page",
		``:                                                     "unknown",
	}
	for body, want := range cases {
		if got, _ := tools.ClassifySurface(body); got != want {
			t.Errorf("ClassifySurface(%.20q) = %q, want %q", body, got, want)
		}
	}
}
