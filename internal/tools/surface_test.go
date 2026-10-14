package tools

import (
	"reflect"
	"testing"
)

func TestClassifySurface(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"json-object", `{"id":1,"name":"a"}`, "json-api"},
		{"json-array", `[1,2,3]`, "json-api"},
		{"server-html", "<!DOCTYPE html><html><body><p>hi</p></body></html>", "html-page"},
		{"react-spa", `<!doctype html><html><head></head><body><div id="root"></div></body></html>`, "spa-shell"},
		{"angular-spa", `<!DOCTYPE html><html><body><app-root></app-root></body></html>`, "spa-shell"},
		{"plain-text", "just some text", "non-html"},
		{"empty", "   ", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, note := ClassifySurface(c.body)
			if got != c.want {
				t.Errorf("ClassifySurface(%q) class = %q, want %q", c.body, got, c.want)
			}
			if note == "" {
				t.Errorf("ClassifySurface(%q) returned an empty note", c.body)
			}
		})
	}
}

// TestClassifySurfaceRealTargets uses response-body shapes captured from the real targets
// (vulnapp and OWASP Juice Shop, both in the Brig) so the classifier is checked against actual
// bytes, not a contrived fixture (wired-not-stubbed). Pure logic: no network, no model. These
// cases moved here from gored-reconsweep when the classifier became canonical.
func TestClassifySurfaceRealTargets(t *testing.T) {
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
			got, note := ClassifySurface(c.body)
			if got != c.want {
				t.Fatalf("ClassifySurface(%s) class = %q, want %q", c.name, got, c.want)
			}
			if note == "" {
				t.Fatalf("ClassifySurface(%s) returned an empty routing note", c.name)
			}
		})
	}
}

func TestParseDalfoxVerifiedGate(t *testing.T) {
	// A VERIFIED finding (dalfox type "V") is a capture.
	verifiedJSON := `scanning... {"findings":[{"type":"V","severity":"High","poc":"http://t/greeting?name=<script>alert(1)</script>","param":"name"}],"meta":{"target_summary":[{"status":"vulnerable"}]}}`
	v, refl, status, finding := ParseDalfox(verifiedJSON)
	if !v || refl {
		t.Fatalf("verified finding: got verified=%v reflectedOnly=%v, want true/false", v, refl)
	}
	if status != "vulnerable" || finding == "" {
		t.Errorf("verified finding: status=%q finding=%q", status, finding)
	}

	// A merely-reflected parameter (type "R", severity Info) is NOT a capture — this is the
	// escaped-decoy false positive the verified gate exists to stop.
	reflectedJSON := `{"findings":[{"type":"R","severity":"Info","poc":"reflected","param":"q"}],"meta":{"target_summary":[{"status":"reflected"}]}}`
	v, refl, _, finding = ParseDalfox(reflectedJSON)
	if v {
		t.Error("reflected-only must NOT count as verified")
	}
	if !refl || finding != "q" {
		t.Errorf("reflected-only: refl=%v finding=%q, want true/\"q\"", refl, finding)
	}

	// A medium-or-higher severity also verifies even without type "V".
	if v, _, _, _ := ParseDalfox(`{"findings":[{"type":"G","severity":"Medium","param":"x"}]}`); !v {
		t.Error("severity=Medium should verify")
	}

	// Clean scan: no findings.
	v, refl, status, _ = ParseDalfox(`{"findings":[],"meta":{"target_summary":[{"status":"clean"}]}}`)
	if v || refl || status != "clean" {
		t.Errorf("clean scan: verified=%v reflectedOnly=%v status=%q", v, refl, status)
	}

	// No JSON at all.
	if _, _, status, _ := ParseDalfox("dalfox: command not found"); status != "no-json" {
		t.Errorf("no-json: status=%q, want no-json", status)
	}
}

func TestParseWebanalyze(t *testing.T) {
	// Real webanalyze JSON shape, with a banner before the first brace.
	out := `webanalyze v0.4 {"matches":[{"app_name":"React","app":{"category_names":["JavaScript frameworks"]}},{"app_name":"Express","app":{"category_names":["Web servers","Web frameworks"]}},{"app_name":""}]}`
	got := ParseWebanalyze(out)
	want := []string{"React (JavaScript frameworks)", "Express (Web servers, Web frameworks)"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseWebanalyze = %v, want %v", got, want)
	}
	if ParseWebanalyze("no json here") != nil {
		t.Error("ParseWebanalyze on non-JSON should be nil")
	}
}

func TestExtractJSEndpoints(t *testing.T) {
	js := `const base="/api";
	fetch("/api/users");
	axios.get('/rest/products/search');
	const u = "https://cdn.example.com/data.json";
	import("/static/app.js");            // asset, excluded
	const css = "/assets/main.css";      // asset, excluded
	location.href = "/api/users";        // duplicate`
	got := ExtractJSEndpoints(js)
	want := []string{"/api", "/api/users", "/rest/products/search", "https://cdn.example.com/data.json"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtractJSEndpoints = %v, want %v", got, want)
	}
	if len(ExtractJSEndpoints("var x = 1;")) != 0 {
		t.Error("ExtractJSEndpoints on path-free JS should be empty")
	}
}
