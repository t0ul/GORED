package tools

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ClassifySurface infers a URL's surface type from its response body — the one signal
// that survives on a real app (a hardened SPA sets no framework header and ships hashed
// bundles). It returns a short class (json-api | html-page | spa-shell | non-html |
// unknown) and a routing note. Pure and testable; no network. This is the single copy:
// it previously lived, with signature drift, in gored-reconsweep, gored-mapsweep and
// gored-plansweep.
func ClassifySurface(body string) (class, note string) {
	b := strings.TrimSpace(body)
	lb := strings.ToLower(b)
	if b == "" {
		return "unknown", "Empty or unreadable response; re-fetch or try another path."
	}
	if strings.HasPrefix(b, "{") || strings.HasPrefix(b, "[") {
		return "json-api", "A JSON API response; reflected XSS does not apply here. Test server-side classes (authorization, injection) on this surface."
	}
	isHTML := strings.Contains(lb, "<!doctype html") || strings.Contains(lb, "<html")
	if !isHTML {
		return "non-html", "Not an HTML page; reflected XSS is unlikely here."
	}
	// SPA shell markers: an empty root element the client fills at runtime. Reflected XSS on a
	// SPA is DOM-based and needs a browser to confirm (an HTTP-only scanner cannot see it).
	for _, m := range []string{"<app-root", "ng-app", "data-react", "data-beasties", `id="root"`, `id="app"`} {
		if strings.Contains(lb, m) {
			return "spa-shell", "A client-rendered single-page-app shell; any XSS here is DOM-based and needs a browser to confirm (an HTTP-only scanner will see nothing)."
		}
	}
	return "html-page", "A server-rendered HTML page; if it reflects a parameter into the page, reflected XSS may apply."
}

// ParseWebanalyze decodes webanalyze's JSON (tolerating any banner before the first brace)
// into a short list of "Name (Category, Category)" strings.
func ParseWebanalyze(out string) []string {
	i := strings.IndexByte(out, '{')
	if i < 0 {
		return nil
	}
	var doc struct {
		Matches []struct {
			AppName string `json:"app_name"`
			App     struct {
				CatNames []string `json:"category_names"`
			} `json:"app"`
		} `json:"matches"`
	}
	if json.NewDecoder(strings.NewReader(out[i:])).Decode(&doc) != nil {
		return nil
	}
	var techs []string
	for _, m := range doc.Matches {
		if m.AppName == "" {
			continue
		}
		if cats := nonEmpty(m.App.CatNames); len(cats) > 0 {
			techs = append(techs, fmt.Sprintf("%s (%s)", m.AppName, strings.Join(cats, ", ")))
		} else {
			techs = append(techs, m.AppName)
		}
	}
	return techs
}

// ParseDalfox classifies dalfox's JSON. A capture requires a VERIFIED finding — type "V"
// or a real severity (critical/high/medium) — because dalfox also emits type "R" (Info)
// for a parameter that is merely reflected even when the reflection is HTML-escaped and
// not exploitable; counting those would false-positive on an escaped decoy. It tolerates
// any banner before the first brace and any status line the bridge appends after. This is
// the single copy (previously in reconsweep, xsssweep and plansweep, byte-for-byte).
func ParseDalfox(out string) (verified, reflectedOnly bool, status, finding string) {
	i := strings.IndexByte(out, '{')
	if i < 0 {
		return false, false, "no-json", ""
	}
	var doc struct {
		Findings []struct {
			Type     string `json:"type"`
			Severity string `json:"severity"`
			POC      string `json:"poc"`
			Param    string `json:"param"`
		} `json:"findings"`
		Meta struct {
			TargetSummary []struct {
				Status string `json:"status"`
			} `json:"target_summary"`
		} `json:"meta"`
	}
	if json.NewDecoder(strings.NewReader(out[i:])).Decode(&doc) != nil {
		return false, false, "parse-error", ""
	}
	status = "clean"
	if len(doc.Meta.TargetSummary) > 0 {
		status = doc.Meta.TargetSummary[0].Status
	}
	var firstReflected string
	for _, f := range doc.Findings {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		isVerified := strings.EqualFold(f.Type, "V") || sev == "critical" || sev == "high" || sev == "medium"
		desc := fmt.Sprintf("[%s severity=%s param=%s] %s", f.Type, f.Severity, f.Param, strings.TrimSpace(f.POC))
		if isVerified {
			return true, false, status, desc
		}
		if firstReflected == "" {
			firstReflected = f.Param
		}
	}
	return false, firstReflected != "", status, firstReflected
}

// jsPathRe matches a quoted path- or URL-like string literal inside a JavaScript bundle:
// an absolute path ("/api/users", "/rest/user/login") or an http(s) URL. It is
// deliberately conservative (the content must look like a path, not any slash-bearing
// string) to keep ExtractJSEndpoints low-noise. Detection-driven: no app paths baked in.
var jsPathRe = regexp.MustCompile(`["'` + "`" + `](https?://[^"'` + "`" + ` ]+|/[A-Za-z0-9_][A-Za-z0-9_\-./:{}]*)["'` + "`" + `]`)

// ExtractJSEndpoints mines a fetched JavaScript bundle for the paths and URLs it calls,
// so an agent can map a single-page app's API surface from its shipped code. It returns a
// sorted, de-duplicated list and ignores obvious asset paths (./*.js/.css/.map/images).
// Pure and testable; the fetch happens through a Gate in JSEndpointsTool.
func ExtractJSEndpoints(js string) []string {
	seen := map[string]bool{}
	for _, m := range jsPathRe.FindAllStringSubmatch(js, -1) {
		p := m[1]
		if isAssetPath(p) {
			continue
		}
		seen[p] = true
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// isAssetPath drops static-asset references that are not API endpoints.
func isAssetPath(p string) bool {
	low := strings.ToLower(p)
	for _, ext := range []string{".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".html"} {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
