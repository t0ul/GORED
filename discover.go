package gored

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DiscoverTool enumerates a web app's surface deterministically: it fetches a page
// and extracts same-origin paths from links, form actions, and inline JS endpoint
// literals, and probes a small fixed set of well-known descriptors. It exists so a
// small model does not have to parse HTML — recon becomes reliable, and the model's
// job becomes choosing what to attack. All fetches go through the egress gate and
// are read-only (GET) and bounded.
type DiscoverTool struct {
	Base   string
	Egress *Egress
	Max    int // max fetches per call (default 12)
	client *http.Client
}

func NewDiscoverTool(base string, e *Egress) *DiscoverTool {
	return &DiscoverTool{
		Base:   strings.TrimRight(base, "/"),
		Egress: e,
		Max:    24,
		client: &http.Client{Timeout: 8 * time.Second},
	}
}

func (*DiscoverTool) Name() string { return "discover" }
func (*DiscoverTool) Describe() string {
	return `enumerate the app's surface. args: {"path":"/"} (where to start). Fetches that page plus well-known descriptors and returns the same-origin paths it found (from links, form actions, and inline fetch/XHR URLs). Use it first, then http_request the interesting paths.`
}

// well-known descriptors worth a cheap probe on any web app.
var wellKnown = []string{"/robots.txt", "/sitemap.xml", "/openapi.json", "/swagger.json", "/.well-known/", "/api", "/api/"}

var (
	reAttr  = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)["']`)
	reJSURL = regexp.MustCompile(`["'` + "`" + `](/[A-Za-z0-9_\-./{}]+)["'` + "`" + `]`)
)

func (t *DiscoverTool) Call(ctx context.Context, args map[string]any) (string, error) {
	start := asString(args["path"])
	if start == "" {
		start = "/"
	}
	if !strings.HasPrefix(start, "/") {
		start = "/" + start
	}

	found := map[string]bool{}
	fetches := 0
	fetch := func(path string) {
		if fetches >= t.Max {
			return
		}
		raw := t.Base + path
		if !t.Egress.Allowed(raw) {
			return
		}
		fetches++
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return
		}
		resp, err := t.client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		for _, m := range reAttr.FindAllStringSubmatch(string(body), -1) {
			if p := samePath(t.Base, m[1]); p != "" {
				found[p] = true
			}
		}
		for _, m := range reJSURL.FindAllStringSubmatch(string(body), -1) {
			found[m[1]] = true
		}
	}

	fetch(start)
	for _, wk := range wellKnown {
		fetch(wk)
	}
	// Second pass: a SPA keeps its real API routes inside its JS bundles, not in
	// the HTML. Fetch the same-origin .js we found and mine it for path literals.
	for _, p := range sortedKeys(found) {
		if strings.HasSuffix(p, ".js") {
			fetch(p)
		}
	}

	paths := make([]string, 0, len(found))
	for p := range found {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return "discovered 0 paths (surface may be behind auth or rendered client-side)", nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "discovered %d path(s):\n", len(paths))
	for _, p := range paths {
		fmt.Fprintf(&sb, "  %s\n", p)
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

// samePath returns the same-origin absolute path of ref relative to base, or "" if
// ref points off-origin (we only enumerate the target).
func samePath(base, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "mailto:") || strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "data:") {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	if u.IsAbs() {
		b, err := url.Parse(base)
		if err != nil || !strings.EqualFold(u.Host, b.Host) {
			return "" // off-origin
		}
		return cleanPath(u.Path)
	}
	if strings.HasPrefix(ref, "/") {
		return cleanPath(u.Path)
	}
	return "" // skip relative/fragment-only refs; keep enumeration simple and same-origin
}

func sortedKeys(m map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}
