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
//
// With a Sessions registry set (see WebRecon) it crawls as a named identity, so
// after a login through http_request under the same session name it sees the
// authenticated surface — the API routes a login page never links to. Without one
// it crawls jarless, the unauthenticated surface only.
type DiscoverTool struct {
	Base     string
	Egress   *Egress
	Max      int // max fetches per call (default 40)
	Depth    int // how many page levels deep to crawl (default 2)
	Sessions *Sessions
	client   *http.Client
}

func NewDiscoverTool(base string, e *Egress) *DiscoverTool {
	return &DiscoverTool{
		Base:   strings.TrimRight(base, "/"),
		Egress: e,
		Max:    40,
		Depth:  2,
		client: &http.Client{Timeout: 8 * time.Second},
	}
}

func (*DiscoverTool) Name() string { return "discover" }
func (*DiscoverTool) Describe() string {
	return `enumerate the app's surface. args: {"path":"/","session":"name"}. Fetches that page plus well-known descriptors and returns the same-origin paths it found (from links, form actions, and inline fetch/XHR URLs). Pass the same "session" you logged in with via http_request to crawl the AUTHENTICATED surface (the API routes that only appear once signed in). Use it first, then http_request the interesting paths.`
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

	// Crawl as the identity the agent logged in with: when a shared Sessions
	// registry is set, the named session's cookie jar (filled by an earlier
	// http_request login) rides every fetch, so discovery sees the authenticated
	// surface. With no registry it stays jarless — the unauthenticated surface only.
	client := t.client
	if t.Sessions != nil {
		client = t.Sessions.Client(asString(args["session"]))
	}

	found := map[string]bool{}
	fetched := map[string]bool{}
	fetches := 0
	// get fetches one path (GET, read-only), records every same-origin path it
	// references into found, and returns those paths so the crawl can descend.
	get := func(path string) []string {
		if fetches >= t.Max || fetched[path] {
			return nil
		}
		fetched[path] = true
		raw := t.Base + path
		if !t.Egress.Allowed(raw) {
			return nil
		}
		fetches++
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return nil
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		var here []string
		for _, m := range reAttr.FindAllStringSubmatch(string(body), -1) {
			if p := samePath(t.Base, m[1]); p != "" {
				found[p] = true
				here = append(here, p)
			}
		}
		for _, m := range reJSURL.FindAllStringSubmatch(string(body), -1) {
			found[m[1]] = true
			here = append(here, m[1])
		}
		return here
	}

	// Breadth-first crawl of the authenticated surface. A login page links almost
	// nothing; the real routes live one or two pages in (a dashboard that links an
	// upload page) and inside the JS bundles those pages load. So the crawl descends
	// up to Depth levels into same-origin app pages and mines each .js it meets,
	// while only RECORDING /api endpoints — discovery enumerates the surface, it
	// does not exercise it. Bounded by Max fetches; every fetch is a read-only GET.
	type node struct {
		path  string
		depth int
	}
	queue := []node{{start, 0}}
	for _, wk := range wellKnown {
		queue = append(queue, node{wk, 0})
	}
	queued := map[string]bool{start: true}
	for len(queue) > 0 && fetches < t.Max {
		cur := queue[0]
		queue = queue[1:]
		children := get(cur.path)
		if cur.depth >= t.Depth {
			continue
		}
		sort.Strings(children) // deterministic crawl order
		for _, c := range children {
			if !queued[c] && !fetched[c] && crawlable(c) {
				queued[c] = true
				queue = append(queue, node{c, cur.depth + 1})
			}
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

// crawlable reports whether the crawl should fetch a discovered path to go deeper.
// It mines .js bundles (where SPA API routes hide) and descends into same-origin
// app pages, but never fetches an /api endpoint (those are recorded, not exercised),
// a template route, a static asset, or an upload — keeping discovery read-only and
// focused on mapping, not touching, the surface.
func crawlable(p string) bool {
	if strings.ContainsAny(p, "{}") {
		return false // a route template like /api/tickets/{id}, not a real URL
	}
	if strings.HasSuffix(p, ".js") {
		return true
	}
	if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/uploads/") {
		return false
	}
	last := p[strings.LastIndex(p, "/")+1:]
	return !strings.Contains(last, ".") // a page (no file extension), not an asset
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

// WebRecon returns an http_request and a discover tool that share one session
// registry. Give both to the same recon agent so it can log in with http_request
// under a session name and then discover the authenticated surface under that same
// name — the "recon logs in, then crawls" step. onDeny may be nil.
func WebRecon(base string, e *Egress, onDeny func(string)) (*HTTPRequestTool, *DiscoverTool) {
	h := NewHTTPRequestTool(base, e, onDeny)
	d := NewDiscoverTool(base, e)
	d.Sessions = h.Sessions
	return h, d
}
