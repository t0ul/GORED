package appsweep

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/t0ul/GORED/internal/core"
)

// Pure helpers shared by the map and plan stages (previously copy-pasted in gored-mapsweep and
// gored-plansweep). They mine endpoint paths from HTML/JS, resolve references, and read the
// blackboard. No network, no app-specific knowledge.

var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']?([^"'>\s]+)`)
	// absolute multi-segment path literals — the general shape of an endpoint in JS/HTML source.
	pathLitRe = regexp.MustCompile(`/[A-Za-z][A-Za-z0-9/_.\-]{1,120}`)
	assetExt  = regexp.MustCompile(`(?i)\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|json|txt|xml|html?)$`)
)

func scriptSrcs(html string) []string {
	var out []string
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		out = append(out, m[1])
	}
	return out
}

// mineEndpoints adds endpoint-shaped path literals from src into dst, dropping static assets
// and fragments that are clearly not routes (single-segment, host-like, traversal).
func mineEndpoints(src string, dst map[string]bool) {
	for _, m := range pathLitRe.FindAllString(src, -1) {
		p := normPath(m)
		if p == "" || p == "/" || assetExt.MatchString(p) || strings.Contains(p, "//") || strings.Contains(p, "..") {
			continue
		}
		if strings.Count(p, "/") < 2 {
			continue
		}
		if first := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)[0]; strings.Contains(first, ".") {
			continue
		}
		dst[p] = true
	}
}

// normPath trims a URL to its path and strips a trailing slash (except root).
func normPath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if u, err := url.Parse(p); err == nil && u.Path != "" {
		p = u.Path
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

func resolveRef(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	res := b.ResolveReference(r)
	if res.Scheme != "http" && res.Scheme != "https" {
		return ""
	}
	return res.String()
}

func pathOf(u, base string) string {
	if p, err := url.Parse(u); err == nil && p.Path != "" {
		return normPath(p.Path)
	}
	return normPath(strings.TrimPrefix(u, base))
}

// resolveURL turns a {"url":...} or {"path":...} arg into an absolute URL on the target base,
// accepting an absolute http(s) URL as-is (models often pass a bare "/" or "/x" in url).
func resolveURL(args map[string]any, base string) (string, error) {
	u, _ := args["url"].(string)
	if u == "" {
		u, _ = args["path"].(string)
	}
	if u == "" {
		return "", fmt.Errorf("need a url or path argument")
	}
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u, nil
	}
	if !strings.HasPrefix(u, "/") {
		u = "/" + u
	}
	return base + u, nil
}

func joinCap(xs []string, n int) string {
	if len(xs) == 0 {
		return "(none)"
	}
	if len(xs) > n {
		return strings.Join(xs[:n], ", ") + fmt.Sprintf(", …(+%d more)", len(xs)-n)
	}
	return strings.Join(xs, ", ")
}

// boardHas reports whether any finding on the board contains substr — so a phase advance
// depends on durable board state, not just the last tool output (which the Runner's
// repeat-skip can replace with a skip note).
func boardHas(b *core.Blackboard, substr string) bool {
	if b == nil {
		return false
	}
	for _, f := range b.Findings() {
		if strings.Contains(f.Value, substr) {
			return true
		}
	}
	return false
}
