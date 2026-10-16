package eva

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/t0ul/GORED/store"
)

// Phase 2 — prioritize & probe. The recon map is a flat list of endpoints; this classifies each by
// its path+method SHAPE (generic — no app-specific names) into an attack-value tier and routes it to
// the tool that fits the class, so the agent works the crown jewels first instead of poking at random.
// Reads come first; the mutating classes are flagged (GORED's write probes self-scope), so pointing
// this at a real app the operator is not mutating stays safe by default.

type endpointClass struct {
	tier       int // 1 = crown jewels, 2 = state-changing/data, 3 = info/ssrf, 0 = untiered (plain page/asset)
	class      string
	tool       string
	why        string
	difficulty int // how hard this class is for a weak local model to LAND: 1 easy .. 3 hard. The
	// exploit phase works easiest-first (strong one-shot oracles before id-enumeration/authz), so a
	// weak model banks the wins it can get before the hard IDOR/admin classes.
}

// an id-like path segment: a {template} param, an all-numeric segment, or a long opaque token (uuid/slug).
var reIDSeg = regexp.MustCompile(`/(\{[^/}]+\}|[0-9]+|[0-9A-Za-z_-]{8,})(/|$)`)

// classifyEndpoint maps one endpoint to its attack class. Order matters: specific classes win over
// the broad IDOR/API catch-all (e.g. /api/config is info, not just another id endpoint).
func classifyEndpoint(method, path string) endpointClass {
	lp := strings.ToLower(path)
	m := strings.ToUpper(method)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(lp, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("login", "signin", "sign-in", "/auth", "token", "register", "signup", "password", "reset", "activate", "session"):
		return endpointClass{1, "auth", "nosqli / jwt_forge", "authn bypass (operator injection) or forge/replay a token", 2}
	case has("/admin", "krabmin", "administrator"):
		return endpointClass{1, "admin", "bola", "function-level authz: can the low identity reach it?", 3}
	case has("upload", "/images/"):
		return endpointClass{2, "upload", "stored_xss / api_request", "unrestricted upload / path traversal / stored XSS on the shown value", 2}
	case has("ingest", "import", "/parse"):
		return endpointClass{2, "ingest", "stored_xss / api_request", "stored XSS / injection on ingested data shown back on a page", 2}
	case has("export", "download", "report", ".csv", ".ics", ".pdf", "branded"):
		return endpointClass{2, "export", "api_request", "document IDOR / path traversal / info leak", 1}
	case has("search", "query", "filter", "?q=", "/q/"):
		return endpointClass{2, "search", "dom_xss / nosqli", "injection + reflected/DOM XSS on the query param", 1}
	case has("config", "status", "debug", "actuator", "metrics", "health", "/logs", "/stats"):
		return endpointClass{3, "info", "api_request", "info / secret disclosure", 1}
	case has("fetch", "proxy", "webhook", "integration", "url="):
		return endpointClass{3, "ssrf", "api_request", "server-side request forgery", 2}
	case m == "POST" || m == "PUT" || m == "PATCH" || m == "DELETE":
		return endpointClass{2, "write", "mass_assign", "mass assignment / broken-object-write (read-first; self-scoped)", 2}
	case reIDSeg.MatchString(path) || strings.HasPrefix(lp, "/api/"):
		return endpointClass{1, "idor", "api_request / bola", "object-level authz: read your id, then enumerate others'", 3}
	}
	return endpointClass{0, "", "", "", 0}
}

var tierName = map[int]string{
	1: "T1 crown jewels (IDOR / auth / admin)",
	2: "T2 state-changing / data (writes, uploads, export, search, ingest)",
	3: "T3 info / SSRF",
}

// rankedEndpoint is one tiered endpoint from the prioritized map: what to attack and the tool that
// fits. It is the unit Phase 2 pulls from the DB to drive ONE focused exploit run per endpoint, so
// no single model run ever has to hold the whole surface.
type rankedEndpoint struct {
	Method, Path     string
	Class, Tool, Why string
	Tier             int
	Difficulty       int    // 1 easy .. 3 hard; the exploit phase works easiest-first
	Shape            string // body field names reverse-engineered from the client JS, when known
}

// prioritizedEndpoints classifies the mapped surface and returns the tiered endpoints, crown jewels
// first, deduped by method+path. Untiered paths (plain pages/assets) are counted but dropped — the
// exploit worklist is only the endpoints worth a model's attention.
func prioritizedEndpoints(rows []store.SurfaceRow) (eps []rankedEndpoint, untiered int) {
	seen := map[string]bool{}
	for _, r := range rows {
		key := r.Method + " " + r.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		c := classifyEndpoint(r.Method, r.Path)
		if c.tier == 0 {
			untiered++
			continue
		}
		eps = append(eps, rankedEndpoint{Method: r.Method, Path: r.Path, Class: c.class, Tool: c.tool, Why: c.why, Tier: c.tier, Difficulty: c.difficulty, Shape: shapeHint(r.Last)})
	}
	sort.SliceStable(eps, func(i, j int) bool {
		if eps[i].Tier != eps[j].Tier {
			return eps[i].Tier < eps[j].Tier
		}
		return eps[i].Path < eps[j].Path
	})
	return eps, untiered
}

// htmlRenderPages picks the mapped paths that are HTML pages a browser would render — GET paths that
// are not API routes and not static assets — so a stored-XSS attempt knows where planted data could
// execute. Deduped and capped. Generic: it reads the recon map, not any app-specific list.
func htmlRenderPages(rows []store.SurfaceRow) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		if r.Method != "" && strings.ToUpper(r.Method) != "GET" {
			continue
		}
		p := r.Path
		if p == "" || strings.ContainsAny(p, " ") || strings.HasPrefix(strings.ToLower(p), "/api") || isStaticAsset(p) {
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// shapeHint pulls the reverse-engineered body field list out of a surface row's label (recorded by
// reconAPIShapes as "clientshape fields=a,b,c"); "" when the row is not a client-shape note.
func shapeHint(last string) string {
	const pre = "clientshape fields="
	if strings.HasPrefix(last, pre) {
		return strings.TrimPrefix(last, pre)
	}
	return ""
}

func isStaticAsset(p string) bool {
	lp := strings.ToLower(p)
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".map", ".gif"} {
		if strings.HasSuffix(lp, ext) {
			return true
		}
	}
	return false
}

// prioritizedPlan renders the ranked attack plan (crown jewels first, each tagged with class + tool),
// capped and with a tail count of the lower-value paths. It is the human/console view of the same
// worklist prioritizedEndpoints yields.
func prioritizedPlan(rows []store.SurfaceRow) string {
	eps, untiered := prioritizedEndpoints(rows)
	if len(eps) == 0 {
		return ""
	}
	if len(eps) > 40 {
		eps = eps[:40]
	}
	var b strings.Builder
	b.WriteString("ATTACK PLAN (surface prioritized by value — work top-down, use the tool named; do reads first, GORED's write probes self-scope):\n")
	cur := 0
	for _, e := range eps {
		if e.Tier != cur {
			cur = e.Tier
			fmt.Fprintf(&b, "%s:\n", tierName[cur])
		}
		fmt.Fprintf(&b, "- [%s] %s %s -> %s (%s)\n", e.Class, e.Method, e.Path, e.Tool, e.Why)
	}
	if untiered > 0 {
		fmt.Fprintf(&b, "(+ %d other mapped paths — plain pages/assets, lower value)\n", untiered)
	}
	return b.String()
}
