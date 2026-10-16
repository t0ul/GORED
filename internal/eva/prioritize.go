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
	tier  int // 1 = crown jewels, 2 = state-changing/data, 3 = info/ssrf, 0 = untiered (plain page/asset)
	class string
	tool  string
	why   string
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
		return endpointClass{1, "auth", "nosqli / jwt_forge", "authn bypass (operator injection) or forge/replay a token"}
	case has("/admin", "krabmin", "administrator"):
		return endpointClass{1, "admin", "bola", "function-level authz: can the low identity reach it?"}
	case has("upload", "/images/"):
		return endpointClass{2, "upload", "api_request", "unrestricted upload / path traversal / SSRF via parse"}
	case has("ingest", "import", "/parse"):
		return endpointClass{2, "ingest", "api_request", "injection / XXE / deserialization on ingested data"}
	case has("export", "download", "report", ".csv", ".ics", ".pdf", "branded"):
		return endpointClass{2, "export", "api_request", "document IDOR / path traversal / info leak"}
	case has("search", "query", "filter", "?q=", "/q/"):
		return endpointClass{2, "search", "dom_xss / nosqli", "injection + reflected/DOM XSS on the query param"}
	case has("config", "status", "debug", "actuator", "metrics", "health", "/logs", "/stats"):
		return endpointClass{3, "info", "api_request", "info / secret disclosure"}
	case has("fetch", "proxy", "webhook", "integration", "url="):
		return endpointClass{3, "ssrf", "api_request", "server-side request forgery"}
	case m == "POST" || m == "PUT" || m == "PATCH" || m == "DELETE":
		return endpointClass{2, "write", "mass_assign", "mass assignment / broken-object-write (read-first; self-scoped)"}
	case reIDSeg.MatchString(path) || strings.HasPrefix(lp, "/api/"):
		return endpointClass{1, "idor", "api_request / bola", "object-level authz: read your id, then enumerate others'"}
	}
	return endpointClass{0, "", "", ""}
}

var tierName = map[int]string{
	1: "T1 crown jewels (IDOR / auth / admin)",
	2: "T2 state-changing / data (writes, uploads, export, search, ingest)",
	3: "T3 info / SSRF",
}

// prioritizedPlan classifies the mapped surface and renders a ranked attack plan: crown jewels first,
// each endpoint tagged with its class and the tool to use. Untiered paths (plain pages/assets) are
// summarized as a tail so the plan stays focused and bounded.
func prioritizedPlan(rows []store.SurfaceRow) string {
	type item struct {
		c            endpointClass
		method, path string
	}
	var items []item
	seen := map[string]bool{}
	untiered := 0
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
		items = append(items, item{c, r.Method, r.Path})
	}
	if len(items) == 0 {
		return ""
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].c.tier != items[j].c.tier {
			return items[i].c.tier < items[j].c.tier
		}
		return items[i].path < items[j].path
	})
	if len(items) > 40 {
		items = items[:40]
	}
	var b strings.Builder
	b.WriteString("ATTACK PLAN (surface prioritized by value — work top-down, use the tool named; do reads first, GORED's write probes self-scope):\n")
	cur := 0
	for _, it := range items {
		if it.c.tier != cur {
			cur = it.c.tier
			fmt.Fprintf(&b, "%s:\n", tierName[cur])
		}
		fmt.Fprintf(&b, "- [%s] %s %s -> %s (%s)\n", it.c.class, it.method, it.path, it.c.tool, it.c.why)
	}
	if untiered > 0 {
		fmt.Fprintf(&b, "(+ %d other mapped paths — plain pages/assets, lower value)\n", untiered)
	}
	return b.String()
}
