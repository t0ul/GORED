package appsweep

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/tools"
)

// mapConfirmSentinel marks a confirmed unlinked backend surface (the map oracle reads it off
// tool output, never the model's text).
const mapConfirmSentinel = "UNLINKED-SURFACE-CONFIRMED"

// mapStage is the surface-mapping loop (formerly gored-mapsweep): a single-page app links
// nothing in HTML, so recon-by-link misses its real endpoints. The agent mines the JavaScript
// for endpoints, then probes one the index did NOT link. Capture is a probe confirming a
// distinct backend surface (not the SPA catch-all shell a hallucinated path returns).
func mapStage() Stage {
	return Stage{
		Label:      "surface-mapping",
		Goal:       "Map the app's attack surface: find an endpoint the HTML does not link by mining the JavaScript, and confirm it is a real backend surface.",
		Banner:     "vulnapp surface-mapping (JS mining)",
		Title:      "GORED vulnapp surface-mapping",
		TargetName: "vulnapp-in-Brig",
		Flag:       "unlinked-surface",
		Note:       "JS-mining + probe oracle (distinct from the catch-all shell)",
		Skill: core.Skill{
			Name: "surface-mapping", Temp: core.SkillCold,
			Instruction: "You are an authorized recon agent mapping a web app's attack surface. You work in phases. Many modern apps are single-page apps whose HTML links nothing — their real endpoints live in the JavaScript. Use js_endpoints to mine those, then probe_endpoint to confirm an endpoint the page did not link.",
		},
		Detect: surfaceDetector,
		Phases: mapPlaybook,
		BuildTools: func(gate *tools.Gate, base string) *core.Toolbox {
			st := &mapState{base: base, gate: gate}
			return core.NewToolbox(
				mapHTTPTool{gate: gate, base: base},
				mapJSEndpointsTool{gate: gate, base: base, state: st},
				probeEndpointTool{gate: gate, base: base, state: st},
			)
		},
	}
}

// mapState is the per-trial ground truth: the index body and the set of paths it links, so
// "unlinked" is decided against the real index. It is built lazily (once) from the index page
// fetched through the gate, so no setup fetch is needed at wiring time.
type mapState struct {
	base string
	gate *tools.Gate
	once sync.Once
	mu   sync.Mutex

	indexBody string
	linked    map[string]bool
}

func (s *mapState) ensure(ctx context.Context) {
	s.once.Do(func() {
		idx, _ := s.gate.Fetch(ctx, s.base+"/")
		s.mu.Lock()
		s.indexBody = idx
		s.linked = linkedPaths(idx)
		s.mu.Unlock()
	})
}

func (s *mapState) isLinked(p string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.linked[normPath(p)]
}

func (s *mapState) index() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.indexBody
}

// mapHTTPTool (http_request) is the recon primitive: a plain GET through the gate.
type mapHTTPTool struct {
	gate *tools.Gate
	base string
}

func (mapHTTPTool) Name() string { return "http_request" }
func (mapHTTPTool) Describe() string {
	return `HTTP GET a URL on the target and return the response body. ` +
		`args: {"url":"http://127.0.0.1:3000/"} or {"path":"/"}. Use it to read a page or probe a path.`
}
func (t mapHTTPTool) Call(ctx context.Context, args map[string]any) (string, error) {
	u, err := resolveURL(args, t.base)
	if err != nil {
		return "", fmt.Errorf("http_request: %w", err)
	}
	return t.gate.Fetch(ctx, strings.ReplaceAll(u, " ", "%20"))
}

// EgressAuthorities lets the Runner log this stage's allowlist on a denied beacon.
func (t mapHTTPTool) EgressAuthorities() []string { return gateAuthorities(t.gate) }

// mapJSEndpointsTool (js_endpoints) mines a page's JavaScript bundles for endpoint paths and
// marks which the index did NOT link — the discovery. General: no endpoint baked in.
type mapJSEndpointsTool struct {
	gate  *tools.Gate
	base  string
	state *mapState
}

func (mapJSEndpointsTool) Name() string { return "js_endpoints" }
func (mapJSEndpointsTool) Describe() string {
	return `Mine a page's JavaScript bundles for API endpoints it does not link in HTML. ` +
		`args: {"url":"http://127.0.0.1:3000/"} or {"path":"/"} (default "/"). It fetches the page, ` +
		`finds its <script src> bundles, downloads them, and extracts URL paths (for example REST ` +
		`routes). Use this on a single-page app whose HTML links nothing: the real endpoints live in ` +
		`the JavaScript. It marks which endpoints were NOT linked from the page — those are the finds.`
}
func (t mapJSEndpointsTool) Call(ctx context.Context, args map[string]any) (string, error) {
	t.state.ensure(ctx)
	pageURL := t.base + "/"
	if u, err := resolveURL(args, t.base); err == nil {
		pageURL = u
	}
	page, _ := t.gate.Fetch(ctx, pageURL)
	cands := map[string]bool{}
	mineEndpoints(page, cands) // inline literals in the page itself
	for _, src := range scriptSrcs(page) {
		bundleURL := resolveRef(pageURL, src)
		if bundleURL == "" {
			continue
		}
		if body, err := t.gate.Fetch(ctx, bundleURL); err == nil {
			mineEndpoints(body, cands)
		}
	}
	var unlinked, linked []string
	for p := range cands {
		if t.state.isLinked(p) {
			linked = append(linked, p)
		} else {
			unlinked = append(unlinked, p)
		}
	}
	sort.Strings(unlinked)
	sort.Strings(linked)
	if len(unlinked) == 0 && len(linked) == 0 {
		return "[js_endpoints] no endpoint paths found in the page or its scripts.", nil
	}
	return fmt.Sprintf("[js_endpoints] %d endpoints mined from the JavaScript. NOT linked from the page (pick ONE of these and call probe_endpoint with it): %s. Already linked: %s.",
		len(unlinked)+len(linked), joinCap(unlinked, 15), joinCap(linked, 10)), nil
}

// probeEndpointTool (probe_endpoint) confirms a mined endpoint is a real unlinked backend
// surface — a sentinel only when the path is unlinked AND the response is a distinct surface,
// not the SPA catch-all shell a hallucinated path returns.
type probeEndpointTool struct {
	gate  *tools.Gate
	base  string
	state *mapState
}

func (probeEndpointTool) Name() string { return "probe_endpoint" }
func (probeEndpointTool) Describe() string {
	return `GET an endpoint you discovered and confirm it is a real, unlinked backend surface. ` +
		`args: {"path":"/rest/products/search"} or {"url":...}. Use it on an endpoint js_endpoints ` +
		`found that was NOT linked from the page. A confirmation means you found a surface recon-by-link missed.`
}
func (t probeEndpointTool) Call(ctx context.Context, args map[string]any) (string, error) {
	t.state.ensure(ctx)
	u, err := resolveURL(args, t.base)
	if err != nil {
		return "", fmt.Errorf("probe_endpoint: %w", err)
	}
	body, err := t.gate.Fetch(ctx, strings.ReplaceAll(u, " ", "%20"))
	if err != nil {
		return "", err
	}
	p := pathOf(u, t.base)
	class, _ := tools.ClassifySurface(body)
	shellLike := class == "spa-shell" || sameShell(body, t.state.index())
	switch {
	case t.state.isLinked(p):
		return fmt.Sprintf("probe_endpoint: %s is already linked from the index — not an unlinked discovery (surface=%s).", p, class), nil
	case strings.TrimSpace(body) == "":
		return fmt.Sprintf("probe_endpoint: %s returned nothing — not a confirmable surface. Try another endpoint js_endpoints found.", p), nil
	case shellLike:
		return fmt.Sprintf("probe_endpoint: %s returned the app's catch-all shell (surface=%s) — any unknown path returns this, so it is not a real endpoint. Try another endpoint js_endpoints found.", p, class), nil
	default:
		return fmt.Sprintf("probe_endpoint: %s responded with a distinct backend result (surface=%s), unlike the catch-all shell, and was NOT linked from the index — a real surface recon-by-link missed. %s %s", p, class, mapConfirmSentinel, p), nil
	}
}

// --- map-specific helpers ---

var hrefRe = regexp.MustCompile(`(?i)href\s*=\s*["']?(/[^"'>\s]*)`)

func linkedPaths(html string) map[string]bool {
	out := map[string]bool{}
	for _, m := range hrefRe.FindAllStringSubmatch(html, -1) {
		out[normPath(m[1])] = true
	}
	return out
}

// sameShell reports whether body is effectively the app's catch-all shell: identical to the
// index, or another SPA shell of near-identical length.
func sameShell(body, index string) bool {
	b, idx := strings.TrimSpace(body), strings.TrimSpace(index)
	if idx == "" {
		return false
	}
	if b == idx {
		return true
	}
	cb, _ := tools.ClassifySurface(b)
	ci, _ := tools.ClassifySurface(idx)
	if cb == "spa-shell" && ci == "spa-shell" {
		d := len(b) - len(idx)
		if d < 0 {
			d = -d
		}
		return d < 64
	}
	return false
}

func surfaceDetector(out string) (bool, string) {
	if strings.Contains(out, mapConfirmSentinel) {
		return true, "confirmed an unlinked backend surface discovered by JavaScript mining"
	}
	return false, ""
}

func mapPlaybook() []core.Phase {
	return []core.Phase{
		{
			Name:  "recon",
			Brief: "GET \"/\" with http_request and look at what it links. If the page is a near-empty app shell with no links, recon-by-link will miss the real endpoints — move on to mining the JavaScript.",
			Advance: func(b *core.Blackboard, last string) bool {
				return boardHas(b, "[js_endpoints]") || strings.Contains(last, "<") || strings.Contains(last, "{") || len(strings.TrimSpace(last)) > 30
			},
		},
		{
			Name: "map",
			Brief: "Use js_endpoints on \"/\" to mine the app's JavaScript bundles for endpoints the HTML does not link. It returns the endpoints it found and marks which were NOT linked from the page. Then pick ONE not-linked endpoint and call probe_endpoint with it.",
			Advance: func(b *core.Blackboard, last string) bool {
				return boardHas(b, "[js_endpoints]")
			},
		},
		{
			Name:    "probe",
			Brief:   "Confirm a surface recon-by-link missed: call probe_endpoint on one of the endpoints js_endpoints found that was NOT linked from the index. A confirmation means you discovered an unlinked backend surface. If it returns the app shell, it was not a real endpoint — try another one.",
			Advance: nil,
		},
	}
}
