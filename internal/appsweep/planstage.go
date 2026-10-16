package appsweep

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/tools"
)

// planStage is the stack-aware planner loop (formerly gored-plansweep): the agent recons and
// fingerprints the surfaces, calls plan to route a vulnerability class + tool to each (XSS on
// an html-page, never a json-api), then runs the routed tool. Capture is dalfox's VERIFIED
// finding — reusing the canonical sentinel, parser and oracle.
func planStage() Stage {
	return Stage{
		Label:      "stack-aware-planner",
		Goal:       "Recon and fingerprint the surfaces, plan which vulnerability class fits each, then confirm a reflected XSS on the surface the plan routes to it.",
		Banner:     "vulnapp stack-aware planning -> XSS (dalfox)",
		Title:      "GORED vulnapp stack-aware planning",
		TargetName: "vulnapp-in-Brig",
		Flag:       "reflected-xss",
		Note:       "deterministic class routing + dalfox tool-confirmed oracle",
		Skill: core.Skill{
			Name: "stack-aware-planner", Temp: core.SkillCold,
			Instruction: "You are an authorized red-team agent. You work in Phases: recon the app, map its surfaces, call plan to decide which vulnerability class fits each surface, then run the tool the plan routes to that surface. Trust the plan: run the XSS scanner only where the plan routes reflected XSS, never on a JSON API.",
		},
		Detect: tools.DalfoxDetector,
		Phases: planPlaybook,
		BuildTools: func(gate *tools.Gate, base string) *core.Toolbox {
			return core.NewToolbox(
				planHTTPTool{gate: gate, base: base},
				planFingerprintTool{gate: gate, base: base},
				planJSEndpointsTool{gate: gate, base: base},
				planTool{gate: gate, base: base},
				planXSSScanTool{gate: gate, base: base},
			)
		},
	}
}

type planHTTPTool struct {
	gate *tools.Gate
	base string
}

func (planHTTPTool) Name() string { return "http_request" }
func (planHTTPTool) Describe() string {
	return `HTTP GET a URL on the target and return the response body. ` +
		`args: {"url":"http://<target>/"} or {"path":"/"}. Use it to map the app and read each surface.`
}
func (t planHTTPTool) Call(ctx context.Context, args map[string]any) (string, error) {
	u, err := resolveURL(args, t.base)
	if err != nil {
		return "", fmt.Errorf("http_request: %w", err)
	}
	return t.gate.Fetch(ctx, strings.ReplaceAll(u, " ", "%20"))
}

// EgressAuthorities lets the Runner log this stage's allowlist on a denied beacon.
func (t planHTTPTool) EgressAuthorities() []string { return gateAuthorities(t.gate) }

type planFingerprintTool struct {
	gate *tools.Gate
	base string
}

func (planFingerprintTool) Name() string { return "fingerprint" }
func (planFingerprintTool) Describe() string {
	return `Identify a URL's surface type and technology stack. args: {"url":...} or {"path":"/"}. ` +
		`It classifies the surface (html-page, spa-shell, or json-api) from the real response and runs ` +
		`webanalyze for any named technology. Fingerprint the surfaces you found before planning.`
}
func (t planFingerprintTool) Call(ctx context.Context, args map[string]any) (string, error) {
	u, err := resolveURL(args, t.base)
	if err != nil {
		return "", fmt.Errorf("fingerprint: %w", err)
	}
	body, _ := t.gate.Fetch(ctx, strings.ReplaceAll(u, " ", "%20"))
	class, _ := tools.ClassifySurface(body)
	tech := "none detected"
	argv := []string{tools.DefaultWebanalyzeBin, "-host", u, "-apps", tools.DefaultTechDB, "-output", "json", "-silent", "-search=false"}
	if out, derr := t.gate.Detonate(ctx, u, argv); derr == nil {
		if techs := tools.ParseWebanalyze(out); len(techs) > 0 {
			tech = strings.Join(techs, "; ")
		}
	}
	return fmt.Sprintf("[fingerprint] %s: surface=%s. technologies: %s.", u, class, tech), nil
}

type planJSEndpointsTool struct {
	gate *tools.Gate
	base string
}

func (planJSEndpointsTool) Name() string { return "js_endpoints" }
func (planJSEndpointsTool) Describe() string {
	return `Mine a page's JavaScript bundles for endpoints it does not link in HTML (for a single-page app). ` +
		`args: {"path":"/"}. Returns endpoint paths found in the JS. Use it when the page is a near-empty app shell.`
}
func (t planJSEndpointsTool) Call(ctx context.Context, args map[string]any) (string, error) {
	pageURL := t.base + "/"
	if u, err := resolveURL(args, t.base); err == nil {
		pageURL = u
	}
	page, _ := t.gate.Fetch(ctx, pageURL)
	cands := map[string]bool{}
	mineEndpoints(page, cands)
	for _, src := range scriptSrcs(page) {
		if bu := resolveRef(pageURL, src); bu != "" {
			if body, err := t.gate.Fetch(ctx, bu); err == nil {
				mineEndpoints(body, cands)
			}
		}
	}
	var eps []string
	for p := range cands {
		eps = append(eps, p)
	}
	sort.Strings(eps)
	if len(eps) == 0 {
		return "[js_endpoints] no endpoint paths found in the page or its scripts.", nil
	}
	return fmt.Sprintf("[js_endpoints] %d endpoints mined from the JavaScript: %s.", len(eps), joinCap(eps, 20)), nil
}

// planTool (plan) is the deterministic stack-aware router: for each surface it reads the real
// response, classifies it, and routes a vuln class + tool from a fixed class->class table. It
// carries no app-specific knowledge — it decides XSS goes on an html-page, not a json-api.
type planTool struct {
	gate *tools.Gate
	base string
}

func (planTool) Name() string { return "plan" }
func (planTool) Describe() string {
	return `Decide which vulnerability class to test on each surface you found. ` +
		`args: {"surfaces":["/","/<page>","/api/<resource>"]} (paths or URLs). For each, it reads the real ` +
		`response, classifies the surface, and routes the right class and tool: a server-rendered HTML page ` +
		`-> reflected XSS (tool: xss_scan); a JSON API -> authorization/JWT/mass-assignment (NOT XSS); a ` +
		`single-page-app shell -> DOM XSS (needs a browser). Call plan after recon/fingerprint, then run ` +
		`the tool each surface is routed to.`
}
func (t planTool) Call(ctx context.Context, args map[string]any) (string, error) {
	surfaces := toStringList(args["surfaces"])
	if len(surfaces) == 0 {
		if s, _ := args["path"].(string); s != "" {
			surfaces = []string{s}
		} else if s, _ := args["url"].(string); s != "" {
			surfaces = []string{s}
		} else {
			surfaces = []string{"/"}
		}
	}
	var lines []string
	for _, s := range surfaces {
		u, err := resolveURL(map[string]any{"path": s}, t.base)
		if err != nil {
			continue
		}
		body, _ := t.gate.Fetch(ctx, strings.ReplaceAll(u, " ", "%20"))
		class, _ := tools.ClassifySurface(body)
		vulnClass, tool, note := routeClass(class)
		lines = append(lines, fmt.Sprintf("  %s (%s) -> class: %s. tool: %s. (%s)", pathOf(u, t.base), class, vulnClass, tool, note))
	}
	if len(lines) == 0 {
		return "[plan] no surfaces to route — give me the paths you found, e.g. surfaces=[\"/\",\"/api/...\"].", nil
	}
	return "[plan] routing by stack class:\n" + strings.Join(lines, "\n") +
		"\nNext: run the tool each surface is routed to. Use xss_scan ONLY on a surface routed to reflected XSS.", nil
}

// routeClass is the deterministic routing table (stack-aware routing reduced to the surface
// classes we detect). Pure.
func routeClass(class string) (vulnClass, tool, note string) {
	switch class {
	case "html-page":
		return "reflected XSS, SQLi", "xss_scan", "server-rendered HTML that may reflect input — run the XSS scanner here"
	case "spa-shell":
		return "DOM-based XSS (client-side)", "(needs a browser — not wired)", "client-rendered single-page app — an HTTP-only XSS scanner cannot see DOM XSS; test its API instead"
	case "json-api":
		return "broken authorization (BOLA/IDOR), broken auth (JWT), mass-assignment", "(authz/JWT/mass-assign probes)", "a JSON API — do NOT run an XSS scanner here"
	default:
		return "undetermined", "(none)", "re-fetch or map this surface before testing"
	}
}

type planXSSScanTool struct {
	gate *tools.Gate
	base string
}

func (planXSSScanTool) Name() string { return "xss_scan" }
func (planXSSScanTool) Describe() string {
	return `Scan a URL for reflected cross-site scripting with the dalfox scanner. ` +
		`args: {"url":"http://<target>/<path>?name=FUZZ"}. Put FUZZ where a parameter's value goes. ` +
		`XSS applies to a server-rendered HTML page, NOT a JSON API. A confirmed finding means a real XSS.`
}
func (t planXSSScanTool) Call(ctx context.Context, args map[string]any) (string, error) {
	u, err := resolveURL(args, t.base)
	if err != nil {
		return "", fmt.Errorf("xss_scan: %w", err)
	}
	argv := []string{tools.DefaultDalfoxBin, "scan", u, "-f", "json"}
	if strings.Contains(u, "FUZZ") {
		argv = append(argv, "--inject-marker", "FUZZ")
	}
	out, err := t.gate.Detonate(ctx, u, argv)
	if err != nil {
		return "", err
	}
	verified, reflectedOnly, status, finding := tools.ParseDalfox(out)
	switch {
	case verified:
		return fmt.Sprintf("dalfox: VERIFIED XSS on %s (status=%s). %s %s", u, status, finding, tools.XSSConfirmedSentinel), nil
	case reflectedOnly:
		return fmt.Sprintf("dalfox: %q is reflected but NOT a verified XSS (escaped/encoded). Try another reflected parameter on an HTML surface.", finding), nil
	default:
		return fmt.Sprintf("dalfox: no XSS on %s (status=%s). If this was a JSON API, XSS does not apply — scan an HTML surface.", u, status), nil
	}
}

func toStringList(v any) []string {
	var out []string
	switch xs := v.(type) {
	case []any:
		for _, x := range xs {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, xs...)
	case string:
		for _, s := range strings.Split(xs, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func planPlaybook() []core.Phase {
	return []core.Phase{
		{
			Name:  "recon",
			Brief: "GET \"/\" with http_request and note the surfaces it links (HTML pages and JSON APIs).",
			Advance: func(b *core.Blackboard, last string) bool {
				return strings.Contains(last, "<") || strings.Contains(last, "{") || len(strings.TrimSpace(last)) > 30
			},
		},
		{
			Name: "map",
			Brief: "If the page is a near-empty app shell, use js_endpoints to mine the JavaScript for endpoints it does not link. Otherwise note the surfaces from recon and move on.",
			Advance: func(b *core.Blackboard, last string) bool {
				return boardHas(b, "[js_endpoints]") || boardHas(b, "[plan]") || strings.Contains(last, "[fingerprint]")
			},
		},
		{
			Name: "plan",
			Brief: "Call plan with the surfaces you found (an HTML page and a JSON API), e.g. surfaces=[\"/greeting?name=x\",\"/api/greet\"]. It routes a vulnerability class and tool to each. Read which surface is routed to reflected XSS.",
			Advance: func(b *core.Blackboard, last string) bool {
				return boardHas(b, "[plan]")
			},
		},
		{
			Name:    "exploit",
			Brief:   "Follow the plan. Your action this phase MUST be a single xss_scan call aimed at the surface the plan routed to reflected XSS (the html-page), with the literal marker FUZZ in place of the parameter value, e.g. xss_scan {\"url\":\"http://127.0.0.1:8088/greeting?name=FUZZ\"}. Do NOT call http_request, fingerprint, or plan again, and do NOT run xss_scan on a json-api surface. If xss_scan confirms a finding, report it.",
			Advance: nil,
		},
	}
}
