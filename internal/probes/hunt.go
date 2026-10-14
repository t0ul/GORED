package probes

import (
	gored "github.com/t0ul/GORED"
	validate "github.com/t0ul/GORED/internal/validate"
	"github.com/t0ul/GORED/internal/ingest"
	"context"
	"fmt"
	"sort"
	"strings"

	gledger "github.com/t0ul/gledger"
)

// HuntFinding is one broken-access-control candidate a hunt turned up, after the
// verifier has (or has not) reproduced it.
type HuntFinding struct {
	Method           string
	Path             string
	CWE              string // "CWE-862" for broken access control / missing authorization
	Verdict          BACVerdict
	Confidence       gored.Confidence // certain (canary) | high | medium | low (false-positive likelihood)
	ConfidenceReason string
	Verified         bool   // a verifier ran for this finding
	Confirmed        bool   // the model-written repro reproduced the disclosure
	Marker           string // the privileged datum disclosed to the low-priv identity
	Evidence         string
	ReproGo          string // the executed, validated standalone Go repro (when confirmed)
}

// HuntReport is the whole result of one hunt: what surface was mapped, which
// candidates were flagged, and how many reproduced. UNCONFIRMED and UNVERIFIED are
// reported separately from CONFIRMED, never relabeled.
type HuntReport struct {
	Target       string
	SurfaceCount int
	Discovered   []string
	Findings     []HuntFinding
	Confirmed    int
	Unconfirmed  int
	Unverified   int
	TraceID      string
}

// Hunt is the generic end-to-end pipeline: authenticated discovery as one identity,
// a canary-free differential sweep comparing it against a second (low-privilege)
// identity, and a local-model verifier that reproduces each flag. It holds no
// app-specific knowledge — the app is named only by Base, the identities, and the
// login path — so the same hunt runs against any local app.
type Hunt struct {
	Base     string
	Egress   *gored.Egress
	Sessions *gored.Sessions
	Priv     gored.Identity
	Low      gored.Identity
	Anon     *gored.Identity
	Model    gored.ModelClient       // optional; nil leaves findings UNVERIFIED
	Audit    *gledger.AuditLog // optional replayable trace
	Start    string            // discovery start path (default "/")
	Seeder   *gored.CanarySeeder     // optional (6c); when set, plants canaries first so a disclosed marker is a certain finding
	// SeedPaths are extra same-origin paths/URLs to test, from an external crawler
	// (an OWASP ZAP ajax-spider run, a sitemap, a browser). Static discovery misses
	// routes a SPA builds in JS at runtime; feeding a real crawler's URLs here closes
	// that gap without coupling GORED to any one crawler.
	SeedPaths []string
	// SpecPaths are routes from an API spec (OpenAPI/Swagger). For an API-first app the
	// spec is a more complete surface than crawling — collections join the resources,
	// {id} paths join the templates the id-swap step tests.
	SpecPaths []gored.APIPath
}

// Run discovers the surface, flags broken access control differentially, and
// verifies each flag with a local model, returning a report.
func (h *Hunt) Run(ctx context.Context) (HuntReport, error) {
	traceID := gledger.NewTraceID()
	rep := HuntReport{Target: h.Base, TraceID: traceID}
	start := h.Start
	if start == "" {
		start = "/"
	}
	h.emit(traceID, "hunt", "hunt_start", gledger.F{"target": h.Base, "priv": h.Priv.Name, "low": h.Low.Name})

	// 1. Authenticated discovery as the privileged identity (its cookie jar carries a
	// login; a header-only identity crawls whatever surface is reachable).
	disc := NewDiscoverTool(h.Base, h.Egress)
	disc.Sessions = h.Sessions
	out, err := disc.Call(ctx, map[string]any{"path": start, "session": h.Priv.Session})
	if err != nil {
		return rep, fmt.Errorf("hunt discover: %w", err)
	}
	resources := testableResources(out)
	templates := itemTemplates(out)
	// Merge routes a real crawler (e.g. ZAP's ajax spider) found that static crawling
	// missed — the SPA-depth gap.
	seeded := 0
	if len(h.SeedPaths) > 0 {
		resources, seeded = mergeSeedPaths(resources, h.SeedPaths, h.Base)
	}
	if len(h.SpecPaths) > 0 {
		resources, templates = ingest.MergeSpecPaths(resources, templates, h.SpecPaths)
	}
	rep.Discovered, rep.SurfaceCount = resources, len(resources)
	h.emit(traceID, "hunt", "discovered", gledger.F{
		"testable": len(resources), "templates": len(templates), "seeded": seeded, "spec": len(h.SpecPaths), "as": h.Priv.Name,
	})

	// 1b. Optional canary seeding (6c + 7a): plant markers as the privileged identity
	// so a disclosed marker is a certainty. Collection seeds yield item paths
	// (collection/{id}); templated seeds plant at a caller-chosen id. The item paths
	// are then read as the low-priv identity to catch object-level IDOR (7a).
	var markers []string
	itemPaths := map[string]bool{}
	if h.Seeder != nil {
		canaries, err := h.Seeder.Seed(ctx, resources)
		if err != nil {
			return rep, fmt.Errorf("hunt seed: %w", err)
		}
		items, err := h.Seeder.SeedItems(ctx, templates)
		if err != nil {
			return rep, fmt.Errorf("hunt seed items: %w", err)
		}
		for _, c := range append(canaries, items...) {
			if c.Planted {
				markers = append(markers, c.Marker)
				if c.ItemPath != "" {
					itemPaths[c.ItemPath] = true
				}
			}
		}
		h.emit(traceID, "hunt", "seeded", gledger.F{"planted": len(markers), "item_paths": len(itemPaths)})
	}

	// 2. Differential sweep over the testable collections plus the seeded item paths;
	// planted canaries act as a certainty overlay.
	oracle := &DifferentialOracle{
		Base: h.Base, Egress: h.Egress, Sessions: h.Sessions,
		Priv: h.Priv, Low: h.Low, Anon: h.Anon, Markers: markers,
	}
	mps := make([][2]string, 0, len(resources)+len(itemPaths))
	for _, p := range resources {
		mps = append(mps, [2]string{"GET", p})
	}
	for p := range itemPaths {
		mps = append(mps, [2]string{"GET", p})
	}
	findings, err := oracle.Sweep(ctx, mps)
	if err != nil {
		return rep, fmt.Errorf("hunt differential: %w", err)
	}

	// 3. Verify each flag with the local model; a flag counts only if its repro ran.
	for _, f := range findings {
		h.emit(traceID, "differential", "verdict", gledger.F{"path": f.Path, "verdict": string(f.Verdict), "evidence": f.Evidence})
		if !f.Flagged() {
			continue
		}
		cwe := "CWE-862" // missing authorization (collection-level)
		if itemPaths[f.Path] {
			cwe = "CWE-639" // IDOR: an object addressed by id, read by another owner
		}
		hf := HuntFinding{
			Method: f.Method, Path: f.Path, CWE: cwe, Verdict: f.Verdict,
			Confidence: f.Confidence, ConfidenceReason: f.ConfidenceReason,
			Marker: f.Marker, Evidence: f.Evidence,
		}
		if h.Model != nil && f.Marker != "" {
			hf.Verified = true
			v := validate.Verifier{Model: h.Model, Base: h.Base, Marker: f.Marker, Facts: h.facts(f.Path)}
			vr, verr := v.Verify(ctx)
			if verr == nil && vr.Confirmed {
				hf.Confirmed, hf.ReproGo = true, vr.Go
			}
			h.emit(traceID, "verify", "result", gledger.F{"path": f.Path, "confirmed": hf.Confirmed, "attempts": vr.Attempts})
		}
		h.emit(traceID, "hunt", "flag", gledger.F{"path": f.Path, "cwe": hf.CWE, "confidence": string(hf.Confidence), "confirmed": hf.Confirmed})
		rep.Findings = append(rep.Findings, hf)
	}
	for _, hf := range rep.Findings {
		switch {
		case hf.Confirmed:
			rep.Confirmed++
		case hf.Verified:
			rep.Unconfirmed++
		default:
			rep.Unverified++
		}
	}
	h.emit(traceID, "hunt", "hunt_end", gledger.F{
		"flags": len(rep.Findings), "confirmed": rep.Confirmed, "unconfirmed": rep.Unconfirmed, "unverified": rep.Unverified,
	})
	return rep, nil
}

// facts builds the verifier brief for the low-privilege identity: how it
// authenticates (a login or a header) and which resource discloses privileged data.
// The marker is never named here — reproduction, not the model's word, confirms.
func (h *Hunt) facts(path string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target base URL: %s\n", h.Base)
	if h.Low.LoginPath != "" {
		ct := h.Low.LoginContentType
		if ct == "" {
			ct = "application/json"
		}
		fmt.Fprintf(&b, "You are a low-privilege user. Log in with POST %s, Content-Type %s, body: %s.\n", h.Low.LoginPath, ct, h.Low.LoginBody)
		fmt.Fprintf(&b, "Then GET %s — another user's data is disclosed there to your low-privilege account. Write the plan that logs in, then reads it.", path)
	} else {
		var hdr []string
		for k, v := range h.Low.Headers {
			hdr = append(hdr, k+": "+v)
		}
		sort.Strings(hdr)
		fmt.Fprintf(&b, "You are a low-privilege user; send header(s) {%s} on every request.\n", strings.Join(hdr, ", "))
		fmt.Fprintf(&b, "GET %s with that header — another user's data is disclosed there. Write the plan (one GET carrying the header).", path)
	}
	return b.String()
}

func (h *Hunt) emit(traceID, span, event string, f gledger.F) {
	if h.Audit != nil {
		h.Audit.Emit(traceID, span, event, f)
	}
}

// testableResources turns discover output into the paths worth a differential probe:
// same-origin app pages and API data endpoints, minus static assets, auth endpoints,
// and route templates. Keeping the set focused keeps the sweep cheap and the report
// readable; dropped paths would only ever classify as public or blocked anyway.
func testableResources(discoverOut string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(discoverOut, "\n") {
		p := strings.TrimSpace(line)
		if !strings.HasPrefix(p, "/") || seen[p] || !testablePath(p) {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// mergeSeedPaths adds externally-crawled URLs/paths to the testable set: each is
// reduced to a same-origin path, filtered like any discovered resource, and deduped.
// Returns the merged set and how many were newly added.
func mergeSeedPaths(resources, seeds []string, base string) ([]string, int) {
	have := map[string]bool{}
	for _, r := range resources {
		have[r] = true
	}
	out := append([]string{}, resources...)
	added := 0
	for _, s := range seeds {
		s = strings.TrimSpace(s)
		p := samePath(base, s)
		if p == "" && strings.HasPrefix(s, "/") {
			p = cleanPath(s)
		}
		if p == "" || have[p] || !testablePath(p) {
			continue
		}
		have[p] = true
		out = append(out, p)
		added++
	}
	sort.Strings(out)
	return out, added
}

// itemTemplates returns the discovered `{id}`-style item endpoints (the ones
// testableResources drops), which the seeder plants into and the id-swap step reads.
func itemTemplates(discoverOut string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(discoverOut, "\n") {
		p := strings.TrimSpace(line)
		if !strings.HasPrefix(p, "/") || seen[p] {
			continue
		}
		if strings.ContainsAny(p, "{}") && !strings.HasPrefix(p, "/api/auth/") {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func testablePath(p string) bool {
	if strings.ContainsAny(p, "{}") {
		return false // a route template, not a concrete resource
	}
	if strings.HasPrefix(p, "/static/") || strings.HasPrefix(p, "/assets/") {
		return false
	}
	// Auth endpoints are machinery, not resources to compare; logging out mid-sweep
	// would also drop a session.
	for _, skip := range []string{"/api/auth/", "/login", "/register", "/logout", "/signout"} {
		if strings.HasPrefix(p, skip) || p == strings.TrimSuffix(skip, "/") {
			return false
		}
	}
	last := p[strings.LastIndex(p, "/")+1:]
	if strings.Contains(last, ".") {
		return false // a static asset (has a file extension)
	}
	return true
}
