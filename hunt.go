package gored

import (
	"context"
	"fmt"
	"sort"
	"strings"

	gledger "github.com/t0ul/gledger"
)

// HuntFinding is one broken-access-control candidate a hunt turned up, after the
// verifier has (or has not) reproduced it.
type HuntFinding struct {
	Method    string
	Path      string
	CWE       string // "CWE-862" for broken access control / missing authorization
	Verdict   BACVerdict
	Verified  bool   // a verifier ran for this finding
	Confirmed bool   // the model-written repro reproduced the disclosure
	Marker    string // the privileged datum disclosed to the low-priv identity
	Evidence  string
	ReproGo   string // the executed, validated standalone Go repro (when confirmed)
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
	Egress   *Egress
	Sessions *Sessions
	Priv     Identity
	Low      Identity
	Anon     *Identity
	Model    ModelClient       // optional; nil leaves findings UNVERIFIED
	Audit    *gledger.AuditLog // optional replayable trace
	Start    string            // discovery start path (default "/")
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
	rep.Discovered, rep.SurfaceCount = resources, len(resources)
	h.emit(traceID, "hunt", "discovered", gledger.F{"testable": len(resources), "as": h.Priv.Name})

	// 2. Differential sweep: canary-free broken-access-control discovery.
	oracle := &DifferentialOracle{
		Base: h.Base, Egress: h.Egress, Sessions: h.Sessions,
		Priv: h.Priv, Low: h.Low, Anon: h.Anon,
	}
	mps := make([][2]string, 0, len(resources))
	for _, p := range resources {
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
		hf := HuntFinding{Method: f.Method, Path: f.Path, CWE: "CWE-862", Verdict: f.Verdict, Marker: f.Marker, Evidence: f.Evidence}
		if h.Model != nil && f.Marker != "" {
			hf.Verified = true
			v := Verifier{Model: h.Model, Base: h.Base, Marker: f.Marker, Facts: h.facts(f.Path)}
			vr, verr := v.Verify(ctx)
			if verr == nil && vr.Confirmed {
				hf.Confirmed, hf.ReproGo = true, vr.Go
			}
			h.emit(traceID, "verify", "result", gledger.F{"path": f.Path, "confirmed": hf.Confirmed, "attempts": vr.Attempts})
		}
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
		fmt.Fprintf(&b, "You are a low-privilege user. Log in with POST %s, JSON body %s, Content-Type application/json.\n", h.Low.LoginPath, h.Low.LoginBody)
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
