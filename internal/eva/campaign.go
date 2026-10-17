package eva

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/t0ul/GORED/internal/appsweep"
	"github.com/t0ul/GORED/internal/bench"
	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/ingest"
	"github.com/t0ul/GORED/internal/probes"
	"github.com/t0ul/GORED/internal/tools"
	"github.com/t0ul/GORED/store"
)

// campaign is one overnight blind campaign's live state: a named set of targets run
// autonomously, one stage at a time, one model, surviving a restart via the store. The
// scheduler goroutine walks targets×stages, launching a child run per (target, stage) through
// the same execute path an interactive sortie uses — only the pilot gate is gone (autonomous).
type campaign struct {
	ID       string
	Name     string
	Targets  []string // target names, in order
	Model    string
	Status   string // "running" | "done" | "aborted" | "error"
	Started  time.Time
	Elapsed  string
	RunIDs   []string // child run ids, in launch order
	Cur      string   // the "pass · target · stage" in flight, for live status
	Loop     bool     // keep re-running the targets in passes until aborted (non-stop overnight)
	Pass     int      // how many passes the loop has started
	cancel   context.CancelFunc
	nuclei   map[string][]tools.NucleiFinding   // target base -> latest nuclei breadth findings (in-memory)
	ffuf     map[string][]tools.FfufFinding     // target base -> latest ffuf content-discovery hits (in-memory)
	graphql  map[string]ingest.GraphQLSurface   // target base -> introspected GraphQL surface (in-memory)
	scanners map[string][]ingest.ScannerFinding // target base -> ingested SCA (osv) + ZAP findings (in-memory)
}

func toCampaign(c *campaign) store.Campaign {
	return store.Campaign{
		ID: c.ID, Name: c.Name, Targets: strings.Join(c.Targets, ","), Model: c.Model,
		Status: c.Status, Started: c.Started, Elapsed: c.Elapsed,
		RunIDs: strings.Join(c.RunIDs, ","), Cur: c.Cur, Loop: c.Loop, Pass: c.Pass,
	}
}

func fromCampaign(sc store.Campaign) *campaign {
	return &campaign{
		ID: sc.ID, Name: sc.Name, Targets: splitCSV(sc.Targets), Model: sc.Model,
		Status: sc.Status, Started: sc.Started, Elapsed: sc.Elapsed,
		RunIDs: splitCSV(sc.RunIDs), Cur: sc.Cur, Loop: sc.Loop, Pass: sc.Pass,
		nuclei:   map[string][]tools.NucleiFinding{},
		ffuf:     map[string][]tools.FfufFinding{},
		graphql:  map[string]ingest.GraphQLSurface{},
		scanners: map[string][]ingest.ScannerFinding{},
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// persistCampaign writes a snapshot of the campaign (best-effort). Safe to call under s.mu held
// elsewhere only if you do not re-lock — callers here call it without holding s.mu.
func (s *Server) persistCampaign(c *campaign) {
	if s.store == nil {
		return
	}
	s.mu.Lock()
	snap := toCampaign(c)
	s.mu.Unlock()
	_ = s.store.SaveCampaign(snap)
}

// loadCampaigns hydrates the campaign registry from the store on boot; a campaign that was
// in flight when the process died has no scheduler goroutine any more, so it loads as aborted
// (its child runs already loaded as aborted via loadFromStore).
func (s *Server) loadCampaigns() {
	if s.store == nil {
		return
	}
	rows, err := s.store.ListCampaigns()
	if err != nil {
		return
	}
	for _, sc := range rows {
		c := fromCampaign(sc)
		if c.Status == "running" {
			c.Status = "aborted"
			c.Cur = ""
		}
		s.campaigns[c.ID] = c
		s.corder = append(s.corder, c.ID)
	}
}

// defaultTargets is the seed set: the always-on benign demotarget (no auth), and a RiskRancher
// shell (local :8080, cookie login) whose creds the operator fills in. Seeded INSERT-OR-IGNORE,
// so operator edits survive a reseed (mirrors SeedSkills).
func defaultTargets() []store.Target {
	return []store.Target{
		{
			Name: "demotarget", Base: "http://127.0.0.1:8088", Transport: "direct",
			Stages: "apiexploit", Ensure: true,
			Notes: "bundled benign vuln app (planted flags); no auth; auto-launched.",
		},
		{
			Name: "riskrancher", Base: "http://127.0.0.1:8080", Transport: "direct",
			Stages: "apiexploit", Ensure: false,
			LoginPath: "/api/auth/login", LoginType: "json", UserField: "email", PassField: "password",
			Notes: "local RiskRancher on :8080 (run it in a scratch cwd, fresh DB). Fill PrivCreds/LowCreds (email:password) to enable the authenticated surface.",
		},
		{
			Name: "emaildrop", Base: "http://127.0.0.1:4000", Transport: "direct",
			Stages: "apiexploit,llmattack", Ensure: false,
			LoginPath: "/api/auth/login", LoginType: "json", UserField: "email", PassField: "password",
			Notes: "the product (t0ul/emaildrop), first-class target. Gateway :4000. Fill creds + confirm the login recipe; llmattack hits its LLM surface. The whole exercise is for this app.",
		},
		{
			Name: "krabber", Base: "http://127.0.0.1:8090", Transport: "direct",
			Stages: "apiexploit", Ensure: false,
			Notes: "krabber API (/api/v1/molts, bearer-key) — runs on an Amazon Linux VM. Set Base to the VM address and add a PRIV HEADER 'Authorization: Bearer <key>'.",
		},
	}
}

// seedTargets inserts the default targets if absent.
func (s *Server) seedTargets() {
	if s.store == nil {
		return
	}
	for _, t := range defaultTargets() {
		_ = s.store.SeedTarget(t)
	}
}

// campaignInstruction builds the skill instruction for a (target, stage): a KNOWN SURFACE
// preamble (cross-run project memory, so a later pass seeds from what prior passes discovered
// instead of re-enumerating) and/or an AUTHENTICATION preamble (so the autonomous model logs in
// and wields two identities), followed by the stage's own instruction. With neither preamble it
// returns "" — execute then falls back to the stage default, unchanged.
func (s *Server) campaignInstruction(t store.Target, stage string) string {
	base := s.effectiveInstruction(stage)
	var pre []string
	if sp := specPreamble(t); sp != "" {
		pre = append(pre, sp)
	}
	if sp := s.surfacePreamble(t.Name); sp != "" {
		pre = append(pre, sp)
	}
	if ap := authPreamble(t); ap != "" {
		pre = append(pre, ap)
	}
	if len(pre) == 0 {
		return ""
	}
	return strings.Join(pre, "\n\n") + "\n\n" + base
}

// authPreamble is the AUTHENTICATION block for a target (in the same "session" vocabulary the
// tools and AuthReconSkill use), or "" when the target has no auth recipe.
func authPreamble(t store.Target) string {
	var b strings.Builder
	switch {
	case t.PrivCreds != "" || t.LowCreds != "":
		b.WriteString("AUTHENTICATION — you are ALREADY logged in (the harness authenticated for you); do not log in again:\n")
		if t.PrivCreds != "" {
			b.WriteString("- Privileged identity: send \"session\":\"priv\" on your http_request calls to act as the privileged user (its login cookie is already set).\n")
		}
		if t.LowCreds != "" {
			b.WriteString("- Low-privilege identity: send \"session\":\"low\" to act as the low-privilege user.\n")
		}
		b.WriteString("Start by exploring the authenticated surface with \"session\":\"priv\". A resource the privileged user can read but the low-privilege user must not (compare \"session\":\"priv\" vs \"session\":\"low\" on the same path) is a broken-access-control finding.")
	case t.PrivHeader != "" || t.LowHeader != "":
		b.WriteString("AUTHENTICATION — two identities are provided as static headers:\n")
		if t.PrivHeader != "" {
			fmt.Fprintf(&b, "- Privileged: send header %q to act as the privileged identity.\n", t.PrivHeader)
		}
		if t.LowHeader != "" {
			fmt.Fprintf(&b, "- Low-privilege: send header %q to act as the low-privilege identity.\n", t.LowHeader)
		}
		b.WriteString("Compare what each identity can reach; access the privileged identity has that the low-privilege one must not is a finding.")
	default:
		return ""
	}
	return b.String()
}

// specPreamble is the API SPEC block for a target: the routes declared in its OpenAPI/Swagger
// spec (file path or http URL), parsed with core.PathsFromOpenAPI so the model attacks the
// declared surface instead of guessing. "" when the target has no spec or it cannot be read.
func specPreamble(t store.Target) string {
	if t.Spec == "" {
		return ""
	}
	var data []byte
	var err error
	if strings.HasPrefix(t.Spec, "http://") || strings.HasPrefix(t.Spec, "https://") {
		resp, e := http.Get(t.Spec)
		if e != nil {
			return ""
		}
		defer resp.Body.Close()
		data, err = io.ReadAll(resp.Body)
	} else {
		data, err = os.ReadFile(t.Spec)
	}
	if err != nil {
		return ""
	}
	paths, err := core.PathsFromOpenAPI(data)
	if err != nil || len(paths) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("API SPEC (declared routes — attack these, including id-parameter swaps for IDOR/BOLA and privileged fields for mass assignment):\n")
	n := 0
	for _, p := range paths {
		for _, m := range p.Methods {
			fmt.Fprintf(&b, "- %s %s\n", m, p.Path)
			if n++; n >= 50 {
				break
			}
		}
		if n >= 50 {
			break
		}
	}
	b.WriteString("Prefer these declared paths over guessing.")
	return b.String()
}

// surfacePreamble is the KNOWN SURFACE block for a target: the endpoints prior passes discovered,
// so the model starts from them instead of rediscovering. "" when there is no accumulated surface.
func (s *Server) surfacePreamble(target string) string {
	if s.store == nil {
		return ""
	}
	rows, err := s.store.ListSurface(target)
	if err != nil || len(rows) == 0 {
		return ""
	}
	// Prioritize the mapped surface into a ranked attack plan (Phase 2) so the model works the
	// high-value endpoints first with the right tool, instead of poking the flat list at random.
	if plan := prioritizedPlan(rows); plan != "" {
		return "KNOWN SURFACE (discovered in prior passes — start from these, do not re-enumerate).\n" + plan
	}
	// No classifiable endpoints yet (e.g. only plain pages): fall back to the flat list.
	if len(rows) > 40 {
		rows = rows[:40]
	}
	var b strings.Builder
	b.WriteString("KNOWN SURFACE (discovered in prior passes — start from these, do not re-enumerate from scratch):\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "- %s %s\n", r.Method, r.Path)
	}
	b.WriteString("Probe these and obvious variations (id swaps, privileged fields) for broken access control.")
	return b.String()
}

// recordProjectMemory persists a finished child run's discovered surface and findings to the
// target's cross-run project memory, so later passes seed from them. Observations (model chatter)
// are skipped; the surface and the substantive findings are what accumulates.
func (s *Server) recordProjectMemory(target string, rn *run) {
	if s.store == nil {
		return
	}
	_, findings, surface, _, _ := parseRunTrace(rn.Trace)
	for _, n := range surface {
		_ = s.store.SaveSurface(target, rn.Model, rn.ID, n.Method, n.Path, n.Last)
	}
	for _, f := range findings {
		if f.Type == "observation" || f.Value == "" {
			continue
		}
		_ = s.store.SaveFinding(target, rn.Model, rn.ID, string(f.Type), f.Value)
	}
}

// runTargetNuclei runs a contained nuclei breadth scan against the target and caches the findings
// on the campaign (in-memory) for the pentest report. Best-effort: a missing nuclei binary or
// templates yields no findings, so a campaign still runs without it. The scan is single-target,
// gated by the egress allowlist, with nuclei's phone-home off (see NucleiScanTool).
func (s *Server) runTargetNuclei(ctx context.Context, c *campaign, tg store.Target) {
	gate := tools.NewGate(tools.DirectTransport{}, tools.NewEgress(hostPort(tg.Base)), nil)
	fs, err := tools.NucleiScanTool{Gate: gate, Base: tg.Base}.Scan(ctx, tg.Base)
	if err != nil || len(fs) == 0 {
		return
	}
	s.mu.Lock()
	if c.nuclei == nil {
		c.nuclei = map[string][]tools.NucleiFinding{}
	}
	c.nuclei[tg.Base] = fs
	s.mu.Unlock()
}

// addScanners pools ingested scanner findings (SCA, ZAP) for the target, under the lock.
func (s *Server) addScanners(c *campaign, base string, fs []ingest.ScannerFinding) {
	if len(fs) == 0 {
		return
	}
	s.mu.Lock()
	if c.scanners == nil {
		c.scanners = map[string][]ingest.ScannerFinding{}
	}
	c.scanners[base] = append(c.scanners[base], fs...)
	s.mu.Unlock()
}

// runTargetSCA runs source-side software-composition analysis (osv-scanner) over the target's
// SourceDir, folding Node/other-ecosystem dependency vulnerabilities into the pooled scanner
// findings. No-op when the target declares no SourceDir. Best-effort: a missing osv-scanner binary
// or source dir yields nothing, so a campaign still runs without it.
func (s *Server) runTargetSCA(ctx context.Context, c *campaign, tg store.Target) {
	if strings.TrimSpace(tg.SourceDir) == "" {
		return
	}
	fs, err := ingest.OSVScan(ctx, "", tg.SourceDir, tg.Name)
	if err != nil {
		return
	}
	s.addScanners(c, tg.Base, fs)
}

// runTargetZAP ingests a ZAP JSON report declared on the target (an operator runs ZAP out of band),
// folding its alerts into the pooled scanner findings. No-op when the target declares no report.
func (s *Server) runTargetZAP(c *campaign, tg store.Target) {
	if strings.TrimSpace(tg.ZAPReport) == "" {
		return
	}
	data, err := os.ReadFile(tg.ZAPReport)
	if err != nil {
		return
	}
	s.addScanners(c, tg.Base, ingest.ParseZAPReport(data, tg.Name))
}

// runTargetRecon maps the target's surface deterministically before the model loop: it logs in each
// configured identity into a shared jar, then crawls as EACH identity (and anonymously), merging the
// discovered paths into project memory. Role-based access control means different identities are
// shown (and redirected to) different pages, each loading different JS bundles — so only a
// multi-identity crawl enumerates the whole app. The model-loop's KNOWN SURFACE preamble then seeds
// from this accurate map. Best-effort, read-only (GET), egress-gated.
func (s *Server) runTargetRecon(ctx context.Context, c *campaign, tg store.Target) {
	if s.store == nil {
		return
	}
	egress := tools.NewEgress(hostPort(tg.Base))
	sessions := tools.NewSessions()
	// Log in each creds identity into the shared jar (CSRF-aware: GET the login page, extract the
	// token, POST the credentials) so the crawl below sees each identity's authenticated surface.
	login := tools.NewHTTPRequestTool(tg.Base, egress, nil)
	login.Sessions = sessions
	for _, id := range reconIdentities(tg) {
		creds := tg.PrivCreds
		if id == "low" {
			creds = tg.LowCreds
		}
		if id == "" || creds == "" {
			continue // anon needs no login
		}
		user, pass, _ := strings.Cut(creds, ":")
		_, _ = login.Authenticate(ctx, id, tools.LoginSpec{
			Type: tg.LoginType, Path: tg.LoginPath, UserField: tg.UserField, PassField: tg.PassField,
			User: user, Pass: pass,
		})
	}
	discover := probes.NewDiscoverTool(tg.Base, egress)
	discover.Sessions = sessions
	seenAPI := false
	jsPaths := map[string]bool{}
	for _, id := range reconIdentities(tg) {
		out, err := discover.Call(ctx, map[string]any{"path": "/", "session": id})
		if err != nil {
			continue
		}
		label := "recon:anon"
		if id != "" {
			label = "recon:" + id
		}
		for _, p := range discoveredPaths(out) {
			_ = s.store.SaveSurface(tg.Name, "", "", "GET", p, label)
			if strings.HasPrefix(p, "/api") {
				seenAPI = true
			}
			if strings.HasSuffix(strings.ToLower(p), ".js") {
				jsPaths[p] = true
			}
		}
	}
	// Reverse-engineer the API from the app's OWN client code: fetch each discovered script and record
	// the method + request-body shape of every fetch/XHR it makes, so the exploit phase sends a body
	// that matches instead of guessing. Pure recon of the app's JS — no app-specific strings.
	s.reconAPIShapes(ctx, tg, sessions, egress, jsPaths)
	// Active probing (dynamic reverse-engineering): drive the mapped HTML pages in a real browser,
	// submit their forms and fire their htmx/fetch triggers, and record the REAL requests — covers
	// forms/htmx/axios that static JS mining cannot see. It submits, so it is for local throwaway
	// targets; containment still blocks off-target hosts.
	s.reconActiveProbe(ctx, tg, sessions, egress)
	// Ground-truth shapes: if the app serves an OpenAPI/Swagger spec, parse its full schema (typed,
	// required-tagged fields + query/path params for every operation) and fold it in at the highest
	// source precedence — turning the static/active guesses into certainty.
	s.reconOpenAPI(ctx, tg, sessions, egress)
	// Content discovery (ffuf fusion): the crawl only finds LINKED paths, so forced-browse the common
	// unlinked ones (admin, backups, .git, .env, common /api/<word>), authenticated with the priv
	// session cookie so it reaches the signed-in surface too. Fuzz the root and any /api prefix.
	s.reconContentDisc(ctx, c, tg, sessions, egress, seenAPI)
	// Reachability map: with the whole surface now discovered, record what anon/low/priv each get on
	// every GET endpoint, so the exploit phase knows where BAC/IDOR is even possible and which identity
	// reaches it (and the differential oracle gets a baseline). Runs last so it covers ffuf hits too.
	s.reconAuthMap(ctx, tg, sessions, egress)
}

// reconAPIShapes reverse-engineers the API from the app's client JS: it GETs each discovered script
// (as the privileged identity) and records, for every fetch/XHR it finds, the endpoint's method and
// body field names into project memory — so a later write/stored-XSS probe can build a body in the
// shape the endpoint actually wants. Best-effort, read-only, egress-gated.
func (s *Server) reconAPIShapes(ctx context.Context, tg store.Target, sessions *tools.Sessions, egress *tools.Egress, jsPaths map[string]bool) {
	client := sessions.Client("priv") // authed jar; an empty jar just fetches the public scripts
	for jp := range jsPaths {
		raw := strings.TrimRight(tg.Base, "/") + jp
		if !egress.Allowed(raw) {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
		resp.Body.Close()
		for _, sh := range probes.ReverseAPIShapes(string(body)) {
			_ = s.store.SaveContract(tg.Name, sh.Method, sh.Path, "static", shapeToContract(sh))
		}
	}
}

// shapeToContract lifts a reverse-engineered APIShape into an EndpointContract: body field names go
// in as body fields, query keys as query params, each carrying the static parser's inferred type
// when it has one (OpenAPI ingest, a stronger source, overrides any of these on merge).
func shapeToContract(sh probes.APIShape) store.EndpointContract {
	var fs []store.FieldSpec
	for _, f := range sh.Fields {
		fs = append(fs, store.FieldSpec{Name: f, Type: sh.Types[f], In: "body"})
	}
	for _, q := range sh.Query {
		fs = append(fs, store.FieldSpec{Name: q, Type: sh.Types[q], In: "query"})
	}
	return store.EndpointContract{Fields: fs, Headers: sh.Headers}
}

// reconActiveProbe drives the mapped HTML pages in a real browser (as the priv identity), submits
// their forms / fires their htmx+fetch triggers, and records the real request shapes the app sends —
// framework-agnostic reverse-engineering from traffic. Best-effort (no Chrome = no-op); bounded to
// the HTML pages the crawl found. It mutates (it submits), so it is for the local throwaway target.
func (s *Server) reconActiveProbe(ctx context.Context, tg store.Target, sessions *tools.Sessions, egress *tools.Egress) {
	rows, err := s.store.ListSurface(tg.Name)
	if err != nil {
		return
	}
	pages := htmlRenderPages(rows)
	if len(pages) == 0 {
		pages = []string{"/"}
	}
	ap := &probes.ActiveProbe{Base: tg.Base, Egress: egress, Sessions: sessions, Session: "priv"}
	shapes, err := ap.Probe(ctx, pages)
	if err != nil {
		return
	}
	for _, sh := range shapes {
		_ = s.store.SaveContract(tg.Name, sh.Method, sh.Path, "active", shapeToContract(sh))
	}
}

// reconOpenAPI fetches a served OpenAPI/Swagger spec (as the priv identity) and folds its full typed
// schema into the contract at source="openapi" — the highest precedence, so it turns the static/
// active field-name guesses into ground truth (types, required flags, query/path params). Best-effort:
// it tries the common well-known locations, uses the first that returns a parseable JSON spec, and is
// read-only and egress-gated.
func (s *Server) reconOpenAPI(ctx context.Context, tg store.Target, sessions *tools.Sessions, egress *tools.Egress) {
	client := sessions.Client("priv")
	for _, p := range []string{"/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json"} {
		raw := strings.TrimRight(tg.Base, "/") + p
		if !egress.Allowed(raw) {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !looksJSONObject(body) {
			continue
		}
		eps, err := ingest.ContractsFromOpenAPI(body)
		if err != nil {
			continue
		}
		for _, ep := range eps {
			_ = s.store.SaveContract(tg.Name, ep.Method, ep.Path, "openapi", endpointToContract(ep))
		}
		return // the first parseable spec wins
	}
}

// endpointToContract converts a store-agnostic ingest.APIEndpoint into a store.EndpointContract.
func endpointToContract(ep ingest.APIEndpoint) store.EndpointContract {
	fs := make([]store.FieldSpec, 0, len(ep.Fields))
	for _, f := range ep.Fields {
		fs = append(fs, store.FieldSpec{Name: f.Name, Type: f.Type, Required: f.Required, In: f.In})
	}
	return store.EndpointContract{Fields: fs}
}

// looksJSONObject reports whether b begins (after whitespace) with a JSON object, a cheap guard so an
// HTML 404 page is never handed to the spec parser.
func looksJSONObject(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && b[0] == '{'
}

// authMapCap bounds how many GET endpoints the reachability probe touches, so a huge surface cannot
// turn recon into a long scan.
const authMapCap = 40

// reconAuthMap records, per GET endpoint, the status each identity (anon/low/priv) receives — the
// reachability baseline the exploit phase and the differential oracle read. GET only (no mutation),
// bounded, egress-gated. priv/low reuse the jar the recon login filled; anon is cookieless.
func (s *Server) reconAuthMap(ctx context.Context, tg store.Target, sessions *tools.Sessions, egress *tools.Egress) {
	rows, err := s.store.ListSurface(tg.Name)
	if err != nil {
		return
	}
	n := 0
	for _, r := range rows {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.Path, "/") {
			continue
		}
		if n >= authMapCap {
			break
		}
		n++
		auth := map[string]int{}
		for _, id := range []string{"anon", "low", "priv"} {
			if st, ok := s.authProbe(ctx, tg.Base, r.Path, sessions, id, egress); ok {
				auth[id] = st
			}
		}
		if len(auth) > 0 {
			_ = s.store.SaveContract(tg.Name, http.MethodGet, r.Path, "active", store.EndpointContract{Auth: auth})
		}
	}
}

// authProbe GETs path as the named identity and returns its HTTP status (ok=false on egress denial
// or transport error). Redirects are NOT followed, so a 302 to a login page reads as the auth gate
// (302) rather than the 200 of the page it lands on. "anon" is cookieless; low/priv use the login jar.
func (s *Server) authProbe(ctx context.Context, base, path string, sessions *tools.Sessions, id string, egress *tools.Egress) (int, bool) {
	raw := strings.TrimRight(base, "/") + path
	if !egress.Allowed(raw) {
		return 0, false
	}
	var jar http.CookieJar
	if id != "anon" {
		jar = sessions.Client(id).Jar // the priv/low cookies the recon login established
	}
	client := &http.Client{
		Timeout:       8 * time.Second,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	resp.Body.Close()
	return resp.StatusCode, true
}

// reconContentDisc forced-browses the target for unlinked endpoints (ffuf), carrying the priv
// session cookie, and folds the hits into the surface map + the report. Best-effort (missing ffuf
// binary = no-op). It complements the crawl: the crawl finds what is linked, this finds the rest
// that matches a generic wordlist (it will not guess bespoke route names).
func (s *Server) reconContentDisc(ctx context.Context, c *campaign, tg store.Target, sessions *tools.Sessions, egress *tools.Egress, seenAPI bool) {
	var hdrs []string
	if cookie := sessions.CookieHeader("priv", tg.Base); cookie != "" {
		hdrs = []string{"Cookie: " + cookie} // fuzz the authenticated surface
	}
	gate := tools.NewGate(tools.DirectTransport{}, egress, nil)
	targets := []string{tg.Base}
	if seenAPI {
		targets = append(targets, strings.TrimRight(tg.Base, "/")+"/api")
	}
	var hits []tools.FfufFinding
	for _, tgt := range targets {
		fs, err := (tools.FfufScanTool{Gate: gate, Base: tg.Base, Headers: hdrs}).Scan(ctx, tgt)
		if err != nil {
			continue
		}
		for _, f := range fs {
			_ = s.store.SaveSurface(tg.Name, "", "", "GET", urlPath(f.URL), "ffuf")
			hits = append(hits, f)
		}
	}
	if len(hits) == 0 {
		return
	}
	s.mu.Lock()
	if c.ffuf == nil {
		c.ffuf = map[string][]tools.FfufFinding{}
	}
	c.ffuf[tg.Base] = hits
	s.mu.Unlock()
}

// reconIdentities lists the session names to crawl as: anonymous plus each creds-login identity, so
// the recon crawl covers every privilege level's view of the app. Only creds identities are crawled
// authenticated — the crawler reuses a login's cookie jar, so a static-header identity (no login)
// would just crawl anonymously, and is left to the anon pass.
func reconIdentities(tg store.Target) []string {
	ids := []string{""} // always crawl the unauthenticated surface
	if tg.PrivCreds != "" {
		ids = append(ids, "priv")
	}
	if tg.LowCreds != "" {
		ids = append(ids, "low")
	}
	return ids
}

// runTargetGraphQL introspects the target's GraphQL endpoint (if any) and caches the surface on the
// campaign, recording the discovered operations into project memory as POST /graphql surface so later
// passes seed from them. Best-effort: a target with no GraphQL endpoint or introspection disabled
// yields no surface. Single-target, gated by the egress allowlist.
func (s *Server) runTargetGraphQL(ctx context.Context, c *campaign, tg store.Target) {
	gate := tools.NewGate(tools.DirectTransport{}, tools.NewEgress(hostPort(tg.Base)), nil)
	surf, err := (&probes.GraphQLIntrospectProbe{Base: tg.Base, Egress: gate.Egress()}).Introspect(ctx)
	if err != nil || len(surf.Ops) == 0 {
		return
	}
	s.mu.Lock()
	if c.graphql == nil {
		c.graphql = map[string]ingest.GraphQLSurface{}
	}
	c.graphql[tg.Base] = surf
	s.mu.Unlock()
	if s.store != nil {
		for _, o := range surf.Ops {
			_ = s.store.SaveSurface(tg.Name, "", "", "POST", "/graphql "+o.Kind+" "+o.Name, "introspected")
		}
	}
}

// hostPort extracts host:port from a base URL for the egress allowlist (target-only).
func hostPort(base string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	return h
}

// loginBody renders a creds "user:password" into the login request body + content type per the
// target's login recipe (json or form, with the configured field names).
func loginBody(t store.Target, creds string) (body, contentType string) {
	user, pass, _ := strings.Cut(creds, ":")
	uf, pf := t.UserField, t.PassField
	if uf == "" {
		uf = "email"
	}
	if pf == "" {
		pf = "password"
	}
	if t.LoginType == "form" {
		return fmt.Sprintf("%s=%s&%s=%s", uf, user, pf, pass), "application/x-www-form-urlencoded"
	}
	return fmt.Sprintf("{%q:%q,%q:%q}", uf, user, pf, pass), "application/json"
}

// loginPrelude builds the deterministic pre-auth: for each identity the target declares creds for,
// a POST to the login path carrying session:"priv"/"low", run before the model loop so the model
// starts already-authenticated (the session cookie is in the jar). Empty when the target has no
// creds/login path — a header- or no-auth target needs no prelude.
func loginPrelude(t store.Target) []core.PreludeAction {
	if t.LoginPath == "" {
		return nil
	}
	var out []core.PreludeAction
	add := func(creds, session string) {
		if creds == "" {
			return
		}
		user, pass, _ := strings.Cut(creds, ":")
		out = append(out, core.PreludeAction{
			Label: "login as " + session,
			Tool:  "login", // CSRF-aware login dispatched by the Runner's prelude (GET page -> token -> POST)
			Args: map[string]any{
				"login_type": t.LoginType, "login_path": t.LoginPath,
				"user_field": t.UserField, "pass_field": t.PassField,
				"user": user, "pass": pass, "session": session,
			},
		})
	}
	add(t.PrivCreds, "priv")
	add(t.LowCreds, "low")
	return out
}

// targetStages returns the stages to run for a target. A campaign points at a real app's URL,
// which only the DIRECT-transport stages hit (apiexploit, llmattack) — the brig-transport stages
// (recon/map/exploit) run against the sandboxed in-bridge vulnapp, not an arbitrary base URL, so
// they are filtered out. The configured set is filtered to direct stages; empty/none falls back
// to every direct stage the engine has.
func targetStages(t store.Target) []string {
	stages := appsweep.Stages()
	var out []string
	for _, st := range splitCSV(t.Stages) {
		if stg, ok := stages[st]; ok && stg.Transport == "direct" {
			out = append(out, st)
		}
	}
	if len(out) == 0 {
		for name, stg := range stages {
			if stg.Transport == "direct" {
				out = append(out, name)
			}
		}
		sort.Strings(out)
	}
	return out
}

// startCampaign registers a campaign and launches its scheduler goroutine.
func (s *Server) startCampaign(name, model string, targets []string, loop bool) *campaign {
	id := strconv.FormatInt(time.Now().UnixNano(), 36)
	c := &campaign{ID: id, Name: name, Model: model, Targets: targets, Status: "running", Started: time.Now(), Loop: loop, nuclei: map[string][]tools.NucleiFinding{}, ffuf: map[string][]tools.FfufFinding{}, graphql: map[string]ingest.GraphQLSurface{}, scanners: map[string][]ingest.ScannerFinding{}}
	s.mu.Lock()
	s.campaigns[id] = c
	s.corder = append([]string{id}, s.corder...)
	s.mu.Unlock()
	s.persistCampaign(c)
	go s.runCampaign(c)
	return c
}

// runCampaign is the scheduler: walk targets×stages, launching one autonomous child run at a
// time (blocking on the shared concurrency bay, so only one model boots at once), waiting for
// each to land before the next. It survives nothing by itself — durability is the per-run and
// per-campaign store rows; a process death leaves this loop gone and the campaign loads aborted.
func (s *Server) runCampaign(c *campaign) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	c.cancel = cancel
	s.mu.Unlock()
	defer cancel()

	start := time.Now()
	// The outer loop is the non-stop overnight mode: when Loop is set, walk the targets again
	// and again (each pass re-seeds from the accumulated project memory, so later passes build
	// on earlier ones) until aborted; otherwise one pass.
	for {
		s.mu.Lock()
		c.Pass++
		s.mu.Unlock()
		s.persistCampaign(c)
		for _, tname := range c.Targets {
			tg, ok, _ := s.store.GetTarget(tname)
			if !ok {
				continue
			}
			// Map the surface FIRST, deterministically and from every identity, so the model-loop
			// starts with an accurate KNOWN SURFACE (role-based redirects mean each identity sees only
			// its own pages, so a single-identity crawl misses half the app).
			s.runTargetRecon(ctx, c, tg)
			for _, stage := range targetStages(tg) {
				select {
				case <-ctx.Done():
					goto done
				default:
				}
				// The exploit phase is decomposed into one focused model run per prioritized
				// endpoint (pulled from the mapped surface), so no single run carries the whole
				// loop — the reason the full-surface run overflowed the model's context. Other
				// direct stages (e.g. llmattack) are not endpoint-enumeration attacks and run once.
				if endpointPhase(stage) {
					if s.runExploitPhase(ctx, c, tg, stage) {
						goto done
					}
					continue
				}
				// Claim the shared bay (blocking): one model boots at a time, and interactive
				// sorties compete for the same token, so a campaign yields the lab politely.
				var slot int
				select {
				case slot = <-s.slots:
				case <-ctx.Done():
					goto done
				}
				rn := s.launchCampaignRun(c, tg, stage, slot)
				s.execute(rn, rn.flags, stage)     // synchronous: runs to terminal, releases the bay
				s.recordProjectMemory(tg.Name, rn) // accumulate surface + findings for later passes
			}
			// Breadth scan once per target per pass: nuclei covers the web-hygiene / misconfig /
			// exposure / CVE classes the model-loop depth probes do not (headers, host-header,
			// error leak, dir listing). Contained + gated; results feed the pentest report.
			s.runTargetNuclei(ctx, c, tg)
			// (content discovery / ffuf now runs inside runTargetRecon, authenticated + prefix-aware,
			// so its hits also seed the model-loop's KNOWN SURFACE — see reconContentDisc.)
			// Surface ingestion once per target per pass: introspect any GraphQL endpoint and fold
			// the discovered operations into project memory + the report (the REST ingest is blind
			// to GraphQL). Contained + gated; best-effort (no endpoint = no surface).
			s.runTargetGraphQL(ctx, c, tg)
			// Feeders: source-side SCA (osv-scanner over the target's SourceDir) and any ZAP report
			// the target declares, folded into the pooled scanner findings for the report. Both are
			// no-ops unless the target is configured for them.
			s.runTargetSCA(ctx, c, tg)
			s.runTargetZAP(c, tg)
		}
		if !c.Loop {
			break
		}
		// A brief pause between passes: paces the loop (so a fast-failing model does not
		// tight-spin) and gives an abort a clean window; respects cancellation.
		select {
		case <-ctx.Done():
			goto done
		case <-time.After(3 * time.Second):
		}
	}
done:
	s.mu.Lock()
	if c.Status != "aborted" {
		c.Status = "done"
	}
	c.Elapsed = time.Since(start).Round(time.Second).String()
	c.Cur = ""
	s.mu.Unlock()
	s.persistCampaign(c)
}

// launchCampaignRun builds and registers one autonomous child run for a (target, stage) and
// returns it ready to execute. It mirrors the interactive launch, minus the pilot dial.
// exploitEndpointCap bounds how many prioritized endpoints the exploit phase works per pass, so a
// large surface cannot spawn an unbounded number of model runs in one pass (later passes re-walk).
const exploitEndpointCap = 12

// exploitAttemptCap bounds how many times a looping campaign re-works one endpoint that never yields
// a finding, so the loop advances the frontier instead of grinding the same endpoints every pass.
const exploitAttemptCap = 2

// endpointPhase reports whether a stage attacks the mapped surface endpoint-by-endpoint, so the
// scheduler decomposes it into one focused run per endpoint instead of a single whole-surface run.
func endpointPhase(stage string) bool { return stage == "apiexploit" }

// diverseEndpoints round-robins the (tier-sorted) worklist across attack classes and returns up to
// cap endpoints. Without this, a surface with many endpoints of one class (e.g. a dozen /api/admin/*
// routes) would consume the whole cap and starve every other class — so stored-XSS on the single
// ingest endpoint, injection on a search param, etc. would never get a run. Round-robin keeps the
// crown-jewel classes leading each round while guaranteeing every class is reached early. Generic:
// it reasons about classifyEndpoint classes, nothing app-specific.
func diverseEndpoints(eps []rankedEndpoint, cap int) []rankedEndpoint {
	order := []string{}
	byClass := map[string][]rankedEndpoint{}
	classDiff := map[string]int{}
	for _, e := range eps {
		if _, ok := byClass[e.Class]; !ok {
			order = append(order, e.Class)
			classDiff[e.Class] = e.Difficulty
		}
		byClass[e.Class] = append(byClass[e.Class], e)
	}
	// Work EASIEST class first (strong one-shot oracles before id-enumeration/authz), so a weak
	// model banks the wins it can land before the hard IDOR/admin classes (bola) at the bottom.
	sort.SliceStable(order, func(i, j int) bool { return classDiff[order[i]] < classDiff[order[j]] })
	var out []rankedEndpoint
	for round := 0; len(out) < cap; round++ {
		progressed := false
		for _, cl := range order {
			if round < len(byClass[cl]) {
				out = append(out, byClass[cl][round])
				progressed = true
				if len(out) >= cap {
					return out
				}
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

// runExploitPhase is Phase 2 as separate runs: it pulls the prioritized endpoints out of the mapped
// surface (the DB, written by the recon phase) and launches ONE focused model run per endpoint, each
// with a bounded prompt naming just that endpoint. No local model ever has to hold recon+map+exploit
// in one context — the reason the whole-surface run overflowed. Findings persist per model. Returns
// true if the campaign was cancelled mid-phase.
func (s *Server) runExploitPhase(ctx context.Context, c *campaign, tg store.Target, stage string) bool {
	if s.store == nil {
		return false
	}
	rows, err := s.store.ListSurface(tg.Name)
	if err != nil {
		return false
	}
	eps, _ := prioritizedEndpoints(rows)
	// Work the FRONTIER, not the start: skip endpoints already captured, and ones already worked
	// exploitAttemptCap times with nothing, so a looping campaign advances through the surface instead
	// of re-attacking the first endpoints every pass. bola's classes stay out unless opted in.
	kept := eps[:0]
	for _, e := range eps {
		if e.Captured || e.Attempts >= exploitAttemptCap {
			continue
		}
		if !appsweep.BolaEnabled() && (e.Class == "idor" || e.Class == "admin") {
			continue
		}
		kept = append(kept, e)
	}
	eps = kept
	eps = diverseEndpoints(eps, exploitEndpointCap) // spread across classes so one class can't eat the cap
	renderPages := htmlRenderPages(rows)            // where a stored payload could execute (for the ingest/upload class)
	for _, ep := range eps {
		select {
		case <-ctx.Done():
			return true
		default:
		}
		// Claim the shared bay per endpoint run (blocking), same politeness as a whole-stage run.
		var slot int
		select {
		case slot = <-s.slots:
		case <-ctx.Done():
			return true
		}
		rn := s.launchCampaignRunInst(c, tg, stage, slot, exploitInstruction(tg, ep, renderPages))
		s.execute(rn, rn.flags, stage)
		s.recordProjectMemory(tg.Name, rn)
		// Mark the endpoint worked (and captured if a finding landed) so the next pass does not redo it
		// — but ONLY if the run actually executed (made a tool call). A run that died at boot/context
		// with zero tool calls did not attack the endpoint, so it must not burn its attempt budget
		// (else the frontier would skip endpoints that were never really tried).
		events, _, _, _, breached := parseRunTrace(rn.Trace)
		if runMadeToolCall(events) {
			_ = s.store.MarkAttacked(tg.Name, ep.Method, ep.Path, breached)
		}
	}
	return false
}

// runMadeToolCall reports whether a run reached the loop and issued at least one tool call — the
// signal that the endpoint was actually worked (vs a run that failed to boot or died immediately).
func runMadeToolCall(events []traceEvt) bool {
	for _, e := range events {
		if e.Span == "tool" && e.Event == "tool_call" {
			return true
		}
	}
	return false
}

// exploitInstruction builds the FOCUSED prompt for one exploit run: attack a single, already-mapped
// endpoint, no crawling. It stays small on purpose (one endpoint + the auth note + the fitting
// technique), so the model's context never grows to the whole surface.
func exploitInstruction(tg store.Target, ep rankedEndpoint, renderPages []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are an authorized red-team agent. The app at %s is ALREADY MAPPED — do NOT crawl, fingerprint, or hunt for other paths.\n", tg.Base)
	if ap := authPreamble(tg); ap != "" {
		b.WriteString(ap + "\n")
	}
	fmt.Fprintf(&b, "\nAttack EXACTLY this one endpoint:\n  %s %s   [%s — %s]\n\n", ep.Method, ep.Path, ep.Class, ep.Why)
	b.WriteString(exploitHint(ep))
	if blk := contractBlock(ep.Contract); blk != "" {
		// Hand the model the reconned contract directly (field:type, ! = required, plus headers and
		// per-identity reachability), so it builds a schema-valid request instead of guessing a body
		// that 400s — recon ground truth in the prompt, the model still constructs the call.
		b.WriteString("\nThe app's own client calls this endpoint with (field:type, ! = required):" + blk +
			"\nBuild a schema-valid request with EXACTLY these fields and types; send real values, never placeholders.")
	} else if ep.Shape != "" {
		fmt.Fprintf(&b, "\nThe app's own client calls this endpoint with body fields: %s — build your request body with those fields (object or array as the endpoint requires).", ep.Shape)
	}
	b.WriteString("\nFor OTHER mapped endpoints and their contracts, call the recon tool.")
	if (ep.Class == "ingest" || ep.Class == "upload") && len(renderPages) > 0 {
		fmt.Fprintf(&b, "\nRender pages (where stored data is shown — pass these to stored_xss as \"render\"): %s", strings.Join(renderPages, ", "))
	}
	b.WriteString("\nSend real values you obtain, never a placeholder. SELF-CORRECT: if a tool returns an error or an unexpected status, read it, form a hypothesis about why (wrong body shape, missing field, wrong method or render page), and change your NEXT call accordingly — never send the same failing call twice. Confirm any finding on the actual response bytes and report it. If this endpoint is genuinely not vulnerable after you have adapted, say so plainly and stop — do not wander to other paths.")
	return b.String()
}

// exploitHint gives the class-specific technique + tool for the one endpoint, so the model reaches
// for the right primitive instead of re-deriving an approach.
func exploitHint(ep rankedEndpoint) string {
	switch ep.Class {
	case "idor":
		return "This is an object/collection addressed by id. Read your own record, then request OTHER ids (adjacent numbers, and round numbers like 100/1000) with api_request; a record you do not own served without an ownership check is the finding. The bola tool automates the comparison."
	case "admin":
		return "This is an admin / function-level path. With the bola tool (or http_request as session:\"low\" vs session:\"priv\" on the same path), test whether the low-privilege identity can reach it; a low identity receiving privileged data or function is the finding."
	case "auth":
		return "This is an auth endpoint. Try the nosqli tool for operator-injection authentication bypass, or jwt_forge on a token the app issued and replay the escalated token on a protected path. On a login/sign-in path, throttle_probe checks for a missing rate-limit/lockout; on a register/sign-up path, password_policy checks whether a weak password is accepted."
	case "upload", "ingest":
		return "This WRITES/ingests data that is often shown back on an HTML page. Use the stored_xss tool: it plants a nonce payload through this endpoint (field = a text field like title/name/description, plus any other required fields in \"other\") and confirms it EXECUTES when a render page displays it (pass the render pages listed below). Also probe unrestricted upload / path traversal / injection on the parsed input with api_request."
	case "export":
		return "This produces a document/report. Test for document IDOR / path traversal / info leak by varying its id or path parameter with api_request."
	case "search":
		return "This takes a query parameter. Test injection (nosqli) and reflected/DOM XSS (dom_xss, put the marker FUZZ where the value goes) on that parameter."
	case "ssrf":
		return "This fetches a URL / webhook. Test server-side request forgery by pointing it at an off-target host; containment denies the off-target request and it appears in the trace."
	case "write":
		return "This is a write. Use the mass_assign tool to set a privileged field (e.g. role=admin); stay self-scoped. body_limit checks whether the endpoint accepts an unbounded request body (missing size limit)."
	case "info":
		return "This may disclose config / status / secrets. Read it with api_request and report any secret or internal data exposed."
	default:
		return "Use the tool that fits this endpoint's class (api_request / bola / nosqli / jwt_forge / mass_assign / dom_xss)."
	}
}

func (s *Server) launchCampaignRun(c *campaign, tg store.Target, stage string, slot int) *run {
	return s.launchCampaignRunInst(c, tg, stage, slot, s.campaignInstruction(tg, stage))
}

// launchCampaignRunInst is launchCampaignRun with the model instruction supplied by the caller — so
// the exploit phase can hand each run a tiny, FOCUSED prompt (one endpoint pulled from the mapped
// surface) instead of the whole-surface preamble, keeping each run's context bounded.
func (s *Server) launchCampaignRunInst(c *campaign, tg store.Target, stage string, slot int, inst string) *run {
	f := bench.DefaultFlags()
	f.Base = tg.Base
	f.Model = c.Model
	f.Ensure = tg.Ensure
	// A campaign is an autonomous hunt: give each pass a real step/wall budget and tolerate more
	// exploration before the stall-kill (a benchmark's 10 steps / 4-stall is far too short to work
	// a real app). Loop mode then keeps re-running passes, each re-seeding from project memory.
	f.MaxSteps = campaignMaxSteps
	f.Wall = campaignWall
	f.MaxStall = campaignStall
	f.BasePort += slot * portStep
	f.Prelude = loginPrelude(tg) // deterministic pre-auth: log in before the model loop

	id := strconv.FormatInt(time.Now().UnixNano(), 36)
	f.Trace = filepath.Join(s.traces, "gored-eva-"+id+"-trace.jsonl")

	rn := &run{
		ID: id, Stage: stage, Base: tg.Base, Model: c.Model, Trials: 1,
		Autonomy: "autonomous", Status: "running", Started: time.Now(),
		Trace: f.Trace, Prompt: inst, slot: slot, campaignID: c.ID, flags: f,
		targetName: tg.Name,
	}
	s.mu.Lock()
	s.runs[id] = rn
	s.order = append([]string{id}, s.order...)
	c.RunIDs = append(c.RunIDs, id)
	c.Cur = fmt.Sprintf("pass %d · %s · %s", c.Pass, tg.Name, stage)
	s.mu.Unlock()
	s.persist(rn)
	s.persistCampaign(c)
	return rn
}

// abortCampaign stops a running campaign: cancel the scheduler loop and the in-flight child run.
func (s *Server) abortCampaign(id string) {
	s.mu.Lock()
	c := s.campaigns[id]
	var cur *run
	if c != nil && c.Status == "running" {
		c.Status = "aborted"
		c.Cur = ""
		if c.cancel != nil {
			c.cancel()
		}
		if len(c.RunIDs) > 0 {
			cur = s.runs[c.RunIDs[len(c.RunIDs)-1]]
		}
	}
	if cur != nil && (cur.Status == "running" || cur.Status == "waiting") {
		if cur.cancel != nil {
			cur.cancel()
		}
		cur.Status = "aborted"
		cur.Pending = nil
	}
	s.mu.Unlock()
	if c != nil {
		s.persistCampaign(c)
	}
	if cur != nil {
		s.persist(cur)
	}
}
