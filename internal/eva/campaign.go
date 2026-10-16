package eva

import (
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
		_ = s.store.SaveSurface(target, n.Method, n.Path, n.Last)
	}
	for _, f := range findings {
		if f.Type == "observation" || f.Value == "" {
			continue
		}
		_ = s.store.SaveFinding(target, string(f.Type), f.Value, rn.ID)
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
			_ = s.store.SaveSurface(tg.Name, "GET", p, label)
			if strings.HasPrefix(p, "/api") {
				seenAPI = true
			}
		}
	}
	// Content discovery (ffuf fusion): the crawl only finds LINKED paths, so forced-browse the common
	// unlinked ones (admin, backups, .git, .env, common /api/<word>), authenticated with the priv
	// session cookie so it reaches the signed-in surface too. Fuzz the root and any /api prefix.
	s.reconContentDisc(ctx, c, tg, sessions, egress, seenAPI)
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
			_ = s.store.SaveSurface(tg.Name, "GET", urlPath(f.URL), "ffuf")
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
			_ = s.store.SaveSurface(tg.Name, "POST", "/graphql "+o.Kind+" "+o.Name, "introspected")
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
func (s *Server) launchCampaignRun(c *campaign, tg store.Target, stage string, slot int) *run {
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
	inst := s.campaignInstruction(tg, stage)

	rn := &run{
		ID: id, Stage: stage, Base: tg.Base, Model: c.Model, Trials: 1,
		Autonomy: "autonomous", Status: "running", Started: time.Now(),
		Trace: f.Trace, Prompt: inst, slot: slot, campaignID: c.ID, flags: f,
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
