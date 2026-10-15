package eva

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/t0ul/GORED/internal/appsweep"
	"github.com/t0ul/GORED/internal/bench"
	"github.com/t0ul/GORED/store"
)

// campaign is one overnight blind campaign's live state: a named set of targets run
// autonomously, one stage at a time, one model, surviving a restart via the store. The
// scheduler goroutine walks targets×stages, launching a child run per (target, stage) through
// the same execute path an interactive sortie uses — only the pilot gate is gone (autonomous).
type campaign struct {
	ID      string
	Name    string
	Targets []string // target names, in order
	Model   string
	Status  string // "running" | "done" | "aborted" | "error"
	Started time.Time
	Elapsed string
	RunIDs  []string // child run ids, in launch order
	Cur     string   // the "target · stage" in flight, for live status
	cancel  context.CancelFunc
}

func toCampaign(c *campaign) store.Campaign {
	return store.Campaign{
		ID: c.ID, Name: c.Name, Targets: strings.Join(c.Targets, ","), Model: c.Model,
		Status: c.Status, Started: c.Started, Elapsed: c.Elapsed,
		RunIDs: strings.Join(c.RunIDs, ","), Cur: c.Cur,
	}
}

func fromCampaign(sc store.Campaign) *campaign {
	return &campaign{
		ID: sc.ID, Name: sc.Name, Targets: splitCSV(sc.Targets), Model: sc.Model,
		Status: sc.Status, Started: sc.Started, Elapsed: sc.Elapsed,
		RunIDs: splitCSV(sc.RunIDs), Cur: sc.Cur,
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

// authInstruction builds the skill instruction for a (target, stage): when the target carries a
// login recipe or static-header identities, it prepends an AUTHENTICATION preamble (in the same
// "session" vocabulary the tools and AuthReconSkill use) so the autonomous model logs in and
// wields the two identities, then appends the stage's own instruction. With no auth recipe it
// returns "" — execute then falls back to the stage default, unchanged.
func authInstruction(t store.Target, stageDefault string) string {
	var b strings.Builder
	switch {
	case t.PrivCreds != "" || t.LowCreds != "":
		b.WriteString("AUTHENTICATION — do this FIRST (this target requires a login):\n")
		if t.PrivCreds != "" {
			body, ct := loginBody(t, t.PrivCreds)
			fmt.Fprintf(&b, "- Privileged identity: http_request POST %q with header Content-Type: %s and body %s, carrying \"session\":\"priv\". Keep \"session\":\"priv\" on later calls to act as the privileged user.\n", t.LoginPath, ct, body)
		}
		if t.LowCreds != "" {
			body, ct := loginBody(t, t.LowCreds)
			fmt.Fprintf(&b, "- Low-privilege identity: http_request POST %q with header Content-Type: %s and body %s, carrying \"session\":\"low\". Use \"session\":\"low\" to compare access across identities.\n", t.LoginPath, ct, body)
		}
		b.WriteString("A resource the privileged user can read but the low-privilege user must not is a broken-access-control finding.\n\n")
	case t.PrivHeader != "" || t.LowHeader != "":
		b.WriteString("AUTHENTICATION — two identities are provided as static headers:\n")
		if t.PrivHeader != "" {
			fmt.Fprintf(&b, "- Privileged: send header %q to act as the privileged identity.\n", t.PrivHeader)
		}
		if t.LowHeader != "" {
			fmt.Fprintf(&b, "- Low-privilege: send header %q to act as the low-privilege identity.\n", t.LowHeader)
		}
		b.WriteString("Compare what each identity can reach; access the privileged identity has that the low-privilege one must not is a finding.\n\n")
	default:
		return "" // no auth recipe: use the stage default unchanged
	}
	b.WriteString(stageDefault)
	return b.String()
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
func (s *Server) startCampaign(name, model string, targets []string) *campaign {
	id := strconv.FormatInt(time.Now().UnixNano(), 36)
	c := &campaign{ID: id, Name: name, Model: model, Targets: targets, Status: "running", Started: time.Now()}
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
	for _, tname := range c.Targets {
		tg, ok, _ := s.store.GetTarget(tname)
		if !ok {
			continue
		}
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
			s.execute(rn, rn.flags, stage) // synchronous: runs to terminal, releases the bay
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
	f.BasePort += slot * portStep

	id := strconv.FormatInt(time.Now().UnixNano(), 36)
	f.Trace = filepath.Join(s.traces, "gored-eva-"+id+"-trace.jsonl")
	inst := authInstruction(tg, s.effectiveInstruction(stage))

	rn := &run{
		ID: id, Stage: stage, Base: tg.Base, Model: c.Model, Trials: 1,
		Autonomy: "autonomous", Status: "running", Started: time.Now(),
		Trace: f.Trace, Prompt: inst, slot: slot, campaignID: c.ID, flags: f,
	}
	s.mu.Lock()
	s.runs[id] = rn
	s.order = append([]string{id}, s.order...)
	c.RunIDs = append(c.RunIDs, id)
	c.Cur = tg.Name + " · " + stage
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
