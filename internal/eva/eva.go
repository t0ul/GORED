// Package eva is the GORED web cockpit: the surface you pilot a security-testing run from.
// You pick a stage, a target and a model, set the autonomy dial, launch a run, and watch it
// land — the same appsweep.Run the CLI calls, driven in-process. When the dial is piloted or
// assisted it installs a Checkpoint on the Runner and pauses at each phase boundary so the
// pilot can pick the next moves; autonomous installs none and the run is the headless loop.
// It is a thin frontend over the internal library: it holds no testing logic of its own, only
// run orchestration, the pilot's decision relay, and rendering.
package eva

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/t0ul/GORED/internal/appsweep"
	"github.com/t0ul/GORED/internal/bench"
	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/report"
	"github.com/t0ul/GORED/store"
	gledger "github.com/t0ul/gledger"
)

// assistBeat is how long the assisted dial waits at a checkpoint before proceeding on the
// model's top proposal — "acts on its own from time to time" unless the pilot steps in.
const assistBeat = 15 * time.Second

// run is one launched sweep's live state, kept in memory for this process.
type run struct {
	ID       string
	Stage    string
	Base     string
	Model    string
	Trials   int
	Autonomy string // "piloted" | "assisted" | "autonomous"
	Status   string // "running" | "waiting" | "done" | "error" | "aborted"
	Err      string
	Started  time.Time
	Elapsed  string
	Sums     []core.ContenderSummary
	Trace    string
	Prompt   string // skill-instruction override for this run, empty = stage default

	// Pending is the open checkpoint awaiting the pilot, nil when none. cp relays the
	// pilot's decision back to the blocked Runner goroutine. Both are guarded by the
	// Server mutex.
	Pending *pending
	cp      *pilotCheckpoint
	slot    int // the concurrency bay / port offset this run holds
}

// pending is a checkpoint surfaced to the pilot: the phase about to run, the ranked
// proposals to pick from, and a board snapshot for context.
type pending struct {
	Phase     string
	Proposals []core.Move
	Board     []core.Finding
}

// decision is the pilot's answer, relayed from the HTTP handler to the Runner.
type decision struct {
	chosen  []core.Move
	hint    string
	proceed bool
}

// pilotCheckpoint implements core.Checkpoint. Decide publishes the pending checkpoint to
// the run, then blocks until the pilot submits (piloted) or a short beat elapses
// (assisted). It is installed only for the piloted/assisted dial; autonomous runs carry
// no checkpoint at all, so they stay byte-for-byte the headless loop.
type pilotCheckpoint struct {
	srv      *Server
	run      *run
	autonomy string
	decided  chan decision
}

func (c *pilotCheckpoint) Decide(ctx context.Context, phase string, board *core.Blackboard, proposals []core.Move) ([]core.Move, string, bool) {
	c.srv.mu.Lock()
	c.run.Status = "waiting"
	c.run.Pending = &pending{Phase: phase, Proposals: proposals, Board: board.Findings()}
	c.srv.mu.Unlock()
	c.srv.persist(c.run)

	defer func() {
		c.srv.mu.Lock()
		c.run.Pending = nil
		if c.run.Status == "waiting" {
			c.run.Status = "running"
		}
		c.srv.mu.Unlock()
		c.srv.persist(c.run)
	}()

	if c.autonomy == "assisted" {
		select {
		case d := <-c.decided:
			return d.chosen, d.hint, d.proceed
		case <-time.After(assistBeat):
			var def []core.Move
			if len(proposals) > 0 {
				def = proposals[:1] // the model's top-ranked move
			}
			return def, "", true
		case <-ctx.Done():
			return nil, "", false
		}
	}
	// piloted: block until the pilot decides (or the context is cancelled).
	select {
	case d := <-c.decided:
		return d.chosen, d.hint, d.proceed
	case <-ctx.Done():
		return nil, "", false
	}
}

// Server is the cockpit. It keeps a registry of runs and serializes execution: a run boots a
// local model and reclaims its ports, so two at once would fight — one pilot, one EVA.
// portStep spaces each concurrent run's model serve ports apart so two in-flight runs do
// not fight over a port (each run boots one model; 20 is ample headroom).
const portStep = 20

type Server struct {
	mu     sync.Mutex
	runs   map[string]*run
	order  []string     // run ids, most recent first
	slots  chan int     // one token per concurrency bay; the token is the port offset
	traces string       // directory for per-run trace files
	store  *store.Store // durable run registry; nil = memory-only
}

// NewServer builds the cockpit. maxConc is how many runs may be in flight at once (default
// 1 — one at a time, as the local lab's RAM usually requires); each bay gets its own model
// port window. A non-nil store makes the sortie log durable: existing runs load on boot and
// every transition is persisted. Runs that were mid-flight when the process last died load
// as "aborted" (their decision channel is gone).
func NewServer(traceDir string, st *store.Store, maxConc int) *Server {
	if traceDir == "" {
		traceDir = "."
	}
	if maxConc < 1 {
		maxConc = 1
	}
	slots := make(chan int, maxConc)
	for i := 0; i < maxConc; i++ {
		slots <- i
	}
	s := &Server{runs: map[string]*run{}, traces: traceDir, store: st, slots: slots}
	s.loadFromStore()
	if st != nil {
		_ = st.SeedSkills(core.Catalog()) // first step of the Studio migration: skills as data
	}
	return s
}

// loadFromStore hydrates the in-memory registry from the durable store.
func (s *Server) loadFromStore() {
	if s.store == nil {
		return
	}
	rows, err := s.store.ListEVARuns()
	if err != nil {
		return
	}
	for _, er := range rows {
		rn := fromEVARun(er)
		if rn.Status == "running" || rn.Status == "waiting" {
			rn.Status = "aborted" // the process that owned this run is gone
		}
		s.runs[rn.ID] = rn
		s.order = append(s.order, rn.ID)
	}
}

// persist writes a snapshot of rn to the store (best-effort). Safe to call under s.mu.
func (s *Server) persist(rn *run) {
	if s.store == nil {
		return
	}
	_ = s.store.SaveEVARun(toEVARun(rn))
}

func toEVARun(rn *run) store.EVARun {
	return store.EVARun{
		ID: rn.ID, Stage: rn.Stage, Base: rn.Base, Model: rn.Model, Trials: rn.Trials,
		Autonomy: rn.Autonomy, Status: rn.Status, Err: rn.Err, Started: rn.Started,
		Elapsed: rn.Elapsed, Trace: rn.Trace, Prompt: rn.Prompt, Sums: rn.Sums,
	}
}

func fromEVARun(er store.EVARun) *run {
	return &run{
		ID: er.ID, Stage: er.Stage, Base: er.Base, Model: er.Model, Trials: er.Trials,
		Autonomy: er.Autonomy, Status: er.Status, Err: er.Err, Started: er.Started,
		Elapsed: er.Elapsed, Trace: er.Trace, Prompt: er.Prompt, Sums: er.Sums,
	}
}

// Handler wires the routes (Go 1.22+ pattern mux).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("POST /run", s.launch)
	mux.HandleFunc("GET /run/{id}", s.runPage)
	mux.HandleFunc("GET /run/{id}/events", s.events)
	mux.HandleFunc("POST /run/{id}/decide", s.decide)
	mux.HandleFunc("GET /compare", s.compare)
	mux.HandleFunc("GET /studio", s.studio)
	mux.HandleFunc("GET /run/{id}/trace", s.traceView)
	mux.HandleFunc("GET /run/{id}/leaderboard", s.runLeaderboard)
	mux.HandleFunc("GET /leaderboard", s.leaderboard)
	return mux
}

func (s *Server) home(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	recent := make([]*run, 0, len(s.order))
	for _, id := range s.order {
		recent = append(recent, s.runs[id])
	}
	s.mu.Unlock()
	busy := len(s.slots) == 0 // no free bay

	// Stage cards from the library, so the cockpit always matches the real stages. The
	// instruction map pre-fills the editable prompt knob per stage.
	type stageView struct{ Name, Goal string }
	var sv []stageView
	instr := map[string]string{}
	for name, st := range appsweep.Stages() {
		sv = append(sv, stageView{Name: name, Goal: st.Goal})
		instr[name] = st.Skill.Instruction
	}
	sort.Slice(sv, func(i, j int) bool { return sv[i].Name < sv[j].Name })
	ib, _ := json.Marshal(instr)
	first := ""
	if len(sv) > 0 {
		first = instr[sv[0].Name]
	}

	render(w, homeTmpl, map[string]any{
		"Stages": sv, "Recent": recent, "Busy": busy,
		"StageInstr": template.JS(ib), "FirstInstr": first,
	})
}

func (s *Server) launch(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	stage := r.FormValue("stage")
	if _, ok := appsweep.Stages()[stage]; !ok {
		http.Error(w, "unknown stage "+stage, http.StatusBadRequest)
		return
	}
	autonomy := r.FormValue("autonomy")
	switch autonomy {
	case "piloted", "assisted", "autonomous":
	default:
		autonomy = "piloted"
	}
	f := bench.DefaultFlags()
	if v := r.FormValue("model"); v != "" {
		f.Model = v
	}
	if v := r.FormValue("base"); v != "" {
		f.Base = v
	}
	if v := r.FormValue("bridge"); v != "" {
		f.Bridge = v
	}
	// A piloted or assisted run is one interactive session: force a single trial so the
	// checkpoint fires once per phase, not once per trial.
	f.Trials = 1
	if autonomy == "autonomous" {
		if v, err := strconv.Atoi(r.FormValue("trials")); err == nil && v > 0 {
			f.Trials = v
		}
	}
	if r.FormValue("ensure") == "" {
		f.Ensure = false
	}
	// Prompt knob: a per-run skill-instruction override. Empty, or unchanged from the
	// stage default, means use the stage's own instruction.
	promptOverride := ""
	if v := strings.TrimSpace(r.FormValue("skill")); v != "" && v != strings.TrimSpace(appsweep.Stages()[stage].Skill.Instruction) {
		promptOverride = v
	}

	// Claim a concurrency bay; its token is the port offset for this run's model.
	var slot int
	select {
	case slot = <-s.slots:
	default:
		http.Error(w, "all EVA bays occupied — wait for a sortie to land", http.StatusConflict)
		return
	}
	f.BasePort += slot * portStep

	s.mu.Lock()
	id := strconv.FormatInt(time.Now().UnixNano(), 36)
	f.Trace = filepath.Join(s.traces, "gored-eva-"+id+"-trace.jsonl")
	rn := &run{ID: id, Stage: stage, Base: f.Base, Model: f.Model, Trials: f.Trials,
		Autonomy: autonomy, Status: "running", Started: time.Now(), Trace: f.Trace, Prompt: promptOverride, slot: slot}
	s.runs[id] = rn
	s.order = append([]string{id}, s.order...)
	s.mu.Unlock()

	s.persist(rn)
	go s.execute(rn, f, stage)
	http.Redirect(w, r, "/run/"+id, http.StatusSeeOther)
}

// execute runs the sweep (minutes: model boot + loop) and records the outcome. For a
// piloted/assisted dial it installs a pilot checkpoint; autonomous installs none, so that
// path is identical to the headless loop.
func (s *Server) execute(rn *run, f *bench.Flags, stage string) {
	var opts []appsweep.Option
	if rn.Autonomy != "autonomous" {
		cp := &pilotCheckpoint{srv: s, run: rn, autonomy: rn.Autonomy, decided: make(chan decision)}
		s.mu.Lock()
		rn.cp = cp
		s.mu.Unlock()
		opts = append(opts, appsweep.WithCheckpoint(cp))
	}
	if rn.Prompt != "" {
		opts = append(opts, appsweep.WithSkillInstruction(rn.Prompt))
	}

	results, err := appsweep.Run(context.Background(), f, stage, opts...)

	s.mu.Lock()
	rn.Elapsed = time.Since(rn.Started).Round(time.Second).String()
	rn.Pending = nil
	switch {
	case err != nil:
		rn.Status, rn.Err = "error", err.Error()
	default:
		rn.Sums = core.Summarize(results)
		if aborted(results) {
			rn.Status = "aborted"
		} else {
			rn.Status = "done"
		}
	}
	s.mu.Unlock()
	s.persist(rn)
	s.slots <- rn.slot // release the bay
}

// runView is the run plus render-time triage read from its trace (findings, repro). The
// triage is derived from the trace, never recomputed, so it stays an honest account of what
// the run actually did.
type runView struct {
	*run
	Findings []core.Finding
	Repro    string
}

func (s *Server) runPage(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	rn := s.runs[r.PathValue("id")]
	s.mu.Unlock()
	if rn == nil {
		http.NotFound(w, r)
		return
	}
	v := runView{run: rn}
	if rn.Status == "done" || rn.Status == "aborted" || rn.Status == "error" {
		v.Findings, v.Repro = traceTriage(rn.Trace)
	}
	render(w, runTmpl, v)
}

// compare renders two or more runs side by side (their summaries), for the A/B research.
func (s *Server) compare(w http.ResponseWriter, r *http.Request) {
	ids := r.URL.Query()["id"]
	s.mu.Lock()
	var rns []*run
	for _, id := range ids {
		if rn := s.runs[id]; rn != nil {
			rns = append(rns, rn)
		}
	}
	s.mu.Unlock()
	render(w, compareTmpl, map[string]any{"Runs": rns})
}

// studio is the read-only factory surface: the tools the stages actually carry, the skills
// now held as data in the store, and the per-stage prompts. Authoring is deferred — the
// plan is data-first, no edit button over hardcoded Go. This page is the migration milestone.
func (s *Server) studio(w http.ResponseWriter, _ *http.Request) {
	type stageInfo struct {
		Name, Instruction string
		Tools             []string
	}
	toolSet := map[string]bool{}
	var stages []stageInfo
	for name, st := range appsweep.Stages() {
		var names []string
		if st.BuildTools != nil {
			names = st.BuildTools(nil, "").Names() // nil gate: reading names never dials out
		}
		for _, n := range names {
			toolSet[n] = true
		}
		stages = append(stages, stageInfo{Name: name, Instruction: st.Skill.Instruction, Tools: names})
	}
	sort.Slice(stages, func(i, j int) bool { return stages[i].Name < stages[j].Name })
	var tools []string
	for n := range toolSet {
		tools = append(tools, n)
	}
	sort.Strings(tools)

	var skills []store.SkillRow
	if s.store != nil {
		skills, _ = s.store.ListSkills()
	}

	render(w, studioTmpl, map[string]any{"Tools": tools, "Skills": skills, "Stages": stages})
}

// traceView serves the full, self-contained gledger trace viewer for a run: the replayable
// blackboard + capture playback (hash-chain verified), the research view the live log only
// previews. This is one of the research surfaces the MVP cockpit was missing.
func (s *Server) traceView(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	rn := s.runs[r.PathValue("id")]
	s.mu.Unlock()
	if rn == nil {
		http.NotFound(w, r)
		return
	}
	recs, err := gledger.Read(rn.Trace)
	if err != nil {
		http.Error(w, "trace unavailable: "+err.Error(), http.StatusNotFound)
		return
	}
	ok, _ := gledger.VerifyFile(rn.Trace)
	html, err := gledger.RenderHTML("GORED trace "+rn.ID, recs, ok)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(html)
}

// runLeaderboard serves the full research leaderboard HTML for one run (capture-rate bar,
// cap-per-Mtoken, recall/precision) — the real renderer, not EVA's compact table.
func (s *Server) runLeaderboard(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	rn := s.runs[r.PathValue("id")]
	s.mu.Unlock()
	if rn == nil {
		http.NotFound(w, r)
		return
	}
	meta := report.LeaderboardMeta{Title: "EVA · " + rn.Stage, Target: rn.Base, Trials: rn.Trials, Note: rn.Model + " [" + rn.Autonomy + "]"}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(report.RenderLeaderboardHTML(meta, rn.Sums))
}

// leaderboard serves a combined research leaderboard across selected runs (?id=a&id=b), the
// A/B research view over the real renderer.
func (s *Server) leaderboard(w http.ResponseWriter, r *http.Request) {
	ids := r.URL.Query()["id"]
	s.mu.Lock()
	var sums []core.ContenderSummary
	var target string
	for _, id := range ids {
		if rn := s.runs[id]; rn != nil {
			sums = append(sums, rn.Sums...)
			target = rn.Base
		}
	}
	s.mu.Unlock()
	meta := report.LeaderboardMeta{Title: "EVA · compare", Target: target, Note: "selected sorties"}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(report.RenderLeaderboardHTML(meta, sums))
}

// traceTriage reads a run's trace and returns its blackboard findings and the capture repro
// command. It parses the already-written trace, so it reflects exactly what happened.
func traceTriage(path string) ([]core.Finding, string) {
	recs, err := gledger.Read(path)
	if err != nil {
		return nil, ""
	}
	var findings []core.Finding
	var repro string
	for _, rec := range recs {
		switch {
		case rec.Span == "board" && rec.Event == "finding":
			f := core.Finding{}
			if v, ok := rec.Fields["type"].(string); ok {
				f.Type = core.FindingType(v)
			}
			if v, ok := rec.Fields["value"].(string); ok {
				f.Value = v
			}
			if v, ok := rec.Fields["id"].(float64); ok {
				f.ID = int(v)
			}
			findings = append(findings, f)
		case rec.Span == "verify" && rec.Event == "repro":
			if v, ok := rec.Fields["curl"].(string); ok && v != "" {
				repro = v
			}
		}
	}
	return findings, repro
}

// decide relays the pilot's checkpoint decision to the blocked Runner goroutine.
func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	rn := s.runs[id]
	s.mu.Unlock()
	if rn == nil || rn.cp == nil {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()

	s.mu.Lock()
	var chosen []core.Move
	if rn.Pending != nil {
		for _, idxStr := range r.Form["move"] {
			if i, err := strconv.Atoi(idxStr); err == nil && i >= 0 && i < len(rn.Pending.Proposals) {
				chosen = append(chosen, rn.Pending.Proposals[i])
			}
		}
	}
	s.mu.Unlock()

	d := decision{chosen: chosen, hint: r.FormValue("hint"), proceed: r.FormValue("action") != "abort"}
	// The run may already have moved on (assisted beat); don't block the handler forever.
	select {
	case rn.cp.decided <- d:
	case <-time.After(2 * time.Second):
	}
	http.Redirect(w, r, "/run/"+id, http.StatusSeeOther)
}

// events streams a run's trace as Server-Sent Events: it replays the trace file from the
// start, then tails it, emitting a control frame on each status change and at the end. The
// run page uses this instead of a full-page meta-refresh. Each outbound passes nothing new
// to the model — it only mirrors the already-written trace, so it cannot affect a run.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	rn := s.runs[r.PathValue("id")]
	s.mu.Unlock()
	if rn == nil {
		http.NotFound(w, r)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	send := func(data string) {
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	ctx := r.Context()
	sent, lastStatus := 0, ""
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		lines, total := readTraceLines(rn.Trace)
		for ; sent < total; sent++ {
			send(lines[sent])
		}
		s.mu.Lock()
		st := rn.Status
		s.mu.Unlock()
		if st != lastStatus {
			lastStatus = st
			send(fmt.Sprintf(`{"_eva":"status","status":%q}`, st))
		}
		if st == "done" || st == "error" || st == "aborted" {
			lines, total = readTraceLines(rn.Trace)
			for ; sent < total; sent++ {
				send(lines[sent])
			}
			send(`{"_eva":"done"}`)
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// readTraceLines returns the trace file's complete (newline-terminated) lines and their
// count. A trailing partial line mid-write is excluded, so a reader never sees half a
// record. A missing file yields none — the stream just waits for it to appear.
func readTraceLines(path string) ([]string, int) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil, 0
	}
	nl := strings.LastIndexByte(string(b), '\n')
	if nl < 0 {
		return nil, 0
	}
	raw := strings.Split(string(b[:nl]), "\n")
	out := raw[:0]
	for _, ln := range raw {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out, len(out)
}

func render(w http.ResponseWriter, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func captured(sums []core.ContenderSummary) bool {
	for _, c := range sums {
		if c.Captured > 0 {
			return true
		}
	}
	return false
}

// aborted reports whether every trial ended because the pilot aborted at a checkpoint.
func aborted(results []core.SweepResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, r := range results {
		if r.Outcome != "aborted" {
			return false
		}
	}
	return true
}

var funcs = template.FuncMap{
	"pct":      func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) },
	"captured": captured,
	"trunc": func(s string, n int) string {
		s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
		if len(s) > n {
			return s[:n] + "…"
		}
		return s
	},
}

var homeTmpl = template.Must(template.New("home").Funcs(funcs).Parse(baseCSS + nervHead + `
<form method="post" action="/run" class="card frame">
  <div class="card-tag">LAUNCH SEQUENCE</div>
  <label>STAGE
    <select name="stage">{{range .Stages}}<option value="{{.Name}}">{{.Name}} — {{.Goal}}</option>{{end}}</select>
  </label>
  <label>TARGET BASE URL <input name="base" value="http://127.0.0.1:8088"></label>
  <label>MODEL (GGUF) <input name="model" value="qwen2.5-3b-instruct.gguf"></label>
  <label>BRIG BRIDGE <input name="bridge" value="127.0.0.1:5050"></label>
  <label>SYNC PROMPT · SKILL INSTRUCTION <textarea name="skill" id="skill" rows="4">{{.FirstInstr}}</textarea></label>
  <fieldset class="dial">
    <legend>AUTONOMY DIAL</legend>
    <label class="radio"><input type="radio" name="autonomy" value="piloted" checked> <b>PILOTED</b><span>pause at every gate — you pick the moves</span></label>
    <label class="radio"><input type="radio" name="autonomy" value="assisted"> <b>ASSISTED</b><span>acts on its own after a beat unless you intervene</span></label>
    <label class="radio"><input type="radio" name="autonomy" value="autonomous"> <b>BERSERK</b><span>no gate — runs free, the headless/CI loop</span></label>
  </fieldset>
  <label>TRIALS (BERSERK ONLY) <input name="trials" type="number" value="1" min="1"></label>
  <label class="chk"><input type="checkbox" name="ensure" value="1" checked> auto-launch vulnapp</label>
  <button {{if .Busy}}disabled{{end}}>{{if .Busy}}⬡ EVA IN FLIGHT…{{else}}⬡ LAUNCH{{end}}</button>
</form>
<h2>⬡ SORTIE LOG</h2>
{{if .Recent}}
<form method="get" action="/compare">
<ul class="runs">{{range .Recent}}
  <li><input type="checkbox" name="id" value="{{.ID}}" class="pick"> <a href="/run/{{.ID}}">{{.Stage}} <span class="vs">vs</span> {{.Base}}</a> <span class="dim">[{{.Autonomy}}]</span> <span class="badge {{.Status}}">{{.Status}}</span></li>
{{end}}</ul>
<button class="ghost">⬡ COMPARE SELECTED</button>
</form>
{{else}}<p class="muted">no sorties yet</p>{{end}}
<script>
(function(){
  var INSTR = {{.StageInstr}};
  var sel = document.querySelector('select[name=stage]');
  var ta = document.getElementById('skill');
  if (sel && ta) sel.addEventListener('change', function(){ if (INSTR[sel.value] !== undefined) ta.value = INSTR[sel.value]; });
})();
</script>
` + nervFoot))

var runTmpl = template.Must(template.New("run").Funcs(funcs).Parse(baseCSS + `
{{if or (eq .Status "running") (eq .Status "waiting")}}<noscript><meta http-equiv="refresh" content="3"></noscript>{{end}}
` + nervHeadMini + `
<p><a href="/">← cockpit</a></p>
<h1 class="runhdr">{{.Stage}} <span class="badge {{.Status}}">{{.Status}}</span></h1>
<p class="sub">vs {{.Base}} · model {{.Model}} · dial <b class="dim">{{.Autonomy}}</b> · {{.Trials}} trial(s){{if .Prompt}} · <span class="dim">custom prompt</span>{{end}}{{if .Elapsed}} · {{.Elapsed}}{{end}}</p>
{{if eq .Status "running"}}<p class="muted scan">⬡ booting the model and running the loop… live telemetry below.</p>{{end}}

{{if .Pending}}
<div class="card frame alert">
  <div class="card-tag warn">⚠ PILOT DECISION REQUIRED — PHASE: {{.Pending.Phase}}</div>
  <p class="muted">The EVA has reached a phase boundary. Select the moves to spend tokens on, add a constraint, and proceed. The oracle still confirms every finding on the target's real bytes — you choose the move, not the verdict.</p>
  <form method="post" action="/run/{{.ID}}/decide">
    <div class="moves">
    {{range $i, $m := .Pending.Proposals}}
      <label class="move">
        <input type="checkbox" name="move" value="{{$i}}">
        <span class="mv-tool">{{$m.Tool}}</span>
        <span class="mv-path">{{if $m.Path}}{{$m.Path}}{{else}}—{{end}}</span>
        <span class="mv-surface s-{{$m.Surface}}">{{$m.Surface}}</span>
        <span class="mv-src src-{{$m.Source}}">{{$m.Source}}</span>
        <span class="mv-why">{{$m.Why}}</span>
      </label>
    {{else}}
      <p class="muted">no proposals — type a directive below and proceed.</p>
    {{end}}
    </div>
    <label>CONSTRAINT / HINT <input name="hint" placeholder="e.g. focus /greeting, try the reflected name param"></label>
    <div class="btnrow">
      <button name="action" value="proceed">⬡ PROCEED</button>
      <button name="action" value="abort" class="danger">■ ABORT</button>
    </div>
  </form>
  {{if .Pending.Board}}
  <details class="board"><summary>BLACKBOARD ({{len .Pending.Board}} findings)</summary>
    <ul>{{range .Pending.Board}}<li><span class="ft">{{.Type}}</span> {{trunc .Value 160}}</li>{{end}}</ul>
  </details>
  {{end}}
</div>
{{end}}

{{if .Err}}<pre class="err">{{.Err}}</pre>{{end}}
{{if .Sums}}
  {{if captured .Sums}}
  <div class="verdict-bar hit">● PATTERN ORANGE — TARGET CAPTURED (ORACLE-CONFIRMED)</div>
  {{else}}
  <div class="verdict-bar miss">○ NO CAPTURE — TARGET HELD</div>
  {{end}}
  <table><thead><tr><th>contender</th><th>cap%</th><th>captured</th><th>tools</th><th>tokens</th></tr></thead><tbody>
  {{range .Sums}}<tr><td>{{.Contender}}</td><td>{{pct .CaptureRate}}</td><td>{{.Captured}}/{{.Trials}}</td><td>{{printf "%.1f" .MeanToolCall}}</td><td>{{printf "%.0f" .MeanTokens}}</td></tr>{{end}}
  </tbody></table>
{{end}}
{{if .Repro}}<div class="card frame"><div class="card-tag">REPRO — THE CAPTURING REQUEST</div><pre class="repro">{{.Repro}}</pre></div>{{end}}
{{if .Findings}}
<details class="board" open><summary>FINDINGS ({{len .Findings}})</summary>
  <ul>{{range .Findings}}<li><span class="ft">{{.Type}}</span> {{trunc .Value 200}}</li>{{end}}</ul>
</details>
{{end}}
{{if ne .Status "running"}}<p class="nav"><a href="/run/{{.ID}}/trace">⬡ FULL TRACE VIEWER</a>{{if .Sums}} · <a href="/run/{{.ID}}/leaderboard">⬡ LEADERBOARD</a>{{end}}</p>{{end}}
{{if or (eq .Status "running") (eq .Status "waiting")}}
<div class="card frame"><div class="card-tag">LIVE TELEMETRY</div><div id="log" class="log"></div></div>
<script>
(function(){
  var PAGE_STATUS = "{{.Status}}";
  var log = document.getElementById('log');
  function line(txt, cls){ var d=document.createElement('div'); d.className='logln '+(cls||''); d.textContent=txt; log.appendChild(d); log.scrollTop=log.scrollHeight; }
  var es = new EventSource('/run/{{.ID}}/events');
  es.onmessage = function(e){
    var r; try{ r=JSON.parse(e.data); }catch(_){ return; }
    if (r._eva === 'status'){ if (r.status !== PAGE_STATUS){ es.close(); location.reload(); } return; }
    if (r._eva === 'done'){ es.close(); location.reload(); return; }
    var span=r.span||'', ev=r.event||'', f=r.fields||{};
    var detail = f.tool||f.via||f.phase||f.hint||f.value||f.result||f.error||f.reply||'';
    if (typeof detail !== 'string') detail = JSON.stringify(detail);
    if (detail.length > 140) detail = detail.slice(0,140)+'…';
    var cls = ev.indexOf('capture')>=0 ? 'hit' : ((ev.indexOf('error')>=0||ev.indexOf('denied')>=0||ev.indexOf('breach')>=0) ? 'warn' : '');
    line('[' + span + '] ' + ev + (detail ? '  ' + detail : ''), cls);
  };
})();
</script>
{{end}}
<p class="muted">trace: {{.Trace}}</p>
` + nervFoot))

var studioTmpl = template.Must(template.New("studio").Funcs(funcs).Parse(baseCSS + nervHeadMini + `
<p><a href="/">← cockpit</a></p>
<h1 class="runhdr">STUDIO</h1>
<p class="sub">the factory · tools · skills · prompts <span class="dim">(read-only — authoring lands once the registry drives the stages)</span></p>

<h2>⬡ TOOLS</h2>
<div class="chips">{{range .Tools}}<span class="chip">{{.}}</span>{{else}}<span class="muted">none</span>{{end}}</div>

<h2>⬡ SKILLS</h2>
{{if .Skills}}{{range .Skills}}
<div class="card frame skillcard">
  <div class="card-tag">{{.Name}} <span class="temp temp-{{.Temp}}">{{.Temp}}</span> {{if .BuiltIn}}<span class="src-router">built-in</span>{{else}}<span class="src-model">authored</span>{{end}}</div>
  <pre class="repro">{{.Instruction}}</pre>
</div>
{{end}}{{else}}<p class="muted">no skills registry (run with a -store to seed the catalog)</p>{{end}}

<h2>⬡ PROMPTS · PER STAGE</h2>
{{range .Stages}}
<div class="card frame skillcard">
  <div class="card-tag">{{.Name}} <span class="dim">tools: {{range .Tools}}{{.}} {{end}}</span></div>
  <pre class="repro">{{.Instruction}}</pre>
</div>
{{end}}
` + nervFoot))

var compareTmpl = template.Must(template.New("compare").Funcs(funcs).Parse(baseCSS + nervHeadMini + `
<p><a href="/">← cockpit</a></p>
<h1 class="runhdr">COMPARE</h1>
{{if .Runs}}
<p class="nav"><a href="/leaderboard?{{range .Runs}}id={{.ID}}&amp;{{end}}">⬡ OPEN AS RESEARCH LEADERBOARD</a></p>
<table><thead><tr><th>run</th><th>stage</th><th>model</th><th>dial</th><th>status</th><th>cap%</th><th>captured</th><th>tools</th><th>tokens</th></tr></thead><tbody>
{{range .Runs}}{{if .Sums}}{{$c := index .Sums 0}}<tr>
  <td><a href="/run/{{.ID}}">{{.ID}}</a></td><td>{{.Stage}}</td><td>{{.Model}}</td><td class="dim">{{.Autonomy}}</td><td><span class="badge {{.Status}}">{{.Status}}</span></td>
  <td>{{pct $c.CaptureRate}}</td><td>{{$c.Captured}}/{{$c.Trials}}</td><td>{{printf "%.1f" $c.MeanToolCall}}</td><td>{{printf "%.0f" $c.MeanTokens}}</td>
</tr>{{else}}<tr>
  <td><a href="/run/{{.ID}}">{{.ID}}</a></td><td>{{.Stage}}</td><td>{{.Model}}</td><td class="dim">{{.Autonomy}}</td><td><span class="badge {{.Status}}">{{.Status}}</span></td>
  <td colspan="4" class="muted">no summary</td>
</tr>{{end}}{{end}}
</tbody></table>
{{else}}<p class="muted">select two or more runs from the cockpit to compare.</p>{{end}}
` + nervFoot))

// nervHead / nervHeadMini / nervFoot are the shared NERV chrome.
const nervHead = `<div class="hdr">
  <div class="logo">⬡</div>
  <div><h1>EVA</h1><p class="sub">GORED // NERV TACTICAL OPS · PILOT A SECURITY-TESTING RUN AGAINST A LOCAL APP</p></div>
</div><div class="stripe"></div>
<p class="nav"><a href="/">⬡ COCKPIT</a> · <a href="/studio">⬡ STUDIO</a></p>`

const nervHeadMini = `<div class="hdr mini"><div class="logo">⬡</div><div><span class="brand">EVA</span> <span class="sub">GORED // NERV</span></div></div><div class="stripe"></div>`

const nervFoot = `<div class="stripe bottom"></div><p class="foot">⬡ GORED EVANGELION UNIT · ORACLE ON REAL BYTES · EGRESS CONTAINED</p>`

const baseCSS = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>EVA · GORED</title>
<style>
:root{
  --bg:#07080a; --bg2:#0c0e12; --panel:#101319; --panel2:#151a22; --line:#242b36;
  --orange:#ff6a00; --amber:#ffab00; --green:#86d633; --red:#ff2a2a;
  --fg:#d6dee6; --mut:#6f7b8a; --acc:#ff6a00;
}
*{box-sizing:border-box}
body{
  background:
    repeating-linear-gradient(0deg, rgba(255,255,255,.015) 0 1px, transparent 1px 3px),
    radial-gradient(1200px 600px at 70% -10%, rgba(255,106,0,.08), transparent 60%),
    var(--bg);
  color:var(--fg); font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  max-width:860px; margin:0 auto; padding:24px 16px 48px; letter-spacing:.2px;
}
a{color:var(--amber);text-decoration:none}a:hover{text-decoration:underline}
h1,h2{letter-spacing:3px;text-transform:uppercase;margin:.3rem 0}
h2{font-size:14px;color:var(--orange);border-left:3px solid var(--orange);padding-left:8px;margin-top:28px}
.sub{color:var(--mut);margin-top:0;font-size:12px;letter-spacing:1px;text-transform:uppercase}
.muted{color:var(--mut)} .dim{color:var(--amber);font-size:12px;letter-spacing:1px}
.vs{color:var(--mut);font-style:normal}
/* header */
.hdr{display:flex;align-items:center;gap:16px}
.hdr.mini{gap:10px}.hdr.mini .brand{color:var(--orange);font-weight:700;letter-spacing:3px}
.logo{font-size:40px;color:var(--orange);line-height:1;text-shadow:0 0 16px rgba(255,106,0,.6)}
.hdr.mini .logo{font-size:22px}
.hdr h1{font-size:34px;color:var(--orange);text-shadow:0 0 18px rgba(255,106,0,.45);margin:0}
.stripe{height:10px;margin:12px 0 20px;
  background:repeating-linear-gradient(45deg,var(--orange) 0 14px,#111 14px 28px);
  opacity:.8;border-top:1px solid #000;border-bottom:1px solid #000}
.stripe.bottom{margin:28px 0 10px;opacity:.5}
.foot{color:var(--mut);font-size:11px;letter-spacing:1px;text-align:center;text-transform:uppercase}
/* frame card with NERV corner brackets */
.card{background:linear-gradient(var(--panel),var(--bg2));border:1px solid var(--line);padding:18px;display:grid;gap:12px;position:relative}
.frame{box-shadow:inset 0 0 0 1px rgba(255,106,0,.06)}
.frame::before,.frame::after{content:"";position:absolute;width:16px;height:16px;border:2px solid var(--orange)}
.frame::before{top:-1px;left:-1px;border-right:0;border-bottom:0}
.frame::after{bottom:-1px;right:-1px;border-left:0;border-top:0}
.card-tag{font-size:11px;letter-spacing:3px;color:var(--orange);text-transform:uppercase}
.card-tag.warn{color:var(--amber)}
.alert{border-color:var(--amber);box-shadow:inset 0 0 0 1px rgba(255,171,0,.18),0 0 24px rgba(255,171,0,.08);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:inset 0 0 0 1px rgba(255,171,0,.18),0 0 10px rgba(255,171,0,.05)}50%{box-shadow:inset 0 0 0 1px rgba(255,171,0,.35),0 0 30px rgba(255,171,0,.16)}}
/* form */
label{display:grid;gap:5px;font-size:11px;color:var(--mut);letter-spacing:1.5px;text-transform:uppercase}
label.chk{grid-auto-flow:column;justify-content:start;align-items:center;gap:9px;text-transform:none;letter-spacing:.5px}
input,select,textarea{background:#05060a;color:var(--fg);border:1px solid var(--line);border-radius:0;padding:9px 10px;font:inherit;width:100%}
textarea{resize:vertical;line-height:1.4}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--orange);box-shadow:0 0 0 1px var(--orange)}
button{background:var(--orange);color:#0a0a0a;border:0;border-radius:0;padding:11px 16px;font:inherit;font-weight:700;letter-spacing:2px;text-transform:uppercase;cursor:pointer}
button:hover{background:var(--amber)}button:disabled{opacity:.45;cursor:not-allowed}
button.danger{background:transparent;color:var(--red);border:1px solid var(--red)}
button.danger:hover{background:var(--red);color:#0a0a0a}
.btnrow{display:flex;gap:12px;margin-top:4px}
/* autonomy dial */
.dial{border:1px solid var(--line);padding:12px;display:grid;gap:8px}
.dial legend{color:var(--orange);font-size:11px;letter-spacing:3px;padding:0 6px}
.radio{display:grid;grid-template-columns:auto auto 1fr;align-items:center;gap:10px;text-transform:none;letter-spacing:.3px;color:var(--fg);font-size:13px}
.radio b{color:var(--amber);letter-spacing:2px}
.radio span{color:var(--mut);font-size:12px}
/* runs list */
.runs{list-style:none;padding:0}.runs li{padding:9px 0;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.runs a{color:var(--fg)}
/* badges */
.badge{font-size:11px;padding:2px 9px;border:1px solid var(--line);letter-spacing:2px;text-transform:uppercase}
.badge.running{color:var(--green);border-color:var(--green)}
.badge.waiting{color:var(--amber);border-color:var(--amber);animation:pulse 1.6s infinite}
.badge.done{color:var(--green);border-color:var(--green)}
.badge.aborted{color:var(--mut)}
.badge.error{color:var(--red);border-color:var(--red)}
.scan{position:relative}
/* moves */
.moves{display:grid;gap:6px}
.move{display:grid;grid-template-columns:auto 90px 1fr 90px 60px;gap:10px;align-items:center;padding:8px 10px;border:1px solid var(--line);background:#05060a;text-transform:none;letter-spacing:.3px;cursor:pointer;font-size:12px}
.move:hover{border-color:var(--orange)}
.mv-tool{color:var(--orange);font-weight:700}
.mv-path{color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mv-surface{font-size:10px;letter-spacing:1px;text-align:center;padding:2px 4px;border:1px solid var(--line);color:var(--mut)}
.s-html-page{color:var(--amber);border-color:var(--amber)}
.s-json-api{color:#58a6ff;border-color:#58a6ff}
.s-spa-shell{color:#c586ff;border-color:#c586ff}
.mv-src{font-size:10px;letter-spacing:1px;text-align:center;color:var(--mut)}
.src-model{color:var(--green)}.src-router{color:var(--mut)}
.mv-why{grid-column:2/-1;color:var(--mut);font-size:11px}
/* board */
.board{margin-top:6px;font-size:12px}
.board summary{cursor:pointer;color:var(--amber);letter-spacing:1px}
.board ul{list-style:none;padding:8px 0 0;display:grid;gap:4px}
.board .ft{color:var(--orange);font-size:10px;letter-spacing:1px;text-transform:uppercase}
/* verdict */
.verdict-bar{margin:18px 0;padding:14px 16px;font-weight:700;letter-spacing:3px;text-transform:uppercase;border:1px solid}
.verdict-bar.hit{color:var(--orange);border-color:var(--orange);background:rgba(255,106,0,.08);text-shadow:0 0 12px rgba(255,106,0,.5)}
.verdict-bar.miss{color:var(--mut);border-color:var(--line)}
/* table */
table{width:100%;border-collapse:collapse;margin:14px 0}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--orange);font-weight:700;font-size:11px;letter-spacing:1.5px;text-transform:uppercase}
.runhdr{font-size:22px;color:var(--fg)}
.err{background:#1a0606;color:var(--red);padding:12px;border:1px solid var(--red);white-space:pre-wrap}
/* live telemetry log */
.log{max-height:360px;overflow:auto;font-size:12px;line-height:1.5;background:#05060a;border:1px solid var(--line);padding:10px;display:flex;flex-direction:column;gap:2px}
.logln{color:var(--mut);white-space:pre-wrap;word-break:break-word}
.logln.hit{color:var(--orange);font-weight:700}
.logln.warn{color:var(--amber)}
.log:empty::before{content:"⬡ awaiting telemetry…";color:var(--mut)}
.repro{background:#05060a;border:1px solid var(--line);padding:10px;overflow:auto;color:var(--green);font-size:12px;white-space:pre-wrap;word-break:break-word}
.ghost{background:transparent;color:var(--orange);border:1px solid var(--orange);margin-top:10px}
.ghost:hover{background:var(--orange);color:#0a0a0a}
.pick{width:auto;vertical-align:middle;accent-color:var(--orange)}
.nav{font-size:12px;letter-spacing:2px;margin:-8px 0 16px}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{border:1px solid var(--orange);color:var(--orange);padding:4px 10px;font-size:12px;letter-spacing:1px}
.skillcard{margin:10px 0}
.temp{font-size:10px;letter-spacing:1px;padding:1px 6px;border:1px solid var(--line)}
.temp-cold{color:#58a6ff;border-color:#58a6ff}
.temp-warm{color:var(--amber);border-color:var(--amber)}
</style>
`
