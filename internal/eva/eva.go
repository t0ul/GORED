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
	"embed"
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
	Models   string // researcher-matrix model set (CSV); empty = single-model run on Model
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

// IsMatrix reports whether this is a researcher-matrix sortie (several models on one stage).
func (r *run) IsMatrix() bool { return r.Models != "" }

// ModelLabel is the model(s) to show for this run: the matrix set when it is a matrix sortie,
// otherwise the single model. Centralizing it keeps the data columns honest (Model holds a
// single model, Models the set) while every render reads one label.
func (r *run) ModelLabel() string {
	if r.Models != "" {
		return "matrix: " + r.Models
	}
	return r.Model
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
		ID: rn.ID, Stage: rn.Stage, Base: rn.Base, Model: rn.Model, Models: rn.Models, Trials: rn.Trials,
		Autonomy: rn.Autonomy, Status: rn.Status, Err: rn.Err, Started: rn.Started,
		Elapsed: rn.Elapsed, Trace: rn.Trace, Prompt: rn.Prompt, Sums: rn.Sums,
	}
}

func fromEVARun(er store.EVARun) *run {
	return &run{
		ID: er.ID, Stage: er.Stage, Base: er.Base, Model: er.Model, Models: er.Models, Trials: er.Trials,
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
	// Researcher matrix mode: a comma-separated model list runs one contender per model on the
	// chosen stage — bench boots each named GGUF and the leaderboard compares them. A matrix is
	// a research sweep, not an interactive session, so it is always autonomous: a single pilot
	// checkpoint cannot sensibly gate several models at once. Trials stay configurable. When the
	// field is empty the behavior is unchanged — a single model from the "model" field.
	matrixModels := normalizeModelsCSV(r.FormValue("models"))
	if matrixModels != "" {
		f.Models = matrixModels
		autonomy = "autonomous"
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
	model := f.Model
	if matrixModels != "" {
		model = "" // matrix sortie: the model set lives in Models, not a single Model
	}
	rn := &run{ID: id, Stage: stage, Base: f.Base, Model: model, Models: matrixModels, Trials: f.Trials,
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
	Events   []traceEvt     // the FEED lens: the event stream so far
	Findings []core.Finding // the FINDINGS lens
	Repro    string
	Targets  []targetNode // the MAP lens: the discovered surface
	Breached bool         // a capture landed — the Angel's pattern goes red
}

// targetNode is one discovered request on the target surface (the MAP lens).
type targetNode struct {
	Method string
	Path   string
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
	// Seed all three lenses from the trace so far — live or finished. SSE appends new events.
	v.Events, v.Findings, v.Targets, v.Repro, v.Breached = parseRunTrace(rn.Trace)
	if captured(rn.Sums) {
		v.Breached = true
	}
	render(w, runTmpl, v)
}

// parseRunTrace reads a run's trace once and builds all three lenses: the event feed, the
// blackboard findings, the discovered surface (map), the capture repro, and whether a capture
// landed. One pass, so the page seeds live and finished runs the same way.
func parseRunTrace(path string) (events []traceEvt, findings []core.Finding, targets []targetNode, repro string, breached bool) {
	recs, err := gledger.Read(path)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, rec := range recs {
		ev := traceEvt{Span: rec.Span, Event: rec.Event, Detail: eventDetail(rec.Fields)}
		switch {
		case strings.Contains(rec.Event, "capture"), strings.Contains(rec.Event, "breach"):
			ev.Cls = "hit"
			breached = true
		case strings.Contains(rec.Event, "denied"), strings.Contains(rec.Event, "egress"):
			ev.Cls = "contain"
		case strings.Contains(rec.Event, "error"):
			ev.Cls = "warn"
		}
		events = append(events, ev)

		if rec.Span == "board" && rec.Event == "finding" {
			f := core.Finding{}
			if v, ok := rec.Fields["type"].(string); ok {
				f.Type = core.FindingType(v)
			}
			if v, ok := rec.Fields["value"].(string); ok {
				f.Value = v
			}
			findings = append(findings, f)
		}
		if rec.Span == "tool" && rec.Event == "tool_call" {
			if args, ok := rec.Fields["args"].(map[string]any); ok {
				method := strings.ToUpper(asStr(args["method"]))
				if method == "" {
					method = "GET"
				}
				p := asStr(args["path"])
				if p == "" {
					p = urlPath(asStr(args["url"]))
				}
				if p != "" && strings.HasPrefix(p, "/") {
					if len(p) > 80 {
						p = p[:80] + "…"
					}
					if k := method + " " + p; !seen[k] {
						seen[k] = true
						targets = append(targets, targetNode{Method: method, Path: p})
					}
				}
			}
		}
		if rec.Span == "verify" && rec.Event == "repro" {
			if v, ok := rec.Fields["curl"].(string); ok && v != "" {
				repro = v
			}
		}
	}
	return
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
	evs := make([]traceEvt, 0, len(recs))
	for _, rec := range recs {
		ev := traceEvt{Span: rec.Span, Event: rec.Event, Detail: eventDetail(rec.Fields)}
		switch {
		case strings.Contains(rec.Event, "capture"), strings.Contains(rec.Event, "breach"):
			ev.Cls = "hit"
		case strings.Contains(rec.Event, "denied"), strings.Contains(rec.Event, "egress"):
			ev.Cls = "contain"
		case strings.Contains(rec.Event, "error"):
			ev.Cls = "warn"
		}
		evs = append(evs, ev)
	}
	render(w, traceTmpl, map[string]any{"ID": rn.ID, "Verified": ok, "Count": len(evs), "Events": evs})
}

// traceEvt is one trace record themed for the EVA timeline.
type traceEvt struct{ Span, Event, Detail, Cls string }

// eventDetail picks the most informative field for a trace line, truncated.
func eventDetail(f map[string]any) string {
	for _, k := range []string{"tool", "via", "phase", "hint", "value", "result", "error", "reply", "curl", "beacon"} {
		if s := asStr(f[k]); s != "" {
			s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
			if len(s) > 160 {
				s = s[:160] + "…"
			}
			return s
		}
	}
	return ""
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
	render(w, leaderboardTmpl, map[string]any{
		"Title": "EVA · " + rn.Stage, "Target": rn.Base,
		"Note": rn.ModelLabel() + " [" + rn.Autonomy + "]", "Rows": sortedSums(rn.Sums),
	})
}

// leaderboard serves a combined research leaderboard across selected runs (?id=a&id=b), the
// A/B research view over the real renderer.
func (s *Server) leaderboard(w http.ResponseWriter, r *http.Request) {
	ids := r.URL.Query()["id"]
	s.mu.Lock()
	var sums []core.ContenderSummary
	var target, note string
	if len(ids) == 0 {
		// no selection: the global board — every contender from every sortie on record
		for _, rn := range s.runs {
			sums = append(sums, rn.Sums...)
		}
		note = "all sorties"
	} else {
		for _, id := range ids {
			if rn := s.runs[id]; rn != nil {
				sums = append(sums, rn.Sums...)
				target = rn.Base
			}
		}
		note = "selected sorties"
	}
	s.mu.Unlock()
	render(w, leaderboardTmpl, map[string]any{
		"Title": "EVA · leaderboard", "Target": target, "Note": note, "Rows": sortedSums(sums),
	})
}

// sortedSums orders contenders by capture rate, then capture-per-Mtoken, then fewest tokens —
// the leaderboard's own ranking, so the themed table matches the research renderer.
func sortedSums(in []core.ContenderSummary) []core.ContenderSummary {
	out := make([]core.ContenderSummary, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CaptureRate != out[j].CaptureRate {
			return out[i].CaptureRate > out[j].CaptureRate
		}
		if out[i].CapturePerMTok != out[j].CapturePerMTok {
			return out[i].CapturePerMTok > out[j].CapturePerMTok
		}
		return out[i].MeanTokens < out[j].MeanTokens
	})
	return out
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

// traceSitemap reads a run's trace and returns the distinct requests the agent made on the
// target — the surface map the target "Angel" panel draws. It parses the already-written
// tool-call events, so it reflects exactly what was touched, and fills live as the run goes.
func traceSitemap(path string) []targetNode {
	recs, err := gledger.Read(path)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var nodes []targetNode
	for _, rec := range recs {
		if rec.Span != "tool" || rec.Event != "tool_call" {
			continue
		}
		args, ok := rec.Fields["args"].(map[string]any)
		if !ok {
			continue
		}
		method := strings.ToUpper(asStr(args["method"]))
		if method == "" {
			method = "GET"
		}
		p := asStr(args["path"])
		if p == "" {
			p = urlPath(asStr(args["url"]))
		}
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		if len(p) > 80 {
			p = p[:80] + "…"
		}
		if key := method + " " + p; !seen[key] {
			seen[key] = true
			nodes = append(nodes, targetNode{Method: method, Path: p})
		}
	}
	if len(nodes) > 50 {
		nodes = nodes[:50]
	}
	return nodes
}

func asStr(v any) string { s, _ := v.(string); return s }

// urlPath returns the path portion of a full URL, or "" if it has no path.
func urlPath(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		if j := strings.IndexByte(u[i+3:], '/'); j >= 0 {
			return u[i+3+j:]
		}
		return ""
	}
	return u
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
	sent, lastStatus, pendingSent := 0, "", false
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
		pend := rn.Pending
		s.mu.Unlock()
		if st != lastStatus {
			lastStatus = st
			send(fmt.Sprintf(`{"_eva":"status","status":%q}`, st))
		}
		// Live pilot decision: push the open gate so the client raises the decision overlay
		// without a reload; a resume frame clears it when the pilot has acted.
		if pend != nil && !pendingSent {
			pendingSent = true
			type mv struct{ Tool, Path, Surface, Source, Why string }
			ms := make([]mv, 0, len(pend.Proposals))
			for _, m := range pend.Proposals {
				ms = append(ms, mv{m.Tool, m.Path, m.Surface, m.Source, m.Why})
			}
			b, _ := json.Marshal(map[string]any{"_eva": "pending", "phase": pend.Phase, "proposals": ms})
			send(string(b))
		} else if pend == nil && pendingSent {
			pendingSent = false
			send(`{"_eva":"resume"}`)
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
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
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

// normalizeModelsCSV cleans the matrix "models" form field: trim each entry, drop empties,
// rejoin with ", ". Empty in → empty out, which the launch handler reads as a single-model run.
func normalizeModelsCSV(s string) string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ", ")
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
	"add":      func(a, b int) int { return a + b },
	"deref": func(p *float64) float64 {
		if p == nil {
			return 0
		}
		return *p
	},
	"trunc": func(s string, n int) string {
		s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
		if len(s) > n {
			return s[:n] + "…"
		}
		return s
	},
}

//go:embed templates/*.gohtml
var tmplFS embed.FS

// page parses the shared layout + css together with one page's content into a
// renderable template; render executes its "layout".
func page(name string) *template.Template {
	return template.Must(template.New(name).Funcs(funcs).ParseFS(tmplFS,
		"templates/layout.gohtml", "templates/css.gohtml", "templates/"+name+".gohtml"))
}

var (
	homeTmpl        = page("home")
	runTmpl         = page("run")
	studioTmpl      = page("studio")
	compareTmpl     = page("compare")
	leaderboardTmpl = page("leaderboard")
	traceTmpl       = page("trace")
)
