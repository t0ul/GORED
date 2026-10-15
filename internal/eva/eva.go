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

var homeTmpl = template.Must(template.New("home").Funcs(funcs).Parse(baseCSS + `
<div class="hudbar">
  <span class="dtitle">EVA · GORED <span class="badge done">LAUNCH BAY</span></span>
  <span class="hudcfg">piloted app-layer red-team · the model is the weapon</span>
  <span class="hudphase" id="hudphase">MAGI 3 / 3</span>
</div>
<div class="hazard"></div>
<div class="cockpit3">
  <div class="slot slot-left" id="slot-left">
    <section class="role lens">
      <div class="rolehdr">◣ SYSTEM · MAGI</div>
      <div class="readout">
        <div class="ro">MAGI <b class="grn">3 / 3</b></div>
        <div class="ro">EGRESS <b>SEALED</b></div>
        <div class="ro">ORACLE <b>REAL-BYTES</b></div>
        <div class="ro">CONTAINMENT <b class="grn">OK</b></div>
        <div class="ro">LINK <b>NOMINAL</b></div>
        <div class="ro">A.T. FIELD <b>ACTIVE</b></div>
      </div>
      <p class="hint" style="margin-top:14px">Target only on the egress allowlist. The oracle confirms capture on real bytes — the blackboard is untrusted target output, never the verdict.</p>
    </section>
  </div>
  <div class="slot slot-center" id="slot-center">
    <section class="role lens">
      <div class="rolehdr">◉ LAUNCH CONFIG</div>
      <form method="post" action="/run" id="launchform">
        <label>STAGE <select name="stage">{{range .Stages}}<option value="{{.Name}}">{{.Name}} — {{.Goal}}</option>{{end}}</select></label>
        <label>TARGET BASE URL <input name="base" value="http://127.0.0.1:8088"></label>
        <label>MODEL (GGUF) <input name="model" value="qwen2.5-3b-instruct.gguf"></label>
        <label>MODEL MATRIX · RESEARCHER MODE <input name="models" placeholder="qwen2.5-0.5b-instruct.gguf, qwen2.5-1.5b-instruct.gguf"></label>
        <p class="hint">Leave blank for a single-model run. A comma-separated list runs one contender per model and compares them on the leaderboard — always autonomous.</p>
        <label>BRIG BRIDGE <input name="bridge" value="127.0.0.1:5050"></label>
        <label>SYNC PROMPT · SKILL INSTRUCTION <textarea name="skill" id="skill" rows="4">{{.FirstInstr}}</textarea></label>
        <fieldset class="dial">
          <legend>AUTONOMY DIAL</legend>
          <label class="radio"><input type="radio" name="autonomy" value="piloted" checked> <b>PILOTED</b><span>pause at every gate — you pick the moves</span></label>
          <label class="radio"><input type="radio" name="autonomy" value="assisted"> <b>ASSISTED</b><span>acts on its own after a beat unless you intervene</span></label>
          <label class="radio"><input type="radio" name="autonomy" value="autonomous"> <b>BERSERK</b><span>no gate — runs free, the headless/CI loop</span></label>
        </fieldset>
        <label>TRIALS (BERSERK / MATRIX) <input name="trials" type="number" value="1" min="1"></label>
        <label class="chk"><input type="checkbox" name="ensure" value="1" checked> auto-launch vulnapp</label>
      </form>
    </section>
  </div>
  <div class="slot slot-right" id="slot-right">
    <section class="role lens">
      <div class="rolehdr">◥ SORTIE LOG</div>
      {{if .Recent}}
      <form method="get" action="/compare">
        <ul class="runs">{{range .Recent}}
          <li><input type="checkbox" name="id" value="{{.ID}}" class="pick"> <a href="/run/{{.ID}}">{{.Stage}} <span class="vs">vs</span> {{.Base}}</a> <span class="dim">[{{.Autonomy}}]</span>{{if .IsMatrix}} <span class="badge matrix">matrix</span>{{end}} <span class="badge {{.Status}}">{{.Status}}</span>{{if captured .Sums}} <span class="badge cap">⬡ CAPTURED</span>{{end}}</li>
        {{end}}</ul>
        <button class="ghost">COMPARE</button>
      </form>
      {{else}}<p class="muted">no sorties yet</p>{{end}}
    </section>
  </div>
</div>
<div class="dock homedock">
  <span></span>
  <button form="launchform" {{if .Busy}}disabled{{end}}>{{if .Busy}}EVA IN FLIGHT…{{else}}LAUNCH{{end}}</button>
  <nav class="docknav"><a href="/">COCKPIT</a> · <a href="/leaderboard">LEADERBOARD</a> · <a href="/studio">STUDIO</a></nav>
</div>
<script>
(function(){
  var INSTR = {{.StageInstr}};
  var sel = document.querySelector('select[name=stage]');
  var ta = document.getElementById('skill');
  if (sel && ta) sel.addEventListener('change', function(){ if (INSTR[sel.value] !== undefined) ta.value = INSTR[sel.value]; });
})();
</script>
`))

var runTmpl = template.Must(template.New("run").Funcs(funcs).Parse(baseCSS + `
{{if or (eq .Status "running") (eq .Status "waiting")}}<noscript><meta http-equiv="refresh" content="3"></noscript>{{end}}
<div class="hudbar">
  <span class="dtitle">{{.Stage}} <span class="badge {{.Status}}">{{.Status}}</span></span>
  <span class="hudcfg">{{.Base}} · {{.ModelLabel}} · {{.Autonomy}}{{if .Prompt}} · custom prompt{{end}}{{if .Elapsed}} · {{.Elapsed}}{{end}}</span>
  <span class="hudphase" id="hudphase">PHASE —</span>
</div>
<div class="hazard"></div>
<div class="cockpit3 immersive">
  <div class="slot slot-left" id="slot-left" onclick="manualSwap('left')"></div>
  <div class="slot slot-center" id="slot-center">
    <div class="decision" id="decision" hidden>
      <div class="card-tag warn">⚠ PILOT DECISION — PHASE <span id="dphase"></span></div>
      <p class="muted">Pick the moves to spend tokens on, add a constraint, proceed. The oracle confirms on real bytes — you pick the move, not the verdict.</p>
      <div class="moves" id="dmoves"></div>
      <label>CONSTRAINT / HINT <input id="dhint" placeholder="e.g. focus /greeting, try the reflected param"></label>
      <div class="btnrow"><button type="button" onclick="submitDecision('proceed')">PROCEED</button><button type="button" class="danger" onclick="submitDecision('abort')">ABORT</button></div>
    </div>
  </div>
  <div class="slot slot-right" id="slot-right" onclick="manualSwap('right')"></div>
</div>
<div class="dock">
  <button class="swap" onclick="manualSwap('left')" title="focus left ( &lt; )">◀</button>
  <div class="dockmid">
    <button class="swap reset" onclick="resetFocus()">RESET</button>
    <nav class="docknav"><a href="/">COCKPIT</a> · <a href="/studio">STUDIO</a> · <a href="/run/{{.ID}}/trace">TRACE</a>{{if .Sums}} · <a href="/run/{{.ID}}/leaderboard">LEADERBOARD</a>{{end}}</nav>
  </div>
  <button class="swap" onclick="manualSwap('right')" title="focus right ( &gt; )">▶</button>
</div>

<div id="roles" hidden>
  <section class="role lens" data-lens="feed" id="lens-feed">
    <div class="rolehdr">◢ FEED</div>
    <div id="feed" class="log">{{range .Events}}<div class="logln {{.Cls}}">[{{.Span}}] {{.Event}}{{if .Detail}}  {{.Detail}}{{end}}</div>{{end}}</div>
  </section>
  <section class="role lens" data-lens="map" id="lens-map">
    <div class="rolehdr">◉ MAP · <span class="count" id="mapcount">{{len .Targets}} paths</span></div>
    <div class="angel{{if .Breached}} breached{{end}}" id="angel"><div class="core"><div class="cross"></div><div class="ring"></div><div class="ring r2"></div><div class="ring r3"></div><div class="pat" id="angelpat">{{if .Breached}}● BREACH{{else}}◎ LOCKED{{end}}</div></div></div>
    <div class="nodes" id="mapnodes">{{range .Targets}}<div class="node"><span class="m">{{.Method}}</span><span class="p">{{.Path}}</span></div>{{end}}</div>
  </section>
  <section class="role lens" data-lens="findings" id="lens-findings">
    <div class="rolehdr">◆ FINDINGS · <span class="count" id="findcount">{{len .Findings}}</span></div>
    {{if .Sums}}{{if captured .Sums}}<div class="verdict-bar hit">● CAPTURED</div>{{else}}<div class="verdict-bar miss">○ HELD</div>{{end}}
    <div class="tblwrap"><table><thead><tr><th>contender</th><th>cap%</th><th>cap</th><th>tools</th><th>tok</th></tr></thead><tbody>{{range .Sums}}<tr><td>{{.Contender}}</td><td>{{pct .CaptureRate}}</td><td>{{.Captured}}/{{.Trials}}</td><td>{{printf "%.1f" .MeanToolCall}}</td><td>{{printf "%.0f" .MeanTokens}}</td></tr>{{end}}</tbody></table></div>{{end}}
    <div id="findlist" class="evlog">{{range .Findings}}<div class="ev"><span class="ft">{{.Type}}</span> {{trunc .Value 200}}</div>{{end}}</div>
    {{if .Repro}}<div class="card-tag">REPRO</div><pre class="repro">{{.Repro}}</pre>{{end}}
  </section>
</div>

<script>
(function(){
  var PAGE_STATUS = "{{.Status}}";
  var RUN_ID = "{{.ID}}";
  var state = {left:'lens-feed', center:'lens-map', right:'lens-findings'};
  var manual = false, lastPhase = '';
  function el(id){ return document.getElementById(id); }
  function place(){ ['left','center','right'].forEach(function(s){ var ln=el(state[s]); if(ln) el('slot-'+s).appendChild(ln); }); }
  function slotOf(lens){ for(var s in state){ if(state[s]===lens) return s; } return null; }
  function setCenter(lens){ var s=slotOf(lens); if(!s||s==='center') return; var t=state.center; state.center=lens; state[s]=t; place(); }
  function focus(lens){ if(manual) return; setCenter(lens); }
  function lensForPhase(p){ p=(p||'').toLowerCase();
    if(p.indexOf('recon')>=0||p.indexOf('finger')>=0||p.indexOf('map')>=0||p.indexOf('discover')>=0) return 'lens-map';
    if(p.indexOf('exploit')>=0||p.indexOf('attack')>=0||p.indexOf('probe')>=0||p.indexOf('inject')>=0) return 'lens-feed';
    if(p.indexOf('valid')>=0||p.indexOf('verif')>=0||p.indexOf('chain')>=0) return 'lens-findings';
    return 'lens-map'; }
  window.manualSwap=function(side){ manual=true; var t=state.center; state.center=state[side]; state[side]=t; place(); };
  window.resetFocus=function(){ manual=false; if(PAGE_STATUS==='running'||PAGE_STATUS==='waiting'){ focus(lensForPhase(lastPhase)); } else { setCenter('lens-findings'); } };
  place();

  document.addEventListener('keydown', function(e){
    if(e.target && /INPUT|TEXTAREA|SELECT/.test(e.target.tagName)) return;
    if(e.key==='<'||e.key===',') manualSwap('left');
    else if(e.key==='>'||e.key==='.') manualSwap('right');
  });

  var feed=el('feed'), mapnodes=el('mapnodes'), findlist=el('findlist'), seenPath={};
  function feedLine(span,ev,detail,cls){ var d=document.createElement('div'); d.className='logln '+(cls||''); d.textContent='['+span+'] '+ev+(detail?'  '+detail:''); feed.appendChild(d); feed.scrollTop=feed.scrollHeight; }
  function pathOf(u){ var i=(''+u).indexOf('://'); if(i>=0){ var j=(''+u).indexOf('/',i+3); return j>=0?(''+u).slice(j):''; } return ''+u; }
  function addNode(method,p){ if(!p||p[0]!=='/') return; if(p.length>80)p=p.slice(0,80)+'…'; var k=method+' '+p; if(seenPath[k])return; seenPath[k]=1; var d=document.createElement('div'); d.className='node'; var ms=document.createElement('span'); ms.className='m'; ms.textContent=method; var ps=document.createElement('span'); ps.className='p'; ps.textContent=p; d.appendChild(ms); d.appendChild(ps); mapnodes.appendChild(d); el('mapcount').textContent=mapnodes.children.length+' paths'; }
  function addFinding(type,val){ var d=document.createElement('div'); d.className='ev'; var ft=document.createElement('span'); ft.className='ft'; ft.textContent=type; d.appendChild(ft); d.appendChild(document.createTextNode(' '+(val.length>200?val.slice(0,200)+'…':val))); findlist.appendChild(d); el('findcount').textContent=findlist.children.length; }
  function setBreach(){ var a=el('angel'); if(a) a.classList.add('breached'); var p=el('angelpat'); if(p) p.textContent='● BREACH'; }
  [].forEach.call(mapnodes.children, function(n){ seenPath[(n.children[0].textContent+' '+n.children[1].textContent)]=1; });

  var decision=el('decision'), cockpit=document.querySelector('.cockpit3');
  function raiseDecision(phase, proposals){
    el('dphase').textContent=(phase||'').toUpperCase();
    var box=el('dmoves'); box.innerHTML='';
    (proposals||[]).forEach(function(m,i){
      var l=document.createElement('label'); l.className='move';
      var cb=document.createElement('input'); cb.type='checkbox'; cb.name='move'; cb.value=i; l.appendChild(cb);
      function sp(c,t){ var s=document.createElement('span'); s.className=c; s.textContent=t; l.appendChild(s); }
      sp('mv-tool',m.Tool||''); sp('mv-path',m.Path||'—'); sp('mv-surface s-'+(m.Surface||''),m.Surface||''); sp('mv-src src-'+(m.Source||''),m.Source||''); sp('mv-why',m.Why||'');
      box.appendChild(l);
    });
    if(!proposals||!proposals.length){ box.innerHTML='<p class="muted">no proposals — type a directive and proceed.</p>'; }
    decision.hidden=false; decision.classList.remove('rise'); void decision.offsetWidth; decision.classList.add('rise');
    cockpit.classList.add('decided');
  }
  function lowerDecision(){ decision.hidden=true; cockpit.classList.remove('decided'); if(!manual) focus(lensForPhase(lastPhase)); }
  window.submitDecision=function(action){
    var body='action='+action+'&hint='+encodeURIComponent(el('dhint').value);
    [].forEach.call(decision.querySelectorAll('input[name=move]:checked'), function(c){ body+='&move='+c.value; });
    lowerDecision();
    fetch('/run/'+RUN_ID+'/decide', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:body});
  };

  if(PAGE_STATUS==='running'||PAGE_STATUS==='waiting'){
    var es=new EventSource('/run/'+RUN_ID+'/events');
    es.onmessage=function(e){
      var r; try{ r=JSON.parse(e.data); }catch(_){ return; }
      if(r._eva==='status'){ var b=document.querySelector('.hudbar .badge'); if(b){ b.textContent=r.status; b.className='badge '+r.status; } return; }
      if(r._eva==='done'){ es.close(); location.reload(); return; }
      if(r._eva==='pending'){ raiseDecision(r.phase, r.proposals); return; }
      if(r._eva==='resume'){ lowerDecision(); return; }
      var span=r.span||'', ev=r.event||'', f=r.fields||{};
      var detail=f.tool||f.via||f.phase||f.hint||f.value||f.result||f.error||f.reply||'';
      if(typeof detail!=='string') detail=JSON.stringify(detail);
      if(detail.length>140) detail=detail.slice(0,140)+'…';
      var cls= (ev.indexOf('capture')>=0||ev.indexOf('breach')>=0)?'hit':((ev.indexOf('denied')>=0||ev.indexOf('egress')>=0)?'contain':(ev.indexOf('error')>=0?'warn':''));
      feedLine(span,ev,detail,cls);
      if(span==='tool'&&ev==='tool_call'&&f.args){ var m=(f.args.method||'GET').toString().toUpperCase(); addNode(m, f.args.path||pathOf(f.args.url||'')); }
      if(span==='board'&&ev==='finding'&&f.value){ var ty=(f.type||'')+'' , v=(''+f.value); if(ty==='flag-candidate'||ty==='vuln-candidate'||ty==='scanner'||v.indexOf('GORED{')>=0||v.indexOf('CONFIRMED')>=0||v.indexOf('VERIFIED')>=0) addFinding(ty||'finding', v); }
      if(ev.indexOf('capture')>=0){ setBreach(); addFinding('capture', detail); focus('lens-findings'); }
      if(span==='phase'&&ev==='phase_advance'){ lastPhase=((f.to||'')+''); el('hudphase').textContent='PHASE '+lastPhase.toUpperCase(); focus(lensForPhase(lastPhase)); }
    };
    focus('lens-map');
  } else {
    setCenter('lens-findings'); el('hudphase').textContent='PHASE COMPLETE';
  }
})();
</script>
`))

var studioTmpl = template.Must(template.New("studio").Funcs(funcs).Parse(baseCSS + `
<div class="hudbar">
  <span class="dtitle">STUDIO <span class="badge done">FACTORY</span></span>
  <span class="hudcfg">tools · skills · prompts <span class="dim">(read-only until the registry drives the stages)</span></span>
  <span class="hudphase">{{len .Stages}} STAGES</span>
</div>
<div class="hazard"></div>
<div class="cockpit3">
  <div class="slot slot-left" id="slot-left">
    <section class="role lens">
      <div class="rolehdr">◣ CATALOG</div>
      <div class="readout">
        <div class="ro">TOOLS <b>{{len .Tools}}</b></div>
        <div class="ro">SKILLS <b>{{len .Skills}}</b></div>
        <div class="ro">STAGES <b>{{len .Stages}}</b></div>
      </div>
      <p class="hint" style="margin-top:12px">The factory surfaces — the tools an agent can call, the skills (prompts) that steer it, and the per-stage playbooks. Authoring lands once the registry drives the stages.</p>
    </section>
  </div>
  <div class="slot slot-center" id="slot-center">
    <section class="role lens">
      <div class="rolehdr">◉ TOOLS · <span class="count">{{len .Tools}}</span></div>
      <div class="chips">{{range .Tools}}<span class="chip">{{.}}</span>{{else}}<span class="muted">none</span>{{end}}</div>
      <div class="rolehdr" style="margin-top:18px">◉ SKILLS</div>
      {{if .Skills}}{{range .Skills}}
      <div class="card frame skillcard">
        <div class="card-tag">{{.Name}} <span class="temp temp-{{.Temp}}">{{.Temp}}</span> {{if .BuiltIn}}<span class="src-router">built-in</span>{{else}}<span class="src-model">authored</span>{{end}}</div>
        <pre class="repro">{{.Instruction}}</pre>
      </div>
      {{end}}{{else}}<p class="muted">no skills registry (run with -store to seed the catalog)</p>{{end}}
      <div class="rolehdr" style="margin-top:18px">◉ PROMPTS · PER STAGE</div>
      {{range .Stages}}
      <div class="card frame skillcard">
        <div class="card-tag">{{.Name}} <span class="dim">tools: {{range .Tools}}{{.}} {{end}}</span></div>
        <pre class="repro">{{.Instruction}}</pre>
      </div>
      {{end}}
    </section>
  </div>
  <div class="slot slot-right" id="slot-right">
    <section class="role lens">
      <div class="rolehdr">◥ INVENTORY</div>
      <div class="readout">
        {{range .Stages}}<div class="ro">{{.Name}} <b>{{len .Tools}} tools</b></div>{{end}}
      </div>
    </section>
  </div>
</div>
<div class="dock">
  <span></span>
  <div class="dockmid"><nav class="docknav"><a href="/">COCKPIT</a> · <a href="/leaderboard">LEADERBOARD</a> · <a href="/studio">STUDIO</a></nav></div>
  <span></span>
</div>
`))

var compareTmpl = template.Must(template.New("compare").Funcs(funcs).Parse(baseCSS + `
<div class="hudbar">
  <span class="dtitle">COMPARE <span class="badge matrix">SORTIES</span></span>
  <span class="hudcfg">side-by-side sortie summaries</span>
  <span class="hudphase">{{len .Runs}} RUNS</span>
</div>
<div class="hazard"></div>
<div class="cockpit3">
  <div class="slot slot-left" id="slot-left">
    <section class="role lens">
      <div class="rolehdr">◣ COMPARE</div>
      <p class="hint" style="margin-top:8px">Each row is one sortie's headline contender. Promote the set to the research leaderboard to rank every contender across them on real target bytes.</p>
    </section>
  </div>
  <div class="slot slot-center" id="slot-center">
    <section class="role lens">
      <div class="rolehdr">◉ SORTIES · <span class="count">{{len .Runs}}</span></div>
      {{if .Runs}}
      <div class="tblwrap"><table class="lb"><thead><tr><th>run</th><th>stage</th><th>model</th><th>dial</th><th>status</th><th>cap%</th><th>cap</th><th>tools</th><th>tok</th></tr></thead><tbody>
      {{range .Runs}}{{if .Sums}}{{$c := index .Sums 0}}<tr>
        <td><a href="/run/{{.ID}}">{{.ID}}</a></td><td>{{.Stage}}</td><td>{{.ModelLabel}}</td><td class="dim">{{.Autonomy}}</td><td><span class="badge {{.Status}}">{{.Status}}</span></td>
        <td>{{pct $c.CaptureRate}}</td><td>{{$c.Captured}}/{{$c.Trials}}</td><td>{{printf "%.1f" $c.MeanToolCall}}</td><td>{{printf "%.0f" $c.MeanTokens}}</td>
      </tr>{{else}}<tr>
        <td><a href="/run/{{.ID}}">{{.ID}}</a></td><td>{{.Stage}}</td><td>{{.ModelLabel}}</td><td class="dim">{{.Autonomy}}</td><td><span class="badge {{.Status}}">{{.Status}}</span></td>
        <td colspan="4" class="muted">no summary</td>
      </tr>{{end}}{{end}}
      </tbody></table></div>
      {{else}}<p class="muted">select two or more runs from the cockpit to compare.</p>{{end}}
    </section>
  </div>
  <div class="slot slot-right" id="slot-right">
    <section class="role lens">
      <div class="rolehdr">◥ ACTIONS</div>
      {{if .Runs}}<a class="chip" href="/leaderboard?{{range .Runs}}id={{.ID}}&amp;{{end}}">OPEN AS RESEARCH LEADERBOARD</a>{{else}}<p class="muted">—</p>{{end}}
    </section>
  </div>
</div>
<div class="dock">
  <span></span>
  <div class="dockmid"><nav class="docknav"><a href="/">COCKPIT</a> · <a href="/leaderboard">LEADERBOARD</a> · <a href="/studio">STUDIO</a></nav></div>
  <span></span>
</div>
`))

var leaderboardTmpl = template.Must(template.New("lb").Funcs(funcs).Parse(baseCSS + `
<div class="hudbar">
  <span class="dtitle">LEADERBOARD <span class="badge done">MAGI</span></span>
  <span class="hudcfg">{{.Title}}{{if .Target}} · {{.Target}}{{end}}{{if .Note}} · {{.Note}}{{end}}</span>
  <span class="hudphase">{{len .Rows}} CONTENDERS</span>
</div>
<div class="hazard"></div>
<div class="cockpit3">
  <div class="slot slot-left" id="slot-left">
    <section class="role lens">
      <div class="rolehdr">◣ READ-OUT</div>
      <div class="readout">
        <div class="ro">RANK <b>capture %</b></div>
        <div class="ro">CAP <b>oracle-confirmed</b></div>
        <div class="ro">CAP/MTOK <b>efficiency</b></div>
        <div class="ro">VERDICT <b class="grn">REAL BYTES</b></div>
      </div>
      <p class="hint" style="margin-top:12px">Each row is a contender — a model × skill — scored on real target bytes. The top row is the sharpest weapon on record.</p>
    </section>
  </div>
  <div class="slot slot-center" id="slot-center">
    <section class="role lens">
      <div class="rolehdr">◉ CONTENDERS · <span class="count">{{len .Rows}}</span></div>
      {{if .Rows}}
      <div class="tblwrap"><table class="lb"><thead><tr><th>#</th><th>contender</th><th class="capcell">capture</th><th>cap</th><th>tools</th><th>tok</th><th>cap/Mtok</th></tr></thead><tbody>
      {{range $i, $r := .Rows}}<tr{{if eq $i 0}} class="top"{{end}}>
        <td class="rank">{{add $i 1}}</td>
        <td>{{$r.Contender}}</td>
        <td class="capcell"><div class="capbar"><i style="width:{{pct $r.CaptureRate}}"></i><span>{{pct $r.CaptureRate}}</span></div></td>
        <td>{{$r.Captured}}/{{$r.Trials}}</td>
        <td>{{printf "%.1f" $r.MeanToolCall}}</td>
        <td>{{printf "%.0f" $r.MeanTokens}}</td>
        <td>{{if gt $r.CapturePerMTok 0.0}}{{printf "%.0f" $r.CapturePerMTok}}{{else}}—{{end}}</td>
      </tr>{{end}}
      </tbody></table></div>
      {{else}}<p class="muted">no contenders yet — launch a sortie from the cockpit.</p>{{end}}
    </section>
  </div>
  <div class="slot slot-right" id="slot-right">
    <section class="role lens">
      <div class="rolehdr">◥ TOP WEAPON</div>
      {{if .Rows}}{{with index .Rows 0}}
      <div class="verdict-bar hit">● {{.Contender}}</div>
      <div class="readout">
        <div class="ro">CAPTURE <b>{{pct .CaptureRate}}</b></div>
        <div class="ro">CAPTURED <b>{{.Captured}}/{{.Trials}}</b></div>
        <div class="ro">TOOLS <b>{{printf "%.1f" .MeanToolCall}}</b></div>
        <div class="ro">TOKENS <b>{{printf "%.0f" .MeanTokens}}</b></div>
        <div class="ro">CAP/MTOK <b>{{if gt .CapturePerMTok 0.0}}{{printf "%.0f" .CapturePerMTok}}{{else}}—{{end}}</b></div>
      </div>
      {{end}}{{else}}<p class="muted">—</p>{{end}}
    </section>
  </div>
</div>
<div class="dock">
  <span></span>
  <div class="dockmid"><nav class="docknav"><a href="/">COCKPIT</a> · <a href="/leaderboard">LEADERBOARD</a> · <a href="/studio">STUDIO</a></nav></div>
  <span></span>
</div>
`))

var traceTmpl = template.Must(template.New("trace").Funcs(funcs).Parse(baseCSS + `
<div class="hudbar">
  <span class="dtitle">TRACE <span class="badge {{if .Verified}}done{{else}}error{{end}}">{{if .Verified}}VERIFIED{{else}}UNVERIFIED{{end}}</span></span>
  <span class="hudcfg">run {{.ID}} · gledger append-only audit</span>
  <span class="hudphase">{{.Count}} RECORDS</span>
</div>
<div class="hazard"></div>
<div class="cockpit3">
  <div class="slot slot-left" id="slot-left">
    <section class="role lens">
      <div class="rolehdr">◣ RUN</div>
      <div class="readout">
        <div class="ro">RUN <b>{{.ID}}</b></div>
        <div class="ro">RECORDS <b>{{.Count}}</b></div>
        <div class="ro">CHAIN <b class="{{if .Verified}}grn{{end}}">{{if .Verified}}VERIFIED{{else}}BROKEN{{end}}</b></div>
      </div>
      <p class="hint" style="margin-top:12px">Replay the sortie step by step. Each record is hash-chained to the one before it — tampering breaks the chain.</p>
    </section>
  </div>
  <div class="slot slot-center" id="slot-center">
    <section class="role lens">
      <div class="rolehdr">◉ REPLAY · <span class="count" id="tpos">0 / {{.Count}}</span></div>
      <div class="player"><button onclick="tstep(-1)">◀ STEP</button><button onclick="tplay()">▶ PLAY</button><button onclick="tstep(1)">STEP ▶</button><button class="ghost" onclick="treset()">RESET</button></div>
      <div class="tl" id="tl">
      {{range .Events}}<div class="tlev seen {{.Cls}}"><span class="sp">[{{.Span}}] {{.Event}}</span>{{if .Detail}}<div class="tx">{{.Detail}}</div>{{end}}</div>{{end}}
      </div>
    </section>
  </div>
  <div class="slot slot-right" id="slot-right">
    <section class="role lens">
      <div class="rolehdr">◥ INTEGRITY</div>
      {{if .Verified}}<div class="verdict-bar hit">● HASH-CHAIN VERIFIED</div>{{else}}<div class="verdict-bar miss">○ UNVERIFIED</div>{{end}}
      <p class="hint" style="margin-top:10px">gledger stamps each record with the hash of the previous — an append-only, tamper-evident ledger. The verdicts shown in the cockpit are reproduced from exactly these bytes.</p>
    </section>
  </div>
</div>
<div class="dock">
  <span></span>
  <div class="dockmid"><nav class="docknav"><a href="/run/{{.ID}}">BACK TO SORTIE</a> · <a href="/">COCKPIT</a> · <a href="/leaderboard">LEADERBOARD</a></nav></div>
  <span></span>
</div>
<script>
(function(){
  var evs=[].slice.call(document.querySelectorAll('#tl .tlev')); var i=-1; var timer=null;
  var pos=document.getElementById('tpos'); var total=evs.length;
  function show(n){ if(n<-1)n=-1; if(n>=evs.length)n=evs.length-1; evs.forEach(function(e,k){e.classList.toggle('active',k===n);}); if(n>=0&&evs[n])evs[n].scrollIntoView({block:'nearest'}); i=n; pos.textContent=(n+1)+' / '+total; }
  window.tstep=function(d){ if(timer){clearInterval(timer);timer=null;} show(i+d); };
  window.treset=function(){ if(timer){clearInterval(timer);timer=null;} show(-1); };
  window.tplay=function(){ if(timer){clearInterval(timer);timer=null;return;} timer=setInterval(function(){ if(i>=evs.length-1){clearInterval(timer);timer=null;return;} show(i+1); },450); };
})();
</script>
`))

const baseCSS =`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>EVA · GORED</title>
<style>
:root{
  --bg:#0a0603; --bg2:#140a04; --panel:#19100a; --panel2:#201609; --line:#3a240f;
  --orange:#ff6a00; --amber:#ffab00; --yellow:#ffd21a; --green:#8bd450; --red:#ff2a2a; --blue:#58a6ff;
  --purple:#965fd4; --purple-d:#734f9a; /* EVA-01 unit colours: the pilot / sync accent */
  --fg:#f0dcc0; --mut:#9a7a52; --acc:#ff6a00;
  --hex:url("data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' width='28' height='49'><path d='M13.99 9.25l13 7.5v15l-13 7.5L1 31.75v-15l12.99-7.5zM3 17.9v12.7l10.99 6.34 11-6.35V17.9l-11-6.34L3 17.9zM0 15l12.98-7.5V0h-2v6.35L0 12.69v2.3zm0 18.5L12.98 41v8h-2v-6.85L0 35.81v-2.3zM15 0v7.5L27.99 15H28v-2.31h-.01L17 6.35V0h-2zm0 49v-8l12.99-7.5H28v2.31h-.01L17 42.15V49h-2z' fill='%23ffb020' fill-opacity='0.09'/></svg>");
  --scan:repeating-linear-gradient(0deg,rgba(0,0,0,.22) 0 1px,transparent 1px 3px);
}
*{box-sizing:border-box}
body{
  background:
    var(--hex),
    radial-gradient(1200px 620px at 70% -12%, rgba(255,120,0,.10), transparent 62%),
    var(--bg);
  background-attachment:fixed;
  color:var(--fg); font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  max-width:none; margin:0; padding:14px 14px; letter-spacing:.2px;
}
a{color:var(--amber);text-decoration:none}a:hover{text-decoration:underline}
h1,h2{letter-spacing:3px;text-transform:uppercase;margin:.3rem 0}
h2{font-size:14px;color:var(--orange);border-left:3px solid var(--orange);padding-left:8px;margin-top:24px}
.sub{color:var(--mut);margin-top:0;font-size:12px;letter-spacing:1px;text-transform:uppercase}
.muted{color:var(--mut)} .dim{color:var(--amber);font-size:12px;letter-spacing:1px}
.vs{color:var(--mut);font-style:normal} .grn{color:var(--green)}
/* top entry-plug bar */
.topbar{display:flex;align-items:center;gap:14px}
.logo{font-size:36px;color:var(--orange);line-height:1;text-shadow:0 0 16px rgba(255,106,0,.6)}
.brandblock{display:flex;flex-direction:column;line-height:1.1}
.brand{font-size:30px;color:var(--orange);letter-spacing:5px;font-weight:700;text-shadow:0 0 18px rgba(255,106,0,.45)}
.sysline{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.sys{font-size:10px;letter-spacing:2px;color:var(--mut);border:1px solid var(--line);padding:3px 8px}
.sys.ok{color:var(--green);border-color:rgba(134,214,51,.4)}
.stripe{height:9px;margin:10px 0 16px;
  background:repeating-linear-gradient(45deg,var(--orange) 0 14px,#111 14px 28px);
  opacity:.8;border-top:1px solid #000;border-bottom:1px solid #000}
.stripe.bottom{margin:24px 0 10px;opacity:.5}
.foot{color:var(--mut);font-size:11px;letter-spacing:1px;text-align:center;text-transform:uppercase}
/* three-column cockpit: the side consoles are tall bowtie wings — full-height outer edge,
   converging to a short inner edge at the central viewscreen. The slant is fixed-angle: the
   top edge drops tan(15deg)*width, so console(200w)=54px and sidepanel(240w)=64px, and the
   content is counter-rotated by the same 15deg so the words run PARALLEL to the top edge. */
/* MECHA COCKPIT: full-height bowtie console wings that run top to bottom of the viewport,
   their big outer ends converging to a compact central monitor that scrolls. */
.cockpit{max-width:none;margin:0;display:grid;grid-template-columns:1fr 440px 1fr;gap:18px;align-items:stretch;min-height:calc(100vh - 28px)}
.console,.sidepanel{background:linear-gradient(var(--panel),var(--bg2));border:1px solid rgba(255,106,0,.6);overflow:hidden;display:flex;align-items:center;justify-content:center}
/* %-based taper scales with the full height: big outer ends, converging inner waist at the box */
.console{clip-path:polygon(0 0, 100% 20%, 100% 80%, 0 100%)}
.sidepanel{clip-path:polygon(0 20%, 100% 0, 100% 100%, 0 80%)}
/* text on the wing lies on a plane receding toward the central horizon (one-point perspective) */
.wing-face{display:grid;gap:16px;width:78%;text-transform:uppercase;letter-spacing:2px}
.wf-title{font-size:26px;letter-spacing:5px;color:var(--orange);text-shadow:0 0 14px rgba(255,106,0,.4)}
.wf-row{font-size:15px;color:var(--mut);border-bottom:1px solid var(--line);padding-bottom:5px;white-space:nowrap}
a.wf-row{color:var(--fg);text-decoration:none}a.wf-row:hover{color:var(--orange)}
.wf-left{transform:perspective(1000px) rotateY(38deg);transform-origin:center}
.wf-right{transform:perspective(1000px) rotateY(-38deg);transform-origin:center}
/* the central monitor: centred and sized to the wings' inner-edge span (the 20%/80% taper),
   so its top and bottom sit flush with the waist of the bowtie; content scrolls inside */
.viewscreen{min-width:0;align-self:center;height:60vh;overflow:auto;border:1px solid var(--orange);background:linear-gradient(180deg,rgba(255,106,0,.05),transparent 45%);padding:16px 18px;box-shadow:0 0 34px rgba(255,106,0,.12),inset 0 0 44px rgba(0,0,0,.55)}
.hexmark{font-size:40px;color:var(--orange);text-align:center;opacity:.55;text-shadow:0 0 18px rgba(255,106,0,.5)}
.cnav{display:grid;gap:6px}
.cnav a{color:var(--fg);border:1px solid var(--line);padding:8px 10px;font-size:12px;letter-spacing:2px}
.cnav a:hover{border-color:var(--orange);color:var(--orange);text-decoration:none;background:rgba(255,106,0,.06)}
.readout{display:grid;gap:5px;font-size:11px}
.ro{display:flex;justify-content:space-between;gap:8px;border-bottom:1px dotted var(--line);padding-bottom:3px;color:var(--mut);letter-spacing:1px}
.ro b{color:var(--amber);font-weight:700}.ro b.grn{color:var(--green)}
.panel-tag{font-size:10px;letter-spacing:3px;color:var(--orange);text-transform:uppercase}
.reticle{font-size:42px;color:var(--orange);text-align:center;opacity:.5;text-shadow:0 0 16px rgba(255,106,0,.5)}
@media(max-width:840px){.cockpit{grid-template-columns:1fr}.console,.sidepanel{position:static;clip-path:none;min-height:auto}.tilt-l,.tilt-r{transform:none}.cwrap{width:auto}}
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
input,select,textarea{background:#0c0703;color:var(--fg);border:1px solid var(--line);border-radius:0;padding:9px 10px;font:inherit;width:100%}
textarea{resize:vertical;line-height:1.4}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--orange);box-shadow:0 0 0 1px var(--orange)}
.hint{color:var(--mut);font-size:11px;letter-spacing:.3px;text-transform:none;margin:-4px 0 2px;line-height:1.4}
/* hexagonal action buttons: clip to a horizontal hex, text centred inside; glow via drop-shadow
   (box-shadow would be clipped away by clip-path), outline variants become translucent fills */
button{position:relative;background:var(--orange);color:#140a04;border:0;border-radius:0;padding:12px 30px;font:inherit;font-weight:700;letter-spacing:2px;text-transform:uppercase;cursor:pointer;clip-path:polygon(8% 0,92% 0,100% 50%,92% 100%,8% 100%,0 50%);filter:drop-shadow(0 0 9px rgba(255,120,0,.45))}
button:hover{background:var(--amber);color:#140a04}button:disabled{opacity:.45;cursor:not-allowed;filter:none}
button.danger{background:rgba(255,42,42,.2);color:#ff8a8a}
button.danger:hover{background:var(--red);color:#140a04}
button.ghost,button.reset,button.swap{background:rgba(255,120,0,.14);color:var(--amber);filter:drop-shadow(0 0 7px rgba(255,120,0,.3))}
button.ghost:hover,button.reset:hover,button.swap:hover{background:rgba(255,170,20,.3);color:var(--amber)}
button.swap{padding:11px 18px}
.hazard{height:7px;background:repeating-linear-gradient(45deg,var(--orange) 0 12px,var(--bg2) 12px 24px);opacity:.85}
@keyframes breathe{0%,100%{box-shadow:0 0 54px rgba(255,120,0,.22),inset 0 0 70px rgba(255,150,30,.07)}50%{box-shadow:0 0 86px rgba(255,140,0,.4),inset 0 0 96px rgba(255,160,40,.13)}}
.btnrow{display:flex;gap:12px;margin-top:4px}
/* autonomy dial */
.dial{border:1px solid var(--line);padding:12px;display:grid;gap:8px}
.dial legend{color:var(--orange);font-size:11px;letter-spacing:3px;padding:0 6px}
.radio{display:grid;grid-template-columns:auto auto 1fr;align-items:center;gap:10px;text-transform:none;letter-spacing:.3px;color:var(--fg);font-size:13px}
.radio b{color:var(--amber);letter-spacing:2px}
.dial .radio:first-of-type b{color:var(--purple)}
.dial .radio:first-of-type input{accent-color:var(--purple)}
.radio span{color:var(--mut);font-size:12px}
/* runs list */
.runs{list-style:none;padding:0;max-height:42vh;overflow-y:auto}.runs li{padding:9px 0;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.runs a{color:var(--fg)}
/* badges */
.badge{font-size:11px;padding:2px 9px;border:1px solid var(--line);letter-spacing:2px;text-transform:uppercase}
.badge.running{color:var(--green);border-color:var(--green);animation:livepulse 1.6s infinite}
@keyframes livepulse{0%,100%{box-shadow:0 0 0 rgba(134,214,51,0)}50%{box-shadow:0 0 12px rgba(134,214,51,.5)}}
.badge.waiting{color:var(--amber);border-color:var(--amber);animation:pulse 1.6s infinite}
.badge.done{color:var(--green);border-color:var(--green)}
.badge.aborted{color:var(--mut)}
.badge.error{color:var(--red);border-color:var(--red)}
.badge.matrix{color:var(--purple);border-color:var(--purple)}
.badge.cap{color:var(--yellow);border-color:var(--yellow);text-shadow:0 0 8px rgba(255,210,26,.5)}
.scan{position:relative}
/* moves */
.moves{display:grid;gap:6px}
.move{display:grid;grid-template-columns:auto 90px 1fr 90px 60px;gap:10px;align-items:center;padding:8px 10px;border:1px solid var(--line);background:#0c0703;text-transform:none;letter-spacing:.3px;cursor:pointer;font-size:12px}
.move:hover{border-color:var(--orange)}
.mv-tool{color:var(--orange);font-weight:700}
.mv-path{color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mv-surface{font-size:10px;letter-spacing:1px;text-align:center;padding:2px 4px;border:1px solid var(--line);color:var(--mut)}
.s-html-page{color:var(--amber);border-color:var(--amber)}
.s-json-api{color:#58a6ff;border-color:#58a6ff}
.s-spa-shell{color:var(--purple);border-color:var(--purple)}
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
.verdict-bar.hit{color:var(--yellow);border-color:var(--yellow);background:rgba(255,210,26,.1);text-shadow:0 0 14px rgba(255,210,26,.6)}
.verdict-bar.miss{color:var(--mut);border-color:var(--line)}
/* table */
table{width:100%;border-collapse:collapse;margin:14px 0}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--orange);font-weight:700;font-size:11px;letter-spacing:1.5px;text-transform:uppercase}
.runhdr{font-size:22px;color:var(--fg)}
.err{background:#1a0606;color:var(--red);padding:12px;border:1px solid var(--red);white-space:pre-wrap}
/* live telemetry log */
.log{max-height:360px;overflow:auto;font-size:12px;line-height:1.5;background:#0c0703;border:1px solid var(--line);padding:10px;display:flex;flex-direction:column;gap:2px}
.logln{color:var(--mut);white-space:pre-wrap;word-break:break-word}
.logln.hit{color:var(--yellow);font-weight:700}
.logln.warn{color:var(--amber)}
.logln.contain{color:var(--green)}
.log:empty::before{content:"⬡ awaiting telemetry…";color:var(--mut)}
.repro{background:#0c0703;border:1px solid var(--line);padding:10px;overflow:auto;color:var(--green);font-size:12px;white-space:pre-wrap;word-break:break-word}
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
/* trace timeline (themed replay) */
.trace-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
.vbadge{font-size:11px;letter-spacing:2px;padding:2px 9px;border:1px solid var(--green);color:var(--green)}
.vbadge.no{border-color:var(--red);color:var(--red)}
.tl{display:grid;gap:4px;max-height:560px;overflow:auto;border:1px solid var(--line);background:#0c0703;padding:10px}
.tlev{border-left:2px solid var(--line);padding:5px 10px;font-size:12px;color:var(--mut);opacity:.5;transition:opacity .15s}
.tlev.seen{opacity:1}
.tlev.active{border-left-color:var(--orange);background:rgba(255,106,0,.08)}
.tlev .sp{color:var(--amber);letter-spacing:1px}
.tlev.hit{border-left-color:var(--yellow)}.tlev.hit .sp{color:var(--yellow)}
.tlev.contain{border-left-color:var(--green)}.tlev.contain .sp{color:var(--green)}
.tlev.warn .sp{color:var(--red)}
.tlev .tx{color:var(--fg);white-space:pre-wrap;word-break:break-word}
.player{display:flex;gap:8px;align-items:center;margin:10px 0}
.player button{padding:7px 12px;font-size:12px}
.player .pos{color:var(--mut);font-size:11px;letter-spacing:1px}
/* wide tables scroll inside the viewscreen instead of clipping under the side panel */
.tblwrap{overflow-x:auto;max-width:100%;margin:12px 0}
.tblwrap table,.tblwrap .lb{margin:0}
/* leaderboard (themed) */
.lb{width:100%;border-collapse:collapse;margin:12px 0;min-width:560px}
.lb th,.lb td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);font-size:12px}
.lb th{color:var(--orange);letter-spacing:1.5px;text-transform:uppercase;font-size:11px}
.lb tr.top td{color:var(--fg)}
.lb tr.top .rank{color:var(--yellow);text-shadow:0 0 10px rgba(255,210,26,.5)}
.capcell{min-width:150px}
.capbar{height:12px;background:#0c0703;border:1px solid var(--line);position:relative;overflow:hidden}
.capbar>i{display:block;height:100%;background:linear-gradient(90deg,var(--amber),var(--yellow))}
.capbar>span{position:absolute;right:4px;top:-1px;font-size:10px;color:var(--fg)}
.rank{color:var(--orange);font-weight:700}
/* target "Angel" viz */
.angel{display:grid;gap:10px}
.angel .core{position:relative;height:88px;display:flex;align-items:center;justify-content:center}
.angel .ring{position:absolute;inset:0;margin:auto;width:84px;height:84px;border:1px solid var(--line);border-radius:50%}
.angel .ring.r2{width:56px;height:56px;border-color:rgba(255,106,0,.3)}
.angel .ring.r3{width:30px;height:30px;border-color:rgba(255,106,0,.5)}
.angel .pat{font-size:12px;letter-spacing:2px;color:var(--green);z-index:1;text-align:center}
.angel.breached .ring{border-color:rgba(255,210,26,.6);animation:pulse 1.4s infinite}
.angel.breached .pat{color:var(--yellow);text-shadow:0 0 12px rgba(255,210,26,.6)}
.angel .cross{position:absolute;inset:0;background:
  linear-gradient(var(--line),var(--line)) center/1px 100% no-repeat,
  linear-gradient(var(--line),var(--line)) center/100% 1px no-repeat;opacity:.4}
.nodes{display:grid;gap:3px;max-height:110px;overflow:hidden;font-size:11px}
.node{display:flex;gap:6px;align-items:center;border:1px solid var(--line);padding:4px 7px;color:var(--mut);background:#0c0703}
.node .m{color:var(--amber);font-size:10px;min-width:30px}
.node .p{color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.node.hit{border-color:var(--orange);color:var(--orange)}
.node.hit .p{color:var(--orange)}
.count{font-size:11px;color:var(--mut);letter-spacing:1px}
/* THREE-ROLE SWAPPABLE COCKPIT (run view): input | execution | output. Arrows swap a wing
   into the centre to focus it; the two side wings recede toward the centre in perspective. */
.cockpit3{display:grid;grid-template-columns:1fr 46vw 1fr;gap:18px;align-items:center;min-height:calc(100vh - 96px)}
.slot{min-width:0}
.slot-center{align-self:center;height:66vh;overflow:auto;border:1px solid rgba(255,138,0,.85);background:radial-gradient(135% 105% at 50% -5%,rgba(255,150,12,.14),rgba(255,105,0,.05) 44%,rgba(10,6,2,.96) 100%);padding:16px 18px;box-shadow:0 0 64px rgba(255,120,0,.28),0 0 140px rgba(255,80,0,.12),inset 0 0 80px rgba(255,150,30,.06);animation:breathe 3.4s ease-in-out infinite}
.slot-left,.slot-right{height:calc(100vh - 96px);background:radial-gradient(125% 85% at 50% 50%,rgba(255,142,12,.12),rgba(255,100,0,.04) 46%,rgba(9,5,2,.96) 100%);overflow:hidden;display:flex;align-items:center;justify-content:center;cursor:pointer;filter:drop-shadow(0 0 1.5px rgba(255,165,45,.95)) drop-shadow(0 0 20px rgba(255,120,0,.3))}
.slot-left{clip-path:polygon(0 0,100% 17%,100% 83%,0 100%)}
.slot-right{clip-path:polygon(0 17%,100% 0,100% 100%,0 83%)}
/* wing content lies on a plane receding toward the central horizon: the words slant parallel
   to the converging trapezoid edges (every view, not just the immersive run) */
.slot-left .role,.slot-right .role{width:82%;transform:perspective(1100px) rotateY(34deg);transform-origin:center}
.slot-right .role{transform:perspective(1100px) rotateY(-34deg)}
.slot-center .role{width:100%}
/* config-view wings behave exactly like the run view's wings: the base perspective recede alone,
   so every div — the title and each body line — slants on the receding plane. No title-specific
   transforms, no anchoring hacks. A long wing list (the sortie log) scrolls inside its own fixed
   box (like the run view's FEED log) so the title stays put and nothing overflows the trapezoid. */
.cockpit3:not(.immersive) .slot-center{height:72vh;animation:none}
.cockpit3:not(.immersive) .slot-left,.cockpit3:not(.immersive) .slot-right{cursor:default}
/* big wing titles anchored at the top of the receding plane (the wide outer end) */
.slot-left .rolehdr,.slot-right .rolehdr{font-size:20px;letter-spacing:4px;padding-bottom:9px}
.role{display:grid;gap:11px;align-content:start}
.rolehdr{font-size:13px;letter-spacing:3px;color:var(--orange);text-transform:uppercase;border-bottom:1px solid rgba(255,120,0,.35);padding-bottom:6px;text-shadow:0 0 12px rgba(255,120,0,.5)}
.slot-center .rolehdr{font-size:15px}
.kv{display:flex;justify-content:space-between;gap:10px;font-size:13px;letter-spacing:1px;border-bottom:1px solid var(--line);padding-bottom:5px;text-transform:uppercase}
.kv span{color:var(--mut)} .kv b{color:var(--amber);font-weight:700;text-align:right}
.kv b.brk{word-break:break-all;font-weight:400;color:var(--fg);text-align:left}
.ev{font-size:12px;color:var(--mut);border-bottom:1px solid var(--line);padding:4px 0;white-space:pre-wrap;word-break:break-word}
.ev .ft{color:var(--orange);font-size:10px;letter-spacing:1px;text-transform:uppercase}
.evlog{display:grid;gap:2px}
/* bottom dock: swap arrows + site nav */
.dock{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:16px;margin-top:10px;border-top:1px solid rgba(255,106,0,.3);padding-top:10px}
.homedock{grid-template-columns:1fr 46vw 1fr}
.homedock>button{justify-self:center}
.homedock .docknav{justify-self:end}
.swap{background:transparent;color:var(--orange);border:1px solid var(--orange);font-size:18px;padding:6px 18px;letter-spacing:0}
.swap:hover{background:var(--orange);color:#0a0a0a}
.dockmid{display:flex;flex-direction:column;align-items:center;gap:4px;text-align:center}
.dtitle{font-size:16px;letter-spacing:3px;text-transform:uppercase;color:var(--fg)}
.docknav{font-size:12px;letter-spacing:2px;color:var(--mut)}
.docknav a{color:var(--amber)}
@media(max-width:860px){.cockpit3{grid-template-columns:1fr;min-height:auto}.slot-left,.slot-right{height:auto;clip-path:none}.slot-left .role,.slot-right .role{transform:none;width:auto}.slot-center{height:auto}}
/* config header strip + live lenses + rising decision overlay */
.hudbar{display:flex;gap:14px;align-items:center;flex-wrap:wrap;border:1px solid rgba(255,106,0,.3);padding:8px 14px;margin-bottom:10px;background:linear-gradient(90deg,rgba(255,106,0,.05),transparent)}
.hudbar .dtitle{font-size:15px;letter-spacing:3px;text-transform:uppercase}
.hudbar .hudcfg{color:var(--mut);font-size:12px;letter-spacing:1px}
.hudbar .hudphase{margin-left:auto;color:var(--yellow);font-size:12px;letter-spacing:2px;text-shadow:0 0 10px rgba(255,210,26,.45)}
.slot-center{position:relative}
.slot-center .log,.slot-center .evlog{max-height:none}
.lens .rolehdr .count{color:var(--mut);font-size:11px}
.lens .log,.lens .evlog,.lens .tblwrap,.lens .repro,.lens .tl{background:transparent;border-color:rgba(255,120,0,.22)}
.lens .node{background:rgba(255,120,0,.06);border-color:rgba(255,120,0,.28)}
.lens table tr{border-color:rgba(255,120,0,.16)}
.decision{position:absolute;inset:0;z-index:5;background:linear-gradient(180deg,rgba(20,10,30,.97),rgba(10,6,14,.98));border:1px solid var(--purple);padding:16px 18px;overflow:auto;display:grid;gap:12px;align-content:start;box-shadow:inset 0 0 44px rgba(150,95,212,.14),0 0 46px rgba(150,95,212,.3)}
.decision .card-tag.warn{color:var(--purple)}
.decision[hidden]{display:none}
.decision.rise{animation:rise .35s ease-out}
@keyframes rise{from{transform:translateY(26px);opacity:0}to{transform:translateY(0);opacity:1}}
.cockpit3.decided .slot-left,.cockpit3.decided .slot-right{opacity:.3;filter:blur(1px)}
.reset{font-size:11px;letter-spacing:2px;padding:5px 14px}
</style>
`
