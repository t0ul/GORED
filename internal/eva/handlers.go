package eva

import (
	"encoding/json"
	"fmt"
	"github.com/t0ul/GORED/internal/appsweep"
	"github.com/t0ul/GORED/internal/bench"
	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/store"
	gledger "github.com/t0ul/gledger"
	"html/template"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	recent := make([]*run, 0, len(s.order))
	for _, id := range s.order {
		recent = append(recent, s.runs[id])
	}
	s.mu.Unlock()
	busy := len(s.slots) == 0 // no free bay

	// Stage cards from the library, so the cockpit always matches the real stages. The
	// instruction map pre-fills the editable prompt knob per stage, registry-aware: an
	// authored skill in the store overrides the in-code default (see effectiveInstruction).
	type stageView struct{ Name, Goal string }
	var sv []stageView
	instr := map[string]string{}
	for name, st := range appsweep.Stages() {
		sv = append(sv, stageView{Name: name, Goal: st.Goal})
		instr[name] = s.effectiveInstruction(name)
	}
	sort.Slice(sv, func(i, j int) bool { return sv[i].Name < sv[j].Name })
	ib, _ := json.Marshal(instr)

	// Prefill the form from query params, so presets and the Studio ARM deep-links can hand a
	// ready loadout (?stage=…&base=…&model=…). Empty params fall back to the defaults.
	q := r.URL.Query()
	pick := func(key, dflt string) string {
		if v := q.Get(key); v != "" {
			return v
		}
		return dflt
	}
	selStage := q.Get("stage")
	if selStage == "" && len(sv) > 0 {
		selStage = sv[0].Name
	}
	skillText := q.Get("skill")
	if skillText == "" {
		skillText = instr[selStage]
	}

	render(w, homeTmpl, map[string]any{
		"Stages": sv, "Recent": recent, "Busy": busy,
		"StageInstr":   template.JS(ib),
		"Models":       listModels(),
		"SelStage":     selStage,
		"SkillText":    skillText,
		"Ensure":       q.Get("ensure") != "0",
		"Base":         pick("base", "http://127.0.0.1:8088"),
		"Model":        pick("model", "qwen2.5-3b-instruct.gguf"),
		"MatrixModels": q.Get("models"),
		"Bridge":       pick("bridge", "127.0.0.1:5050"),
		"Trials":       pick("trials", "1"),
		"Autonomy":     pick("autonomy", "piloted"),
	})
}

// preflight is a light reachability check for the TARGET light: a short-timeout GET of the
// configured base. It makes no judgement — just whether something answered.
func (s *Server) preflight(w http.ResponseWriter, r *http.Request) {
	base := r.URL.Query().Get("base")
	ok := false
	if base != "" {
		cl := &http.Client{Timeout: 2 * time.Second}
		if resp, err := cl.Get(base); err == nil {
			resp.Body.Close()
			ok = true
		}
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"ok":%v}`, ok)
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
	if v := strings.TrimSpace(r.FormValue("skill")); v != "" && v != strings.TrimSpace(s.effectiveInstruction(stage)) {
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
		Name, Skill, Goal string
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
		stages = append(stages, stageInfo{Name: name, Skill: st.Skill.Name, Goal: st.Goal, Tools: names})
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

// saveSkill writes an edited skill instruction into the registry. Because the stages read
// their instruction from the registry (effectiveInstruction), an edit here changes what any
// run of a stage that uses this skill will actually do.
func (s *Server) saveSkill(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "no registry (run with a -store)", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "skill name required", http.StatusBadRequest)
		return
	}
	temp := core.SkillTemp(r.FormValue("temp"))
	if temp == "" {
		temp = core.SkillCold
	}
	_ = s.store.UpsertSkill(core.Skill{Name: name, Temp: temp, Instruction: r.FormValue("instruction")})
	http.Redirect(w, r, "/studio", http.StatusSeeOther)
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

// directive queues a mid-run hint on a live run; the next pilot checkpoint folds it into the
// agent's directive (see pilotCheckpoint.Decide / mergeHints). It never decides a verdict — it
// only steers which move the loop spends tokens on next, like the gate hint.
func (s *Server) directive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = r.ParseForm()
	h := strings.TrimSpace(r.FormValue("hint"))
	s.mu.Lock()
	if rn := s.runs[id]; rn != nil && (rn.Status == "running" || rn.Status == "waiting") && h != "" {
		rn.queuedHint = mergeHints(rn.queuedHint, h)
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// abort hard-cancels a live run: it cancels the run's context (interrupting in-flight model
// and tool calls, and releasing a blocked pilot gate — Decide selects on ctx.Done()) and
// marks it aborted. The clean stop is still the gate abort via decide; this is the e-stop.
func (s *Server) abort(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	rn := s.runs[id]
	if rn != nil && (rn.Status == "running" || rn.Status == "waiting") {
		if rn.cancel != nil {
			rn.cancel()
		}
		rn.Status = "aborted"
		rn.Pending = nil
	}
	s.mu.Unlock()
	if rn != nil {
		s.persist(rn)
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
