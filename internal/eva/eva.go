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
	"github.com/t0ul/GORED/internal/appsweep"
	"github.com/t0ul/GORED/internal/bench"
	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/store"
	"net/http"
	"sync"
	"time"
)

// Server is the cockpit. It keeps a registry of runs and serializes execution: a run boots a
// local model and reclaims its ports, so two at once would fight — one pilot, one EVA.
// portStep spaces each concurrent run's model serve ports apart so two in-flight runs do
// not fight over a port (each run boots one model; 20 is ample headroom).
const portStep = 20

// stallBound stops an EVA run after this many consecutive unproductive steps (a small model
// flailing — no usable new tool call). EVA sets it on interactive runs it launches; the CLI/CI
// path (bench.DefaultFlags, MaxStall 0) is unaffected, so the benchmark loop stays byte-for-byte.
const stallBound = 4

// A CAMPAIGN is an autonomous hunt, not a 10-step benchmark: it should work the app for many steps
// and, under Loop mode, keep re-running. These give a campaign run a real budget (the benchmark /
// interactive paths keep the smaller defaults). A run still stops early on capture or a done-claim.
const (
	campaignMaxSteps = 60               // steps per pass before the run ends (vs the benchmark's 10)
	campaignWall     = 20 * time.Minute // wall-clock safety cap per pass (vs the benchmark's 240s)
	campaignStall    = 12               // tolerate more exploration/dead-ends before giving up (vs stallBound=4)
)

type Server struct {
	mu        sync.Mutex
	runs      map[string]*run
	order     []string             // run ids, most recent first
	campaigns map[string]*campaign // overnight blind campaigns
	corder    []string             // campaign ids, most recent first
	slots     chan int             // one token per concurrency bay; the token is the port offset
	traces    string               // directory for per-run trace files
	store     *store.Store         // durable run registry; nil = memory-only
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
	s := &Server{runs: map[string]*run{}, campaigns: map[string]*campaign{}, traces: traceDir, store: st, slots: slots}
	if st != nil {
		// Let the store tag each surface row with its attack class (store stays free of an eva import;
		// classifyEndpoint lives here). The recon tool and ranker filter/sort on this column.
		st.Classify = func(method, path string) string { return classifyEndpoint(method, path).class }
	}
	s.loadFromStore()
	s.loadCampaigns()
	if st != nil {
		// Seed the registry with the catalog AND each stage's own skill, so every prompt a run
		// can use is authorable data (INSERT OR IGNORE keeps any prior edit). This is what lets
		// Studio authoring actually drive the stages via effectiveInstruction.
		_ = st.SeedSkills(core.Catalog())
		var stageSkills []core.Skill
		for _, stg := range appsweep.Stages() {
			stageSkills = append(stageSkills, stg.Skill)
		}
		_ = st.SeedSkills(stageSkills)
		// Seed the default target set (demotarget + a RiskRancher shell) so the campaign console
		// has something to point at out of the box; INSERT OR IGNORE keeps operator edits.
		s.seedTargets()
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

// effectiveInstruction is the skill instruction a run of this stage will actually use: the
// store's authored version if present (the registry drives the stage), otherwise the stage's
// in-code default. This is the wiring the skills-table comment calls out — authoring in Studio
// changes what runs, resolved here at the orchestration layer over appsweep.WithSkillInstruction.
func (s *Server) effectiveInstruction(stage string) string {
	st, ok := appsweep.Stages()[stage]
	if !ok {
		return ""
	}
	def := st.Skill.Instruction
	if s.store == nil {
		return def
	}
	if row, found, _ := s.store.GetSkill(st.Skill.Name); found && row.Instruction != "" {
		return row.Instruction
	}
	return def
}

// pristineInstruction returns the in-code default for a skill name (a stage's own skill, else
// the catalog) — the target of a REVERT. Resolved server-side so the full instruction never has
// to round-trip through the browser (which normalises whitespace and would defeat the match).
func (s *Server) pristineInstruction(skill string) (string, core.SkillTemp, bool) {
	for _, st := range appsweep.Stages() {
		if st.Skill.Name == skill {
			return st.Skill.Instruction, st.Skill.Temp, true
		}
	}
	for _, sk := range core.Catalog() {
		if sk.Name == skill {
			return sk.Instruction, sk.Temp, true
		}
	}
	return "", "", false
}

// Handler wires the routes (Go 1.22+ pattern mux).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("POST /run", s.launch)
	mux.HandleFunc("GET /run/{id}", s.runPage)
	mux.HandleFunc("GET /run/{id}/events", s.events)
	mux.HandleFunc("POST /run/{id}/decide", s.decide)
	mux.HandleFunc("POST /run/{id}/abort", s.abort)
	mux.HandleFunc("POST /run/{id}/directive", s.directive)
	mux.HandleFunc("GET /compare", s.compare)
	mux.HandleFunc("GET /difftrace", s.diffTrace)
	mux.HandleFunc("GET /studio", s.studio)
	mux.HandleFunc("POST /studio/skill", s.saveSkill)
	mux.HandleFunc("POST /studio/revert", s.revertSkill)
	mux.HandleFunc("GET /run/{id}/trace", s.traceView)
	mux.HandleFunc("GET /run/{id}/leaderboard", s.runLeaderboard)
	mux.HandleFunc("GET /leaderboard", s.leaderboard)
	mux.HandleFunc("GET /preflight", s.preflight)
	mux.HandleFunc("GET /runs.json", s.runsJSON)
	// Overnight blind campaign: the console, launch, live status, and the target registry.
	mux.HandleFunc("GET /campaigns", s.campaignsPage)
	mux.HandleFunc("POST /campaign", s.campaignCreate)
	mux.HandleFunc("GET /campaign/{id}", s.campaignPage)
	mux.HandleFunc("GET /campaign/{id}/status", s.campaignStatus)
	mux.HandleFunc("GET /campaign/{id}/report", s.campaignReportHandler)
	mux.HandleFunc("GET /campaign/{id}/pentest", s.campaignPentest)
	mux.HandleFunc("GET /campaign/{id}/report.md", s.campaignReportMD)
	mux.HandleFunc("GET /campaign/{id}/surface.csv", s.campaignSurfaceCSV)
	mux.HandleFunc("POST /campaign/{id}/abort", s.campaignAbortHandler)
	mux.HandleFunc("GET /campaigns.json", s.campaignsJSON)
	mux.HandleFunc("POST /targets", s.targetSave)
	mux.HandleFunc("POST /targets/delete", s.targetDelete)
	mux.HandleFunc("GET /target/{name}/project", s.projectPage)
	return mux
}

// execute runs the sweep (minutes: model boot + loop) and records the outcome. For a
// piloted/assisted dial it installs a pilot checkpoint; autonomous installs none, so that
// path is identical to the headless loop.
func (s *Server) execute(rn *run, f *bench.Flags, stage string) {
	// A cancelable context so a hard ABORT can interrupt the run (in-flight model/tool calls,
	// and a blocked pilot gate — Decide selects on ctx.Done()). The clean stop is still the
	// gate abort; this is the emergency stop.
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	rn.cancel = cancel
	s.mu.Unlock()
	defer cancel()

	var opts []appsweep.Option
	if rn.Autonomy != "autonomous" {
		cp := &pilotCheckpoint{srv: s, run: rn, autonomy: rn.Autonomy, decided: make(chan decision)}
		s.mu.Lock()
		rn.cp = cp
		s.mu.Unlock()
		opts = append(opts, appsweep.WithCheckpoint(cp))
	}
	// The run uses the per-run override if set, else the registry's instruction for this stage
	// (an authored skill in the store, else the in-code default) — the registry drives the stage.
	inst := rn.Prompt
	if inst == "" {
		inst = s.effectiveInstruction(stage)
	}
	if inst != "" {
		opts = append(opts, appsweep.WithSkillInstruction(inst))
	}
	// Give the model a tool to record the surface it finds, attributed to its model — so each
	// model's map is its own (not scraped from the trace, not co-mingled). Campaign runs carry a
	// target name; an interactive sortie without one simply has no recorder.
	if s.store != nil && rn.targetName != "" {
		opts = append(opts, appsweep.WithExtraTools(
			surfaceSaveTool{store: s.store, target: rn.targetName, model: rn.Model, runID: rn.ID},
			// the read side: let the model pull the scoped frontier + each endpoint's contract on demand
			reconTool{store: s.store, target: rn.targetName, attemptCap: exploitAttemptCap},
		))
	}
	// Phase-scope a focused exploit run to its endpoint class's tools (set per endpoint in
	// runExploitPhase): the run then carries only those attack tools, so a weak model has no generic
	// request or crawl tool to default to. Applied after WithExtraTools, so the recorder/recon tools
	// are trimmed too unless the class allows them.
	if len(rn.allowedTools) > 0 {
		opts = append(opts, appsweep.WithAllowedTools(rn.allowedTools...))
	}

	results, err := appsweep.Run(ctx, f, stage, opts...)

	s.mu.Lock()
	rn.Elapsed = time.Since(rn.Started).Round(time.Second).String()
	rn.Pending = nil
	if rn.Status != "aborted" { // a hard ABORT already set the terminal status; don't overwrite
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
	}
	s.mu.Unlock()
	s.persist(rn)
	s.slots <- rn.slot // release the bay
}
