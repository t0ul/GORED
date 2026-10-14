// Package eva is the GORED web cockpit: the surface you pilot a security-testing run from.
// You pick a stage, a target and a model, launch a run, and watch it land — the same
// appsweep.Run the CLI calls, driven in-process. It is a thin frontend over the internal
// library; it holds no testing logic of its own, only run orchestration and rendering.
package eva

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/t0ul/GORED/internal/appsweep"
	"github.com/t0ul/GORED/internal/bench"
	"github.com/t0ul/GORED/internal/core"
)

// run is one launched sweep's live state, kept in memory for this process.
type run struct {
	ID      string
	Stage   string
	Base    string
	Model   string
	Trials  int
	Status  string // "running" | "done" | "error"
	Err     string
	Started time.Time
	Elapsed string
	Sums    []core.ContenderSummary
	Trace   string
}

// Server is the cockpit. It keeps a registry of runs and serializes execution: a run boots a
// local model and reclaims its ports, so two at once would fight — one pilot, one EVA.
type Server struct {
	mu      sync.Mutex
	runs    map[string]*run
	order   []string // run ids, most recent first
	running bool
	traces  string // directory for per-run trace files
}

func NewServer(traceDir string) *Server {
	if traceDir == "" {
		traceDir = "."
	}
	return &Server{runs: map[string]*run{}, traces: traceDir}
}

// Handler wires the routes (Go 1.22+ pattern mux).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("POST /run", s.launch)
	mux.HandleFunc("GET /run/{id}", s.runPage)
	return mux
}

func (s *Server) home(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	recent := make([]*run, 0, len(s.order))
	for _, id := range s.order {
		recent = append(recent, s.runs[id])
	}
	busy := s.running
	s.mu.Unlock()

	// Stage cards from the library, so the cockpit always matches the real stages.
	type stageView struct{ Name, Goal string }
	var sv []stageView
	for name, st := range appsweep.Stages() {
		sv = append(sv, stageView{Name: name, Goal: st.Goal})
	}
	sort.Slice(sv, func(i, j int) bool { return sv[i].Name < sv[j].Name })

	render(w, homeTmpl, map[string]any{"Stages": sv, "Recent": recent, "Busy": busy})
}

func (s *Server) launch(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	stage := r.FormValue("stage")
	if _, ok := appsweep.Stages()[stage]; !ok {
		http.Error(w, "unknown stage "+stage, http.StatusBadRequest)
		return
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
	if v, err := strconv.Atoi(r.FormValue("trials")); err == nil && v > 0 {
		f.Trials = v
	}
	if r.FormValue("ensure") == "" {
		f.Ensure = false
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		http.Error(w, "a run is already in flight — one EVA at a time", http.StatusConflict)
		return
	}
	id := strconv.FormatInt(time.Now().UnixNano(), 36)
	f.Trace = filepath.Join(s.traces, "gored-eva-"+id+"-trace.jsonl")
	rn := &run{ID: id, Stage: stage, Base: f.Base, Model: f.Model, Trials: f.Trials,
		Status: "running", Started: time.Now(), Trace: f.Trace}
	s.runs[id] = rn
	s.order = append([]string{id}, s.order...)
	s.running = true
	s.mu.Unlock()

	go s.execute(rn, f, stage)
	http.Redirect(w, r, "/run/"+id, http.StatusSeeOther)
}

// execute runs the sweep (minutes: model boot + loop) and records the outcome.
func (s *Server) execute(rn *run, f *bench.Flags, stage string) {
	results, err := appsweep.Run(context.Background(), f, stage)
	s.mu.Lock()
	defer s.mu.Unlock()
	rn.Elapsed = time.Since(rn.Started).Round(time.Second).String()
	if err != nil {
		rn.Status, rn.Err = "error", err.Error()
	} else {
		rn.Status, rn.Sums = "done", core.Summarize(results)
	}
	s.running = false
}

func (s *Server) runPage(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	rn := s.runs[r.PathValue("id")]
	s.mu.Unlock()
	if rn == nil {
		http.NotFound(w, r)
		return
	}
	render(w, runTmpl, rn)
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

var funcs = template.FuncMap{
	"pct":      func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) },
	"captured": captured,
}

var homeTmpl = template.Must(template.New("home").Funcs(funcs).Parse(baseCSS + `
<h1>GORED · EVA</h1>
<p class="sub">Pilot a security-testing run against a local app. One stage, one target, one model.</p>
<form method="post" action="/run" class="card">
  <label>Stage
    <select name="stage">{{range .Stages}}<option value="{{.Name}}">{{.Name}} — {{.Goal}}</option>{{end}}</select>
  </label>
  <label>Target base URL <input name="base" value="http://127.0.0.1:8088"></label>
  <label>Model (GGUF) <input name="model" value="qwen2.5-3b-instruct.gguf"></label>
  <label>Brig bridge <input name="bridge" value="127.0.0.1:5050"></label>
  <label>Trials <input name="trials" type="number" value="1" min="1"></label>
  <label class="chk"><input type="checkbox" name="ensure" value="1" checked> auto-launch vulnapp</label>
  <button {{if .Busy}}disabled{{end}}>{{if .Busy}}a run is in flight…{{else}}Launch{{end}}</button>
</form>
<h2>Recent runs</h2>
{{if .Recent}}<ul class="runs">{{range .Recent}}
  <li><a href="/run/{{.ID}}">{{.Stage}} vs {{.Base}}</a> <span class="badge {{.Status}}">{{.Status}}</span></li>
{{end}}</ul>{{else}}<p class="muted">none yet</p>{{end}}
`))

var runTmpl = template.Must(template.New("run").Funcs(funcs).Parse(baseCSS + `
{{if eq .Status "running"}}<meta http-equiv="refresh" content="3">{{end}}
<p><a href="/">← cockpit</a></p>
<h1>{{.Stage}} <span class="badge {{.Status}}">{{.Status}}</span></h1>
<p class="sub">vs {{.Base}} · model {{.Model}} · {{.Trials}} trial(s){{if .Elapsed}} · {{.Elapsed}}{{end}}</p>
{{if eq .Status "running"}}<p class="muted">booting the model and running the loop… this page refreshes itself.</p>{{end}}
{{if .Err}}<pre class="err">{{.Err}}</pre>{{end}}
{{if .Sums}}
  <p class="verdict {{if captured .Sums}}hit{{else}}miss{{end}}">{{if captured .Sums}}● captured — oracle-confirmed{{else}}○ no capture{{end}}</p>
  <table><thead><tr><th>contender</th><th>cap%</th><th>captured</th><th>tools</th><th>tokens</th></tr></thead><tbody>
  {{range .Sums}}<tr><td>{{.Contender}}</td><td>{{pct .CaptureRate}}</td><td>{{.Captured}}/{{.Trials}}</td><td>{{printf "%.1f" .MeanToolCall}}</td><td>{{printf "%.0f" .MeanTokens}}</td></tr>{{end}}
  </tbody></table>
{{end}}
<p class="muted">trace: {{.Trace}}</p>
`))

const baseCSS = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GORED · EVA</title>
<style>
:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--card:#161b22;--line:#30363d;--acc:#7c3aed;--hit:#3fb950;--miss:#8b949e;--err:#f85149}
body{background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 16px}
h1{margin:.2rem 0}.sub{color:var(--mut);margin-top:0}.muted{color:var(--mut)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;display:grid;gap:10px}
label{display:grid;gap:4px;font-size:13px;color:var(--mut)}label.chk{grid-auto-flow:column;justify-content:start;align-items:center;gap:8px}
input,select{background:#0d1117;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:7px 9px;font:inherit}
button{background:var(--acc);color:#fff;border:0;border-radius:7px;padding:9px 14px;font:inherit;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
table{width:100%;border-collapse:collapse;margin:12px 0}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}th{color:var(--mut);font-weight:600;font-size:12px}
.badge{font-size:12px;padding:2px 8px;border-radius:999px;border:1px solid var(--line)}.badge.running{color:#d29922}.badge.done{color:var(--hit)}.badge.error{color:var(--err)}
.runs{list-style:none;padding:0}.runs li{padding:7px 0;border-bottom:1px solid var(--line)}.runs a{color:var(--fg)}
.verdict{font-weight:700}.verdict.hit{color:var(--hit)}.verdict.miss{color:var(--miss)}
.err{background:#2d0f0f;color:var(--err);padding:12px;border-radius:8px;white-space:pre-wrap}
a{color:#58a6ff}
</style>
`
