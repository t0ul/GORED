package eva

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/t0ul/GORED/store"
)

// campaignChild is one child run of a campaign, for the detail view.
type campaignChild struct {
	ID     string
	Stage  string
	Base   string
	Status string
	Model  string
	Found  bool
}

// campaignView is a campaign rendered for the console/detail pages.
type campaignView struct {
	ID       string
	Name     string
	Model    string
	Status   string
	Cur      string
	Elapsed  string
	Targets  string
	Loop     bool
	Pass     int
	NumRuns  int
	Findings int
	Children []campaignChild
}

// viewCampaign snapshots a campaign and its child runs under the lock.
func (s *Server) viewCampaign(c *campaign) campaignView {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := campaignView{
		ID: c.ID, Name: c.Name, Model: c.Model, Status: c.Status, Cur: c.Cur,
		Elapsed: c.Elapsed, Targets: strings.Join(c.Targets, ", "), Loop: c.Loop, Pass: c.Pass, NumRuns: len(c.RunIDs),
	}
	for _, rid := range c.RunIDs {
		rn := s.runs[rid]
		if rn == nil {
			continue
		}
		isFound := captured(rn.Sums) // helper reads the run's confirmed-finding outcome
		if isFound {
			v.Findings++
		}
		v.Children = append(v.Children, campaignChild{
			ID: rn.ID, Stage: phaseLabel(rn.Stage), Base: rn.Base, Status: rn.Status, Model: rn.Model, Found: isFound,
		})
	}
	return v
}

// targetView is a registered target plus its accumulated cross-run project-memory counts.
type targetView struct {
	store.Target
	SurfaceN int
	FindingN int
}

// campaignsPage is the campaign console: the target registry, the launch form, and the campaign log.
func (s *Server) campaignsPage(w http.ResponseWriter, _ *http.Request) {
	var targets []targetView
	if s.store != nil {
		rows, _ := s.store.ListTargets()
		for _, t := range rows {
			targets = append(targets, targetView{Target: t, SurfaceN: s.store.CountSurface(t.Name), FindingN: s.store.CountFindings(t.Name)})
		}
	}
	s.mu.Lock()
	cvs := make([]campaignView, 0, len(s.corder))
	for _, id := range s.corder {
		if c := s.campaigns[id]; c != nil {
			cvs = append(cvs, campaignView{
				ID: c.ID, Name: c.Name, Model: c.Model, Status: c.Status, Cur: c.Cur,
				Elapsed: c.Elapsed, Targets: strings.Join(c.Targets, ", "), Loop: c.Loop, Pass: c.Pass, NumRuns: len(c.RunIDs),
			})
		}
	}
	busy := len(s.slots) == 0
	s.mu.Unlock()

	render(w, campaignsTmpl, map[string]any{
		"Targets":   targets,
		"Campaigns": cvs,
		"Models":    listModels(),
		"Model":     "qwen2.5-3b-instruct.gguf",
		"Busy":      busy,
	})
}

// campaignCreate launches a campaign over the selected targets with one model.
func (s *Server) campaignCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "campaign"
	}
	model := strings.TrimSpace(r.FormValue("model"))
	if model == "" {
		model = "qwen2.5-3b-instruct.gguf"
	}
	var targets []string
	for _, t := range r.Form["target"] {
		if t = strings.TrimSpace(t); t != "" {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		http.Error(w, "select at least one target", http.StatusBadRequest)
		return
	}
	loop := r.FormValue("loop") != ""
	c := s.startCampaign(name, model, targets, loop)
	http.Redirect(w, r, "/campaign/"+c.ID, http.StatusSeeOther)
}

// campaignPage renders one campaign's live detail.
func (s *Server) campaignPage(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	c := s.campaigns[r.PathValue("id")]
	s.mu.Unlock()
	if c == nil {
		http.NotFound(w, r)
		return
	}
	render(w, campaignTmpl, s.viewCampaign(c))
}

// campaignStatus returns one campaign's live state as JSON, for the detail page's poller.
func (s *Server) campaignStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	c := s.campaigns[r.PathValue("id")]
	s.mu.Unlock()
	if c == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.viewCampaign(c))
}

// campaignAbortHandler stops a running campaign.
func (s *Server) campaignAbortHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.abortCampaign(id)
	http.Redirect(w, r, "/campaign/"+id, http.StatusSeeOther)
}

// campaignsJSON is the campaign list as data (ambient UI / polling).
func (s *Server) campaignsJSON(w http.ResponseWriter, _ *http.Request) {
	type row struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Status  string `json:"status"`
		Cur     string `json:"cur"`
		NumRuns int    `json:"runs"`
	}
	s.mu.Lock()
	out := make([]row, 0, len(s.corder))
	for _, id := range s.corder {
		if c := s.campaigns[id]; c != nil {
			out = append(out, row{ID: c.ID, Name: c.Name, Status: c.Status, Cur: c.Cur, NumRuns: len(c.RunIDs)})
		}
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// projectPage renders a target's accumulated cross-run project memory: the discovered surface
// and the findings pooled across every pass.
func (s *Server) projectPage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if s.store == nil {
		http.NotFound(w, r)
		return
	}
	t, ok, _ := s.store.GetTarget(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	surface, _ := s.store.ListSurface(name)
	findings, _ := s.store.ListFindings(name)
	render(w, projectTmpl, map[string]any{"Target": t, "Surface": surface, "Findings": findings})
}

// targetSave upserts a target from the console form.
func (s *Server) targetSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || s.store == nil {
		http.Error(w, "target name required", http.StatusBadRequest)
		return
	}
	t := store.Target{
		Name:       name,
		Base:       strings.TrimSpace(r.FormValue("base")),
		Transport:  valOr(r.FormValue("transport"), "direct"),
		Stages:     normalizeModelsCSV(r.FormValue("stages")),
		Ensure:     r.FormValue("ensure") != "",
		LoginPath:  strings.TrimSpace(r.FormValue("login_path")),
		LoginType:  valOr(r.FormValue("login_type"), "json"),
		UserField:  strings.TrimSpace(r.FormValue("user_field")),
		PassField:  strings.TrimSpace(r.FormValue("pass_field")),
		PrivCreds:  strings.TrimSpace(r.FormValue("priv_creds")),
		LowCreds:   strings.TrimSpace(r.FormValue("low_creds")),
		PrivHeader: strings.TrimSpace(r.FormValue("priv_header")),
		LowHeader:  strings.TrimSpace(r.FormValue("low_header")),
		Spec:       strings.TrimSpace(r.FormValue("spec")),
		Notes:      strings.TrimSpace(r.FormValue("notes")),
	}
	_ = s.store.SaveTarget(t)
	http.Redirect(w, r, "/campaigns", http.StatusSeeOther)
}

// targetDelete removes a target.
func (s *Server) targetDelete(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if s.store != nil {
		_ = s.store.DeleteTarget(strings.TrimSpace(r.FormValue("name")))
	}
	http.Redirect(w, r, "/campaigns", http.StatusSeeOther)
}

func valOr(v, dflt string) string {
	if v = strings.TrimSpace(v); v != "" {
		return v
	}
	return dflt
}
