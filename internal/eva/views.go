package eva

import (
	"embed"
	"fmt"
	"github.com/t0ul/GORED/internal/core"
	"html/template"
	"net/http"
	"strings"
)

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
	difftraceTmpl   = page("difftrace")
)
