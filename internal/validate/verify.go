package validate

import (
	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/internal/tools"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"sort"
	"strings"
	"time"
)

// ReproStep is one HTTP request in a reproduction plan. The system only ever makes
// method+path+headers+body requests against the target's base URL — the model
// cannot name a host or run a command — so executing a plan can do nothing but talk
// to the target. That is why the repro is a PLAN the system runs, not bash the
// system evals: a bad plan can only make an on-target HTTP request.
type ReproStep struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// ReproPlan is an ordered sequence of requests sharing one cookie session.
type ReproPlan struct {
	Steps []ReproStep `json:"steps"`
}

// VerifyResult is the outcome of a verification.
type VerifyResult struct {
	Confirmed bool
	Plan      ReproPlan
	Curl      string // deterministic curl rendering of the plan, for a human
	Go        string // deterministic standalone Go program (no shell/curl deps)
	Attempts  int
	LastBody  string // last response (trimmed), for diagnosis when unconfirmed
}

// Verifier confirms a suspected disclosure by having a LOCAL model draft a repro
// plan from the facts, then EXECUTING that plan and checking the real marker
// actually appears. The model never sees the marker value (so it cannot fabricate
// a pass), and confirmation rests on execution, not the model's word.
type Verifier struct {
	Model   gored.ModelClient
	Base    string
	Marker  string // the system checks for this; NOT shown to the model
	Facts   string // what the attack did, minus the marker value
	Tries   int    // model drafts; default 3
	Timeout time.Duration
}

// Verify asks the model for a plan, runs it, and reports whether the marker leaked.
func (v Verifier) Verify(ctx context.Context) (VerifyResult, error) {
	tries := v.Tries
	if tries <= 0 {
		tries = 3
	}
	var res VerifyResult
	sys := `You verify a suspected broken-access-control finding by writing a minimal reproduction PLAN as JSON and nothing else:
{"steps":[{"method":"POST","path":"/...","body":"{...}","headers":{"Content-Type":"application/json"}},{"method":"GET","path":"/..."}]}
The steps run in order sharing ONE cookie session. As an UNPRIVILEGED user: first log in with the given credentials, then make the request that would disclose data you should not see. A secret marker is in that response if the app is vulnerable; you do not know its value. Output ONLY the JSON plan.`
	for attempt := 1; attempt <= tries; attempt++ {
		res.Attempts = attempt
		reply, _, err := v.Model.Chat(ctx, []gored.Message{
			{Role: gored.RoleSystem, Content: sys},
			{Role: gored.RoleUser, Content: v.Facts + "\n\nReproduction plan (JSON only):"},
		}, gored.ChatOpts{Temperature: 0.2, MaxTokens: 400})
		if err != nil {
			return res, err
		}
		plan, ok := parsePlan(reply)
		if !ok || len(plan.Steps) == 0 {
			continue
		}
		leaked, lastBody := v.run(ctx, plan)
		res.Plan, res.Curl, res.Go, res.LastBody = plan, v.renderCurl(plan), v.renderGo(plan), lastBody
		if leaked {
			res.Confirmed = true
			return res, nil
		}
	}
	return res, nil
}

// run executes the plan against the base URL with one cookie jar and reports
// whether the marker appeared in any response.
func (v Verifier) run(ctx context.Context, plan ReproPlan) (bool, string) {
	jar, _ := cookiejar.New(nil)
	to := v.Timeout
	if to == 0 {
		to = 10 * time.Second
	}
	client := &http.Client{Timeout: to, Jar: jar}
	base := strings.TrimRight(v.Base, "/")
	last := ""
	for _, s := range plan.Steps {
		method := strings.ToUpper(s.Method)
		if method == "" {
			method = http.MethodGet
		}
		p := s.Path
		if p != "" && !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		var body io.Reader
		if s.Body != "" {
			body = strings.NewReader(s.Body)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+p, body) // target only; model names no host
		if err != nil {
			continue
		}
		for k, val := range s.Headers {
			req.Header.Set(k, val)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		last = string(data)
		if strings.Contains(last, v.Marker) {
			return true, trimTo(last, 400)
		}
	}
	return false, trimTo(last, 400)
}

func (v Verifier) renderCurl(plan ReproPlan) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\nset -euo pipefail\nB=\"${1:-" + v.Base + "}\"\njar=$(mktemp)\n")
	for i, s := range plan.Steps {
		path := s.Path
		if path != "" && !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		var line strings.Builder
		line.WriteString(`curl -s -c "$jar" -b "$jar"`)
		if m := strings.ToUpper(s.Method); m != "" && m != "GET" {
			line.WriteString(" -X " + m)
		}
		keys := sortedStrKeys(s.Headers)
		for _, k := range keys {
			line.WriteString(" -H " + tools.ShellQuote(k+": "+s.Headers[k]))
		}
		if s.Body != "" {
			line.WriteString(" --data " + tools.ShellQuote(s.Body))
		}
		// Double-quote the URL so $B expands at run time.
		line.WriteString(` "$B` + path + `"`)
		if i == len(plan.Steps)-1 {
			line.WriteString(" | grep -qF " + tools.ShellQuote(v.needle()) + " && echo 'CONFIRMED: marker disclosed' || echo 'not reproduced'")
		} else {
			line.WriteString(" >/dev/null")
		}
		b.WriteString(line.String() + "\n")
	}
	return b.String()
}

// needle is the exact string the repro must find in a response to count as a
// reproduction. For a canary it is the planted marker; for a canary-free
// differential finding it is the privileged datum that leaked to the low-priv
// identity. It falls back to the GORED canary prefix when no marker is set.
func (v Verifier) needle() string {
	if v.Marker != "" {
		return v.Marker
	}
	return "GORED{"
}

// renderGo emits a self-contained Go program that replays the plan and exits 0 iff
// the marker leaks. It is the same HTTP logic the verifier itself runs, so a human
// can compile and run the exact check. No shell, curl, or grep needed.
func (v Verifier) renderGo(plan ReproPlan) string {
	var sb strings.Builder
	sb.WriteString("// Auto-generated by GORED's verifier: the repro plan was drafted by a local\n")
	sb.WriteString("// model and validated by execution. Run:  go run <this-file> [baseURL]\n")
	sb.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"io\"\n\t\"net/http\"\n\t\"net/http/cookiejar\"\n\t\"os\"\n\t\"strings\"\n)\n\n")
	sb.WriteString("func main() {\n")
	fmt.Fprintf(&sb, "\tbase := %q\n", strings.TrimRight(v.Base, "/"))
	sb.WriteString("\tif len(os.Args) > 1 {\n\t\tbase = os.Args[1]\n\t}\n")
	fmt.Fprintf(&sb, "\tNEEDLE := %q\n", v.needle())
	sb.WriteString("\tjar, _ := cookiejar.New(nil)\n\tc := &http.Client{Jar: jar}\n")
	sb.WriteString("\ttype step struct {\n\t\tmethod, path, body string\n\t\theaders            map[string]string\n\t}\n")
	sb.WriteString("\tsteps := []step{\n")
	for _, s := range plan.Steps {
		p := s.Path
		if p != "" && !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		fmt.Fprintf(&sb, "\t\t{method: %q, path: %q, body: %q, headers: %s},\n", orGet(s.Method), p, s.Body, goMap(s.Headers))
	}
	sb.WriteString("\t}\n")
	sb.WriteString(`	for _, s := range steps {
		var body io.Reader
		if s.body != "" {
			body = strings.NewReader(s.body)
		}
		req, err := http.NewRequest(s.method, base+s.path, body)
		if err != nil {
			continue
		}
		for k, v := range s.headers {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 262144))
		resp.Body.Close()
		if strings.Contains(string(b), NEEDLE) {
			fmt.Println("CONFIRMED: marker disclosed")
			os.Exit(0)
		}
	}
	fmt.Println("not reproduced")
	os.Exit(1)
}
`)
	return sb.String()
}

func orGet(m string) string {
	if m == "" {
		return "GET"
	}
	return strings.ToUpper(m)
}

func goMap(m map[string]string) string {
	if len(m) == 0 {
		return "nil"
	}
	parts := make([]string, 0, len(m))
	for _, k := range sortedStrKeys(m) {
		parts = append(parts, fmt.Sprintf("%q: %q", k, m[k]))
	}
	return "map[string]string{" + strings.Join(parts, ", ") + "}"
}

func sortedStrKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func parsePlan(reply string) (ReproPlan, bool) {
	raw, ok := gored.ExtractJSON(reply)
	if !ok {
		return ReproPlan{}, false
	}
	var p ReproPlan
	if json.Unmarshal([]byte(raw), &p) != nil {
		return ReproPlan{}, false
	}
	return p, len(p.Steps) > 0
}

func trimTo(s string, n int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
