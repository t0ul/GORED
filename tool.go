package gored

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrEgressDenied is returned by a network tool when a request targets a host that
// is not on the egress allowlist. The loop records it as a denied beacon in the
// trace — the observable proof that containment holds even if a tool argument was
// prompt-injected by untrusted target output.
var ErrEgressDenied = errors.New("egress denied: host not on allowlist")

// Tool is a sharp, bounded capability the agent can invoke. Keeping the set small
// (http_request, exec) is deliberate: the measurement is the model's reasoning, not
// the richness of the toolbelt.
type Tool interface {
	Name() string
	Describe() string
	Call(ctx context.Context, args map[string]any) (result string, err error)
}

// Toolbox is an ordered registry of tools.
type Toolbox struct {
	order []string
	tools map[string]Tool
}

func NewToolbox(ts ...Tool) *Toolbox {
	b := &Toolbox{tools: map[string]Tool{}}
	for _, t := range ts {
		b.tools[t.Name()] = t
		b.order = append(b.order, t.Name())
	}
	return b
}

func (b *Toolbox) Get(name string) (Tool, bool) { t, ok := b.tools[name]; return t, ok }

// names returns the registered tool names in order.
func (b *Toolbox) names() []string { return b.order }

// Resolve looks up a tool tolerantly. Weak models sometimes echo a placeholder
// like "http_request|exec" or "http_request (GET)"; Resolve first tries an exact
// match, then returns the first registered tool named in the string. It reports the
// resolved canonical name so the trace records what actually ran.
func (b *Toolbox) Resolve(name string) (Tool, string, bool) {
	if t, ok := b.tools[name]; ok {
		return t, name, true
	}
	lower := strings.ToLower(name)
	for _, n := range b.order {
		if strings.Contains(lower, n) {
			return b.tools[n], n, true
		}
	}
	return nil, "", false
}

// Describe renders the toolbox for the model prompt.
func (b *Toolbox) Describe() string {
	var sb strings.Builder
	for _, n := range b.order {
		fmt.Fprintf(&sb, "- %s: %s\n", n, b.tools[n].Describe())
	}
	return sb.String()
}

// Egress is the allowlist gate every outbound network request passes through. The
// allowlist is set to the target host:port(s) only (plan §9), so the agent can
// reach the target and nothing else — the containment boundary.
type Egress struct {
	allow map[string]bool
}

// NewEgress allows exactly the given host:port authorities. A bare host with no
// port allows any port on that host.
func NewEgress(authorities ...string) *Egress {
	e := &Egress{allow: map[string]bool{}}
	for _, a := range authorities {
		e.allow[strings.ToLower(a)] = true
	}
	return e
}

// Allowed reports whether a URL's host:port is permitted.
func (e *Egress) Allowed(rawurl string) bool {
	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return e.allow[host+":"+port] || e.allow[host]
}

// Authorities returns the allowlist, sorted, for logging.
func (e *Egress) Authorities() []string {
	out := make([]string, 0, len(e.allow))
	for a := range e.allow {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Sessions is a registry of named cookie-jar HTTP clients shared across tools. Its
// point is authenticated discovery: an identity established by a login through
// http_request is carried into discover's crawl because both tools draw their
// client from the same registry (see WebRecon). Each name gets its own jar — the
// empty name included — so distinct identities ("attacker"/"victim") stay isolated.
// A registry lives for one run and one agent, so trials never bleed cookies.
type Sessions struct {
	mu      sync.Mutex
	clients map[string]*http.Client
	timeout time.Duration
}

func NewSessions() *Sessions {
	return &Sessions{clients: map[string]*http.Client{}, timeout: 8 * time.Second}
}

// Client returns the client for a session name, lazily giving each its own cookie
// jar so logging in once keeps the agent logged in as that identity. Every name,
// the empty default included, is stateful — statefulness by default — while named
// sessions give isolated identities for differential tests.
func (s *Sessions) Client(session string) *http.Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clients[session]; ok {
		return c
	}
	c := &http.Client{Timeout: s.timeout}
	jar, _ := cookiejar.New(nil)
	c.Jar = jar
	s.clients[session] = c
	return c
}

// HTTPRequestTool performs HTTP requests, but only through the Egress gate. The
// agent may give a path (resolved against the target base URL) or an absolute URL;
// either way the final host:port must be on the allowlist or the call is denied.
type HTTPRequestTool struct {
	Base   string // target base URL, e.g. http://127.0.0.1:18080
	Egress *Egress
	// OnDeny is called with the denied URL so the loop can emit the beacon event.
	OnDeny func(rawurl string)
	// AllowMethods, when non-nil, is the set of HTTP methods the agent may use
	// (upper-case). It is the safety rail for pointing the agent at a real app you
	// are building: restrict it to read-only verbs so a stochastic agent cannot
	// mutate or destroy real data. Nil means every method is allowed.
	AllowMethods map[string]bool
	// Sessions holds the per-identity cookie jars. Share one registry with a
	// DiscoverTool (WebRecon does this) so a login made here is reused by discovery.
	Sessions *Sessions
}

func NewHTTPRequestTool(base string, e *Egress, onDeny func(string)) *HTTPRequestTool {
	return &HTTPRequestTool{
		Base:     strings.TrimRight(base, "/"),
		Egress:   e,
		OnDeny:   onDeny,
		Sessions: NewSessions(),
	}
}

func (*HTTPRequestTool) Name() string { return "http_request" }
func (*HTTPRequestTool) Describe() string {
	return `issue an HTTP request. args: {"method":"GET|POST","path":"/...","headers":{...},"body":"...","session":"name"}. "session" keeps cookies across calls under that name, so log in once and reuse it (use two names like "attacker" and "victim" to compare identities). Returns "HTTP <status>\n<key headers incl set-cookie/location>\n<body>".`
}

func (t *HTTPRequestTool) Call(ctx context.Context, args map[string]any) (string, error) {
	method := strings.ToUpper(asString(args["method"]))
	if method == "" {
		method = http.MethodGet
	}
	if t.AllowMethods != nil && !t.AllowMethods[method] {
		return fmt.Sprintf("refused: method %s not permitted by policy (read-only)", method), nil
	}
	raw := asString(args["url"])
	if raw == "" {
		p := asString(args["path"])
		if p == "" {
			return "", fmt.Errorf("http_request: need path or url")
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		raw = t.Base + p
	}
	if !t.Egress.Allowed(raw) {
		if t.OnDeny != nil {
			t.OnDeny(raw)
		}
		return "", fmt.Errorf("%w: %s", ErrEgressDenied, raw)
	}
	var body io.Reader
	if b := asString(args["body"]); b != "" {
		body = strings.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, raw, body)
	if err != nil {
		return "", err
	}
	if hdrs, ok := args["headers"].(map[string]any); ok {
		for k, v := range hdrs {
			req.Header.Set(k, asString(v))
		}
	}
	resp, err := t.Sessions.Client(asString(args["session"])).Do(req)
	if err != nil {
		// A transport failure is retryable; label it so the agent backs off and
		// retries rather than treating it as a verdict about the target.
		return "", fmt.Errorf("transport error [retryable]: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	// Prefix the status with an error class + what to do next, so the agent branches
	// on the class instead of guessing from a bare status (jp3g's retryable-flag idea).
	return fmt.Sprintf("HTTP %d [%s]\n%s%s", resp.StatusCode, classifyStatus(resp.StatusCode), headerLines(resp.Header), string(data)), nil
}

// classifyStatus maps an HTTP status to an action class for the agent: whether the
// response is data to act on, an auth problem to re-login for, a rate limit to back
// off from, or a server error worth one retry.
func classifyStatus(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "ok"
	case status == 401 || status == 403:
		return "auth: authenticate or try another identity, do not retry unchanged"
	case status == 429:
		return "rate-limited: back off before retrying"
	case status >= 500:
		return "server error: retry once, then treat as data"
	case status >= 400:
		return "client error: treat as data, fix the request"
	default:
		return "redirect"
	}
}

// interestingHeaders are surfaced to the agent: they carry the session, redirects,
// content type, and auth challenges that drive access-control reasoning.
var interestingHeaders = []string{"Set-Cookie", "Location", "Content-Type", "WWW-Authenticate", "Www-Authenticate"}

func headerLines(h http.Header) string {
	var sb strings.Builder
	seen := map[string]bool{}
	for _, name := range interestingHeaders {
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, v := range h.Values(name) {
			fmt.Fprintf(&sb, "%s: %s\n", key, v)
		}
	}
	return sb.String()
}

// ExecTool runs a short, allowlisted, non-network command in a bounded sandbox.
// The allowlist deliberately excludes any network binary: the only sanctioned way
// off the box is HTTPRequestTool through the Egress gate, so exec cannot be a
// containment hole. It is here for decode/transform/inspect steps.
type ExecTool struct {
	Allow   map[string]bool
	Timeout time.Duration
}

func NewExecTool() *ExecTool {
	return &ExecTool{
		Allow:   map[string]bool{"echo": true, "cat": true, "grep": true, "base64": true, "head": true, "wc": true},
		Timeout: 5 * time.Second,
	}
}

func (*ExecTool) Name() string { return "exec" }
func (e *ExecTool) Describe() string {
	return `run an allowlisted local command for decode/inspect. args: {"argv":["base64","-d"],"stdin":"..."}. Allowed: echo cat grep base64 head wc. No network commands.`
}

func (e *ExecTool) Call(ctx context.Context, args map[string]any) (string, error) {
	rawv, ok := args["argv"].([]any)
	if !ok || len(rawv) == 0 {
		return "", fmt.Errorf("exec: need non-empty argv array")
	}
	argv := make([]string, len(rawv))
	for i, a := range rawv {
		argv[i] = asString(a)
	}
	if !e.Allow[argv[0]] {
		return "", fmt.Errorf("exec: command %q not on allowlist", argv[0])
	}
	cctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	if stdin := asString(args["stdin"]); stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	trimmed := string(out)
	if len(trimmed) > 8<<10 {
		trimmed = trimmed[:8<<10] + "…"
	}
	if err != nil {
		return trimmed, fmt.Errorf("exec: %w", err)
	}
	return trimmed, nil
}

// DiffTool compares two texts (typically two identities' responses to the same
// resource). The access-control signal is a diff: if a victim's resource comes
// back byte-identical to an unauthorized request, authorization is broken.
type DiffTool struct{}

func (DiffTool) Name() string { return "diff" }
func (DiffTool) Describe() string {
	return `compare two responses. args: {"a":"...","b":"..."}. Reports whether they are identical and the first line that differs — use it to tell whether one identity sees another identity's data.`
}

func (DiffTool) Call(_ context.Context, args map[string]any) (string, error) {
	a, b := asString(args["a"]), asString(args["b"])
	if a == b {
		return fmt.Sprintf("identical (%d bytes) — same bytes for both inputs", len(a)), nil
	}
	la, lb := strings.Split(a, "\n"), strings.Split(b, "\n")
	n := len(la)
	if len(lb) < n {
		n = len(lb)
	}
	for i := 0; i < n; i++ {
		if la[i] != lb[i] {
			return fmt.Sprintf("differ: len(a)=%d len(b)=%d; first diff at line %d:\n  a: %s\n  b: %s",
				len(a), len(b), i+1, trunc(la[i], 120), trunc(lb[i], 120)), nil
		}
	}
	return fmt.Sprintf("differ only in length: len(a)=%d len(b)=%d (one is a prefix of the other)", len(a), len(b)), nil
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// CurlFor renders an http_request tool call as a curl command, so a finding comes
// with a human-runnable reproduction. It does NOT invent the session cookie (that
// is held in the agent's jar, established by an earlier login request); a full
// verification script re-runs that login first. Use it for the repro line in a
// write-up; use a harness-emitted script for a fully self-contained re-run.
func CurlFor(base string, args map[string]any) string {
	method := strings.ToUpper(asString(args["method"]))
	if method == "" {
		method = "GET"
	}
	where := asString(args["url"])
	if where == "" {
		p := asString(args["path"])
		if p != "" && !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		where = strings.TrimRight(base, "/") + p
	}
	var b strings.Builder
	b.WriteString("curl -i")
	if method != "GET" {
		fmt.Fprintf(&b, " -X %s", method)
	}
	if hdrs, ok := args["headers"].(map[string]any); ok {
		keys := make([]string, 0, len(hdrs))
		for k := range hdrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, " -H %s", shellQuote(k+": "+asString(hdrs[k])))
		}
	}
	if body := asString(args["body"]); body != "" {
		fmt.Fprintf(&b, " --data %s", shellQuote(body))
	}
	fmt.Fprintf(&b, " %s", shellQuote(where))
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%v", t)
	case bool:
		return fmt.Sprintf("%v", t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
