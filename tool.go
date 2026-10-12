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

	mu      sync.Mutex
	clients map[string]*http.Client // per-session cookie jars; "" = default jarless
	timeout time.Duration
}

func NewHTTPRequestTool(base string, e *Egress, onDeny func(string)) *HTTPRequestTool {
	return &HTTPRequestTool{
		Base:    strings.TrimRight(base, "/"),
		Egress:  e,
		OnDeny:  onDeny,
		clients: map[string]*http.Client{},
		timeout: 8 * time.Second,
	}
}

// clientFor returns the HTTP client for a named session, lazily giving each
// session its own cookie jar so the agent can authenticate and stay authenticated
// as that identity. The empty session is jarless (stateless). Jars are per-tool,
// which is per-run and per-agent, so trials stay independent.
func (t *HTTPRequestTool) clientFor(session string) *http.Client {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.clients[session]; ok {
		return c
	}
	c := &http.Client{Timeout: t.timeout}
	if session != "" {
		jar, _ := cookiejar.New(nil)
		c.Jar = jar
	}
	t.clients[session] = c
	return c
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
	resp, err := t.clientFor(asString(args["session"])).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return fmt.Sprintf("HTTP %d\n%s%s", resp.StatusCode, headerLines(resp.Header), string(data)), nil
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
