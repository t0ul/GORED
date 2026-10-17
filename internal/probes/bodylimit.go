package probes

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/tools"
)

// BodyLimitFinding is one write endpoint's request-body-size result: the HTTP status it returned
// to a multi-megabyte body. A 2xx means it read and accepted the oversized body with no cap (the
// finding, CWE-770); a 413/431 means it enforced a limit (defended); anything else is inconclusive.
type BodyLimitFinding struct {
	Method    string
	Path      string
	Status    int
	SizeBytes int
	CWE       string
	Evidence  string
	flagged   bool
}

// Flagged reports that the endpoint accepted the oversized body (a 2xx) rather than rejecting it.
func (f BodyLimitFinding) Flagged() bool { return f.flagged }

// BodyLimitProbe sends one deliberately oversized request body to a write endpoint and reads the
// server's status. A server with no body-size limit reads the whole thing and processes it (2xx);
// a defended one rejects it with 413 before the handler runs. This is the unbounded-body / resource-
// exhaustion bug (CWE-770) that scanners skip because it depends on how the server is configured,
// not on a response signature. It is contained (Egress gate) and self-scoped (writes only the path
// it is given, as the identity it is given) and sends exactly one request.
type BodyLimitProbe struct {
	Base      string
	Egress    *core.Egress
	Sessions  *core.Sessions // the run's cookie jar; nil -> a fresh one (header-only auth)
	Identity  core.Identity  // the authenticated caller (cookie session and/or static headers)
	SizeBytes int            // default 2 MiB
	Timeout   time.Duration
}

// Probe sends the oversized body to path (method defaults to POST) and classifies the response.
func (p *BodyLimitProbe) Probe(ctx context.Context, method, path string) (BodyLimitFinding, error) {
	if method == "" {
		method = http.MethodPost
	}
	size := p.SizeBytes
	if size <= 0 {
		size = 2 << 20 // 2 MiB — well past any sane limit, small enough not to hurt the target
	}
	raw := urlJoin(p.Base, path)
	if !p.Egress.Allowed(raw) {
		return BodyLimitFinding{}, fmt.Errorf("%w: %s", core.ErrEgressDenied, raw)
	}
	// A generic valid-JSON body: a decoder ignoring the unknown "data" field still has to read the
	// whole request, so the oversized body exercises the size limit regardless of the endpoint schema.
	body := `{"data":"` + strings.Repeat("A", size) + `"}`
	status := p.send(ctx, method, raw, body)

	f := BodyLimitFinding{Method: method, Path: path, Status: status, SizeBytes: size, CWE: "CWE-770"}
	switch {
	case status == http.StatusRequestEntityTooLarge || status == http.StatusRequestHeaderFieldsTooLarge: // 413 / 431
		// enforced a limit — defended, not flagged
	case ok2xx(status):
		f.flagged = true
		f.Evidence = fmt.Sprintf("%s %s accepted a %d-byte request body (HTTP %d) with no size limit — unbounded request body (CWE-770): an attacker can exhaust server memory",
			method, path, size, status)
	}
	return f, nil
}

func (p *BodyLimitProbe) send(ctx context.Context, method, raw, body string) int {
	req, err := http.NewRequestWithContext(ctx, method, raw, strings.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range p.Identity.Headers {
		req.Header.Set(k, v)
	}
	sess := p.Sessions
	if sess == nil {
		sess = core.NewSessions()
	}
	to := p.Timeout
	if to == 0 {
		to = 12 * time.Second
	}
	resp, err := (&http.Client{
		Timeout:       to,
		Jar:           sess.Client(p.Identity.Session).Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// BodyLimitTool (body_limit) is the agent-callable wrapper: the model aims it at a write endpoint
// it discovered; the probe confirms the missing limit on the real status and emits the sentinel.
type BodyLimitTool struct {
	Gate     *tools.Gate
	Base     string
	Sessions *core.Sessions
}

func (BodyLimitTool) Name() string { return "body_limit" }
func (BodyLimitTool) Describe() string {
	return `Test a write endpoint for a missing request body-size limit (CWE-770). ` +
		`args: {"path":"/<write-path>","method":"POST"}. ` +
		`By default it uses the privileged session you are already logged into (do NOT pass credentials as a header); for a header-auth app add {"session_header":"<Header>","session_value":"<token>"}. ` +
		`Use a write path you actually discovered. It sends one multi-megabyte body; a 2xx acceptance instead of 413 is the finding.`
}

func (t BodyLimitTool) Call(ctx context.Context, args map[string]any) (string, error) {
	id := bolaIdentity(args, "priv", "session", "session_header", "session_value")
	p := &BodyLimitProbe{Base: t.Base, Egress: t.Gate.Egress(), Sessions: t.Sessions, Identity: id}
	method := strings.ToUpper(tools.AsString(args["method"]))
	f, err := p.Probe(ctx, method, tools.AsString(args["path"]))
	if err != nil {
		return "", fmt.Errorf("body_limit: %w", err)
	}
	if f.Flagged() {
		return NoBodyLimitSentinel + " " + f.Evidence, nil
	}
	if f.Status == http.StatusRequestEntityTooLarge || f.Status == http.StatusRequestHeaderFieldsTooLarge {
		return "body size limited: the endpoint rejected the oversized body with 413/431 — not a finding", nil
	}
	return fmt.Sprintf("inconclusive: %s %s returned HTTP %d to an oversized body (neither 2xx nor 413); confirm the path is a write endpoint you can reach authenticated",
		f.Method, f.Path, f.Status), nil
}
