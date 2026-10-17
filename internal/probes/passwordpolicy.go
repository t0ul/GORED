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

// PasswordPolicyFinding is one account-creation endpoint's password-strength result: the HTTP
// status it returned when offered a trivially weak password. A 2xx means it accepted the weak
// password (the finding, CWE-521); a 4xx means it enforced a policy (defended).
type PasswordPolicyFinding struct {
	Path     string
	Status   int
	Weak     string
	CWE      string
	Evidence string
	flagged  bool
}

// Flagged reports that the endpoint accepted the weak password.
func (f PasswordPolicyFinding) Flagged() bool { return f.flagged }

// PasswordPolicyProbe asks a registration / set-password endpoint to accept a trivially weak
// password for a fresh, throwaway account. If the server creates the account (2xx), it enforces
// no password-strength policy (CWE-521) — a design bug scanners skip because it is pure app logic.
// It is contained (Egress gate), sends one request, and uses a random non-existent username so it
// never touches an existing account.
type PasswordPolicyProbe struct {
	Base      string
	Egress    *core.Egress
	UserField string // default "username"
	PassField string // default "password"
	WeakPass  string // default "123"
	Timeout   time.Duration
}

// Probe POSTs a weak-password registration to path and classifies the response.
func (p *PasswordPolicyProbe) Probe(ctx context.Context, path string) (PasswordPolicyFinding, error) {
	uf := firstNonEmpty(p.UserField, "username")
	pf := firstNonEmpty(p.PassField, "password")
	weak := firstNonEmpty(p.WeakPass, "123")
	raw := urlJoin(p.Base, path)
	if !p.Egress.Allowed(raw) {
		return PasswordPolicyFinding{}, fmt.Errorf("%w: %s", core.ErrEgressDenied, raw)
	}
	user := fmt.Sprintf("gored_probe_%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{%q:%q,%q:%q}`, uf, user, pf, weak)
	status := p.send(ctx, raw, body)

	f := PasswordPolicyFinding{Path: path, Status: status, Weak: weak, CWE: "CWE-521"}
	if ok2xx(status) {
		f.flagged = true
		f.Evidence = fmt.Sprintf("%s accepted a trivially weak password (%q) for a new account (HTTP %d) — no password-strength policy (CWE-521)",
			path, weak, status)
	}
	return f, nil
}

func (p *PasswordPolicyProbe) send(ctx context.Context, raw, body string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, strings.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	to := p.Timeout
	if to == 0 {
		to = 8 * time.Second
	}
	resp, err := (&http.Client{
		Timeout:       to,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// PasswordPolicyTool (password_policy) is the agent-callable wrapper: the model aims it at a
// registration / sign-up path it discovered; the probe confirms the weak password was accepted
// on the real status and emits the sentinel.
type PasswordPolicyTool struct {
	Gate *tools.Gate
	Base string
}

func (PasswordPolicyTool) Name() string { return "password_policy" }
func (PasswordPolicyTool) Describe() string {
	return `Test a registration / sign-up endpoint for a missing password-strength policy (CWE-521). ` +
		`args: {"path":"/<register-path>","user_field":"username","pass_field":"password"}. ` +
		`Use a register/sign-up path you actually discovered. user_field/pass_field are optional (default username/password; for an email sign-up pass "user_field":"email"). ` +
		`It creates one throwaway account with a trivially weak password; a 2xx acceptance is the finding.`
}

func (t PasswordPolicyTool) Call(ctx context.Context, args map[string]any) (string, error) {
	p := &PasswordPolicyProbe{
		Base:      t.Base,
		Egress:    t.Gate.Egress(),
		UserField: tools.AsString(args["user_field"]),
		PassField: tools.AsString(args["pass_field"]),
	}
	f, err := p.Probe(ctx, tools.AsString(args["path"]))
	if err != nil {
		return "", fmt.Errorf("password_policy: %w", err)
	}
	if f.Flagged() {
		return WeakPwSentinel + " " + f.Evidence, nil
	}
	return fmt.Sprintf("no finding: %s returned HTTP %d to a weak password (rejected or unreachable) — a strength policy appears to be enforced, or this is not a registration endpoint",
		f.Path, f.Status), nil
}
