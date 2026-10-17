package probes

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/tools"
)

// ThrottleFinding is one authentication endpoint's rate-limiting result: whether a burst of
// wrong-credential attempts was ever blocked (429 / account lockout). Blocked -> defended;
// never blocked across the whole burst -> the finding (CWE-307).
type ThrottleFinding struct {
	Path       string
	Attempts   int         // how many attempts the probe planned to send
	Sent       int         // how many actually completed (got an HTTP status back)
	Blocked    bool        // a 429 (Too Many Requests) or 423 (Locked) was seen
	StatusHist map[int]int // the status-code histogram, for the evidence line
	CWE        string
	Evidence   string
}

// Flagged reports a missing throttle: every planned attempt completed and none was blocked.
// Requiring all attempts to complete keeps a flaky/half-reachable endpoint from being flagged.
func (f ThrottleFinding) Flagged() bool {
	return f.Attempts > 0 && f.Sent >= f.Attempts && !f.Blocked
}

// ThrottleProbe fires a burst of wrong-credential login attempts at an auth endpoint and
// watches whether any is ever rate-limited or locked out — the missing-throttle bug (CWE-307)
// that scanners skip because it is stateful app behaviour, not a single-request signature. It
// uses a bounded worker pool (jobs channel + results channel + WaitGroup) so the attempts land
// as a real concurrent burst, the way an attacker would and the way a rate limiter is meant to
// catch; the pool is small and every request goes through the Egress gate, so containment holds.
type ThrottleProbe struct {
	Base      string
	Egress    *core.Egress
	Attempts  int    // default 12 (above any reasonable lockout threshold, below a self-DoS)
	Workers   int    // default 6
	UserField string // default "username"
	PassField string // default "password"
	BadUser   string // default a random non-existent user
	BadPass   string // default a wrong password
	Timeout   time.Duration
}

// Probe sends the burst and returns whether the endpoint ever throttled it. userField/passField
// override the JSON credential field names (e.g. "email"); empty falls back to the probe's
// defaults, then to username/password.
func (p *ThrottleProbe) Probe(ctx context.Context, path, userField, passField string) (ThrottleFinding, error) {
	n := p.Attempts
	if n <= 0 {
		n = 12
	}
	workers := p.Workers
	if workers <= 0 {
		workers = 6
	}
	if workers > n {
		workers = n
	}
	uf := firstNonEmpty(userField, p.UserField, "username")
	pf := firstNonEmpty(passField, p.PassField, "password")
	badUser := p.BadUser
	if badUser == "" {
		badUser = fmt.Sprintf("gored_probe_%d", time.Now().UnixNano())
	}
	badPass := firstNonEmpty(p.BadPass, "wrong-"+badUser)

	raw := urlJoin(p.Base, path)
	if !p.Egress.Allowed(raw) {
		return ThrottleFinding{}, fmt.Errorf("%w: %s", core.ErrEgressDenied, raw)
	}
	body := fmt.Sprintf(`{%q:%q,%q:%q}`, uf, badUser, pf, badPass)

	// bhg-style bounded worker pool: fan the N attempts out over a jobs channel to a fixed set
	// of workers, collect each real HTTP status on a results channel. A single closer goroutine
	// waits for the workers then closes results, so the range below terminates cleanly.
	jobs := make(chan int, n)
	results := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				results <- p.attempt(ctx, raw, body)
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	go func() { wg.Wait(); close(results) }()

	hist := map[int]int{}
	sent, blocked := 0, false
	for st := range results {
		hist[st]++
		if st > 0 {
			sent++
		}
		if st == http.StatusTooManyRequests || st == http.StatusLocked { // 429 / 423
			blocked = true
		}
	}
	f := ThrottleFinding{Path: path, Attempts: n, Sent: sent, Blocked: blocked, StatusHist: hist, CWE: "CWE-307"}
	if f.Flagged() {
		f.Evidence = fmt.Sprintf("sent %d authentication attempts to %s; none was blocked with 429 or a lockout (statuses %s) — no rate limiting or account lockout on authentication (CWE-307)",
			n, path, histString(hist))
	}
	return f, nil
}

// attempt performs one login POST with the wrong-credential body and returns its HTTP status
// (0 on a transport error). Each call uses its own short-lived client so the burst is honest.
func (p *ThrottleProbe) attempt(ctx context.Context, raw, body string) int {
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

// ThrottleProbeTool (throttle_probe) is the agent-callable wrapper: the model aims it at a login
// path it discovered, the probe confirms the missing throttle on real responses, and it emits the
// NoThrottle sentinel the oracle reads. A model cannot emit the sentinel — only the real burst can.
type ThrottleProbeTool struct {
	Gate *tools.Gate
	Base string
}

func (ThrottleProbeTool) Name() string { return "throttle_probe" }
func (ThrottleProbeTool) Describe() string {
	return `Test an authentication endpoint for missing rate-limiting / account lockout (CWE-307). ` +
		`args: {"path":"/<login-path>","user_field":"username","pass_field":"password"}. ` +
		`Use a login/sign-in path you actually discovered. user_field/pass_field are optional (default username/password; for an email login pass "user_field":"email"). ` +
		`It sends a burst of wrong-credential attempts; if none is ever blocked with 429 or a lockout, that is the finding.`
}

func (t ThrottleProbeTool) Call(ctx context.Context, args map[string]any) (string, error) {
	p := &ThrottleProbe{Base: t.Base, Egress: t.Gate.Egress()}
	f, err := p.Probe(ctx, tools.AsString(args["path"]), tools.AsString(args["user_field"]), tools.AsString(args["pass_field"]))
	if err != nil {
		return "", fmt.Errorf("throttle_probe: %w", err)
	}
	if f.Flagged() {
		return NoThrottleSentinel + " " + f.Evidence, nil
	}
	if f.Blocked {
		return "rate limiting present: the endpoint returned 429/lockout during the burst, so authentication is throttled — not a finding", nil
	}
	return fmt.Sprintf("inconclusive: only %d of %d attempts completed (statuses %s); confirm the path is a reachable login endpoint and retry",
		f.Sent, f.Attempts, histString(f.StatusHist)), nil
}

// histString renders a status-code histogram like "401x12" for an evidence line, keys sorted.
func histString(h map[int]int) string {
	keys := make([]int, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%dx%d", k, h[k]))
	}
	return strings.Join(parts, " ")
}

// firstNonEmpty returns the first non-empty string, for layered defaults.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
