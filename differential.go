package gored

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Identity is a caller the differential oracle tests a resource as. Session names a
// cookie jar in a shared Sessions registry (filled by an earlier http_request
// login); Headers carries any static per-identity header (an X-Session or
// Authorization token) an app uses instead of cookies. An anonymous identity has
// neither a logged-in jar nor headers.
//
// LoginPath and LoginBody, when set, say how to authenticate this identity from
// scratch (a POST login), so a hunt can tell the verifier how to reproduce a finding
// as this identity without reusing the live cookie jar. A header-based identity
// leaves them empty and carries Headers instead.
type Identity struct {
	Name      string
	Session   string
	Headers   map[string]string
	LoginPath string
	LoginBody string
}

// BACVerdict classifies a resource under differential testing.
type BACVerdict string

const (
	VerdictBAC     BACVerdict = "bac"     // low-privilege identity discloses privileged data
	VerdictScoped  BACVerdict = "scoped"  // low-privilege identity sees only its own data
	VerdictPublic  BACVerdict = "public"  // anonymous sees the content too; not access-controlled
	VerdictBlocked BACVerdict = "blocked" // low-privilege identity is correctly refused
)

// DiffFinding is one resource's differential result.
type DiffFinding struct {
	Method   string
	Path     string
	Verdict  BACVerdict
	Evidence string         // one-line human summary (statuses + what overlapped)
	Marker   string         // a privileged datum disclosed to the low-priv identity (for the 6b repro); "" unless BAC
	Request  map[string]any // the low-priv capturing request, for CurlFor and the verifier facts

	privStatus, lowStatus, anonStatus int
}

// Flagged reports whether this finding is a broken-access-control candidate.
func (f DiffFinding) Flagged() bool { return f.Verdict == VerdictBAC }

// DifferentialOracle flags broken access control WITHOUT a planted canary by
// requesting the same resource as a privileged and a low-privilege identity (and,
// when given, anonymously) and comparing the responses. A resource is flagged when
// it is access-controlled (the privileged content is not public) yet the
// low-privilege response discloses data gated behind privilege — the low-priv and
// privileged views overlap where a correctly scoped resource's would be disjoint.
// It reads only (GET) through the egress gate and plants nothing; the comparison is
// deterministic, so a flag is reproducible, and each flag is then handed to the 6b
// Verifier for a model-written, executed repro before it counts as confirmed.
//
// Pick identities that can both READ the resources under test: the comparison needs
// the privileged identity to actually see the resource. If a role is redirected or
// refused there (e.g. an app routes admins to a different console), it yields no
// content to compare, so use a privileged identity that can read the resource and a
// low-privilege peer that should not see the same data.
type DifferentialOracle struct {
	Base     string
	Egress   *Egress
	Sessions *Sessions
	Priv     Identity
	Low      Identity
	Anon     *Identity // optional public baseline; when set, content anon also sees is not privileged
	OnDeny   func(string)
	Timeout  time.Duration
}

var tokenRE = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9_@./:-]{3,}`)

// Sweep probes each resource and returns one finding per resource, classified.
func (d *DifferentialOracle) Sweep(ctx context.Context, methodPaths [][2]string) ([]DiffFinding, error) {
	out := make([]DiffFinding, 0, len(methodPaths))
	for _, mp := range methodPaths {
		f, err := d.Probe(ctx, mp[0], mp[1])
		if err != nil {
			return out, err
		}
		out = append(out, f)
	}
	return out, nil
}

// Probe tests one resource as each identity and classifies it.
func (d *DifferentialOracle) Probe(ctx context.Context, method, path string) (DiffFinding, error) {
	if method == "" {
		method = http.MethodGet
	}
	f := DiffFinding{Method: method, Path: path, Request: map[string]any{"method": method, "path": path}}
	if len(d.Low.Headers) > 0 {
		f.Request["headers"] = toAnyMap(d.Low.Headers)
	}

	privStatus, privBody, err := d.fetch(ctx, d.Priv, method, path)
	if err != nil {
		return f, err
	}
	lowStatus, lowBody, err := d.fetch(ctx, d.Low, method, path)
	if err != nil {
		return f, err
	}
	f.privStatus, f.lowStatus = privStatus, lowStatus

	var anonBody string
	anonOK := false
	if d.Anon != nil {
		as, ab, err := d.fetch(ctx, *d.Anon, method, path)
		if err != nil {
			return f, err
		}
		f.anonStatus, anonBody, anonOK = as, ab, ok2xx(as)
	}

	// Low-priv correctly refused: not a finding.
	if !ok2xx(lowStatus) {
		f.Verdict, f.Evidence = VerdictBlocked, fmt.Sprintf("low-priv HTTP %d (refused); privileged HTTP %d", lowStatus, privStatus)
		return f, nil
	}

	// Privileged content that is NOT visible anonymously is what privilege gates.
	privTokens := distinctiveTokens(privBody)
	if anonOK {
		privTokens = subtract(privTokens, tokenSetOf(anonBody))
	}
	// If privilege gates nothing beyond what anonymous already sees, the resource is
	// public (or empty) — low-priv seeing it is not a disclosure.
	if len(privTokens) == 0 {
		f.Verdict, f.Evidence = VerdictPublic, fmt.Sprintf("no privileged-only content (anon HTTP %d, priv HTTP %d)", f.anonStatus, privStatus)
		return f, nil
	}

	// Does the low-priv response disclose that privileged-gated content?
	leaked := intersect(privTokens, tokenSetOf(lowBody))
	identical := ok2xx(privStatus) && strings.TrimSpace(privBody) != "" && privBody == lowBody

	if identical || len(leaked) >= 2 {
		f.Verdict = VerdictBAC
		f.Marker = longest(leaked)
		if identical {
			f.Evidence = fmt.Sprintf("low-priv response byte-identical to privileged (HTTP %d, %d bytes)", lowStatus, len(lowBody))
		} else {
			f.Evidence = fmt.Sprintf("low-priv discloses %d privileged-only token(s), e.g. %q", len(leaked), trunc(f.Marker, 48))
		}
		return f, nil
	}

	f.Verdict, f.Evidence = VerdictScoped, fmt.Sprintf("low-priv sees only its own data (HTTP %d; no privileged-only overlap)", lowStatus)
	return f, nil
}

// fetch does one read-only GET as an identity, through the egress gate, without
// following redirects so the real status (401/403/3xx) is visible. The identity's
// cookie jar (from the shared Sessions) carries a cookie login; its Headers carry a
// header-based session.
func (d *DifferentialOracle) fetch(ctx context.Context, id Identity, method, path string) (int, string, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	raw := d.Base + path
	if !d.Egress.Allowed(raw) {
		if d.OnDeny != nil {
			d.OnDeny(raw)
		}
		return 0, "", fmt.Errorf("%w: %s", ErrEgressDenied, raw)
	}
	to := d.Timeout
	if to == 0 {
		to = 8 * time.Second
	}
	client := &http.Client{
		Timeout:       to,
		Jar:           d.Sessions.Client(id.Session).Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, method, raw, nil)
	if err != nil {
		return 0, "", err
	}
	for k, v := range id.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp.StatusCode, string(body), nil
}

func ok2xx(status int) bool { return status >= 200 && status < 300 }

// tokenSetOf returns the set of word-ish tokens in a body.
func tokenSetOf(s string) map[string]bool {
	set := map[string]bool{}
	for _, t := range tokenRE.FindAllString(s, -1) {
		set[t] = true
	}
	return set
}

// distinctiveTokens returns tokens worth treating as a disclosure signal: long
// enough, or carrying an identifier shape (an @, or a digit), so incidental
// boilerplate words do not drive a flag.
func distinctiveTokens(s string) map[string]bool {
	set := map[string]bool{}
	for t := range tokenSetOf(s) {
		if len(t) >= 8 || strings.Contains(t, "@") || hasDigit(t) {
			set[t] = true
		}
	}
	return set
}

func hasDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func subtract(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if !b[k] {
			out[k] = true
		}
	}
	return out
}

func intersect(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}

// longest returns the longest token in the set (ties broken lexicographically for
// determinism), the most distinctive disclosed datum to use as the repro marker.
func longest(set map[string]bool) string {
	best := ""
	for k := range set {
		if len(k) > len(best) || (len(k) == len(best) && k < best) {
			best = k
		}
	}
	return best
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// sortedFindings orders findings by path for stable output.
func sortedFindings(fs []DiffFinding) []DiffFinding {
	sort.Slice(fs, func(i, j int) bool { return fs[i].Path < fs[j].Path })
	return fs
}
