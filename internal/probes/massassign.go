package probes

import (
	gored "github.com/t0ul/GORED"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MassAssignField is one attribute a client should not be able to set on a write, paired
// with the privileged value to try. The defaults below are generic attack knowledge —
// role escalation, ownership takeover, verification/approval flips — not tied to any app
// or language, the same way the id-swap and canary heuristics are generic. Override
// Fields on the probe to test an app's own sensitive attributes.
type MassAssignField struct {
	Name  string // the JSON field to inject, e.g. "role"
	Value any    // the privileged value to try, e.g. "admin" or true
}

// DefaultPrivilegedFields is the field dictionary the probe tries when none is given. It
// is ordered most-dangerous first so the probe reports the strongest escalation it finds.
var DefaultPrivilegedFields = []MassAssignField{
	{"role", "admin"}, {"roles", []string{"admin"}},
	{"isAdmin", true}, {"is_admin", true}, {"admin", true},
	{"isStaff", true}, {"is_staff", true},
	{"owner", "admin"}, {"ownerId", "admin"}, {"owner_id", "admin"},
	{"userId", "admin"}, {"user_id", "admin"},
	{"verified", true}, {"isVerified", true}, {"is_verified", true},
	{"approved", true}, {"active", true}, {"enabled", true},
	{"tier", "enterprise"}, {"plan", "enterprise"},
}

// MassAssignFinding is one write endpoint's mass-assignment result: whether a low-privilege
// caller could set a privileged field it should not control, and how certain that is.
type MassAssignFinding struct {
	Method     string
	WritePath  string
	ReadPath   string
	Field      string         // the privileged field the server honored; "" means not flagged
	SentValue  any            // the value the probe injected
	WasValue   any            // the field's value before the write (the baseline)
	Confidence gored.Confidence     // certain (persisted on an independent read) | high (reflected only); "" when not flagged
	CWE        string         // CWE-915 (mass assignment / improperly controlled object attributes)
	Evidence   string         // one-line human summary
	Request    map[string]any // the capturing write, for a repro / the verifier
}

// Flagged reports whether the endpoint honored a privileged field.
func (f MassAssignFinding) Flagged() bool { return f.Field != "" }

// MassAssignProbe tests whether a write endpoint trusts client-set privileged fields —
// the mass-assignment / parameter-pollution bug scanners miss because it is pure app
// logic (CWE-915). As the low-privilege identity it reads the resource, writes it back
// with a privileged field injected, then reads it again: if the field now holds the
// injected value (and did not before), the server bound an attribute the client should
// not control, and the independent read-back is the executed proof — a certain finding,
// no model needed. If only the write's own response reflected the value, persistence is
// unconfirmed and the finding is high. If the field is ignored, nothing is flagged, so a
// properly whitelisting endpoint does not produce a false positive.
//
// It is contained: every request goes through the Egress gate, and it writes only to the
// endpoint it was told to probe, with the low-privilege identity, never a privileged one.
type MassAssignProbe struct {
	Base     string
	Egress   *gored.Egress
	Sessions *gored.Sessions
	Low      gored.Identity          // the caller that should NOT be able to set privileged fields
	Fields   []MassAssignField // defaults to DefaultPrivilegedFields
	Timeout  time.Duration
}

// Probe writes to writePath as the low-privilege identity, injecting each candidate
// privileged field in turn, and reads readPath back to see which (if any) the server
// honored. method defaults to PUT; readPath defaults to writePath. It returns the
// strongest result: a certain finding if any field persisted, else a high finding if one
// was reflected, else an unflagged result.
func (p *MassAssignProbe) Probe(ctx context.Context, method, writePath, readPath string) (MassAssignFinding, error) {
	if method == "" {
		method = http.MethodPut
	}
	if readPath == "" {
		readPath = writePath
	}
	fields := p.Fields
	if fields == nil {
		fields = DefaultPrivilegedFields
	}

	base, _, err := p.getObject(ctx, readPath)
	if err != nil {
		return MassAssignFinding{}, err
	}

	var fallback *MassAssignFinding // a reflected-only (high) candidate, used if nothing persists
	for _, f := range fields {
		was := base[f.Name]
		if jsonEq(was, f.Value) {
			continue // already that value; writing it would prove nothing
		}
		body := writeBody(base, f)
		wStatus, wBody := p.write(ctx, method, writePath, body)
		if !ok2xx(wStatus) {
			continue // the endpoint rejected the write; not a honored field
		}
		req := map[string]any{"method": method, "path": writePath, "body": body, "field": f.Name}

		// The strong signal: read the resource back independently and see the value stick.
		after, _, _ := p.getObject(ctx, readPath)
		if after != nil && jsonEq(after[f.Name], f.Value) {
			return MassAssignFinding{
				Method: method, WritePath: writePath, ReadPath: readPath,
				Field: f.Name, SentValue: f.Value, WasValue: was,
				Confidence: gored.ConfCertain, CWE: "CWE-915",
				Evidence: fmt.Sprintf("low-priv %q set %s=%v (was %v); read back %s=%v — server bound a client-controlled privileged field",
					p.Low.Name, f.Name, f.Value, was, f.Name, after[f.Name]),
				Request: req,
			}, nil
		}

		// The weak signal: the write's own response echoed the value but an independent
		// read did not confirm it persisted. Keep it only if nothing stronger turns up.
		if fallback == nil {
			if resp := parseObject(wBody); resp != nil && jsonEq(resp[f.Name], f.Value) {
				fallback = &MassAssignFinding{
					Method: method, WritePath: writePath, ReadPath: readPath,
					Field: f.Name, SentValue: f.Value, WasValue: was,
					Confidence: gored.ConfHigh, CWE: "CWE-915",
					Evidence: fmt.Sprintf("low-priv %q set %s=%v and the write response reflected it, but a read-back did not confirm it persisted",
						p.Low.Name, f.Name, f.Value),
					Request: req,
				}
			}
		}
	}
	if fallback != nil {
		return *fallback, nil
	}
	return MassAssignFinding{Method: method, WritePath: writePath, ReadPath: readPath}, nil
}

// writeBody builds the request body: the baseline object with the privileged field set
// (so required fields are preserved), or a minimal object when there is no baseline.
func writeBody(base map[string]any, f MassAssignField) string {
	obj := map[string]any{}
	for k, v := range base {
		obj[k] = v
	}
	obj[f.Name] = f.Value
	b, _ := json.Marshal(obj)
	return string(b)
}

func (p *MassAssignProbe) client() *http.Client {
	to := p.Timeout
	if to == 0 {
		to = 8 * time.Second
	}
	return &http.Client{
		Timeout:       to,
		Jar:           p.Sessions.Client(p.Low.Session).Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// getObject GETs a path as the low-priv identity and parses a JSON object body, or nil.
func (p *MassAssignProbe) getObject(ctx context.Context, path string) (map[string]any, int, error) {
	status, body, err := p.do(ctx, http.MethodGet, path, "")
	if err != nil {
		return nil, status, err
	}
	return parseObject(body), status, nil
}

func (p *MassAssignProbe) write(ctx context.Context, method, path, body string) (int, string) {
	status, resp, err := p.do(ctx, method, path, body)
	if err != nil {
		return 0, ""
	}
	return status, resp
}

func (p *MassAssignProbe) do(ctx context.Context, method, path, body string) (int, string, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	raw := p.Base + path
	if !p.Egress.Allowed(raw) {
		return 0, "", fmt.Errorf("%w: %s", gored.ErrEgressDenied, raw)
	}
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, raw, rdr)
	if err != nil {
		return 0, "", err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range p.Low.Headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp.StatusCode, string(b), nil
}

// parseObject decodes a JSON object body, or returns nil for anything that is not one.
func parseObject(body string) map[string]any {
	t := strings.TrimSpace(body)
	if !strings.HasPrefix(t, "{") {
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(t), &m) != nil {
		return nil
	}
	return m
}

// jsonEq compares two values by their JSON encoding, so "admin"==\"admin\" and the
// probe need not care whether a field is a string, bool, or number.
func jsonEq(a, b any) bool {
	ba, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(ba) == string(bb)
}
