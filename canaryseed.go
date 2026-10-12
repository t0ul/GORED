package gored

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	gledger "github.com/t0ul/gledger"
)

// Canary is one planted marker: the create endpoint it was planted through, the body
// sent, the POST status, and whether it took. A planted canary turns a differential
// guess into a certainty — reading the marker as a low-privilege identity is broken
// access control with no false positive.
//
// ID is the created resource's identifier (parsed from the POST response, or the id
// invented when planting into a templated endpoint). ItemPath is the concrete item
// URL the marker should be readable at — the create collection plus the id, or the
// templated path with the id filled in — so the id-swapping step (phase 7a) can
// request it as the low-privilege identity and catch an object-level IDOR.
type Canary struct {
	Marker   string
	Endpoint string
	Body     string
	Status   int
	Planted  bool
	ID       string
	ItemPath string
}

// CanarySeeder plants a unique marker into each discovered resource-creating
// endpoint, as a privileged identity, so a later read as a low-privilege identity
// that returns the marker is broken access control with ground truth. It is generic:
// it grounds the create body on a real GET sample of the collection's shape, uses the
// local model to infer the body when one is set, and falls back to a minimal body
// built from the sample's writable fields; a POST that is refused is simply skipped,
// so no endpoint needs app-specific code. The POSTs are the one place GORED writes to
// the target, done as the operator-provided privileged identity through the egress
// gate — a privileged, authorized write, never an attack payload.
type CanarySeeder struct {
	Base     string
	Egress   *Egress
	Sessions *Sessions
	Priv     Identity
	Model    ModelClient       // optional; when set, the model drafts the create body first
	Audit    *gledger.AuditLog // optional
	Timeout  time.Duration
}

// Seed plants a canary into each create-candidate endpoint and returns the results.
func (s *CanarySeeder) Seed(ctx context.Context, endpoints []string) ([]Canary, error) {
	traceID := gledger.NewTraceID()
	s.emit(traceID, "seed", "seed_start", gledger.F{"as": s.Priv.Name, "candidates": len(endpoints)})
	var out []Canary
	for _, ep := range endpoints {
		if !createCandidate(ep) {
			continue
		}
		sample := s.get(ctx, ep)
		marker := newCanaryMarker()
		c := Canary{Marker: marker, Endpoint: ep}
		for _, body := range s.candidateBodies(ctx, ep, sample, marker) {
			if !strings.Contains(body, marker) {
				body = injectMarker(body, marker)
			}
			status, respBody := s.post(ctx, ep, body)
			c.Body, c.Status = body, status
			if ok2xx(status) {
				c.Planted = true
				if id := extractID(respBody); id != "" {
					c.ID, c.ItemPath = id, strings.TrimRight(ep, "/")+"/"+id
				}
				break
			}
		}
		s.emit(traceID, "seed", "plant", gledger.F{"endpoint": ep, "status": c.Status, "planted": c.Planted, "item": c.ItemPath})
		out = append(out, c)
	}
	s.emit(traceID, "seed", "seed_end", gledger.F{"planted": countPlanted(out), "attempted": len(out)})
	return out, nil
}

// SeedItems plants a canary into `{id}`-templated endpoints that create a resource at
// a caller-chosen id (a nested create like POST /api/drafts/report/{id}). It invents
// an id, posts the marker there as the privileged identity, and records that concrete
// path as the ItemPath, so the id-swapping step can read it back as a low-privilege
// identity. A refused POST is skipped. This reaches object-level IDOR that a plain
// collection POST cannot.
func (s *CanarySeeder) SeedItems(ctx context.Context, templates []string) ([]Canary, error) {
	traceID := gledger.NewTraceID()
	var out []Canary
	for _, tpl := range templates {
		if !strings.ContainsAny(tpl, "{}") || strings.HasPrefix(tpl, "/api/auth/") {
			continue
		}
		id := "gored7a-" + newCanaryMarker()[13:25] // a distinctive, caller-chosen id
		concrete := fillTemplate(tpl, id)
		if concrete == "" {
			continue
		}
		marker := newCanaryMarker()
		body := minimalBody(s.get(ctx, concrete), marker)
		if !strings.Contains(body, marker) {
			body = injectMarker(body, marker)
		}
		status, _ := s.post(ctx, concrete, body)
		c := Canary{Marker: marker, Endpoint: tpl, Body: body, Status: status, Planted: ok2xx(status), ID: id, ItemPath: concrete}
		s.emit(traceID, "seed", "plant_item", gledger.F{"template": tpl, "item": concrete, "status": status, "planted": c.Planted})
		out = append(out, c)
	}
	return out, nil
}

// fillTemplate replaces the single {...} segment of a path template with an id.
func fillTemplate(tpl, id string) string {
	i, j := strings.IndexByte(tpl, '{'), strings.IndexByte(tpl, '}')
	if i < 0 || j < i {
		return ""
	}
	return tpl[:i] + id + tpl[j+1:]
}

// extractID pulls a created resource's identifier from a create response body.
func extractID(body string) string {
	var m map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &m) != nil {
		return ""
	}
	for _, k := range []string{"id", "ID", "report_id", "filename", "name", "uuid"} {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			case float64:
				return fmt.Sprintf("%v", t)
			}
		}
	}
	return ""
}

// PlantedMarkers returns the markers that actually took, for the test step to look
// for in a low-privilege identity's responses.
func PlantedMarkers(cs []Canary) []string {
	var out []string
	for _, c := range cs {
		if c.Planted {
			out = append(out, c.Marker)
		}
	}
	return out
}

func countPlanted(cs []Canary) int {
	n := 0
	for _, c := range cs {
		if c.Planted {
			n++
		}
	}
	return n
}

// createCandidate reports whether an endpoint looks like a resource collection worth
// a create POST: an API path, not an auth endpoint, not a single-item or templated
// path, not a static asset.
func createCandidate(p string) bool {
	if !strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/api/auth/") {
		return false
	}
	if strings.ContainsAny(p, "{}") {
		return false
	}
	last := p[strings.LastIndex(p, "/")+1:]
	if last == "" || strings.Contains(last, ".") {
		return false
	}
	if isAllDigits(last) {
		return false // /api/tickets/42 is an item, not a collection
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func newCanaryMarker() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "GORED-CANARY-" + hex.EncodeToString(b)
}

// candidateBodies returns create bodies to try in order: the model's (when a model is
// set) first, then a deterministic minimal body built from the GET sample. Trying
// both makes planting robust — the model can name odd fields, the minimal body
// survives strict APIs that reject extra ones.
func (s *CanarySeeder) candidateBodies(ctx context.Context, endpoint, sample, marker string) []string {
	var bodies []string
	if s.Model != nil {
		if b, ok := s.draftWithModel(ctx, endpoint, sample, marker); ok {
			bodies = append(bodies, b)
		}
	}
	bodies = append(bodies, minimalBody(sample, marker))
	return bodies
}

func (s *CanarySeeder) draftWithModel(ctx context.Context, endpoint, sample, marker string) (string, bool) {
	sys := `You seed ONE test record by writing the JSON body of a POST that creates a resource. Output ONLY a JSON object — the request body — or {} if this endpoint does not create a resource. Include only the fields needed to create one; prefer a title/name and a description/body. Put the exact token ` + marker + ` inside a human-readable text field.`
	user := "POST " + endpoint + "\nA GET of this collection returned (for field names):\n" + trunc(sample, 800) + "\n\nJSON body:"
	reply, _, err := s.Model.Chat(ctx, []Message{{Role: RoleSystem, Content: sys}, {Role: RoleUser, Content: user}}, ChatOpts{Temperature: 0.2, MaxTokens: 300})
	if err != nil {
		return "", false
	}
	raw, ok := extractJSON(reply)
	if !ok || strings.TrimSpace(raw) == "{}" || !json.Valid([]byte(raw)) {
		return "", false
	}
	return raw, true
}

// writableField names the fields a create body usually carries; enumField names
// fields that are usually a small required enum, defaulted to a safe value.
var writableField = map[string]bool{
	"title": true, "name": true, "description": true, "body": true, "content": true,
	"text": true, "summary": true, "message": true, "note": true, "comment": true, "label": true,
}
var enumDefault = map[string]string{"severity": "low", "priority": "low", "status": "open"}

// minimalBody builds a create body from the writable fields present in a GET sample
// (so a strict API that rejects unknown fields still accepts it), with the marker in
// the first text field. With no sample it guesses a title/description.
func minimalBody(sample, marker string) string {
	body := map[string]any{}
	textKey := ""
	for _, k := range sampleKeys(sample) {
		lk := strings.ToLower(k)
		if writableField[lk] {
			body[k] = "canary test record"
			if textKey == "" {
				textKey = k
			}
		} else if v, ok := enumDefault[lk]; ok {
			body[k] = v
		}
	}
	if len(body) == 0 {
		body["title"] = "canary test record"
		body["description"] = ""
		textKey = "description"
	}
	if textKey != "" {
		body[textKey] = strings.TrimSpace(fmt.Sprintf("%v %s", body[textKey], marker))
	} else {
		body["note"] = marker
	}
	b, _ := json.Marshal(body)
	return string(b)
}

// sampleKeys returns the field names of the first object in a JSON sample (an array
// of objects, or a single object), sorted for determinism.
func sampleKeys(sample string) []string {
	sample = strings.TrimSpace(sample)
	var obj map[string]json.RawMessage
	if strings.HasPrefix(sample, "[") {
		var arr []map[string]json.RawMessage
		if json.Unmarshal([]byte(sample), &arr) != nil || len(arr) == 0 {
			return nil
		}
		obj = arr[0]
	} else if json.Unmarshal([]byte(sample), &obj) != nil {
		return nil
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// injectMarker ensures the marker is present: it appends it to the longest string
// field of a JSON body, or adds a note field. If the body is not JSON it is returned
// unchanged (the POST will then simply fail and be skipped).
func injectMarker(body, marker string) string {
	var m map[string]any
	if json.Unmarshal([]byte(body), &m) != nil {
		return body
	}
	longestKey := ""
	for k, v := range m {
		if s, ok := v.(string); ok {
			if cur, _ := m[longestKey].(string); longestKey == "" || len(s) > len(cur) {
				longestKey = k
			}
		}
	}
	if longestKey != "" {
		m[longestKey] = strings.TrimSpace(fmt.Sprintf("%v %s", m[longestKey], marker))
	} else {
		m["note"] = marker
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (s *CanarySeeder) client() *http.Client {
	to := s.Timeout
	if to == 0 {
		to = 8 * time.Second
	}
	return &http.Client{Timeout: to, Jar: s.Sessions.Client(s.Priv.Session).Jar}
}

func (s *CanarySeeder) get(ctx context.Context, path string) string {
	raw := s.Base + path
	if !s.Egress.Allowed(raw) {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return ""
	}
	for k, v := range s.Priv.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return string(b)
}

func (s *CanarySeeder) post(ctx context.Context, path, body string) (int, string) {
	raw := s.Base + path
	if !s.Egress.Allowed(raw) {
		return 0, ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, strings.NewReader(body))
	if err != nil {
		return 0, ""
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.Priv.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	return resp.StatusCode, string(b)
}

func (s *CanarySeeder) emit(traceID, span, event string, f gledger.F) {
	if s.Audit != nil {
		s.Audit.Emit(traceID, span, event, f)
	}
}
