package store

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// FieldSpec is one request parameter the exploit phase needs in order to build a schema-valid
// request: its name, inferred type, whether it is required, and where it goes.
type FieldSpec struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`     // string|number|bool|email|enum|object|array|unknown
	Required bool   `json:"required,omitempty"` // union-to-true across sources: if any source marks it required, we send it
	In       string `json:"in,omitempty"`       // body|query|path (default body)
}

// ResponseFP is a light fingerprint of what an endpoint returns, for oracle precision later.
type ResponseFP struct {
	Status      int      `json:"status,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	Reflects    []string `json:"reflects,omitempty"` // request field names echoed back in the response
}

// EndpointContract is the reverse-engineered request contract for one endpoint — the structured
// replacement for the old flat comma-string "shape". It accumulates across recon sources (merged by
// source precedence, never clobbered) so the exploit phase and the probes can build a valid request:
// the right fields with their types/required flags, query/path params, required headers, and what
// each identity gets back. It is marshaled into the project_surface.contract JSON column.
type EndpointContract struct {
	Fields   []FieldSpec    `json:"fields,omitempty"`
	Headers  []string       `json:"headers,omitempty"`  // required/observed request headers (Content-Type, X-CSRF-Token, …)
	Auth     map[string]int `json:"auth,omitempty"`     // identity -> observed HTTP status: "anon"|"low"|"priv"
	Response *ResponseFP    `json:"response,omitempty"` // optional response fingerprint
	Sources  []string       `json:"sources,omitempty"`  // provenance union (openapi|active|static|graphql|ffuf|crawl)
}

// contractSourceRank orders recon sources by how authoritative their field/type information is, so a
// merge never lets a weaker source downgrade a stronger one's contract (openapi is ground truth; a
// crawl only knows the path exists).
var contractSourceRank = map[string]int{
	"openapi": 5, "active": 4, "static": 3, "graphql": 2, "ffuf": 1, "crawl": 0, "": 0,
}

func sourceRank(src string) int { return contractSourceRank[src] }

// topRank returns the highest source rank that has contributed to a contract so far.
func (c *EndpointContract) topRank() int {
	best := 0
	for _, s := range c.Sources {
		if r := sourceRank(s); r > best {
			best = r
		}
	}
	return best
}

// SurfaceRow is one endpoint on a target's canonical map, accumulated across every pass and every
// model. The target is the unit of memory: one row per endpoint, so any later run (any model) seeds
// from the whole map and never starts over. Who found it is recorded separately in SurfaceFind.
type SurfaceRow struct {
	Target    string
	Method    string
	Path      string
	Last      string
	TS        time.Time
	Class     string            // classifyEndpoint class (auth/write/upload/…), precomputed for rank/filter
	Source    string            // best-confidence provenance seen for this endpoint
	HasBody   bool              // the contract has body fields
	NeedsAuth bool              // anon gets 401/403
	ReachLow  bool              // a low-privilege identity gets a 2xx (a BAC/IDOR candidate)
	Contract  *EndpointContract // the structured request contract; nil when only the path is known
	Attempts  int               // times the exploit phase has worked this endpoint
	Captured  bool              // a finding landed here; never re-attack
}

// Shape derives the legacy flat body-field list (comma-joined names) from the contract, so existing
// renders that expect a "shape" string keep working while the structured contract is the source.
func (r SurfaceRow) Shape() string {
	if r.Contract == nil {
		return ""
	}
	var names []string
	for _, f := range r.Contract.Fields {
		if f.In == "" || f.In == "body" {
			names = append(names, f.Name)
		}
	}
	return strings.Join(names, ",")
}

// SurfaceFind attributes a map endpoint to a model that reported it (and the run it was in), so a
// researcher can compare what each model discovered on the same target. Model "" is deterministic
// recon (crawl/ffuf/graphql), shared across models.
type SurfaceFind struct {
	Target string
	Method string
	Path   string
	Model  string
	RunID  string
	Note   string
	TS     time.Time
}

// FindingRow is one finding a campaign has recorded on a target, accumulated across passes
// (deduped by target+type+value, so re-finding the same thing does not bloat the memory).
type FindingRow struct {
	Target string
	Type   string
	Value  string
	RunID  string
	TS     time.Time
}

// SaveSurface records a discovered endpoint on a target's canonical map AND, when a model found it
// (model != "", "" = deterministic recon), a per-model attribution in surface_find. The map is the
// cross-run memory a later pass seeds from (one row per endpoint, so no run restarts from scratch);
// the attribution keeps "who found what" without fragmenting the map.
func (s *Store) SaveSurface(target, model, runID, method, path, last string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	// A bare discovery (crawl/ffuf/graphql): record the row and classify it, but set source="crawl"
	// only when the row is new — a later SaveContract from a stronger source must not be downgraded.
	if _, err := s.db.Exec(
		`INSERT INTO project_surface (target, method, path, last, ts, class, source) VALUES (?,?,?,?,?,?,'crawl')
		 ON CONFLICT(target, method, path) DO UPDATE SET last=excluded.last, ts=excluded.ts, class=excluded.class`,
		target, method, path, last, now, s.classOf(method, path)); err != nil {
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO surface_find (target, method, path, model, run_id, note, ts) VALUES (?,?,?,?,?,?,?)
		 ON CONFLICT(target, method, path, model) DO UPDATE SET run_id=excluded.run_id, note=excluded.note, ts=excluded.ts`,
		target, method, path, model, runID, last, now)
	return err
}

// ListSurface returns a target's canonical map — one row per endpoint, every model's discoveries
// folded in, with the reverse-engineered shape and the exploit-progress counters — which is what a
// run seeds from (so it can skip what is done and work the frontier).
func (s *Store) ListSurface(target string) ([]SurfaceRow, error) {
	return s.scanSurface(`SELECT target, method, path, COALESCE(last,''), COALESCE(ts,''),
		COALESCE(class,''), COALESCE(source,''), COALESCE(has_body,0), COALESCE(needs_auth,0),
		COALESCE(reach_low,0), COALESCE(contract,''), COALESCE(attempts,0), COALESCE(captured,0)
		FROM project_surface WHERE target=? ORDER BY path, method`, target)
}

// scanSurface runs a project_surface SELECT (whose column order must match below) and decodes each
// row, including the structured contract JSON. COALESCE every nullable column: a row created with
// only a contract (no crawl) has a NULL last, and scanning NULL into a Go string would error the
// whole query — the bug that once silently emptied the surface and stalled the exploit phase.
func (s *Store) scanSurface(query string, args ...any) ([]SurfaceRow, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SurfaceRow
	for rows.Next() {
		var r SurfaceRow
		var ts, contract string
		var hasBody, needsAuth, reachLow, cap int
		if err := rows.Scan(&r.Target, &r.Method, &r.Path, &r.Last, &ts, &r.Class, &r.Source,
			&hasBody, &needsAuth, &reachLow, &contract, &r.Attempts, &cap); err != nil {
			return nil, err
		}
		r.TS, _ = time.Parse(time.RFC3339Nano, ts)
		r.HasBody, r.NeedsAuth, r.ReachLow, r.Captured = hasBody != 0, needsAuth != 0, reachLow != 0, cap != 0
		if contract != "" {
			var c EndpointContract
			if json.Unmarshal([]byte(contract), &c) == nil {
				r.Contract = &c
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// QueryOpts scopes a QueryEndpoints call so the model (via the recon tool) pulls a slice, never the
// whole map.
type QueryOpts struct {
	Exercised bool   // include endpoints already worked (attempts>0 / found); default false = frontier only
	AttemptCap int   // when Exercised is false, the attempts ceiling below which an endpoint is still "frontier" (0 -> 1)
	Class      string // restrict to one classifyEndpoint class
	Limit      int    // cap the result (0 -> 20)
}

// QueryEndpoints returns a scoped, ranked slice of a target's endpoints for the recon tool: by
// default only the not-yet-exhausted frontier (so the model advances instead of re-reading done
// work), optionally filtered to one class, ordered easiest-first (not found, fewest attempts), capped.
func (s *Store) QueryEndpoints(target string, o QueryOpts) ([]SurfaceRow, error) {
	cap := o.AttemptCap
	if cap <= 0 {
		cap = 1
	}
	limit := o.Limit
	if limit <= 0 {
		limit = 20
	}
	q := `SELECT target, method, path, COALESCE(last,''), COALESCE(ts,''),
		COALESCE(class,''), COALESCE(source,''), COALESCE(has_body,0), COALESCE(needs_auth,0),
		COALESCE(reach_low,0), COALESCE(contract,''), COALESCE(attempts,0), COALESCE(captured,0)
		FROM project_surface WHERE target=?`
	args := []any{target}
	if !o.Exercised {
		q += ` AND COALESCE(captured,0)=0 AND COALESCE(attempts,0)<?`
		args = append(args, cap)
	}
	if o.Class != "" {
		q += ` AND class=?`
		args = append(args, o.Class)
	}
	q += ` ORDER BY COALESCE(captured,0) ASC, COALESCE(attempts,0) ASC, path ASC LIMIT ?`
	args = append(args, limit)
	return s.scanSurface(q, args...)
}

// SaveContract records (and MERGES) the reverse-engineered request contract for an endpoint on the
// canonical map. It reads any existing contract and folds the new observation in by source
// precedence (openapi > active > static > graphql > ffuf > crawl): a stronger source may overwrite a
// conflicting field type, a weaker one only fills gaps, and nothing ever downgrades a known type to
// unknown. Required is unioned toward true (if any source marks a field required we send it, so a
// built body is not rejected). Headers/sources are unioned; auth takes the newest observation. The
// promoted columns (class/has_body/needs_auth/reach_low) are recomputed from the merged contract so
// the recon tool can filter on them. Upserts the row; does not touch the attempt counters.
func (s *Store) SaveContract(target, method, path, source string, c EndpointContract) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var existing string
	_ = s.db.QueryRow(`SELECT COALESCE(contract,'') FROM project_surface WHERE target=? AND method=? AND path=?`,
		target, method, path).Scan(&existing)
	var cur EndpointContract
	if existing != "" {
		_ = json.Unmarshal([]byte(existing), &cur)
	}
	merged := mergeContract(cur, c, source)
	blob, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	hasBody := 0
	for _, f := range merged.Fields {
		if f.In == "" || f.In == "body" {
			hasBody = 1
			break
		}
	}
	needsAuth := 0
	if st := merged.Auth["anon"]; st == 401 || st == 403 {
		needsAuth = 1
	}
	reachLow := 0
	if st := merged.Auth["low"]; st >= 200 && st < 300 {
		reachLow = 1
	}
	_, err = s.db.Exec(
		`INSERT INTO project_surface (target, method, path, ts, class, source, contract, has_body, needs_auth, reach_low)
		 VALUES (?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(target, method, path) DO UPDATE SET
		   ts=excluded.ts, class=excluded.class, source=excluded.source, contract=excluded.contract,
		   has_body=excluded.has_body, needs_auth=excluded.needs_auth, reach_low=excluded.reach_low`,
		target, method, path, now, s.classOf(method, path), bestSource(merged.Sources), string(blob),
		hasBody, needsAuth, reachLow)
	return err
}

// mergeContract folds a new observation (from source src) into the current contract by precedence.
func mergeContract(cur, in EndpointContract, src string) EndpointContract {
	stronger := sourceRank(src) > cur.topRank()
	key := func(f FieldSpec) string {
		inn := f.In
		if inn == "" {
			inn = "body"
		}
		return inn + "\x00" + f.Name
	}
	m := EndpointContract{Auth: map[string]int{}}
	idx := map[string]int{}
	for _, f := range cur.Fields {
		if f.In == "" {
			f.In = "body"
		}
		idx[key(f)] = len(m.Fields)
		m.Fields = append(m.Fields, f)
	}
	for _, nf := range in.Fields {
		if nf.In == "" {
			nf.In = "body"
		}
		if i, ok := idx[key(nf)]; ok {
			ex := &m.Fields[i]
			if knownType(nf.Type) && (!knownType(ex.Type) || stronger) {
				ex.Type = nf.Type
			}
			ex.Required = ex.Required || nf.Required
		} else {
			idx[key(nf)] = len(m.Fields)
			m.Fields = append(m.Fields, nf)
		}
	}
	m.Headers = unionStrings(cur.Headers, in.Headers)
	for k, v := range cur.Auth {
		m.Auth[k] = v
	}
	for k, v := range in.Auth {
		m.Auth[k] = v
	}
	if len(m.Auth) == 0 {
		m.Auth = nil
	}
	if in.Response != nil {
		m.Response = in.Response
	} else {
		m.Response = cur.Response
	}
	m.Sources = unionStrings(cur.Sources, append([]string{src}, in.Sources...))
	return m
}

func knownType(t string) bool { return t != "" && t != "unknown" }

// unionStrings returns the de-duplicated union preserving first-seen order, skipping empties.
func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// bestSource returns the highest-precedence source among a contract's provenance list.
func bestSource(sources []string) string {
	best, bestR := "", -1
	for _, s := range sources {
		if r := sourceRank(s); r > bestR {
			best, bestR = s, r
		}
	}
	return best
}

// classOf applies the injected endpoint classifier (set by the eva layer, which owns
// classifyEndpoint) if present; "" when no classifier is wired (keeps store free of an eva import).
func (s *Store) classOf(method, path string) string {
	if s.Classify != nil {
		return s.Classify(method, path)
	}
	return ""
}

// MarkAttacked records that the exploit phase worked an endpoint: it bumps the attempt count, sets
// captured if a finding landed, and stamps the time — so a later run (or pass) advances the frontier
// instead of re-attacking the same endpoints from the start.
func (s *Store) MarkAttacked(target, method, path string, captured bool) error {
	cap := 0
	if captured {
		cap = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO project_surface (target, method, path, attempts, captured, last_attacked) VALUES (?,?,?,1,?,?)
		 ON CONFLICT(target, method, path) DO UPDATE SET attempts=COALESCE(attempts,0)+1, captured=MAX(COALESCE(captured,0), excluded.captured), last_attacked=excluded.last_attacked`,
		target, method, path, cap, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// ListSurfaceByModel returns the endpoints one model found on a target (pass "" for deterministic
// recon), so a researcher can compare models' discovery against the same target.
func (s *Store) ListSurfaceByModel(target, model string) ([]SurfaceFind, error) {
	return s.findQuery(`SELECT target, method, path, model, run_id, note, ts FROM surface_find WHERE target=? AND model=? ORDER BY path, method`, target, model)
}

// ListSurfaceFinds returns the whole attribution ledger for a target (every model's sightings),
// the join behind a per-model comparison.
func (s *Store) ListSurfaceFinds(target string) ([]SurfaceFind, error) {
	return s.findQuery(`SELECT target, method, path, model, run_id, note, ts FROM surface_find WHERE target=? ORDER BY model, path, method`, target)
}

func (s *Store) findQuery(q string, args ...any) ([]SurfaceFind, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SurfaceFind
	for rows.Next() {
		var f SurfaceFind
		var runID, note sql.NullString
		var ts string
		if err := rows.Scan(&f.Target, &f.Method, &f.Path, &f.Model, &runID, &note, &ts); err != nil {
			return nil, err
		}
		f.RunID, f.Note = runID.String, note.String
		f.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, f)
	}
	return out, rows.Err()
}

// SaveFinding records a finding on a target's canonical ledger (deduped by target+type+value, so
// re-finding the same thing does not bloat memory) AND, when a model reported it (model != ""), a
// per-model attribution in finding_find — so a researcher can compare which model found which
// finding on the same target, exactly as the surface map and its attribution do.
func (s *Store) SaveFinding(target, model, runID, typ, value string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(
		`INSERT OR IGNORE INTO project_findings (target, type, value, run_id, ts) VALUES (?,?,?,?,?)`,
		target, typ, value, runID, now); err != nil {
		return err
	}
	if model == "" {
		return nil // no model attribution for a non-model source
	}
	_, err := s.db.Exec(
		`INSERT INTO finding_find (target, type, value, model, run_id, ts) VALUES (?,?,?,?,?,?)
		 ON CONFLICT(target, type, value, model) DO UPDATE SET run_id=excluded.run_id, ts=excluded.ts`,
		target, typ, value, model, runID, now)
	return err
}

// ListFindings returns a target's canonical findings (every model folded in), most recent first.
func (s *Store) ListFindings(target string) ([]FindingRow, error) {
	rows, err := s.db.Query(`SELECT target, type, value, run_id, ts FROM project_findings WHERE target=? ORDER BY ts DESC`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var r FindingRow
		var ts string
		if err := rows.Scan(&r.Target, &r.Type, &r.Value, &r.RunID, &ts); err != nil {
			return nil, err
		}
		r.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListFindingsByModel returns the findings one model reported on a target, so models can be
// compared against the same target (the finding-side mirror of ListSurfaceByModel).
func (s *Store) ListFindingsByModel(target, model string) ([]FindingRow, error) {
	return s.findingAttrQuery(`SELECT target, type, value, run_id, ts FROM finding_find WHERE target=? AND model=? ORDER BY ts DESC`, target, model)
}

// ListFindingAttrib returns the whole per-model finding ledger for a target.
func (s *Store) ListFindingAttrib(target string) ([]FindingRow, error) {
	return s.findingAttrQuery(`SELECT target, type, value, run_id, ts FROM finding_find WHERE target=? ORDER BY model, ts DESC`, target)
}

func (s *Store) findingAttrQuery(q string, args ...any) ([]FindingRow, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var r FindingRow
		var runID sql.NullString
		var ts string
		if err := rows.Scan(&r.Target, &r.Type, &r.Value, &runID, &ts); err != nil {
			return nil, err
		}
		r.RunID = runID.String
		r.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountSurface / CountFindings are best-effort counts for the console badges.
func (s *Store) CountSurface(target string) int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM project_surface WHERE target=?`, target).Scan(&n)
	return n
}

func (s *Store) CountFindings(target string) int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM project_findings WHERE target=?`, target).Scan(&n)
	return n
}
