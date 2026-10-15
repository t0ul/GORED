// Package demotarget is a self-contained, benign CTF target for GORED: a tiny web
// app with two deliberately planted vulnerabilities, each guarding an unforgeable
// flag held by a core.Oracle. It is benign by design — the flags are random
// markers, the "SSRF" is scoped to loopback so it can never reach the internet,
// and nothing here attacks anything but itself. It is the one tracked target;
// real target manifests for the author's own apps stay private.
//
// Planted vulnerabilities:
//
//   - idor-notes (IDOR, easy). GET /api/notes/{id} requires a low-privilege
//     session but never checks per-record ownership, so a caller can read the
//     admin note (id 1000), which holds the flag.
//   - ssrf-internal (SSRF, medium). GET /api/fetch?url= proxies a URL for a "link
//     preview" but only validates that the host is loopback, not that it is an
//     intended host. An internal-only endpoint, GET /internal/flag, holds the
//     flag and is gated by a per-process secret header that only the proxy adds,
//     so the flag is reachable only by pointing the proxy at the internal URL.
package demotarget

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/t0ul/GORED/internal/core"
)

const (
	// sessionToken is the low-privilege session the API requires. It stands in for
	// an authenticated non-admin user; the IDOR is that holding it lets you read
	// another user's record anyway.
	sessionToken = "alice-session"
	adminNoteID  = "1000"

	// adminToken is a second, privileged identity. It exists for the differential
	// oracle: the same resource requested as alice vs admin reveals broken access
	// control WITHOUT a planted flag — alice should not see admin's data.
	adminToken = "admin-session"

	// jwtDevSecret is the HS256 signing secret the VULNERABLE build uses. It is a weak
	// secret committed to the source — exactly the mistake the JWT probe exploits: anyone
	// with the repo can forge a token with role=admin. The hardened build replaces it with
	// a strong per-process secret that is not in the source.
	jwtDevSecret = "dev-signing-key-do-not-ship"
)

// ownerForSession maps a session header to the identity that holds it, or "" for an
// unknown/absent session.
func ownerForSession(token string) string {
	switch token {
	case sessionToken:
		return "alice"
	case adminToken:
		return "admin"
	default:
		return ""
	}
}

// note is one record. Only the admin note carries a flag.
type note struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

// profile is a user's own account record. Role is a privileged attribute the server
// assigns — a client must not be able to set it. PUT /api/profile is the mass-assignment
// surface: the vulnerable build binds the whole request body onto the model (so a
// client-set role is honored), the hardened build binds only a name/bio whitelist.
type profile struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	Bio   string `json:"bio"`
	Role  string `json:"role"`
}

// Server is the running demo target. It implements core.Target.
type Server struct {
	oracle    *core.Oracle
	manifest  core.Manifest
	mux       *http.ServeMux
	notes     map[string]note
	mu        sync.Mutex         // guards memos and profiles (written by the POST/PUT handlers)
	memos     map[string]note    // the differential-oracle surface: owned records, no planted flag
	profiles  map[string]profile // the mass-assignment surface: each identity's own account record
	users     map[string]string  // the NoSQL-injection surface: username -> password for POST /api/login
	internalK string             // per-process secret header the fetch proxy injects
	jwtSecret string             // HS256 signing secret: weak/in-source (vuln) or strong/per-process (hardened)
	hardened  bool               // when true, the controls are wired and neither flag is reachable
}

// Option configures a demo target.
type Option func(*Server)

// WithHardened turns on the controls: per-record ownership on the notes API
// (closing the IDOR) and a path allowlist on the preview proxy that refuses the
// internal endpoint (closing the SSRF). It is the defended counterpart of the
// default vulnerable build — the pair an ADD AutonomousAdversary case attacks.
func WithHardened() Option { return func(s *Server) { s.hardened = true } }

var demoFlags = []core.FlagSpec{
	{
		ID:         "idor-notes",
		Class:      core.ClassIDOR,
		Difficulty: core.DiffEasy,
		Where:      "GET /api/notes/{id} with a valid session but no per-record ownership check; admin note id 1000 holds the flag",
		Detect:     "oracle records capture when the admin note's flag is served",
	},
	{
		ID:         "ssrf-internal",
		Class:      core.ClassSSRF,
		Difficulty: core.DiffMedium,
		Where:      "GET /api/fetch?url= proxies to loopback without an intended-host allowlist; GET /internal/flag holds the flag behind a header only the proxy sets",
		Detect:     "oracle records capture when /internal/flag is served through the proxy",
	},
	{
		ID:         "nosqli-login",
		Class:      core.ClassInjection,
		Difficulty: core.DiffMedium,
		Where:      "POST /api/login builds its query from the JSON body without neutralizing operators, so {\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}} authenticates and discloses the flag",
		Detect:     "oracle records capture when the flag is served on an operator-injection bypass",
	},
}

// New builds the demo target with a fresh oracle (new unforgeable flags). With no
// options it is the vulnerable build; WithHardened yields the defended build.
func New(opts ...Option) (*Server, error) {
	oracle, err := core.NewOracle(demoFlags)
	if err != nil {
		return nil, err
	}
	s := &Server{
		oracle:    oracle,
		manifest:  core.Manifest{Name: "demotarget", Description: "Self-contained benign CTF target for GORED (IDOR + loopback SSRF).", Flags: demoFlags},
		notes:     map[string]note{},
		memos:     map[string]note{},
		profiles:  map[string]profile{},
		users:     map[string]string{"alice": "correct-horse-battery", "admin": "s3cr3t-admin-" + mint()[:8]},
		internalK: mint(),
	}
	for _, opt := range opts {
		opt(s)
	}
	// The JWT signing secret. The vulnerable build ships the weak secret that lives in
	// the source; the hardened build mints a strong per-process secret not in the source,
	// so a forged token cannot be signed.
	if s.hardened {
		s.jwtSecret = mint()
	} else {
		s.jwtSecret = jwtDevSecret
	}
	// Low-privilege notes the session legitimately owns.
	s.notes["1"] = note{ID: "1", Owner: "alice", Title: "groceries", Body: "milk, eggs, bread"}
	s.notes["2"] = note{ID: "2", Owner: "alice", Title: "todo", Body: "call the plumber"}
	s.notes["3"] = note{ID: "3", Owner: "alice", Title: "idea", Body: "name the cat Mittens"}
	// The admin note carries the planted flag.
	flag, _ := s.oracle.Secret("idor-notes")
	s.notes[adminNoteID] = note{ID: adminNoteID, Owner: "admin", Title: "admin-only", Body: "internal config flag: " + flag}

	// Memos are the differential-oracle surface: owned records with NO planted flag.
	// alice owns an ordinary memo; admin owns a confidential one whose distinctive
	// contents are the datum a differential test watches for leaking to alice.
	s.memos["a1"] = note{ID: "a1", Owner: "alice", Title: "lunch", Body: "alice reminder: order sandwiches"}
	s.memos["x9"] = note{ID: "x9", Owner: "admin", Title: "deal", Body: "acquisition-target-Umbrella-Corporation, do not disclose"}

	// Account profiles for the mass-assignment surface. alice is an ordinary user; the
	// server assigns the role, so alice must not be able to make herself an admin.
	s.profiles["alice"] = profile{Owner: "alice", Name: "Alice", Bio: "just here for notes", Role: "user"}
	s.profiles["admin"] = profile{Owner: "admin", Name: "Admin", Bio: "the boss", Role: "admin"}

	s.mux = http.NewServeMux()
	s.routes()
	return s, nil
}

func mint() string {
	// Reuse the oracle's secret generator shape without exposing it; a short random
	// token is enough to gate the internal endpoint for one process.
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("demotarget: crypto/rand unavailable: " + err.Error())
	}
	return fmt.Sprintf("ik_%x", b)
}

// Handler returns the app's HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

// Oracle returns the authoritative capture oracle.
func (s *Server) Oracle() *core.Oracle { return s.oracle }

// Manifest implements core.Target.
func (s *Server) Manifest() core.Manifest { return s.manifest }

// Status implements core.Target.
func (s *Server) Status() []core.FlagStatus { return s.oracle.Status() }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /api/notes/{id}", s.handleNote)
	s.mux.HandleFunc("GET /api/memos", s.handleMemos)
	s.mux.HandleFunc("GET /api/memos/mine", s.handleMyMemos)
	s.mux.HandleFunc("GET /api/memos/{id}", s.handleGetMemo)
	s.mux.HandleFunc("POST /api/memos", s.handleCreateMemo)
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /graphql", s.handleGraphQL)
	s.mux.HandleFunc("GET /api/profile", s.handleGetProfile)
	s.mux.HandleFunc("PUT /api/profile", s.handleUpdateProfile)
	s.mux.HandleFunc("POST /api/token", s.handleIssueToken)
	s.mux.HandleFunc("GET /api/whoami", s.handleWhoami)
	s.mux.HandleFunc("GET /api/fetch", s.handleFetch)
	s.mux.HandleFunc("GET /internal/flag", s.handleInternalFlag)
	s.mux.HandleFunc("GET /oracle/status", s.handleOracleStatus)
	s.mux.HandleFunc("POST /oracle/submit", s.handleOracleSubmit)
}

// handleIndex serves a small HTML home page that LINKS the app's surface, so a
// crawler (the discover tool) can enumerate it the way it would a real app. The
// user's own notes (1-3) are linked; the admin note (1000) is NOT — reaching it is
// the IDOR the exploit agent must discover by changing the id.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	const page = `<!doctype html>
<html><head><title>Notes</title></head><body>
<h1>Notes</h1>
<p>Authorized local testing target. Log in as alice with request header
<code>X-Session: ` + sessionToken + `</code>.</p>
<ul>
  <li><a href="/api/notes/1">note 1</a></li>
  <li><a href="/api/notes/2">note 2</a></li>
  <li><a href="/api/notes/3">note 3</a></li>
</ul>
<p>Memos: <a href="/api/memos">/api/memos</a> (all) and <a href="/api/memos/mine">/api/memos/mine</a> (yours).</p>
<p>Your account: <a href="/api/profile">/api/profile</a> (GET to view, PUT to update your name and bio).</p>
<p>API tokens: POST /api/token for a bearer JWT, then <a href="/api/whoami">/api/whoami</a> with it.</p>
<p>Link preview tool: <a href="/api/fetch?url=">/api/fetch</a></p>
<p>Oracle status: <a href="/oracle/status">/oracle/status</a></p>
</body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

// handleNote is the IDOR: it authenticates the session but never checks that the
// session owns the requested note.
func (s *Server) handleNote(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Session") != sessionToken {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid X-Session"})
		return
	}
	id := r.PathValue("id")
	n, ok := s.notes[id]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such note"})
		return
	}
	// The control (hardened build): enforce per-record ownership. The session
	// belongs to alice, who owns notes 1-3; anything else is refused, closing the
	// IDOR so the admin note's flag never discloses.
	if s.hardened && n.Owner != "alice" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: not your record"})
		return
	}
	// The bug (default build): no ownership check here. Serving the admin note
	// discloses the flag, so the oracle records capture at this genuine exploit site.
	if id == adminNoteID {
		s.oracle.Disclosed("idor-notes", "idor:GET /api/notes/"+adminNoteID, "admin note served to session "+sessionToken)
	}
	writeJSON(w, http.StatusOK, n)
}

// handleMemos is the identity-based broken access control the differential oracle
// finds: any valid session lists EVERY memo, so a low-privilege caller (alice) sees
// the privileged caller's (admin's) confidential memo. No planted flag — the signal
// is purely that alice's response discloses admin's data. The hardened build scopes
// the list to the caller, closing it.
func (s *Server) handleMemos(w http.ResponseWriter, r *http.Request) {
	owner := ownerForSession(r.Header.Get("X-Session"))
	if owner == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid X-Session"})
		return
	}
	writeJSON(w, http.StatusOK, s.listMemos(owner, s.hardened))
}

// handleGetMemo is the OBJECT-LEVEL IDOR (CWE-639): it reads a memo by id for any
// valid session without checking the session owns it, so a low-privilege caller can
// read another identity's memo by its id. It is the surface the id-swapping step
// (phase 7a) exercises: plant a memo as the privileged identity, then read it by id
// as the low-privilege one. The hardened build enforces per-record ownership.
func (s *Server) handleGetMemo(w http.ResponseWriter, r *http.Request) {
	owner := ownerForSession(r.Header.Get("X-Session"))
	if owner == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid X-Session"})
		return
	}
	s.mu.Lock()
	m, ok := s.memos[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such memo"})
		return
	}
	if s.hardened && m.Owner != owner {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: not your record"})
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// handleMyMemos is the correctly-scoped control: it always lists only the caller's
// own memos, so alice and admin get disjoint data and a differential test does NOT
// flag it. It bounds the oracle's false positives.
func (s *Server) handleMyMemos(w http.ResponseWriter, r *http.Request) {
	owner := ownerForSession(r.Header.Get("X-Session"))
	if owner == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid X-Session"})
		return
	}
	writeJSON(w, http.StatusOK, s.listMemos(owner, true))
}

// handleCreateMemo lets a session create a memo it owns. It is the resource-creating
// endpoint the auto-canary-seeder plants into: a privileged identity POSTs a memo
// carrying a unique marker, which then shows up in the unscoped list — the reachable
// canary the test step confirms a low-privilege identity should not see.
func (s *Server) handleCreateMemo(w http.ResponseWriter, r *http.Request) {
	owner := ownerForSession(r.Header.Get("X-Session"))
	if owner == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid X-Session"})
		return
	}
	var in struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	s.mu.Lock()
	id := fmt.Sprintf("c%d", len(s.memos)+1)
	m := note{ID: id, Owner: owner, Title: in.Title, Body: in.Body}
	s.memos[id] = m
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, m)
}

// handleLogin is the NoSQL-injection surface. The vulnerable build checks credentials against a
// naive query built from the JSON body without neutralizing operator objects, so an object value
// ($ne/$gt/$regex) matches any user/password — an operator-injection auth bypass that discloses
// the flag. The hardened build requires scalar strings, closing it.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var in map[string]any
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	u, p := in["username"], in["password"]
	if s.hardened {
		// The control: credentials must be scalar strings; operator objects are rejected.
		us, uok := u.(string)
		ps, pok := p.(string)
		if !uok || !pok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password must be strings"})
			return
		}
		if us != "" && s.users[us] == ps {
			writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": us})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	// The bug: a string must match exactly, but an operator object matches ANY value.
	user, ok := s.naiveAuth(u, p)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	resp := map[string]any{"authenticated": true, "user": user}
	// A match that used an operator object is the injection bypass: disclose the flag, the way
	// the other planted vulns do when their control is defeated.
	if isOperator(u) || isOperator(p) {
		if flag, ok := s.oracle.Secret("nosqli-login"); ok {
			resp["flag"] = flag
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// naiveAuth simulates an auth query built from the request body: an operator object matches any.
func (s *Server) naiveAuth(u, p any) (string, bool) {
	for name, pass := range s.users {
		if matchVal(u, name) && matchVal(p, pass) {
			return name, true
		}
	}
	return "", false
}

// matchVal is the naive comparison: a string must equal the stored value; an operator object
// (a Mongo-style {"$ne":null}) matches anything — the un-neutralized operator that is the bug.
func matchVal(v any, actual string) bool {
	switch t := v.(type) {
	case string:
		return t == actual
	case map[string]any:
		return len(t) > 0
	default:
		return false
	}
}

func isOperator(v any) bool { _, ok := v.(map[string]any); return ok }

// graphqlSchema is the canned introspection response for the demo GraphQL endpoint: a query that
// takes an id (note(id:ID) — the IDOR/BAC candidate the probe looks for), a list query, and a
// mutation. It is the schema an attacker learns when introspection is left enabled.
const graphqlSchema = `{"data":{"__schema":{` +
	`"queryType":{"name":"Query","fields":[` +
	`{"name":"note","args":[{"name":"id","type":{"kind":"SCALAR","name":"ID","ofType":null}}],"type":{"kind":"OBJECT","name":"Note","ofType":null}},` +
	`{"name":"notes","args":[],"type":{"kind":"LIST","name":null,"ofType":{"kind":"OBJECT","name":"Note"}}}` +
	`]},` +
	`"mutationType":{"name":"Mutation","fields":[` +
	`{"name":"createNote","args":[{"name":"title","type":{"kind":"SCALAR","name":"String","ofType":null}},{"name":"body","type":{"kind":"SCALAR","name":"String","ofType":null}}],"type":{"kind":"OBJECT","name":"Note","ofType":null}}` +
	`]}` +
	`}}}`

// handleGraphQL is the GraphQL ingestion surface. The vulnerable build leaves schema introspection
// enabled — a common GraphQL misconfiguration (CWE-200 information disclosure) — so a POST of the
// introspection query returns the full schema, handing an attacker every operation (including the
// id-taking note(id) query, a GraphQL IDOR candidate). The hardened build disables introspection,
// so the schema is not disclosed and the ingestion probe finds no surface. Only introspection is
// wired here; exploiting a discovered operation is driven through api_request.
func (s *Server) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var in struct {
		Query string `json:"query"`
	}
	_ = json.Unmarshal(body, &in)
	if strings.Contains(in.Query, "__schema") {
		if s.hardened {
			// The control: introspection is disabled, so the schema is never disclosed.
			writeJSON(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "GraphQL introspection is disabled"}}})
			return
		}
		// The bug: introspection is enabled, disclosing the full attackable surface.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(graphqlSchema))
		return
	}
	// Non-introspection operations are not resolved by this demo endpoint; the agent exploits a
	// discovered operation via api_request against the real app, not this fixture.
	writeJSON(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "only introspection is wired in this demo endpoint"}}})
}

// handleGetProfile returns the caller's own account record. It is correctly scoped to the
// caller, so it is a clean read-back for the mass-assignment probe.
func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	owner := ownerForSession(r.Header.Get("X-Session"))
	if owner == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid X-Session"})
		return
	}
	s.mu.Lock()
	p := s.profiles[owner]
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, p)
}

// handleUpdateProfile is the MASS-ASSIGNMENT surface (CWE-915). The caller may update
// their own name and bio, but role is a privileged attribute the server assigns. The
// vulnerable build binds the whole request body onto the stored model, so a client-set
// "role" is honored and alice can make herself an admin. The hardened build binds only a
// name/bio whitelist, ignoring any role in the body — the control the probe must respect.
func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	owner := ownerForSession(r.Header.Get("X-Session"))
	if owner == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid X-Session"})
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.profiles[owner]
	if s.hardened {
		// The control: accept only the fields a user is allowed to change.
		var in struct {
			Name string `json:"name"`
			Bio  string `json:"bio"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
			return
		}
		cur.Name = in.Name
		cur.Bio = in.Bio
	} else {
		// The bug: unmarshal the raw request straight onto the model, binding every
		// field the client sent — including the privileged Role.
		if err := json.Unmarshal(body, &cur); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
			return
		}
	}
	cur.Owner = owner // the owner is always the caller; this is a privilege bug, not an ownership swap
	s.profiles[owner] = cur
	writeJSON(w, http.StatusOK, cur)
}

// handleIssueToken issues the caller an HS256 JWT carrying their identity and role, the
// way a login endpoint would. The role is the server-assigned one from the profile — the
// token is only as trustworthy as the signature, which is the JWT probe's target.
func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	owner := ownerForSession(r.Header.Get("X-Session"))
	if owner == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid X-Session"})
		return
	}
	s.mu.Lock()
	role := s.profiles[owner].Role
	s.mu.Unlock()
	claims := map[string]any{"sub": owner, "role": role, "iat": time.Now().Unix()}
	writeJSON(w, http.StatusOK, map[string]string{"token": signHS256(claims, s.jwtSecret)})
}

// handleWhoami is the protected endpoint a forged token is replayed against. It verifies
// the Bearer JWT's signature with the server's secret and rejects anything but HS256 (so
// alg:none is refused), then trusts the verified role. Both builds verify correctly; the
// only difference is the secret — weak and in the source (vuln) vs strong and private
// (hardened) — so the forgery lands only on the vulnerable build.
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims, ok := verifyHS256(tok, s.jwtSecret)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	role, _ := claims["role"].(string)
	out := map[string]any{"sub": claims["sub"], "role": role}
	if role == "admin" {
		out["admin_area"] = "welcome, administrator" // the escalated view a forged role unlocks
	}
	writeJSON(w, http.StatusOK, out)
}

// signHS256 and verifyHS256 are the app's own JWT implementation, independent of the
// attacker's code: sign builds header.payload.signature; verify rejects a non-HS256 alg
// (closing alg:none) and checks the HMAC in constant time (closing unsigned/wrong-secret
// tokens). The app is secure here regardless of the attack code — only the secret varies.
func signHS256(claims map[string]any, secret string) string {
	enc := base64.RawURLEncoding.EncodeToString
	h := enc([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, _ := json.Marshal(claims)
	p := enc(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + enc(mac.Sum(nil))
}

func verifyHS256(raw, secret string) (map[string]any, bool) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return nil, false
	}
	dec := base64.RawURLEncoding.DecodeString
	hdrRaw, err := dec(parts[0])
	if err != nil {
		return nil, false
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hdrRaw, &hdr) != nil || hdr.Alg != "HS256" {
		return nil, false // reject alg:none and anything that is not HS256
	}
	sig, err := dec(parts[2])
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, false // the signature does not verify under the server's secret
	}
	payRaw, err := dec(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if json.Unmarshal(payRaw, &claims) != nil {
		return nil, false
	}
	return claims, true
}

// listMemos returns every memo, or only those the owner holds when scoped.
func (s *Server) listMemos(owner string, scoped bool) []note {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.memos))
	for id := range s.memos {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []note{}
	for _, id := range ids {
		m := s.memos[id]
		if scoped && m.Owner != owner {
			continue
		}
		out = append(out, m)
	}
	return out
}

// handleFetch is the SSRF: a link-preview proxy that validates only that the host
// is loopback (keeping it off the internet), not that it is an intended host, so a
// caller can point it at the internal flag endpoint.
func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing url"})
		return
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url must be http(s)"})
		return
	}
	if !isLoopbackHost(u.Hostname()) {
		// Containment: the preview proxy is scoped to loopback and cannot reach the
		// internet. The SSRF is that within loopback it reaches endpoints it should
		// not, not that it reaches the outside world.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "preview restricted to local host"})
		return
	}
	// The control (hardened build): a path allowlist refuses internal routes, so
	// the proxy can no longer be pointed at /internal/flag — closing the SSRF.
	if s.hardened && strings.HasPrefix(u.Path, "/internal/") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: internal route not previewable"})
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, raw, nil)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "bad upstream request"})
		return
	}
	// The proxy marks its own outbound requests; this is what the internal endpoint
	// trusts, and what an external caller cannot forge without this secret.
	req.Header.Set("X-Internal-Auth", s.internalK)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream fetch failed"})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleInternalFlag serves the SSRF flag only to a request bearing the per-process
// internal header, which only the fetch proxy adds. A direct external request lacks
// it and is refused, so the proxy is the required path.
func (s *Server) handleInternalFlag(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Internal-Auth") != s.internalK {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "internal endpoint"})
		return
	}
	flag, _ := s.oracle.Secret("ssrf-internal")
	s.oracle.Disclosed("ssrf-internal", "ssrf:GET /api/fetch -> /internal/flag", "internal flag served to proxied request")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "internal service flag: %s\n", flag)
}

func (s *Server) handleOracleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"flags": s.oracle.Status()})
}

func (s *Server) handleOracleSubmit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		FlagID string `json:"flag_id"`
		Value  string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	ok := s.oracle.Submit(in.FlagID, in.Value)
	writeJSON(w, http.StatusOK, map[string]any{"captured": ok})
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
