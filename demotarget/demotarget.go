// Package demotarget is a self-contained, benign CTF target for GORED: a tiny web
// app with two deliberately planted vulnerabilities, each guarding an unforgeable
// flag held by a gored.Oracle. It is benign by design — the flags are random
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
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	gored "github.com/t0ul/GORED"
)

const (
	// sessionToken is the low-privilege session the API requires. It stands in for
	// an authenticated non-admin user; the IDOR is that holding it lets you read
	// another user's record anyway.
	sessionToken = "alice-session"
	adminNoteID  = "1000"
)

// note is one record. Only the admin note carries a flag.
type note struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

// Server is the running demo target. It implements gored.Target.
type Server struct {
	oracle    *gored.Oracle
	manifest  gored.Manifest
	mux       *http.ServeMux
	notes     map[string]note
	internalK string // per-process secret header the fetch proxy injects
}

var demoFlags = []gored.FlagSpec{
	{
		ID:         "idor-notes",
		Class:      gored.ClassIDOR,
		Difficulty: gored.DiffEasy,
		Where:      "GET /api/notes/{id} with a valid session but no per-record ownership check; admin note id 1000 holds the flag",
		Detect:     "oracle records capture when the admin note's flag is served",
	},
	{
		ID:         "ssrf-internal",
		Class:      gored.ClassSSRF,
		Difficulty: gored.DiffMedium,
		Where:      "GET /api/fetch?url= proxies to loopback without an intended-host allowlist; GET /internal/flag holds the flag behind a header only the proxy sets",
		Detect:     "oracle records capture when /internal/flag is served through the proxy",
	},
}

// New builds the demo target with a fresh oracle (new unforgeable flags).
func New() (*Server, error) {
	oracle, err := gored.NewOracle(demoFlags)
	if err != nil {
		return nil, err
	}
	s := &Server{
		oracle:    oracle,
		manifest:  gored.Manifest{Name: "demotarget", Description: "Self-contained benign CTF target for GORED (IDOR + loopback SSRF).", Flags: demoFlags},
		notes:     map[string]note{},
		internalK: mint(),
	}
	// Low-privilege notes the session legitimately owns.
	s.notes["1"] = note{ID: "1", Owner: "alice", Title: "groceries", Body: "milk, eggs, bread"}
	s.notes["2"] = note{ID: "2", Owner: "alice", Title: "todo", Body: "call the plumber"}
	s.notes["3"] = note{ID: "3", Owner: "alice", Title: "idea", Body: "name the cat Mittens"}
	// The admin note carries the planted flag.
	flag, _ := s.oracle.Secret("idor-notes")
	s.notes[adminNoteID] = note{ID: adminNoteID, Owner: "admin", Title: "admin-only", Body: "internal config flag: " + flag}

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
func (s *Server) Oracle() *gored.Oracle { return s.oracle }

// Manifest implements gored.Target.
func (s *Server) Manifest() gored.Manifest { return s.manifest }

// Status implements gored.Target.
func (s *Server) Status() []gored.FlagStatus { return s.oracle.Status() }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /api/notes/{id}", s.handleNote)
	s.mux.HandleFunc("GET /api/fetch", s.handleFetch)
	s.mux.HandleFunc("GET /internal/flag", s.handleInternalFlag)
	s.mux.HandleFunc("GET /oracle/status", s.handleOracleStatus)
	s.mux.HandleFunc("POST /oracle/submit", s.handleOracleSubmit)
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"app":  "demotarget",
		"note": "benign GORED CTF target; authorized local testing only",
		"endpoints": []string{
			"GET /api/notes/{id}  (needs header X-Session)",
			"GET /api/fetch?url=  (link preview)",
			"GET /oracle/status",
			"POST /oracle/submit",
		},
	})
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
	// The bug: no ownership check here. Serving the admin note discloses the flag,
	// so the oracle records capture at this genuine exploit site.
	if id == adminNoteID {
		s.oracle.Disclosed("idor-notes", "idor:GET /api/notes/"+adminNoteID, "admin note served to session "+sessionToken)
	}
	writeJSON(w, http.StatusOK, n)
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
