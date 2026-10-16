package probes

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/t0ul/GORED/internal/core"
)

// A real app with the stored-XSS shape: POST /ingest stores a title, GET /feed renders every stored
// title on a SEPARATE page. The vulnerable build writes the title into the HTML raw; the hardened
// build escapes it. This is the RR-H1 shape (ingested text -> rendered unescaped on another page),
// generic — no app-specific strings; the probe only gets the write endpoint + the render page.
func startStoredApp(t *testing.T, escape bool) (string, func()) {
	t.Helper()
	var mu sync.Mutex
	var titles []string
	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Title string `json:"title"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		titles = append(titles, body.Title)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/feed", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<!doctype html><html><body><ul>")
		for _, tt := range titles {
			v := tt
			if escape {
				v = html.EscapeString(tt) // hardened: the payload becomes inert text
			}
			fmt.Fprintf(w, "<li>%s</li>", v) // vulnerable: raw title into the DOM
		}
		io.WriteString(w, "</ul></body></html>")
	})
	ts := httptest.NewServer(mux)
	return ts.URL, ts.Close
}

// Live, real browser: a payload stored through /ingest must EXECUTE when /feed renders it, and the
// stored_xss tool must confirm it (injected at A, executed at B). The browser is the oracle.
func TestStoredXSSLive(t *testing.T) {
	chromeOrSkip(t)
	base, done := startStoredApp(t, false)
	defer done()
	out, err := StoredXSSTool{Gate: demoGate(t, base), Base: base, Sessions: core.NewSessions()}.Call(
		ctxWithTimeout(t), map[string]any{
			"method": "POST", "path": "/ingest", "field": "title",
			"render": []any{"/feed"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, DOMXSSSentinel) {
		t.Fatalf("stored_xss should confirm execution on the unescaped render page; got: %s", out)
	}
}

// An app whose write endpoint requires a JSON ARRAY (like RR's /api/ingest) and renders each stored
// name raw on /feed. It 400s a non-array body, so the simple {field:...} object form is rejected.
func startArrayIngestApp(t *testing.T) (string, func()) {
	t.Helper()
	var mu sync.Mutex
	var names []string
	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var arr []map[string]any
		if json.Unmarshal(b, &arr) != nil {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "expected array")
			return
		}
		mu.Lock()
		for _, o := range arr {
			if n, ok := o["name"].(string); ok {
				names = append(names, n)
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/feed", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<!doctype html><html><body>")
		for _, n := range names {
			fmt.Fprintf(w, "<div>%s</div>", n) // raw: vulnerable
		}
		io.WriteString(w, "</body></html>")
	})
	ts := httptest.NewServer(mux)
	return ts.URL, ts.Close
}

// The self-correction payoff: a raw body template lets the model express the array shape the
// endpoint demands, so the stored payload executes — the exact capability RR-H1 needs.
func TestStoredXSSBodyTemplate(t *testing.T) {
	chromeOrSkip(t)
	base, done := startArrayIngestApp(t)
	defer done()
	out, err := StoredXSSTool{Gate: demoGate(t, base), Base: base, Sessions: core.NewSessions()}.Call(
		ctxWithTimeout(t), map[string]any{
			"method": "POST", "path": "/ingest",
			"body":   `[{"name":"__PAYLOAD__"}]`,
			"render": []any{"/feed"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, DOMXSSSentinel) {
		t.Fatalf("body-template array should plant + execute; got: %s", out)
	}
}

// (a) shape self-heals: the simple object FIELD form against an array-only endpoint now plants +
// executes without the model giving a template, because plant auto-wraps object -> array.
func TestStoredXSSAutoArrayShape(t *testing.T) {
	chromeOrSkip(t)
	base, done := startArrayIngestApp(t)
	defer done()
	out, err := StoredXSSTool{Gate: demoGate(t, base), Base: base, Sessions: core.NewSessions()}.Call(
		ctxWithTimeout(t), map[string]any{
			"method": "POST", "path": "/ingest", "field": "name", // object form; tool auto-adapts to the array the app wants
			"render": []any{"/feed"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, DOMXSSSentinel) {
		t.Fatalf("object form should auto-adapt to the array shape and execute; got: %s", out)
	}
}

// (c) actionable reject: when EVERY shape is rejected (the endpoint needs a field the tool was not
// given), the diagnostic must be actionable — say it was rejected, surface the response, and show a
// GENERIC body-template example (placeholder field, never a real app's schema).
func startAlwaysRejectApp(t *testing.T) (string, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "missing required field: owner")
	})
	mux.HandleFunc("/feed", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<!doctype html><html><body></body></html>")
	})
	ts := httptest.NewServer(mux)
	return ts.URL, ts.Close
}

func TestStoredXSSRejectFeedback(t *testing.T) {
	chromeOrSkip(t)
	base, done := startAlwaysRejectApp(t)
	defer done()
	out, err := StoredXSSTool{Gate: demoGate(t, base), Base: base, Sessions: core.NewSessions()}.Call(
		ctxWithTimeout(t), map[string]any{
			"method": "POST", "path": "/ingest", "field": "name",
			"render": []any{"/feed"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "REJECTED") || !strings.Contains(out, "missing required field: owner") {
		t.Fatalf("rejection must surface the status/reason so the model self-corrects; got: %s", out)
	}
	if !strings.Contains(out, "__PAYLOAD__") {
		t.Errorf("reject diag should include the GENERIC body-template example; got: %s", out)
	}
}

// The hardened build escapes the stored title, so nothing executes — no false positive.
func TestStoredXSSHardenedNoFP(t *testing.T) {
	chromeOrSkip(t)
	base, done := startStoredApp(t, true)
	defer done()
	out, err := StoredXSSTool{Gate: demoGate(t, base), Base: base, Sessions: core.NewSessions()}.Call(
		ctxWithTimeout(t), map[string]any{
			"method": "POST", "path": "/ingest", "field": "title",
			"render": []any{"/feed"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, DOMXSSSentinel) {
		t.Fatalf("stored_xss must not flag the hardened build (render escaped); got: %s", out)
	}
}
