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
