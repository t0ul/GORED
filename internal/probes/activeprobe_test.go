package probes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/t0ul/GORED/internal/core"
)

// Active probing must reverse-engineer a request shape that NO source parser would see here: a plain
// server-rendered <form> with no JS and no fetch. The probe drives it in a real browser, submits it,
// and records the actual POST (method, path, body fields) — the framework-agnostic win.
func TestActiveProbeFormSubmit(t *testing.T) {
	chromeOrSkip(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// no JS, no fetch — just HTML a classic/htmx app renders
		_, _ = w.Write([]byte(`<!doctype html><html><body>
			<form method="POST" action="/subscribe">
			  <input name="email" type="email">
			  <input name="note" type="text">
			  <button type="submit">Go</button>
			</form></body></html>`))
	})
	mux.HandleFunc("/subscribe", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	ts := httptest.NewServer(mux)
	defer ts.Close()

	p := &ActiveProbe{Base: ts.URL, Egress: core.NewEgress(hostOf(ts.URL)), Sessions: core.NewSessions()}
	shapes, err := p.Probe(ctxWithTimeout(t), []string{"/"})
	if err != nil {
		t.Fatal(err)
	}
	var got *APIShape
	for i := range shapes {
		if shapes[i].Method == "POST" && shapes[i].Path == "/subscribe" {
			got = &shapes[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("active probe did not capture the form POST; shapes=%+v", shapes)
	}
	has := map[string]bool{}
	for _, f := range got.Fields {
		has[f] = true
	}
	if !has["email"] || !has["note"] {
		t.Errorf("captured body fields = %v, want email+note", got.Fields)
	}
	// The control types are recovered from the page's own inputs (type=email / type=text), so a
	// server-rendered form with no OpenAPI spec still yields typed fields.
	if got.Types["email"] != "email" {
		t.Errorf("email input should be typed email, got %q (types=%v)", got.Types["email"], got.Types)
	}
	if got.Types["note"] != "string" {
		t.Errorf("text input note should be typed string, got %q (types=%v)", got.Types["note"], got.Types)
	}
}
