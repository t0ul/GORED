package gored

import (
	"strings"
	"testing"
)

func TestCreateCandidate(t *testing.T) {
	yes := []string{"/api/tickets", "/api/memos", "/api/reports"}
	no := []string{"/api/auth/login", "/api/tickets/42", "/api/tickets/{id}", "/login", "/static/app.js"}
	for _, p := range yes {
		if !createCandidate(p) {
			t.Errorf("%s should be a create candidate", p)
		}
	}
	for _, p := range no {
		if createCandidate(p) {
			t.Errorf("%s should NOT be a create candidate", p)
		}
	}
}

// A ticket-shaped sample yields a body with the writable fields only (a strict API
// that 500s on extras still accepts it), the marker in a text field, severity set,
// and no read-only id echoed back.
func TestMinimalBodyFromSample(t *testing.T) {
	body := minimalBody(`[{"id":1,"title":"x","description":"y","severity":"high","status":"open"}]`, "MARK-123")
	for _, want := range []string{`"title"`, `"description"`, `"severity"`, "MARK-123"} {
		if !strings.Contains(body, want) {
			t.Errorf("minimal body missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, `"id"`) {
		t.Errorf("minimal body should not echo the read-only id: %s", body)
	}
}

func TestInjectMarkerAddsNoteWhenNoString(t *testing.T) {
	got := injectMarker(`{"count":5}`, "MARK-9")
	if !strings.Contains(got, "MARK-9") {
		t.Errorf("marker not injected: %s", got)
	}
}
