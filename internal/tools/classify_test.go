package tools

import "testing"

// apiShellNote must flag an API path that answered 2xx with the app's HTML shell (a dead-end), and
// stay quiet for real JSON data, non-API HTML pages, and error statuses.
func TestAPIShellNote(t *testing.T) {
	html := `<!DOCTYPE html><html lang="en"><head><title>RiskRancher</title></head><body>...</body></html>`
	json := `[{"id":1,"title":"ticket"}]`
	cases := []struct {
		name        string
		status      int
		path, body  string
		wantFlagged bool
	}{
		{"api path returns html shell", 200, "/api/adapters/1", html, true},
		{"api path returns json data", 200, "/api/tickets", json, false},
		{"non-api html page is fine", 200, "/dashboard", html, false},
		{"error status left to status class", 404, "/api/x", html, false},
		{"json suffix path html shell", 200, "/data.json", html, true},
	}
	for _, c := range cases {
		got := apiShellNote(c.status, c.path, c.body) != ""
		if got != c.wantFlagged {
			t.Errorf("%s: apiShellNote flagged=%v, want %v", c.name, got, c.wantFlagged)
		}
	}
}
