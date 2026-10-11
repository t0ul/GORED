package demotarget

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gored "github.com/t0ul/GORED"
)

// newLive starts the real demo target over a real TCP listener (httptest), so the
// SSRF proxy makes a genuine loopback HTTP call back into the same app. No mocks.
func newLive(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, s
}

func get(t *testing.T, ts *httptest.Server, path string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func captured(s *Server, id string) bool {
	for _, st := range s.Status() {
		if st.ID == id {
			return st.Captured
		}
	}
	return false
}

func TestIDORDisclosesAdminNoteAndFlipsOracle(t *testing.T) {
	ts, s := newLive(t)
	if captured(s, "idor-notes") {
		t.Fatal("captured before exploit")
	}
	// No session: refused.
	if code, _ := get(t, ts, "/api/notes/1000", nil); code != http.StatusUnauthorized {
		t.Fatalf("want 401 without session, got %d", code)
	}
	if captured(s, "idor-notes") {
		t.Fatal("a refused request captured the flag")
	}
	// Low-priv session reading its own note does not capture.
	get(t, ts, "/api/notes/1", map[string]string{"X-Session": sessionToken})
	if captured(s, "idor-notes") {
		t.Fatal("reading an owned note captured the admin flag")
	}
	// The IDOR: same session reads the admin note → flag disclosed → oracle flips.
	code, body := get(t, ts, "/api/notes/1000", map[string]string{"X-Session": sessionToken})
	if code != http.StatusOK {
		t.Fatalf("want 200 for IDOR, got %d", code)
	}
	secret, _ := s.Oracle().Secret("idor-notes")
	if !strings.Contains(body, secret) {
		t.Fatalf("admin note did not contain the flag")
	}
	if !captured(s, "idor-notes") {
		t.Fatal("IDOR did not flip the oracle")
	}
}

func TestSSRFReachesInternalFlagOnlyViaProxy(t *testing.T) {
	ts, s := newLive(t)
	// Direct external hit on the internal endpoint is refused and captures nothing.
	if code, _ := get(t, ts, "/internal/flag", nil); code != http.StatusForbidden {
		t.Fatalf("want 403 on direct internal hit, got %d", code)
	}
	if captured(s, "ssrf-internal") {
		t.Fatal("direct internal hit captured the flag")
	}
	// External host through the proxy is refused (containment: loopback only).
	if code, _ := get(t, ts, "/api/fetch?url=http://example.com/", nil); code != http.StatusForbidden {
		t.Fatalf("want 403 for non-loopback fetch, got %d", code)
	}
	// The SSRF: proxy the internal URL → flag disclosed → oracle flips.
	code, body := get(t, ts, "/api/fetch?url="+ts.URL+"/internal/flag", nil)
	if code != http.StatusOK {
		t.Fatalf("want 200 via proxy, got %d", code)
	}
	secret, _ := s.Oracle().Secret("ssrf-internal")
	if !strings.Contains(body, secret) {
		t.Fatalf("proxied response did not contain the flag")
	}
	if !captured(s, "ssrf-internal") {
		t.Fatal("SSRF did not flip the oracle")
	}
}

func TestOracleStatusEndpointHidesSecrets(t *testing.T) {
	ts, s := newLive(t)
	get(t, ts, "/api/notes/1000", map[string]string{"X-Session": sessionToken})
	code, body := get(t, ts, "/oracle/status", nil)
	if code != http.StatusOK {
		t.Fatalf("status endpoint %d", code)
	}
	var out struct {
		Flags []gored.FlagStatus `json:"flags"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	secret, _ := s.Oracle().Secret("idor-notes")
	if strings.Contains(body, secret) {
		t.Fatal("status endpoint leaked the secret")
	}
	var found bool
	for _, f := range out.Flags {
		if f.ID == "idor-notes" {
			found = f.Captured
		}
	}
	if !found {
		t.Fatal("status did not report the capture")
	}
}

func TestManifestMatchesTrackedJSON(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	m, err := gored.LoadManifest("demo.target.json")
	if err != nil {
		t.Fatal(err)
	}
	got := s.Manifest()
	if len(got.Flags) != len(m.Flags) {
		t.Fatalf("flag count: code %d json %d", len(got.Flags), len(m.Flags))
	}
	for i := range got.Flags {
		if got.Flags[i].ID != m.Flags[i].ID || got.Flags[i].Class != m.Flags[i].Class {
			t.Fatalf("flag %d mismatch between code and tracked json", i)
		}
	}
}
