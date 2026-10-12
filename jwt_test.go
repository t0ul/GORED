package gored_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/demotarget"
)

func base64urlJSON(seg string) (map[string]any, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	err = json.Unmarshal(b, &m)
	return m, err
}

func writeFile(dir, name, content string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
}

// aliceToken logs the low-priv alice in at /api/token and returns her bearer JWT.
func aliceToken(t *testing.T, base string) string {
	t.Helper()
	req, _ := http.NewRequest("POST", base+"/api/token", nil)
	req.Header.Set("X-Session", "alice-session")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out struct{ Token string }
	if err := json.Unmarshal(b, &out); err != nil || out.Token == "" {
		t.Fatalf("no token issued: %s", b)
	}
	return out.Token
}

func jwtProbe(t *testing.T, base string, secrets []string) *gored.JWTProbe {
	t.Helper()
	return &gored.JWTProbe{
		Base: base, Egress: gored.NewEgress(authority(t, base)), Sessions: gored.NewSessions(),
		Low:     gored.Identity{Name: "alice", Session: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		Secrets: secrets,
	}
}

// TestJWTForgeWithSourceSecret is the success line: the signing secret lives in the
// source, so GORED harvests it, forges a token with role=admin, and the server accepts it
// on replay — a certain CWE-347 finding. The whole chain runs against a real server.
func TestJWTForgeWithSourceSecret(t *testing.T) {
	_, base := liveTarget(t) // vulnerable build, signs with the in-source secret

	secrets := gored.HarvestSecrets("demotarget") // finds jwtDevSecret in demotarget.go
	if len(secrets) == 0 {
		t.Fatal("expected to harvest the dev signing secret from the demotarget source")
	}

	f, err := jwtProbe(t, base, secrets).Analyze(context.Background(), aliceToken(t, base), "/api/whoami")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Flagged() {
		t.Fatalf("source-secret token should be forgeable; got %+v", f)
	}
	if f.Vector != "secret-in-source" {
		t.Errorf("want vector secret-in-source, got %q", f.Vector)
	}
	if f.Confidence != gored.ConfCertain {
		t.Errorf("forged token accepted on replay, want certain, got %q (replay=%d)", f.Confidence, f.ReplayStatus)
	}
	if f.CWE != "CWE-347" {
		t.Errorf("want CWE-347, got %q", f.CWE)
	}
}

// TestJWTHardenedNotForged confirms the wiring: the hardened build signs with a strong
// per-process secret not in the source, so cracking fails, alg:none is refused, and
// nothing is flagged.
func TestJWTHardenedNotForged(t *testing.T) {
	s, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	base := serveTarget(t, s)
	f, err := jwtProbe(t, base, gored.HarvestSecrets("demotarget")).Analyze(context.Background(), aliceToken(t, base), "/api/whoami")
	if err != nil {
		t.Fatal(err)
	}
	if f.Flagged() {
		t.Errorf("hardened build uses a strong non-source secret; should not flag, got %+v", f)
	}
}

// TestJWTAlgNoneAccepted exercises the alg:none vector against a real server that trusts
// the header's alg and skips the signature — the probe forges an unsigned escalated token
// and the replay confirms acceptance.
func TestJWTAlgNoneAccepted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/whoami", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			w.WriteHeader(401)
			return
		}
		// The bug: if the header says alg:none, accept without checking a signature.
		hdr, _ := base64urlJSON(parts[0])
		if hdr["alg"] == "none" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(401)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	// Any HS256 token the app "issued"; its secret is unknown to the probe, so only the
	// alg:none path can land here.
	token := gored.ForgeHS256(map[string]any{"sub": "alice", "role": "user"}, "a-secret-the-probe-does-not-have")
	f, err := jwtProbe(t, ts.URL, nil).Analyze(context.Background(), token, "/api/whoami")
	if err != nil {
		t.Fatal(err)
	}
	if f.Vector != "alg-none" || f.Confidence != gored.ConfCertain {
		t.Fatalf("want alg-none/certain, got vector=%q conf=%q (replay=%d)", f.Vector, f.Confidence, f.ReplayStatus)
	}
}

// TestCrackAndHarvest covers the offline primitives: a token forged with a secret is
// cracked back to it, and HarvestSecrets pulls a signing secret out of a source file.
func TestCrackAndHarvest(t *testing.T) {
	tok, err := gored.ParseJWT(gored.ForgeHS256(map[string]any{"sub": "x"}, "hunter2key"))
	if err != nil {
		t.Fatal(err)
	}
	if got := gored.CrackHS256(tok, []string{"nope", "hunter2key", "other"}); got != "hunter2key" {
		t.Errorf("crack: want hunter2key, got %q", got)
	}
	if got := gored.CrackHS256(tok, []string{"nope", "other"}); got != "" {
		t.Errorf("crack: a wrong dictionary must not match, got %q", got)
	}

	dir := t.TempDir()
	if err := writeFile(dir, "config.go", "package c\n\nconst jwtSecret = \"topsecretvalue\"\n"); err != nil {
		t.Fatal(err)
	}
	found := gored.HarvestSecrets(dir)
	if !contains(found, "topsecretvalue") {
		t.Errorf("harvest: want topsecretvalue, got %v", found)
	}
}
