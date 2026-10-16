package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ffuf is the content-discovery (forced-browsing) scanner GORED wraps for the surface its route
// ingestion and crawl cannot see: unlinked endpoints, leftover backups, config/secret files, and
// exposed VCS/metadata. It is wordlist-driven and app-agnostic — the wrapper only ever hands it the
// target URL and a generic, curated path list (no app-specific paths) — so it does not overfit. It
// runs contained: single target, no recursion, authorized by the Gate's egress allowlist. ffuf is
// MIT-licensed, so bundling it is fine commercially.

// ffufWordlist is the generic, curated forced-browsing list: common leftover backups, config/secret
// files, exposed VCS/metadata, and a few sensitive dirs. Generic discovery knowledge, never
// app-specific paths — this is what keeps the scan generic across targets.
var ffufWordlist = []string{
	// backups / dumps
	"backup", "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql", "db.sql", "database.sql",
	"backup.bak", "site.zip", "www.zip", "release.zip",
	// config / secrets
	".env", ".env.local", ".env.production", "config.json", "config.yml", "config.yaml",
	"settings.json", "secrets.json", "credentials.json", "app.config", "web.config", ".htaccess",
	".npmrc", ".dockerenv", "docker-compose.yml", "Dockerfile",
	// VCS / metadata exposure
	".git/config", ".git/HEAD", ".gitignore", ".svn/entries", ".hg/hgrc", ".DS_Store",
	// keys / dependency manifests
	"id_rsa", "id_rsa.pub", "package.json", "package-lock.json", "composer.json", "go.mod",
	// ops / status / docs endpoints
	"robots.txt", "sitemap.xml", "server-status", "actuator", "actuator/health", "metrics",
	"swagger.json", "openapi.json", "api-docs", "phpinfo.php",
	// stale/dev dirs
	"old", "test", "debug", "tmp", "uploads", "admin", "backup/",
}

// DefaultFfufBin resolves the host install location (fail-closed bootstrap default; a datastore
// override belongs on top of this per config-in-db).
func DefaultFfufBin() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".riskrancher", "tools", "ffuf")
}

// FfufFinding is one discovered path.
type FfufFinding struct {
	URL    string
	Path   string // the FUZZ value that matched
	Status int
	Size   int
}

// FfufScanTool runs a contained ffuf content-discovery scan against the target.
type FfufScanTool struct {
	Gate     *Gate
	Base     string
	Bin      string   // default DefaultFfufBin()
	Wordlist []string // default ffufWordlist
}

func (FfufScanTool) Name() string { return "ffuf_scan" }
func (FfufScanTool) Describe() string {
	return `Discover unlinked endpoints, leftover backups, config/secret files, and exposed VCS metadata with the ffuf content-discovery scanner. args: {"url":"<optional base url>"}. It fuzzes a generic curated path list against the target; a hit is a path that exists but is not linked from the app.`
}

// Call runs the scan and returns a human summary (for the agent-tool form).
func (t FfufScanTool) Call(ctx context.Context, args map[string]any) (string, error) {
	target := t.Base
	if u := asString(args["url"]); u != "" {
		target = u
	}
	fs, err := t.Scan(ctx, target)
	if err != nil {
		return "", err
	}
	if len(fs) == 0 {
		return "ffuf: no content discovered", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ffuf: %d path(s) discovered\n", len(fs))
	for _, f := range fs {
		fmt.Fprintf(&b, "- %d %s (%d bytes)\n", f.Status, f.URL, f.Size)
	}
	return b.String(), nil
}

// Scan runs ffuf against target (contained) and returns the discovered paths.
func (t FfufScanTool) Scan(ctx context.Context, target string) ([]FfufFinding, error) {
	bin := t.Bin
	if bin == "" {
		bin = DefaultFfufBin()
	}
	words := t.Wordlist
	if len(words) == 0 {
		words = ffufWordlist
	}
	// Write the curated list to a temp wordlist file (ffuf reads -w from a file).
	wl, err := os.CreateTemp("", "gored-ffuf-*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(wl.Name())
	if _, err := wl.WriteString(strings.Join(words, "\n") + "\n"); err != nil {
		wl.Close()
		return nil, err
	}
	wl.Close()
	base := strings.TrimRight(target, "/")
	// Contained invocation: single target, no recursion, JSON records to stdout, silent.
	argv := []string{bin, "-u", base + "/FUZZ", "-w", wl.Name(),
		"-mc", "200,204,301,302,307,401,403", "-json", "-s"}
	out, err := t.Gate.Detonate(ctx, target, argv)
	if err != nil {
		return nil, err
	}
	return ParseFfuf(out), nil
}

// ParseFfuf parses ffuf's -json output (newline-delimited JSON records) and deduplicates by URL.
func ParseFfuf(out string) []FfufFinding {
	type raw struct {
		Input  map[string]string `json:"input"`
		Status int               `json:"status"`
		Length int               `json:"length"`
		URL    string            `json:"url"`
	}
	seen := map[string]bool{}
	var fs []FfufFinding
	for _, line := range strings.Split(out, "\n") {
		// ffuf prefixes each record with an ANSI escape (e.g. \x1b[2K) even when piped, so slice
		// from the first "{" to the last "}" to recover just the JSON object.
		i, j := strings.IndexByte(line, '{'), strings.LastIndexByte(line, '}')
		if i < 0 || j <= i {
			continue
		}
		var r raw
		if err := json.Unmarshal([]byte(line[i:j+1]), &r); err != nil || r.URL == "" {
			continue
		}
		if seen[r.URL] {
			continue
		}
		seen[r.URL] = true
		fs = append(fs, FfufFinding{URL: r.URL, Path: decodeFUZZ(r.Input["FUZZ"]), Status: r.Status, Size: r.Length})
	}
	return fs
}

// decodeFUZZ decodes the FUZZ value, which ffuf base64-encodes in its JSON "input" map; a value
// that is not valid base64 is returned as-is.
func decodeFUZZ(v string) string {
	if v == "" {
		return ""
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil {
		return string(b)
	}
	return v
}
