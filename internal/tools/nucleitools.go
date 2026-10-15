package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Nuclei is the breadth scanner GORED wraps for the web-hygiene / misconfiguration / exposure /
// CVE classes its native probes do not cover (missing security headers, host-header, error/info
// leak, directory listing, known CVEs). It is template-driven and app-agnostic: the wrapper only
// ever hands it the target URL and a generic, category-based template selection — no app-specific
// paths or payloads — so it does not overfit to any one target. It runs contained: single target,
// phone-home off (-no-interactsh -duc), authorized by the Gate's egress allowlist before it runs.
//
// nuclei (engine) and its community templates are MIT-licensed, so bundling it is fine commercially.

// nucleiCategories is the generic, pentest-relevant template selection. Category dirs, never
// app-specific template ids — this is what keeps the scan generic across targets.
var nucleiCategories = []string{
	"http/misconfiguration", "http/exposures", "http/vulnerabilities",
	"http/cves", "http/exposed-panels", "http/default-logins", "http/takeovers",
}

// DefaultNucleiBin / DefaultNucleiTemplates resolve the host install locations (fail-closed
// bootstrap defaults; a datastore override belongs on top of these per config-in-db).
func DefaultNucleiBin() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".riskrancher", "tools", "nuclei")
}
func DefaultNucleiTemplates() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "nuclei-templates")
}

// NucleiFinding is one deduplicated nuclei result, normalized for the Proof adapter.
type NucleiFinding struct {
	TemplateID string
	Name       string
	Severity   string // info | low | medium | high | critical
	CWEs       []string
	MatchedAt  string // the URL the finding was observed at (representative)
	Count      int    // how many raw matches collapsed into this one (e.g. headers across paths)
}

// NucleiScanTool runs a contained nuclei scan against the target and returns a short summary.
// The structured findings come from Scan (used by the campaign's deterministic pass).
type NucleiScanTool struct {
	Gate      *Gate
	Base      string
	Bin       string // default DefaultNucleiBin()
	Templates string // default DefaultNucleiTemplates()
}

func (NucleiScanTool) Name() string { return "nuclei_scan" }
func (NucleiScanTool) Describe() string {
	return `Run a contained nuclei scan of the target for misconfiguration, exposure, missing security headers, and known CVEs. args: {"url":"<optional path or full url>"}. Breadth coverage; the oracle-scored depth probes (BAC/IDOR, mass-assign, JWT) stay separate.`
}

// Call runs the scan and returns a human summary (for the agent-tool form).
func (t NucleiScanTool) Call(ctx context.Context, args map[string]any) (string, error) {
	target := t.Base
	if u := asString(args["url"]); u != "" {
		target = u
	}
	fs, err := t.Scan(ctx, target)
	if err != nil {
		return "", err
	}
	if len(fs) == 0 {
		return "nuclei: no findings", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "nuclei: %d finding(s)\n", len(fs))
	for _, f := range fs {
		fmt.Fprintf(&b, "- [%s] %s (%s) at %s\n", f.Severity, f.TemplateID, strings.Join(f.CWEs, ","), f.MatchedAt)
	}
	return b.String(), nil
}

// Scan runs nuclei against target (contained) and returns deduplicated findings.
func (t NucleiScanTool) Scan(ctx context.Context, target string) ([]NucleiFinding, error) {
	bin := t.Bin
	if bin == "" {
		bin = DefaultNucleiBin()
	}
	tpl := t.Templates
	if tpl == "" {
		tpl = DefaultNucleiTemplates()
	}
	// Contained invocation: single target, no update check, no out-of-band interaction server.
	argv := []string{bin, "-u", target, "-jsonl", "-silent", "-duc", "-no-interactsh",
		"-severity", "info,low,medium,high,critical"}
	for _, c := range nucleiCategories {
		argv = append(argv, "-t", filepath.Join(tpl, c))
	}
	out, err := t.Gate.Detonate(ctx, target, argv)
	if err != nil {
		return nil, err
	}
	return ParseNuclei(out), nil
}

// ParseNuclei parses nuclei JSONL and deduplicates by template id (so e.g. a missing-headers
// template matched on thirty paths collapses to one finding, with a count of how many it hit).
func ParseNuclei(jsonl string) []NucleiFinding {
	type rawInfo struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Classification struct {
			CWEID []string `json:"cwe-id"`
		} `json:"classification"`
	}
	type raw struct {
		TemplateID string  `json:"template-id"`
		Info       rawInfo `json:"info"`
		MatchedAt  string  `json:"matched-at"`
	}
	byID := map[string]*NucleiFinding{}
	var order []string
	for _, line := range strings.Split(jsonl, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var r raw
		if err := json.Unmarshal([]byte(line), &r); err != nil || r.TemplateID == "" {
			continue
		}
		f := byID[r.TemplateID]
		if f == nil {
			f = &NucleiFinding{
				TemplateID: r.TemplateID, Name: r.Info.Name, Severity: r.Info.Severity,
				CWEs: r.Info.Classification.CWEID, MatchedAt: r.MatchedAt,
			}
			byID[r.TemplateID] = f
			order = append(order, r.TemplateID)
		}
		f.Count++
	}
	out := make([]NucleiFinding, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}
