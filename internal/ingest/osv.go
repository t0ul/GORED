package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Node (and other non-Go) software-composition analysis. GORED's SCA is Go-only (govulncheck,
// trivy), so a Node app's vulnerable dependencies are invisible. osv-scanner (Apache-2.0) reads a
// project's lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml, and more) and reports known
// vulnerabilities from the OSV database. This feeder runs it and maps each vulnerability to a
// ScannerFinding, so the existing validate.Correlate/Validator seam fuses and ranks it alongside the
// Go SCA and the runtime findings — no new validation path. It is source-side (it scans a directory
// of lockfiles, not a URL), so it does not go through the egress Gate; reachability is unknown (osv
// reports presence), which Correlate already handles.

// osvReport is the subset of osv-scanner's JSON output this feeder reads.
type osvReport struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID               string   `json:"id"`
				Aliases          []string `json:"aliases"`
				Summary          string   `json:"summary"`
				DatabaseSpecific struct {
					CWEIDs   []string `json:"cwe_ids"`
					Severity string   `json:"severity"` // GHSA word: LOW/MODERATE/HIGH/CRITICAL
				} `json:"database_specific"`
			} `json:"vulnerabilities"`
			Groups []struct {
				IDs         []string `json:"ids"`
				MaxSeverity string   `json:"max_severity"` // CVSS numeric score as a string
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

// ParseOSV maps an osv-scanner JSON report to ScannerFindings, one per vulnerability. The package is
// the Location (so Correlate groups a package's CVEs and shares the "upgrade" remediation); severity
// comes from the GHSA word when present, else from the group's CVSS score; the CWE and a CVE alias
// are carried through. Reachable stays nil (unknown) — osv reports presence, not reachability.
func ParseOSV(data []byte, app string) []ScannerFinding {
	var rep osvReport
	if json.Unmarshal(data, &rep) != nil {
		return nil
	}
	var out []ScannerFinding
	for _, r := range rep.Results {
		for _, p := range r.Packages {
			// group max_severity by vuln id, for vulns without a GHSA severity word.
			maxByID := map[string]string{}
			for _, g := range p.Groups {
				for _, id := range g.IDs {
					maxByID[id] = g.MaxSeverity
				}
			}
			for _, v := range p.Vulnerabilities {
				sev := normalizeOSVSeverity(v.DatabaseSpecific.Severity)
				if sev == "" {
					sev = cvssWord(maxByID[v.ID])
				}
				cwe := ""
				if len(v.DatabaseSpecific.CWEIDs) > 0 {
					cwe = strings.ToUpper(v.DatabaseSpecific.CWEIDs[0])
				}
				ref := v.ID
				for _, a := range v.Aliases {
					if strings.HasPrefix(a, "CVE-") {
						ref = a + " (" + v.ID + ")"
						break
					}
				}
				title := ref
				if v.Summary != "" {
					title = ref + ": " + v.Summary
				}
				out = append(out, ScannerFinding{
					Source:   "osv-scanner",
					App:      app,
					Location: p.Package.Name,
					Asset:    app + ":" + p.Package.Name,
					Severity: sev,
					Title:    title,
					CWE:      cwe,
					Description: fmt.Sprintf("%s@%s (%s) is affected by %s", p.Package.Name, p.Package.Version,
						p.Package.Ecosystem, v.ID),
				})
			}
		}
	}
	return out
}

// OSVScan runs osv-scanner against a source directory (its lockfiles) and returns the findings.
// osv-scanner writes JSON to stdout and logs to stderr, and exits non-zero when it finds
// vulnerabilities, so the JSON is parsed whenever stdout is non-empty regardless of the exit code.
func OSVScan(ctx context.Context, bin, dir, app string) ([]ScannerFinding, error) {
	if bin == "" {
		bin = "osv-scanner"
	}
	cctx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, 120*time.Second)
		defer cancel()
	}
	cmd := exec.CommandContext(cctx, bin, "--format", "json", dir)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	out := stdout.Bytes()
	if len(out) == 0 {
		if err != nil {
			return nil, fmt.Errorf("osv-scanner: %w", err)
		}
		return nil, nil
	}
	return ParseOSV(out, app), nil
}

// normalizeOSVSeverity maps a GHSA severity word to the vocabulary Correlate ranks (it already
// understands moderate==medium). Empty stays empty so the CVSS fallback can apply.
func normalizeOSVSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return ""
	}
}

// cvssWord maps a CVSS numeric score (osv group max_severity) to a severity word.
func cvssWord(score string) string {
	f, err := strconv.ParseFloat(strings.TrimSpace(score), 64)
	if err != nil {
		return ""
	}
	switch {
	case f >= 9.0:
		return "critical"
	case f >= 7.0:
		return "high"
	case f >= 4.0:
		return "medium"
	case f > 0:
		return "low"
	default:
		return ""
	}
}
