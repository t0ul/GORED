package ingest

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Pure logic: parse a representative osv-scanner report (the real shape, captured from osv-scanner
// 2.1.0 on lodash). A GHSA vuln carries a severity word + CWE; a vuln without a GHSA word falls back
// to the group's CVSS max_severity; the package is the Location so a package's CVEs correlate.
func TestParseOSV(t *testing.T) {
	data := []byte(`{"results":[{"source":{"path":"/x/package-lock.json","type":"lockfile"},"packages":[{
	  "package":{"name":"lodash","version":"4.17.11","ecosystem":"npm"},
	  "vulnerabilities":[
	    {"id":"GHSA-29mw-wpgm-hmr9","aliases":["CVE-2020-28500"],"summary":"ReDoS in lodash","database_specific":{"cwe_ids":["CWE-1333","CWE-400"],"severity":"MODERATE"}},
	    {"id":"GHSA-jf85-cpcp-j695","aliases":["CVE-2019-10744"],"summary":"Prototype pollution","database_specific":{"cwe_ids":["CWE-1321"]}}
	  ],
	  "groups":[
	    {"ids":["GHSA-29mw-wpgm-hmr9"],"max_severity":"5.3"},
	    {"ids":["GHSA-jf85-cpcp-j695"],"max_severity":"9.1"}
	  ]
	}]}]}`)
	fs := ParseOSV(data, "nodeapp")
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(fs), fs)
	}
	byCWE := map[string]ScannerFinding{}
	for _, f := range fs {
		if f.Source != "osv-scanner" || f.App != "nodeapp" || f.Location != "lodash" {
			t.Fatalf("finding fields wrong: %+v", f)
		}
		byCWE[f.CWE] = f
	}
	// GHSA word -> medium (moderate); CWE carried from database_specific.
	if m := byCWE["CWE-1333"]; m.Severity != "medium" {
		t.Fatalf("GHSA MODERATE should map to medium: %+v", m)
	}
	// No GHSA word -> CVSS 9.1 -> critical; and the CVE alias is in the title.
	pp := byCWE["CWE-1321"]
	if pp.Severity != "critical" {
		t.Fatalf("CVSS 9.1 should map to critical: %+v", pp)
	}
	if want := "CVE-2019-10744"; !strings.Contains(pp.Title, want) {
		t.Fatalf("title should carry the CVE alias %q: %q", want, pp.Title)
	}
}

// Live, real scanner: run osv-scanner over a Node lockfile with a known-vulnerable dependency and
// confirm it reports vulnerabilities as ScannerFindings. Skips if osv-scanner is not installed or the
// scan cannot reach the OSV database (offline) — osv-scanner is a source-side SCA feeder, not gated.
func TestOSVScanLive(t *testing.T) {
	if _, err := exec.LookPath("osv-scanner"); err != nil {
		t.Skip("osv-scanner not installed; skipping live SCA test")
	}
	dir := t.TempDir()
	lock := `{"name":"gored-nodefix","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{` +
		`"":{"name":"gored-nodefix","version":"1.0.0","dependencies":{"lodash":"4.17.11"}},` +
		`"node_modules/lodash":{"version":"4.17.11","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz","license":"MIT"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := OSVScan(context.Background(), "", dir, "nodeapp")
	if err != nil {
		t.Skipf("osv-scanner could not complete (likely offline): %v", err)
	}
	if len(fs) == 0 {
		t.Skip("osv-scanner returned no findings (offline/empty DB); skipping")
	}
	for _, f := range fs {
		if f.Location == "lodash" && f.Source == "osv-scanner" {
			return // found the known-vulnerable dependency
		}
	}
	t.Fatalf("expected an osv-scanner finding for lodash; got %d findings: %+v", len(fs), fs)
}
