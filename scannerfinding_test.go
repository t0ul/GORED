package gored_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	gored "github.com/t0ul/GORED"
	_ "modernc.org/sqlite"
)

// TestSQLFindingSourceReadsAndDerives builds a real SQLite findings store shaped like
// RiskRancher's tickets table, reads it back through the source, and checks the
// derived fields (app/location, CWE, reachability). Real SQLite, no mocks.
func TestSQLFindingSourceReadsAndDerives(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "findings.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE tickets(
		source TEXT, title TEXT, asset_identifier TEXT, severity TEXT,
		description TEXT, recommended_remediation TEXT)`); err != nil {
		t.Fatal(err)
	}
	ins := func(source, title, asset, sev, desc, rem string) {
		if _, err := db.Exec(`INSERT INTO tickets VALUES(?,?,?,?,?,?)`, source, title, asset, sev, desc, rem); err != nil {
			t.Fatal(err)
		}
	}
	ins("govulncheck", "[reachable] GO-2026-6603 in stdlib", "riskrancher:stdlib", "High", "HTTP/2 memory exhaustion | govulncheck reachable=true", "Upgrade")
	ins("govulncheck", "[not-reachable] GO-2026-5932 in golang.org/x/crypto", "riskrancher:golang.org/x/crypto", "Low", "openpgp unmaintained | govulncheck reachable=false", "Review")
	ins("Semgrep", "cookie-missing-secure (CWE-614)", "riskrancher:pkg/auth/auth_handlers.go:111", "Medium", "Session cookie missing Secure flag | CWE-614 | pkg/auth/auth_handlers.go:111", "Set Secure")
	db.Close()

	src := gored.SQLFindingSource{DBPath: dbPath}
	got, err := src.Findings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 findings, got %d", len(got))
	}

	by := map[string]gored.ScannerFinding{}
	for _, f := range got {
		by[f.Source+"|"+f.Severity] = f
	}

	reachable := by["govulncheck|High"]
	if reachable.App != "riskrancher" || reachable.Location != "stdlib" {
		t.Errorf("asset not split: app=%q loc=%q", reachable.App, reachable.Location)
	}
	if reachable.Reachable == nil || !*reachable.Reachable {
		t.Errorf("GO-2026-6603 should derive reachable=true, got %v", reachable.Reachable)
	}

	ruledOut := by["govulncheck|Low"]
	if ruledOut.Reachable == nil || *ruledOut.Reachable {
		t.Errorf("GO-2026-5932 should derive reachable=false, got %v", ruledOut.Reachable)
	}

	semgrep := by["Semgrep|Medium"]
	if semgrep.CWE != "CWE-614" {
		t.Errorf("semgrep CWE not derived, got %q", semgrep.CWE)
	}
	if semgrep.Location != "pkg/auth/auth_handlers.go:111" {
		t.Errorf("semgrep location wrong: %q", semgrep.Location)
	}
	if semgrep.Reachable != nil {
		t.Errorf("semgrep reachability should be unknown (nil), got %v", *semgrep.Reachable)
	}
}
