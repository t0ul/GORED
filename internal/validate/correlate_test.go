package validate_test

import (
	"testing"

	"github.com/t0ul/GORED/internal/core"
	validate "github.com/t0ul/GORED/internal/validate"
)

// TestCorrelate mirrors the real shape of the RiskRancher lab findings and checks that
// the disjoint rows collapse the way triage needs: the same CVE from two scanners folds
// to one issue (with a reachability-aware scanner's verdict winning), many header alerts
// on one route fold to one route issue, many CVEs on one dependency fold to one module
// issue, and two rules at one file:line fold to one file issue — each keeping its sources.
func TestCorrelate(t *testing.T) {
	yes, no := true, false
	findings := []core.ScannerFinding{
		// The money shot: Trivy says present (unknown reachability), govulncheck ruled it
		// not-reachable. Same app, same module -> one issue, ruled-out, both sources.
		{Source: "Trivy", App: "riskrancher", Location: "golang.org/x/crypto", Severity: "UNKNOWN", Title: "GO-2026-5932"},
		{Source: "govulncheck", App: "riskrancher", Location: "golang.org/x/crypto", Severity: "Low", Reachable: &no, Title: "[not-reachable] GO-2026-5932"},

		// ZAP: three header alerts on one route -> one route issue, severity = worst.
		{Source: "OWASP ZAP", App: "riskrancher", Location: "/", Severity: "Medium", Title: "CSP header not set"},
		{Source: "OWASP ZAP", App: "riskrancher", Location: "/", Severity: "Low", Title: "Permissions-Policy not set"},
		{Source: "OWASP ZAP", App: "riskrancher", Location: "/", Severity: "Info", Title: "Storable content"},

		// Two reachable stdlib CVEs on one app -> one module issue, reachable.
		{Source: "govulncheck", App: "riskrancher", Location: "stdlib", Severity: "High", Reachable: &yes, Title: "[reachable] GO-2026-6599"},
		{Source: "govulncheck", App: "riskrancher", Location: "stdlib", Severity: "High", Reachable: &yes, Title: "[reachable] GO-2026-6600"},

		// Two semgrep cookie rules at the same file:line -> one file issue, two CWEs.
		{Source: "Semgrep", App: "riskrancher", Location: "cmd/stresstest/main.go:79", Severity: "Medium", CWE: "CWE-1004", Title: "cookie-missing-httponly"},
		{Source: "Semgrep", App: "riskrancher", Location: "cmd/stresstest/main.go:79", Severity: "Medium", CWE: "CWE-614", Title: "cookie-missing-secure"},

		// Same CVE, different app -> must NOT fold into riskrancher's issue.
		{Source: "Trivy", App: "krabber", Location: "golang.org/x/crypto", Severity: "UNKNOWN", Title: "GO-2026-5932"},
	}

	issues := validate.Correlate(findings)

	byKey := map[string]validate.CorrelatedIssue{}
	for _, c := range issues {
		byKey[c.App+":"+c.Locus] = c
	}

	// 10 findings -> 5 issues (crypto@rr, /@rr, stdlib@rr, main.go@rr, crypto@krabber).
	if len(issues) != 5 {
		t.Fatalf("want 5 issues, got %d: %+v", len(issues), issues)
	}

	crypto := byKey["riskrancher:golang.org/x/crypto"]
	if crypto.Count() != 2 {
		t.Errorf("crypto: want 2 findings folded, got %d", crypto.Count())
	}
	if len(crypto.Sources) != 2 || crypto.Sources[0] != "Trivy" || crypto.Sources[1] != "govulncheck" {
		t.Errorf("crypto: want sources [Trivy govulncheck], got %v", crypto.Sources)
	}
	if crypto.Reachable == nil || *crypto.Reachable {
		t.Errorf("crypto: reachability-aware scanner ruled it out, want ruled-out, got %v", crypto.Reachable)
	}
	if crypto.Severity != "low" {
		t.Errorf("crypto: want worst severity low (max of unknown,low), got %q", crypto.Severity)
	}
	if crypto.Kind != "module" {
		t.Errorf("crypto: want kind module, got %q", crypto.Kind)
	}

	route := byKey["riskrancher:/"]
	if route.Count() != 3 || route.Kind != "route" {
		t.Errorf("route: want 3 findings kind route, got %d %q", route.Count(), route.Kind)
	}
	if route.Severity != "medium" {
		t.Errorf("route: want worst severity medium, got %q", route.Severity)
	}

	std := byKey["riskrancher:stdlib"]
	if std.Reachable == nil || !*std.Reachable {
		t.Errorf("stdlib: has reachable members, want reachable, got %v", std.Reachable)
	}
	if std.Severity != "high" {
		t.Errorf("stdlib: want high, got %q", std.Severity)
	}

	file := byKey["riskrancher:cmd/stresstest/main.go"]
	if file.Count() != 2 || file.Kind != "file" {
		t.Errorf("file: want 2 findings kind file, got %d %q", file.Count(), file.Kind)
	}
	if len(file.CWEs) != 2 {
		t.Errorf("file: want 2 CWEs unioned, got %v", file.CWEs)
	}

	if _, ok := byKey["krabber:golang.org/x/crypto"]; !ok {
		t.Errorf("krabber crypto must stay its own issue, not fold into riskrancher's")
	}

	// Priority order: the reachable High (stdlib) must rank first; a ruled-out Low last
	// among the real ones. Just assert the top is the reachable high-severity issue.
	if issues[0].App+":"+issues[0].Locus != "riskrancher:stdlib" {
		t.Errorf("priority: want stdlib (reachable/high) first, got %s:%s", issues[0].App, issues[0].Locus)
	}
}

// TestLocusClassification checks the by-shape classification that lets different scanners'
// locators collapse: routes, modules, files, and the folding of instance ids in a route.
func TestLocusClassification(t *testing.T) {
	cases := []struct {
		loc  string
		want string // app:locus after correlation of a single finding
		kind string
	}{
		{"/api/drafts/5", "a:/api/drafts/{id}", "route"},
		{"/api/reports/9c/view", "a:/api/reports/9c/view", "route"}, // 9c is short alnum, not an id, stays
		{"golang.org/x/crypto/openpgp", "a:golang.org/x/crypto", "module"},
		{"stdlib", "a:stdlib", "module"},
		{"pkg/auth/auth_handlers.go:111", "a:pkg/auth/auth_handlers.go", "file"},
		{"src/app.ts", "a:src/app.ts", "file"},
	}
	for _, c := range cases {
		issues := validate.Correlate([]core.ScannerFinding{{App: "a", Location: c.loc, Severity: "Low"}})
		got := issues[0].App + ":" + issues[0].Locus
		if got != c.want || issues[0].Kind != c.kind {
			t.Errorf("loc %q: want %q/%s, got %q/%s", c.loc, c.want, c.kind, got, issues[0].Kind)
		}
	}
}
