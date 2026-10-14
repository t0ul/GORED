package report

import (
	gored "github.com/t0ul/GORED"
	"strings"
	"testing"
)

func TestRemediationFor(t *testing.T) {
	if !strings.Contains(RemediationFor("CWE-78"), "shell") {
		t.Error("CWE-78 remediation should mention the shell")
	}
	if !strings.Contains(RemediationFor("CWE-915"), "allow-list") {
		t.Error("CWE-915 remediation should mention an allow-list")
	}
	// Unknown CWE still returns a non-empty safe default.
	if RemediationFor("CWE-99999") == "" {
		t.Error("unknown CWE should get a generic remediation")
	}
}

func TestSeverityDerivation(t *testing.T) {
	cases := []struct {
		v    gored.Verdict
		want string
	}{
		{gored.Verdict{Exploitable: true, CWEs: []string{"CWE-78"}}, "Critical"},
		{gored.Verdict{Exploitable: true, CWEs: []string{"CWE-862"}}, "High"},
		{gored.Verdict{Exploitable: true, Chain: []string{"x"}}, "Critical"},
		{gored.Verdict{Rung: gored.LadderReachable}, "Medium"},
		{gored.Verdict{Rung: gored.LadderPresent}, "Low"},
		{gored.Verdict{Rung: "ruled-out"}, "Info"},
		{gored.Verdict{Severity: "High"}, "High"}, // explicit wins
	}
	for _, c := range cases {
		if got := severityOf(c.v); got != c.want {
			t.Errorf("severityOf(%+v)=%q want %q", c.v, got, c.want)
		}
	}
}

func TestRenderReportHTML(t *testing.T) {
	verdicts := []gored.Verdict{
		{App: "rr", Locus: "/api/reports/{id}", Rung: gored.LadderReachable, Confidence: "high", CWEs: []string{"CWE-862"}, Sources: []string{"gored-hunt"}},
		{App: "brig-target", Locus: "/exec", Rung: gored.LadderExploitable, Confidence: "certain", Exploitable: true,
			Repro: "http://127.0.0.1:8088/exec?cmd=id", CWEs: []string{"CWE-78"}, Sources: []string{"gored-brigsweep"},
			Chain: []string{"app RCE + root container = host compromise"}},
	}
	out := string(RenderReportHTML(ReportMeta{Title: "Test report", Target: "lab"}, verdicts))

	for _, want := range []string{
		"<title>Test report</title>", "Executive summary", "Findings",
		"CWE-78", "Reproduction", "Remediation", "app RCE + root container",
		"confirmed exploitable", `prefers-color-scheme:dark`, "background:var(--bg)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
	// Critical (exploitable CWE-78) must render before the Medium authz finding.
	if strings.Index(out, "/exec") > strings.Index(out, "/api/reports/{id}") {
		t.Error("findings not ordered most-severe first")
	}
	if strings.Contains(strings.ToLower(out), "<script") {
		t.Error("report must not embed scripts")
	}
}
