package report

import (
	gored "github.com/t0ul/GORED"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"
)

// This file is the Documentation & Reporting stage (HTB stage 8): it assembles the
// verdicts GORED already produces — each with its rung, CWEs, executed repro, evidence,
// and chain — into a readable pentest report (exec summary + technical findings +
// remediation). It does no network or model work; it only formats what the Validator
// proved, so every line in the report traces to a verdict.

// ReportMeta labels a report.
type ReportMeta struct {
	Title  string
	Target string
	Scope  string // one line on authorization/containment, shown in the report
	Date   time.Time
}

// RemediationFor returns the fix for a CWE. The map covers the classes GORED discovers
// and validates; anything else gets a safe generic remediation.
func RemediationFor(cwe string) string {
	switch strings.ToUpper(strings.TrimSpace(cwe)) {
	case "CWE-78":
		return "Never pass user input to a shell. Invoke the program with an explicit argument array (no shell), and allow-list the inputs you accept."
	case "CWE-862", "CWE-285":
		return "Enforce authorization on every object access server-side: verify the caller is permitted to read or modify the specific resource, not just that they are logged in."
	case "CWE-639", "CWE-566":
		return "Scope every object lookup to the authenticated principal; never trust a client-supplied id to pick whose data is returned."
	case "CWE-915":
		return "Bind only an explicit allow-list of fields from the request body; never let the client set privileged fields (role, owner, verified, is_admin)."
	case "CWE-347", "CWE-345":
		return "Verify token signatures with a strong, server-only secret; reject alg=none and unexpected algorithms; rotate any secret that has leaked."
	case "CWE-250", "CWE-269":
		return "Run as a non-root user, drop Linux capabilities, enable a seccomp profile, and remove writable host mounts from the container."
	case "CWE-798", "CWE-259":
		return "Remove credentials from source and config; load them from a secret manager at runtime; rotate any secret that was committed."
	case "CWE-918":
		return "Allow-list outbound destinations, block internal and cloud-metadata addresses, and do not fetch user-supplied URLs server-side."
	case "CWE-89":
		return "Use parameterized queries / prepared statements; never concatenate user input into SQL."
	case "CWE-79":
		return "Contextually output-encode untrusted data and apply a strict Content-Security-Policy."
	default:
		return "Validate and constrain untrusted input, enforce least privilege, and apply server-side authorization on every sensitive operation."
	}
}

// severityOf returns the verdict's severity, deriving one from the rung, exploitability,
// CWE, and chain when the verdict did not carry an explicit Severity.
func severityOf(v gored.Verdict) string {
	if v.Severity != "" {
		return v.Severity
	}
	critical := map[string]bool{"CWE-78": true, "CWE-250": true, "CWE-918": true, "CWE-89": true}
	if v.Exploitable {
		for _, c := range v.CWEs {
			if critical[strings.ToUpper(c)] {
				return "Critical"
			}
		}
		if len(v.Chain) > 0 {
			return "Critical"
		}
		return "High"
	}
	switch v.Rung {
	case gored.LadderTriggerable, gored.LadderReachable:
		return "Medium"
	case gored.LadderPresent, gored.LadderReported:
		return "Low"
	default:
		return "Info"
	}
}

func severityRank(s string) int {
	switch s {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	default:
		return 0
	}
}

// RenderReportHTML renders the verdicts as a self-contained, theme-aware, script-free
// pentest report. Findings are ordered most-severe first.
func RenderReportHTML(meta ReportMeta, verdicts []gored.Verdict) []byte {
	rows := make([]gored.Verdict, len(verdicts))
	copy(rows, verdicts)
	sort.SliceStable(rows, func(i, j int) bool {
		si, sj := severityRank(severityOf(rows[i])), severityRank(severityOf(rows[j]))
		if si != sj {
			return si > sj
		}
		return gored.LadderRank(rows[i].Rung) > gored.LadderRank(rows[j].Rung)
	})

	counts := map[string]int{}
	exploitable := 0
	for _, v := range rows {
		counts[severityOf(v)]++
		if v.Exploitable {
			exploitable++
		}
	}

	title := meta.Title
	if title == "" {
		title = "GORED penetration test report"
	}
	date := meta.Date
	if date.IsZero() {
		date = time.Now()
	}

	var sum strings.Builder
	for _, s := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		if counts[s] > 0 {
			fmt.Fprintf(&sum, `<span class="pill sev-%s">%d %s</span>`, strings.ToLower(s), counts[s], html.EscapeString(s))
		}
	}

	var body strings.Builder
	for i, v := range rows {
		sev := severityOf(v)
		cwes := html.EscapeString(strings.Join(v.CWEs, ", "))
		if cwes == "" {
			cwes = "—"
		}
		mark := ""
		if v.Exploitable {
			mark = `<span class="exploit">exploitable</span>`
		}
		fmt.Fprintf(&body, `<section class="finding">
<h3><span class="sev sev-%s">%s</span> %s <span class="locus">%s:%s</span> %s</h3>
<div class="grid">
<div><b>CWE</b> %s</div><div><b>Evidence rung</b> %s (%s)</div>`,
			strings.ToLower(sev), html.EscapeString(sev), finvTitle(i+1),
			html.EscapeString(v.App), html.EscapeString(v.Locus), mark,
			cwes, html.EscapeString(string(v.Rung)), html.EscapeString(string(v.Confidence)))
		if v.Repro != "" {
			fmt.Fprintf(&body, `</div><div class="repro"><b>Reproduction</b><pre>%s</pre></div><div class="grid">`, html.EscapeString(v.Repro))
		}
		if len(v.Chain) > 0 {
			fmt.Fprintf(&body, `<div class="full"><b>Attack chain</b> %s</div>`, html.EscapeString(strings.Join(v.Chain, " → ")))
		}
		if len(v.Evidence) > 0 {
			fmt.Fprintf(&body, `<div class="full"><b>Evidence</b> %s</div>`, html.EscapeString(strings.Join(v.Evidence, "; ")))
		}
		// One remediation per distinct CWE.
		seen := map[string]bool{}
		var rem strings.Builder
		for _, c := range v.CWEs {
			if seen[c] {
				continue
			}
			seen[c] = true
			fmt.Fprintf(&rem, "<li>%s</li>", html.EscapeString(RemediationFor(c)))
		}
		if rem.Len() == 0 {
			rem.WriteString("<li>" + html.EscapeString(RemediationFor("")) + "</li>")
		}
		fmt.Fprintf(&body, `<div class="full"><b>Remediation</b><ul>%s</ul></div>`, rem.String())
		if len(v.Sources) > 0 {
			fmt.Fprintf(&body, `<div class="full src">found by: %s</div>`, html.EscapeString(strings.Join(v.Sources, ", ")))
		}
		body.WriteString(`</div></section>`)
	}

	scope := meta.Scope
	if scope == "" {
		scope = "Authorized testing of the author's own application; capture is oracle-authoritative and all execution was contained."
	}

	page := strings.NewReplacer(
		"__TITLE__", html.EscapeString(title),
		"__TARGET__", html.EscapeString(orDash(meta.Target)),
		"__DATE__", date.Format("2006-01-02"),
		"__SCOPE__", html.EscapeString(scope),
		"__SUMMARY__", sum.String(),
		"__TOTAL__", fmt.Sprintf("%d", len(rows)),
		"__EXPLOIT__", fmt.Sprintf("%d", exploitable),
		"__FINDINGS__", body.String(),
	).Replace(reportTmpl)
	return []byte(page)
}

func finvTitle(n int) string { return fmt.Sprintf("Finding %d", n) }

const reportTmpl = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#f7f8fa;--panel:#fff;--line:#e3e6ea;--fg:#1a1f24;--mut:#6b7482;--acc:#2f6feb;
--crit:#b4232a;--high:#c2410c;--med:#b7791f;--low:#2f6feb;--info:#6b7482}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0d1117;--panel:#161b22;--line:#2a313a;--fg:#e6edf3;--mut:#8b949e;--acc:#58a6ff;--crit:#f85149;--high:#db6d28;--med:#d29922;--low:#58a6ff;--info:#8b949e;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#0d1117;--panel:#161b22;--line:#2a313a;--fg:#e6edf3;--mut:#8b949e;--acc:#58a6ff;--crit:#f85149;--high:#db6d28;--med:#d29922;--low:#58a6ff;--info:#8b949e;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14.5px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding-block:32px;padding-inline:16px}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:28px 0 10px}
.meta{color:var(--mut);font-size:13px;margin:0 0 18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.pill{display:inline-block;font-size:12.5px;font-weight:650;color:#fff;border-radius:999px;padding:3px 11px;margin:0 6px 6px 0}
.sev-critical{background:var(--crit)}.sev-high{background:var(--high)}.sev-med,.sev-medium{background:var(--med)}.sev-low{background:var(--low)}.sev-info{background:var(--info)}
.big{font-size:15px}
.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.finding h3{font-size:15px;margin:0 0 10px;display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.sev{font-size:11px;font-weight:700;color:#fff;border-radius:5px;padding:2px 7px}
.locus{color:var(--mut);font-weight:500;font-size:13px}
.exploit{font-size:11px;font-weight:700;color:#fff;background:var(--crit);border-radius:5px;padding:2px 7px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:4px 18px;font-size:13.5px}
.grid .full{grid-column:1 / -1}
.repro{grid-column:1 / -1}
.repro pre,pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:9px 11px;overflow-x:auto;font:12.5px ui-monospace,Menlo,monospace;margin:4px 0;white-space:pre-wrap;word-break:break-word}
ul{margin:4px 0 0;padding-left:20px}
.src{color:var(--mut);font-size:12px}
.foot{color:var(--mut);font-size:12.5px;margin-top:26px;border-top:1px solid var(--line);padding-top:12px}
</style></head>
<body>
<div class="wrap">
  <h1>__TITLE__</h1>
  <p class="meta">Target <b>__TARGET__</b> · __DATE__</p>

  <h2>Executive summary</h2>
  <div class="card">
    <p class="big">__TOTAL__ findings, __EXPLOIT__ confirmed exploitable with an executed reproduction.</p>
    <p>__SUMMARY__</p>
    <p class="meta" style="margin:8px 0 0">Scope: __SCOPE__</p>
  </div>

  <h2>Findings</h2>
  __FINDINGS__

  <p class="foot">Severities are CVSS-aligned heuristics from the vulnerability class, the evidence rung, and whether an executed reproduction exists; they are not full CVSS vectors. Every finding above corresponds to a GORED verdict with the listed evidence. A reproduction shown is the exact request a reviewer re-runs to confirm the finding.</p>
</div>
</body></html>`
