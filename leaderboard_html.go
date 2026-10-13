package gored

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"
)

// LeaderboardMeta labels a rendered leaderboard: what target and how many trials
// produced it, so a reviewer reads the numbers in context.
type LeaderboardMeta struct {
	Title  string
	Target string
	Flag   string
	Trials int
	Note   string
}

// RenderLeaderboardHTML renders contender summaries as a self-contained, theme-aware
// HTML leaderboard for review: one row per contender (a model×shape cell), sorted by
// capture rate then compute, with a capture-rate bar and the iso-budget cap-per-Mtoken
// column. It is pure (no I/O) and embeds no scripts, so it is safe to open or publish
// anywhere. The headline it is built to answer: which local setup captures most per
// unit compute.
func RenderLeaderboardHTML(meta LeaderboardMeta, sums []ContenderSummary) []byte {
	rows := make([]ContenderSummary, len(sums))
	copy(rows, sums)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].CaptureRate != rows[j].CaptureRate {
			return rows[i].CaptureRate > rows[j].CaptureRate
		}
		if rows[i].CapturePerMTok != rows[j].CapturePerMTok {
			return rows[i].CapturePerMTok > rows[j].CapturePerMTok
		}
		return rows[i].MeanTokens < rows[j].MeanTokens
	})

	title := meta.Title
	if title == "" {
		title = "GORED leaderboard"
	}
	maxCPM := 0.0
	for _, r := range rows {
		if r.CapturePerMTok > maxCPM {
			maxCPM = r.CapturePerMTok
		}
	}

	var tb strings.Builder
	for i, r := range rows {
		scored := "—"
		if r.MeanRecall != nil {
			scored = fmt.Sprintf("%.2f / %.2f", *r.MeanRecall, *r.MeanPrecision)
		}
		cpm := "—"
		if r.CapturePerMTok > 0 {
			cpm = fmt.Sprintf("%.0f", r.CapturePerMTok)
		}
		// cap-per-Mtok efficiency bar, relative to the best in the table.
		eff := 0.0
		if maxCPM > 0 {
			eff = r.CapturePerMTok / maxCPM
		}
		fmt.Fprintf(&tb, `<tr>
<td class="rank">%d</td>
<td class="name">%s</td>
<td><span class="chip %s">%s</span></td>
<td class="num"><div class="bar"><span style="width:%.0f%%"></span></div><b>%.0f%%</b> <span class="mut">%d/%d</span></td>
<td class="num">%.1f</td>
<td class="num">%s</td>
<td class="num">%.1f</td>
<td class="num eff"><div class="bar alt"><span style="width:%.0f%%"></span></div>%s</td>
<td class="num">%s</td>
</tr>`,
			i+1,
			html.EscapeString(r.Contender),
			shapeClass(r.Shape), html.EscapeString(string(r.Shape)),
			r.CaptureRate*100, r.CaptureRate*100, r.Captured, r.Trials,
			r.MeanToolCall,
			commaInt(r.MeanTokens),
			r.ParamsB,
			eff*100, cpm,
			scored,
		)
	}

	metaLine := fmt.Sprintf("target <b>%s</b>", html.EscapeString(orDash(meta.Target)))
	if meta.Flag != "" {
		metaLine += " · flag <b>" + html.EscapeString(meta.Flag) + "</b>"
	}
	if meta.Trials > 0 {
		metaLine += fmt.Sprintf(" · %d trial(s)/cell", meta.Trials)
	}
	metaLine += " · " + time.Now().Format("2006-01-02 15:04")
	if meta.Note != "" {
		metaLine += " · " + html.EscapeString(meta.Note)
	}

	page := strings.NewReplacer(
		"__TITLE__", html.EscapeString(title),
		"__META__", metaLine,
		"__ROWS__", tb.String(),
		"__COUNT__", fmt.Sprintf("%d", len(rows)),
	).Replace(leaderboardTmpl)
	return []byte(page)
}

func shapeClass(s Shape) string {
	switch s {
	case ShapeSolo:
		return "a"
	case ShapePlanner:
		return "b"
	case ShapeStatic:
		return "e"
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// commaInt formats a rounded float with thousands separators.
func commaInt(f float64) string {
	n := int64(f + 0.5)
	s := fmt.Sprintf("%d", n)
	if n < 1000 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

const leaderboardTmpl = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--line:#e3e6ea;--fg:#1a1f24;--mut:#6b7482;--acc:#2f6feb;
--a:#2f6feb;--b:#8957e5;--e:#1a7f5a;--bar:#dfe7f5;--barfill:#2f6feb;--alt:#e9f3ee;--altfill:#1a7f5a}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0d1117;--panel:#161b22;--line:#2a313a;--fg:#e6edf3;--mut:#8b949e;--acc:#58a6ff;--a:#58a6ff;--b:#bc8cff;--e:#3fb950;--bar:#1d2633;--barfill:#58a6ff;--alt:#17251d;--altfill:#3fb950;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#0d1117;--panel:#161b22;--line:#2a313a;--fg:#e6edf3;--mut:#8b949e;--acc:#58a6ff;--a:#58a6ff;--b:#bc8cff;--e:#3fb950;--bar:#1d2633;--barfill:#58a6ff;--alt:#17251d;--altfill:#3fb950;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding-block:28px;padding-inline:16px}
h1{font-size:20px;margin:0 0 4px;font-weight:650;letter-spacing:-.01em}
.meta{color:var(--mut);font-size:12.5px;margin:0 0 18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:720px;font-variant-numeric:tabular-nums}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--panel)}
tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right}
.rank{color:var(--mut);width:34px}
.name{font-weight:600;max-width:260px;white-space:normal;word-break:break-word}
.mut{color:var(--mut);font-weight:400;font-size:12px}
.chip{display:inline-block;font-size:11px;font-weight:600;border-radius:999px;padding:2px 9px;color:#fff}
.chip.a{background:var(--a)}.chip.b{background:var(--b)}.chip.e{background:var(--e)}
.bar{display:block;height:6px;border-radius:4px;background:var(--bar);margin:0 0 3px;overflow:hidden}
.bar span{display:block;height:100%;background:var(--barfill);border-radius:4px}
.bar.alt{background:var(--alt)}.bar.alt span{background:var(--altfill)}
.eff b,td b{font-weight:650}
.legend{color:var(--mut);font-size:12px;margin:14px 2px 0;line-height:1.7}
.legend code{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:1px 5px}
</style></head>
<body>
<div class="wrap">
  <h1>__TITLE__</h1>
  <p class="meta">__META__ · __COUNT__ contenders</p>
  <div class="card scroll">
    <table>
      <thead><tr>
        <th>#</th><th>contender</th><th>shape</th>
        <th class="num">capture rate</th><th class="num">tools</th><th class="num">tokens</th>
        <th class="num">params B</th><th class="num">cap / Mtok</th><th class="num">recall / prec</th>
      </tr></thead>
      <tbody>
__ROWS__
      </tbody>
    </table>
  </div>
  <p class="legend">
    <b>capture rate</b> = fraction of trials the oracle confirmed a capture (dark bar).
    <b>cap / Mtok</b> = capture rate per million tokens spent — the iso-budget headline (green bar, relative to the best cell).
    <b>tokens</b> = mean prompt+completion per trial. <b>shape</b>: <span class="chip a">A-solo</span> one model+tools ·
    <span class="chip b">B-planner</span> model planner + doers · <span class="chip e">E-static</span> deterministic planner + doers.
    <b>recall / prec</b> shown only when scored against a frozen ruler.
  </p>
</div>
</body></html>`
