package gored

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	_ "modernc.org/sqlite"
)

// ScannerFinding is one finding a scanner reported, read back from an aggregator
// (RiskRancher, a SARIF file, DefectDojo). It is UNTRUSTED input — a claim to be
// validated, never a verdict — so it carries what the scanner said plus the fields
// GORED derives to decide how to validate it. The validator pushes each one up the
// evidence ladder (present -> reachable -> triggerable -> exploitable) and only ever
// claims the rung it proved.
type ScannerFinding struct {
	Source      string // the scanner: Trivy, govulncheck, Semgrep, ...
	Title       string
	Asset       string // the aggregator's asset id, conventionally "app:location"
	App         string // derived: the part before the first ':' in Asset
	Location    string // derived: the part after it (a file:line, a package, a URL)
	Severity    string
	Description string
	Remediation string
	CWE         string // derived from the title/description if present
	Reachable   *bool  // derived from a reachability marker; nil = unknown
}

// Line renders a finding as one compact, grid-safe line for the blackboard / a report.
func (f ScannerFinding) Line() string {
	reach := ""
	if f.Reachable != nil {
		if *f.Reachable {
			reach = " reachable"
		} else {
			reach = " not-reachable"
		}
	}
	cwe := ""
	if f.CWE != "" {
		cwe = " " + f.CWE
	}
	return strings.TrimSpace(fmt.Sprintf("[%s%s%s] %s @ %s (%s)", f.Source, cwe, reach, f.Title, f.Asset, f.Severity))
}

// FindingSource yields scanner findings from an aggregator. Implementations are
// adapters over a store (a DB, a file); the engine depends only on this interface,
// so RiskRancher, SARIF, or anything else plugs in without touching the validator.
type FindingSource interface {
	Findings(ctx context.Context) ([]ScannerFinding, error)
}

// FindingCols names the columns that hold each field in a findings table, so the SQL
// source reads any aggregator's schema without GORED hard-coding one.
type FindingCols struct {
	Source, Title, Asset, Severity, Description, Remediation string
}

// RiskRancherCols maps RiskRancher's `tickets` table. Reading the DB directly gets the
// full rows — RR's list API blanks source/description (its own broken-access-control
// behavior), but those columns are intact in the store.
var RiskRancherCols = FindingCols{
	Source: "source", Title: "title", Asset: "asset_identifier",
	Severity: "severity", Description: "description", Remediation: "recommended_remediation",
}

// SQLFindingSource reads findings from a SQLite findings store (RiskRancher's tickets
// table by default) through a column mapping. It opens the DB read-only and derives
// App/Location/CWE/Reachable from the stored fields.
type SQLFindingSource struct {
	DBPath string
	Table  string      // default "tickets"
	Cols   FindingCols // default RiskRancherCols
	Where  string      // optional SQL filter (without the WHERE keyword)
}

// Findings reads and derives the findings.
func (s SQLFindingSource) Findings(ctx context.Context) ([]ScannerFinding, error) {
	table := s.Table
	if table == "" {
		table = "tickets"
	}
	cols := s.Cols
	if (cols == FindingCols{}) {
		cols = RiskRancherCols
	}
	db, err := sql.Open("sqlite", s.DBPath+"?_pragma=busy_timeout(5000)&mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open findings db: %w", err)
	}
	defer db.Close()

	where := ""
	if strings.TrimSpace(s.Where) != "" {
		where = " WHERE " + s.Where
	}
	// COALESCE every column so a NULL (common in aggregator schemas) reads as "".
	c := func(name string) string { return "COALESCE(" + name + ",'')" }
	q := fmt.Sprintf("SELECT %s, %s, %s, %s, %s, %s FROM %s%s",
		c(cols.Source), c(cols.Title), c(cols.Asset), c(cols.Severity), c(cols.Description), c(cols.Remediation), table, where)
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	var out []ScannerFinding
	for rows.Next() {
		var f ScannerFinding
		if err := rows.Scan(&f.Source, &f.Title, &f.Asset, &f.Severity, &f.Description, &f.Remediation); err != nil {
			return nil, err
		}
		deriveFinding(&f)
		out = append(out, f)
	}
	return out, rows.Err()
}

var (
	reCWE       = regexp.MustCompile(`CWE[-\s]?(\d+)`)
	reReachable = regexp.MustCompile(`(?i)\breachable=(true|false)\b|\[(not-)?reachable\]`)
)

// deriveFinding fills App/Location/CWE/Reachable from the scanner's fields.
func deriveFinding(f *ScannerFinding) {
	if i := strings.IndexByte(f.Asset, ':'); i >= 0 {
		f.App, f.Location = f.Asset[:i], f.Asset[i+1:]
	} else {
		f.App = f.Asset
	}
	if m := reCWE.FindStringSubmatch(f.Title + " " + f.Description); m != nil {
		f.CWE = "CWE-" + m[1]
	}
	hay := f.Title + " " + f.Description
	if m := reReachable.FindStringSubmatch(hay); m != nil {
		var r bool
		if m[1] == "true" || m[1] == "false" { // reachable=true|false
			r = m[1] == "true"
		} else { // [reachable] / [not-reachable]
			r = m[2] == "" // m[2] is "not-" when not reachable
		}
		f.Reachable = &r
	}
}
