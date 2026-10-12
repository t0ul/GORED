package gored

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Rung is how far up the static side of the evidence ladder a finding reached, from a
// whitebox look at the source. It is the triage signal: "ruled-out" deletes noise
// (most dependency CVEs sit in code that is never present or never reached), while
// "reachable" is a real priority. The dynamic rungs (triggerable, exploitable) are
// added later by the verifier.
type Rung string

const (
	RungUnknown   Rung = "unknown"   // no source, unsupported language, or a non-source finding (e.g. DAST)
	RungAbsent    Rung = "ruled-out" // the vulnerable code/dependency is not in this source
	RungPresent   Rung = "present"   // it is in the source, reachability not determined
	RungReachable Rung = "reachable" // it is in the invocation path from an entry point
	RungRuledOut  Rung = "ruled-out" // present but not reachable — deprioritize
)

// SourceAnalyzer raises a finding up the static rungs against a codebase. Each
// language has its own analyzer; the engine picks one by detecting the codebase, so
// no language is hardcoded or default. An unsupported language or missing source
// yields RungUnknown — GORED never pretends to analyze what it cannot.
type SourceAnalyzer interface {
	Lang() string
	Analyze(f ScannerFinding) (Rung, string) // the rung reached and one line of evidence
}

// DetectAnalyzer returns the analyzer for a source tree, or nil if the language is
// not supported. Detection is by the project's own marker file (go.mod, package.json,
// …) — a new language is added by a new analyzer + a new marker, never by special-
// casing the engine.
func DetectAnalyzer(sourceDir string) SourceAnalyzer {
	if sourceDir == "" {
		return nil
	}
	switch {
	case fileExists(filepath.Join(sourceDir, "go.mod")):
		return newGoAnalyzer(sourceDir)
	// Future: package.json -> JS/TS, pyproject.toml/requirements.txt -> Python,
	// Cargo.toml -> Rust. Each is its own SourceAnalyzer, selected here.
	default:
		return nil
	}
}

// goAnalyzer analyses a Go module. It leverages the reachability a Go scanner
// (govulncheck) already computed — surfaced on ScannerFinding.Reachable — and checks
// the source for presence: a dependency CVE is "present" only if its module is in
// go.mod, a SAST finding only if its file exists.
type goAnalyzer struct {
	dir   string
	goMod string // go.mod contents
}

func newGoAnalyzer(dir string) *goAnalyzer {
	b, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	return &goAnalyzer{dir: dir, goMod: string(b)}
}

func (g *goAnalyzer) Lang() string { return "go" }

var reFileLine = regexp.MustCompile(`([^\s:]+\.go):\d+`)

func (g *goAnalyzer) Analyze(f ScannerFinding) (Rung, string) {
	loc := strings.TrimSpace(f.Location)
	switch {
	case loc == "" || strings.HasPrefix(loc, "/"):
		// A URL path (a DAST finding) — not a static/source question; validate it
		// dynamically instead.
		return RungUnknown, "not a source location (validate dynamically)"

	case strings.Contains(loc, ".go"):
		// A SAST finding: the code is present only if its file is in the tree.
		m := reFileLine.FindStringSubmatch(loc)
		file := loc
		if m != nil {
			file = m[1]
		}
		if !fileExists(filepath.Join(g.dir, file)) {
			return RungAbsent, "source file not found: " + file
		}
		if f.Reachable != nil && *f.Reachable {
			return RungReachable, "code present and reachable at " + loc
		}
		return RungPresent, "code present at " + loc + " (call-graph reachability not computed)"

	case loc == "stdlib":
		// A standard-library vuln: always "present"; reachability per the scanner.
		return g.byReachability(f, "Go stdlib")

	default:
		// A dependency module path (e.g. golang.org/x/crypto). Anything that does not
		// look like a Go module — a Dockerfile, an image, some other artifact — is not
		// this analyzer's concern: return unknown rather than falsely ruling it out as a
		// dependency that happens not to be in go.mod.
		if !looksLikeModule(loc) {
			return RungUnknown, "not a Go source artifact: " + loc
		}
		mod := modulePath(loc)
		if !strings.Contains(g.goMod, mod) {
			return RungAbsent, "dependency not in go.mod: " + mod
		}
		return g.byReachability(f, "dependency "+mod+" in go.mod")
	}
}

// byReachability maps a present finding to a rung using the scanner's reachability.
func (g *goAnalyzer) byReachability(f ScannerFinding, present string) (Rung, string) {
	switch {
	case f.Reachable != nil && *f.Reachable:
		return RungReachable, present + ", reachable"
	case f.Reachable != nil && !*f.Reachable:
		return RungRuledOut, present + ", but not reachable — deprioritize"
	default:
		return RungPresent, present + " (reachability unknown)"
	}
}

// modulePath reduces a package path to its module-ish prefix for a go.mod lookup:
// the domain plus the first two path segments (github.com/org/repo, golang.org/x/net).
func modulePath(pkg string) string {
	parts := strings.Split(pkg, "/")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], "/")
	}
	return pkg
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
