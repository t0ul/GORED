package gored

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// A full-fledged tool considers how an app RUNS, not just its code. The runtime axis is
// orthogonal to the language axis: a Go service in a container has both a goAnalyzer (its
// dependencies and handlers) and a container to reason about (its image and how it is
// built). So runtime analysis is a parallel analyzer, selected by its own detection, that
// speaks the same Rung vocabulary so it composes with correlation and whitebox triage.

// ContainerIssue is one container/runtime misconfiguration read straight from a build
// artifact (a Dockerfile). GORED both DISCOVERS these (scanners miss or under-rank them)
// and VALIDATES a scanner's claim against the file. Because it is read from the file, a
// discovered issue is present/confirmed, not a guess.
type ContainerIssue struct {
	Rule        string // short id: runs-as-root | secret-in-env | curl-pipe-sh | add-remote-url | unpinned-base
	Title       string
	Line        int    // 1-based line in the Dockerfile (0 if the whole file)
	Instruction string // the offending line, trimmed (empty for a whole-file rule)
	CWE         string
	Severity    string
	Why         string
}

// Line renders an issue as one grid-safe line for a report.
func (c ContainerIssue) LineStr() string {
	loc := ""
	if c.Line > 0 {
		loc = ":" + strconv.Itoa(c.Line)
	}
	return strings.TrimSpace("[" + c.CWE + " " + c.Severity + "] " + c.Title + " (Dockerfile" + loc + ") — " + c.Why)
}

// RuntimeAnalyzer raises and discovers findings on the deployment axis. Like SourceAnalyzer
// it is selected by detecting the artifact (a Dockerfile), never defaulted, and an
// unsupported or absent runtime yields nothing.
type RuntimeAnalyzer interface {
	Runtime() string                         // "container"
	Analyze(f ScannerFinding) (Rung, string) // validate a scanner's runtime finding against the artifact
	Issues() []ContainerIssue                // the misconfigurations discovered in the artifact
}

// DetectRuntimeAnalyzer returns a runtime analyzer for a directory, or nil when there is
// no runtime artifact to reason about. Detection is by the artifact's own name
// (Dockerfile) — a new runtime is a new analyzer plus a new marker, never a change to the
// engine. It is independent of DetectAnalyzer: a dir can have both a language and a
// runtime analyzer, and the caller runs whichever it has.
func DetectRuntimeAnalyzer(dir string) RuntimeAnalyzer {
	if dir == "" {
		return nil
	}
	for _, name := range []string{"Dockerfile", "dockerfile", "Containerfile"} {
		p := filepath.Join(dir, name)
		if b, err := os.ReadFile(p); err == nil {
			return &dockerAnalyzer{path: p, issues: AnalyzeDockerfile(b)}
		}
	}
	return nil
}

type dockerAnalyzer struct {
	path   string
	issues []ContainerIssue
}

func (d *dockerAnalyzer) Runtime() string          { return "container" }
func (d *dockerAnalyzer) Issues() []ContainerIssue { return d.issues }

// Analyze validates a scanner's runtime finding against what the Dockerfile actually says.
// A misconfig the file confirms is present; one the file contradicts is ruled out (a
// scanner false positive caught against ground truth); anything that is not a Dockerfile
// question — an image/OS CVE, a URL — is unknown here and validated elsewhere.
func (d *dockerAnalyzer) Analyze(f ScannerFinding) (Rung, string) {
	rule := d.classify(f)
	if rule == "" {
		return RungUnknown, "not a Dockerfile misconfiguration (validate against the image/host instead)"
	}
	for _, is := range d.issues {
		if is.Rule == rule {
			return RungPresent, "confirmed in the Dockerfile: " + is.Why
		}
	}
	return RungRuledOut, "the Dockerfile does not have this misconfiguration (e.g. it sets a non-root USER)"
}

// classify maps a scanner finding to the misconfig rule it is about, by the words it uses
// — so it does not hardcode any one scanner's rule ids. It first gates on the finding
// being Dockerfile-scoped at all: a dependency or image CVE whose description merely
// mentions "root" is not a Dockerfile question and stays unknown here.
func (d *dockerAnalyzer) classify(f ScannerFinding) string {
	if !isDockerfileFinding(f) {
		return ""
	}
	text := strings.ToLower(f.Title + " " + f.Description)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(text, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("non-root", "root user", "run as root", "runs as root", "as root", "'root'", "user command", "user instruction"):
		return "runs-as-root"
	case has("secret", "credential", "password", "api key", "access key"):
		return "secret-in-env"
	case has("| sh", "pipe", "piped", "curl | ", "untrusted"):
		return "curl-pipe-sh"
	case has("add ") && has("remote", "url", "http"):
		return "add-remote-url"
	case has("latest", "unpinned", "not pinned", "pin the", "tag"):
		return "unpinned-base"
	default:
		return ""
	}
}

// isDockerfileFinding reports whether a finding is scoped to a Dockerfile/Containerfile —
// the only kind the Dockerfile analyzer can validate. Image/OS CVEs and dependency CVEs
// are validated elsewhere, so they stay unknown here even if their text says "root".
func isDockerfileFinding(f ScannerFinding) bool {
	loc := strings.ToLower(f.Location + " " + f.Asset)
	return strings.Contains(loc, "dockerfile") || strings.Contains(loc, "containerfile")
}

var (
	reDockerSecret = regexp.MustCompile(`(?i)\b(secret|signing[_-]?key|jwt|hmac|token|private[_-]?key|passw|api[_-]?key|access[_-]?key|credential)\w*`)
	rePipeToShell  = regexp.MustCompile(`\|\s*(sh|bash|zsh)\b`)
)

// AnalyzeDockerfile reads a Dockerfile and returns the misconfigurations it finds. It is
// generic — a Dockerfile is a Dockerfile regardless of the app's language — and is the
// discover lane for the container runtime: these are real findings GORED surfaces whether
// or not a scanner did.
func AnalyzeDockerfile(dockerfile []byte) []ContainerIssue {
	lines := logicalLines(string(dockerfile))
	var issues []ContainerIssue

	lastFrom, lastUserAfterFrom, lastUserVal := -1, -1, ""
	for _, ln := range lines {
		kw, rest := instruction(ln.text)
		switch kw {
		case "FROM":
			lastFrom, lastUserAfterFrom = ln.num, -1
			if is, ok := unpinnedBase(rest, ln.num, ln.text); ok {
				issues = append(issues, is)
			}
		case "USER":
			if ln.num > lastFrom {
				lastUserAfterFrom, lastUserVal = ln.num, firstField(rest)
			}
		case "ENV", "ARG":
			if is, ok := secretInEnv(kw, rest, ln.num, ln.text); ok {
				issues = append(issues, is)
			}
		case "RUN":
			low := strings.ToLower(rest)
			if rePipeToShell.MatchString(rest) && (strings.Contains(low, "curl") || strings.Contains(low, "wget")) {
				issues = append(issues, ContainerIssue{
					Rule: "curl-pipe-sh", Title: "Remote script piped into a shell", Line: ln.num, Instruction: ln.text,
					CWE: "CWE-494", Severity: "high", Why: "downloads code over the network and runs it unverified at build time",
				})
			}
		case "ADD":
			if addRemote(rest) {
				issues = append(issues, ContainerIssue{
					Rule: "add-remote-url", Title: "ADD fetches a remote URL", Line: ln.num, Instruction: ln.text,
					CWE: "CWE-494", Severity: "medium", Why: "ADD of a remote URL fetches without integrity checking; use COPY or a verified download",
				})
			}
		}
	}

	// Runs-as-root: no USER after the final build stage, or the last one is root/0. This
	// is the headline misconfig — it turns any app RCE into RCE as container root.
	if runsAsRoot(lastUserAfterFrom, lastUserVal) {
		issues = append(issues, ContainerIssue{
			Rule: "runs-as-root", Title: "Container runs as root", CWE: "CWE-250", Severity: "high",
			Why: "no non-root USER is set for the final stage, so the process runs as root — escalating the blast radius of any app RCE to host root (chain, not exploited)",
		})
	}
	return issues
}

func runsAsRoot(lastUserLine int, lastUserVal string) bool {
	if lastUserLine < 0 {
		return true // no USER at all
	}
	v := strings.ToLower(strings.TrimSpace(lastUserVal))
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[:i] // USER user:group
	}
	return v == "root" || v == "0" || v == ""
}

func unpinnedBase(rest string, num int, raw string) (ContainerIssue, bool) {
	img := firstField(rest)
	if img == "" || strings.EqualFold(img, "scratch") || strings.HasPrefix(img, "$") {
		return ContainerIssue{}, false // scratch and build-arg images are not drift risks here
	}
	tagged := false
	if i := strings.LastIndexByte(img, ':'); i >= 0 && !strings.Contains(img[i:], "/") {
		tag := img[i+1:]
		tagged = tag != "" && !strings.EqualFold(tag, "latest")
	}
	if strings.Contains(img, "@sha256:") {
		tagged = true // digest-pinned
	}
	if tagged {
		return ContainerIssue{}, false
	}
	return ContainerIssue{
		Rule: "unpinned-base", Title: "Unpinned base image", Line: num, Instruction: raw,
		CWE: "CWE-1104", Severity: "low", Why: "base image " + img + " is untagged or :latest — the build is not reproducible and drifts onto new CVEs",
	}, true
}

func secretInEnv(kw, rest string, num int, raw string) (ContainerIssue, bool) {
	// ENV KEY=VALUE or ENV KEY VALUE (and ARG KEY=VALUE). Flag only when a secret-ish key
	// has a non-empty, non-placeholder value baked in.
	key, val := envKeyVal(rest)
	if key == "" || !reDockerSecret.MatchString(key) {
		return ContainerIssue{}, false
	}
	val = strings.TrimSpace(val)
	if val == "" || strings.HasPrefix(val, "$") || strings.Contains(val, "${") {
		return ContainerIssue{}, false // a reference, not a baked-in secret
	}
	return ContainerIssue{
		Rule: "secret-in-env", Title: "Secret baked into an image layer", Line: num, Instruction: raw,
		CWE: "CWE-798", Severity: "high", Why: kw + " " + key + " bakes a secret into the image layers, where anyone who pulls the image can read it",
	}, true
}

func envKeyVal(rest string) (string, string) {
	rest = strings.TrimSpace(rest)
	if i := strings.IndexByte(rest, '='); i >= 0 {
		return strings.TrimSpace(rest[:i]), strings.Trim(strings.TrimSpace(rest[i+1:]), `"'`)
	}
	if f := strings.Fields(rest); len(f) >= 2 {
		return f[0], strings.Trim(strings.Join(f[1:], " "), `"'`)
	}
	return "", ""
}

func addRemote(rest string) bool {
	for _, f := range strings.Fields(rest) {
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
			return true
		}
	}
	return false
}

type dline struct {
	num  int
	text string
}

// logicalLines returns the Dockerfile's instruction lines, joining backslash
// continuations and dropping comments and blanks, each tagged with its starting line.
func logicalLines(src string) []dline {
	raw := strings.Split(src, "\n")
	var out []dline
	for i := 0; i < len(raw); i++ {
		t := strings.TrimSpace(raw[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		start := i + 1
		joined := t
		for strings.HasSuffix(joined, "\\") && i+1 < len(raw) {
			joined = strings.TrimSuffix(joined, "\\") + " " + strings.TrimSpace(raw[i+1])
			i++
		}
		out = append(out, dline{num: start, text: strings.TrimSpace(joined)})
	}
	return out
}

// instruction splits a logical line into its keyword (upper-cased) and the rest.
func instruction(line string) (string, string) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return "", ""
	}
	return strings.ToUpper(f[0]), strings.TrimSpace(strings.TrimPrefix(line, f[0]))
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}
