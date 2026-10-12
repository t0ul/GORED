package gored_test

import (
	"os"
	"path/filepath"
	"testing"

	gored "github.com/t0ul/GORED"
)

const vulnDockerfile = `
FROM golang:latest
ENV JWT_SECRET=dev-signing-key-do-not-ship
RUN curl -fsSL https://example.com/install.sh | sh
ADD https://example.com/tool.tar.gz /tmp/tool.tar.gz
COPY . /app
RUN go build -o /app/server ./cmd/rr
EXPOSE 8080
CMD ["/app/server"]
`

const hardenedDockerfile = `
FROM golang:1.27.1-alpine AS build
COPY . /src
RUN go build -o /server ./cmd/rr

FROM alpine:3.21
COPY --from=build /server /server
RUN adduser -D -u 10001 app
USER app
EXPOSE 8080
ENTRYPOINT ["/server"]
`

func issueByRule(issues []gored.ContainerIssue, rule string) *gored.ContainerIssue {
	for i := range issues {
		if issues[i].Rule == rule {
			return &issues[i]
		}
	}
	return nil
}

// TestAnalyzeDockerfileVulnerable checks the discover lane finds every planted misconfig:
// the final stage runs as root (no USER), a secret is baked into an ENV layer, a remote
// script is piped to a shell, ADD fetches a URL, and the base image is :latest.
func TestAnalyzeDockerfileVulnerable(t *testing.T) {
	issues := gored.AnalyzeDockerfile([]byte(vulnDockerfile))
	for _, rule := range []string{"runs-as-root", "secret-in-env", "curl-pipe-sh", "add-remote-url", "unpinned-base"} {
		if issueByRule(issues, rule) == nil {
			t.Errorf("expected rule %q in a vulnerable Dockerfile; got %+v", rule, issues)
		}
	}
	if is := issueByRule(issues, "runs-as-root"); is != nil && is.CWE != "CWE-250" {
		t.Errorf("runs-as-root should be CWE-250, got %q", is.CWE)
	}
}

// TestAnalyzeDockerfileHardened checks the control: a non-root USER in the final stage, a
// pinned alpine base, and no baked secret or remote fetch — nothing is flagged. In
// particular, a USER only in the build stage would not have protected the final stage, so
// this also checks the multi-stage reasoning (USER must follow the last FROM).
func TestAnalyzeDockerfileHardened(t *testing.T) {
	issues := gored.AnalyzeDockerfile([]byte(hardenedDockerfile))
	if len(issues) != 0 {
		t.Errorf("hardened Dockerfile should have no misconfigurations, got %+v", issues)
	}
}

// TestRuntimeDetectAndValidate checks detection is opt-in by artifact, and that a scanner
// finding is validated against the file: a trivy-style "image user should not be root"
// finding is confirmed present against the vulnerable file and ruled out against the
// hardened one, while an image CVE is unknown to the Dockerfile analyzer.
func TestRuntimeDetectAndValidate(t *testing.T) {
	vulnDir := writeDockerfileDir(t, vulnDockerfile)
	hardDir := writeDockerfileDir(t, hardenedDockerfile)

	if gored.DetectRuntimeAnalyzer(t.TempDir()) != nil {
		t.Error("a dir with no Dockerfile should yield no runtime analyzer")
	}
	ra := gored.DetectRuntimeAnalyzer(vulnDir)
	if ra == nil || ra.Runtime() != "container" {
		t.Fatalf("expected a container analyzer, got %v", ra)
	}

	// A trivy-config finding is scoped to the Dockerfile (asset/location names it).
	rootFinding := gored.ScannerFinding{Source: "Trivy", Title: "Specify at least 1 USER command with a non-root user", Description: "Running containers as root", Location: "Dockerfile", Asset: "riskrancher:Dockerfile"}
	if rung, _ := ra.Analyze(rootFinding); rung != gored.RungPresent {
		t.Errorf("runs-as-root should be confirmed present on the vulnerable file, got %q", rung)
	}
	if rung, _ := gored.DetectRuntimeAnalyzer(hardDir).Analyze(rootFinding); rung != gored.RungRuledOut {
		t.Errorf("runs-as-root should be ruled out on the hardened file, got %q", rung)
	}

	// An image CVE is not a Dockerfile question, even though its text says "root".
	cve := gored.ScannerFinding{Source: "Trivy", Title: "CVE-2026-0001 in libssl", Description: "privilege escalation to root in the base image", Location: "alpine:3.21", Asset: "riskrancher:alpine"}
	if rung, _ := ra.Analyze(cve); rung != gored.RungUnknown {
		t.Errorf("an image CVE is not a Dockerfile question, want unknown, got %q", rung)
	}

	// A dependency CVE whose description mentions root must also stay unknown here.
	dep := gored.ScannerFinding{Source: "govulncheck", Title: "GO-2026-6604 in stdlib", Description: "root cause: improper validation", Location: "stdlib", Asset: "riskrancher:stdlib"}
	if rung, _ := ra.Analyze(dep); rung != gored.RungUnknown {
		t.Errorf("a stdlib CVE is not a Dockerfile question, want unknown, got %q", rung)
	}

	// A Dockerfile rule GORED does not model (HEALTHCHECK) stays unknown — it is not
	// silently bucketed into one GORED does, even though its text mentions containers.
	hc := gored.ScannerFinding{Source: "Trivy", Title: "AVD-DS-0026 No HEALTHCHECK defined", Description: "add a HEALTHCHECK to perform the health check on running containers", Location: "Dockerfile", Asset: "riskrancher:Dockerfile"}
	if rung, _ := ra.Analyze(hc); rung != gored.RungUnknown {
		t.Errorf("an unmodeled Dockerfile rule should stay unknown, got %q", rung)
	}
}

func writeDockerfileDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}
