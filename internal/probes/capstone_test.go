package probes_test

import (
	"context"
	"testing"

	"github.com/t0ul/GORED/internal/core"
	validate "github.com/t0ul/GORED/internal/validate"
	probes "github.com/t0ul/GORED/internal/probes"
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

func issueByRule(issues []core.ContainerIssue, rule string) *core.ContainerIssue {
	for i := range issues {
		if issues[i].Rule == rule {
			return &issues[i]
		}
	}
	return nil
}

func findVerdict(vs []core.Verdict, app, locus string) *core.Verdict {
	for i := range vs {
		if vs[i].App == app && vs[i].Locus == locus {
			return &vs[i]
		}
	}
	return nil
}

// TestValidatorLiveCapstone is the end-to-end proof with no mocks: real probes run against
// the demo target, produce real exploitable proofs, and the validator fuses them with a
// scanner finding and a discovered container misconfig into ranked, chained verdicts. The
// mass-assignment and JWT probes confirm their own exploits (read-back / replay), so this
// needs no model. It lives with the probes because it drives them; it imports gored for the
// validator and the shared vocabulary.
func TestValidatorLiveCapstone(t *testing.T) {
	_, base := liveTarget(t) // vulnerable build

	// JWT first (alice's token is still role=user), then mass assignment (which flips it).
	jf, err := jwtProbe(t, base, probes.HarvestSecrets("../../demotarget")).Analyze(context.Background(), aliceToken(t, base), "/api/whoami")
	if err != nil {
		t.Fatal(err)
	}
	mf, err := aliceProbe(t, base).Probe(context.Background(), "PUT", "/api/profile", "/api/profile")
	if err != nil {
		t.Fatal(err)
	}

	jp, ok1 := probes.ProofFromJWT(jf, "demo", "/api/whoami")
	mp, ok2 := probes.ProofFromMassAssign(mf, "demo")
	if !ok1 || !ok2 || !jp.Exploitable || !mp.Exploitable {
		t.Fatalf("both probes should yield exploitable proofs; jwt=%+v mass=%+v", jp, mp)
	}
	cissues := core.AnalyzeDockerfile([]byte(vulnDockerfile))
	cp := validate.ProofFromContainerIssue(*issueByRule(cissues, "runs-as-root"), "demo")

	// A representative scanner claim on the same route GORED proved exploitable.
	scanners := []core.ScannerFinding{{Source: "Semgrep", App: "demo", Location: "/api/profile", Severity: "Medium", CWE: "CWE-862", Title: "missing authorization"}}

	vs := (&validate.Validator{}).Validate(scanners, []core.Proof{jp, mp, cp})

	prof := findVerdict(vs, "demo", "/api/profile")
	if prof == nil || !prof.Exploitable || prof.Repro == "" || len(prof.Chain) == 0 {
		t.Fatalf("fused /api/profile verdict should be exploitable, have a repro and the host chain; got %+v", prof)
	}
	if vs[0].Rung != core.LadderExploitable {
		t.Errorf("a confirmed-exploitable verdict must rank first, got %s", vs[0].Rung)
	}
}
