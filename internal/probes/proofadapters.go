package probes

import (
	"fmt"
	"strings"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/ingest"
	"github.com/t0ul/GORED/internal/tools"
)

// Adapters: a probe's own finding -> a normalized core Proof. They live with the probes
// (they read probe-specific finding fields) and produce the shared core.Proof vocabulary,
// so the validate layer consumes Proofs without knowing any probe's finding shape.

// ProofFromHunt normalizes a gored-hunt access-control finding. A confirmed finding (the
// model-written repro reproduced the disclosure) is exploitable and carries that repro;
// a certain-but-unconfirmed one is triggerable; a high one is reachable.
func ProofFromHunt(f HuntFinding, app string) (core.Proof, bool) {
	if f.Verdict != VerdictBAC {
		return core.Proof{}, false
	}
	locus, kind := core.NormLocus(f.Path)
	p := core.Proof{App: app, Locus: locus, Kind: kind, CWE: f.CWE, Confidence: f.Confidence,
		Source: "gored-hunt", Evidence: f.Evidence}
	switch {
	case f.Confirmed:
		p.Rung, p.Exploitable, p.Repro = core.LadderExploitable, true, f.ReproGo
	case f.Confidence == core.ConfCertain:
		p.Rung = core.LadderTriggerable
	case f.Confidence == core.ConfHigh:
		p.Rung = core.LadderReachable
	default:
		p.Rung = core.LadderReported
	}
	return p, true
}

// ProofFromNuclei normalizes a (deduplicated) nuclei finding into a Proof. nuclei is a breadth
// scanner, not GORED's executing oracle, so a nuclei result never reaches the exploitable rung
// (that is reserved for an executed repro); it confirms a condition is present on the real
// response, and its severity sets the rung/confidence. The repro is the re-runnable nuclei
// command, so a reviewer can reproduce it. info-severity findings stay low so they sink.
func ProofFromNuclei(f tools.NucleiFinding, app string) (core.Proof, bool) {
	if f.TemplateID == "" {
		return core.Proof{}, false
	}
	locus, kind := core.NormLocus(f.MatchedAt)
	if f.Name != "" {
		kind = f.Name
	}
	cwe := ""
	if len(f.CWEs) > 0 {
		cwe = strings.ToUpper(f.CWEs[0])
	}
	ev := fmt.Sprintf("nuclei %s (%s)", f.TemplateID, f.Severity)
	if f.Count > 1 {
		ev = fmt.Sprintf("%s — matched on %d locations", ev, f.Count)
	}
	p := core.Proof{App: app, Locus: locus, Kind: kind, CWE: cwe, Source: "gored-nuclei",
		Evidence: ev, Repro: fmt.Sprintf("nuclei -id %s -u %s", f.TemplateID, f.MatchedAt)}
	switch f.Severity {
	case "critical", "high":
		p.Rung, p.Confidence = core.LadderReachable, core.ConfHigh
	case "medium":
		p.Rung, p.Confidence = core.LadderPresent, core.ConfMedium
	case "low":
		p.Rung, p.Confidence = core.LadderPresent, core.ConfLow
	default: // info
		p.Rung, p.Confidence = core.LadderReported, core.ConfLow
	}
	return p, true
}

// ProofFromNoSQLi normalizes a NoSQL-injection finding. A confirmed bypass is an executed
// authentication bypass on real bytes — exploitable, certain — so it carries the operator
// payload as the repro.
func ProofFromNoSQLi(f NoSQLiFinding, app string) (core.Proof, bool) {
	if !f.Flagged() {
		return core.Proof{}, false
	}
	locus, kind := core.NormLocus(f.Path)
	p := core.Proof{App: app, Locus: locus, Kind: kind, CWE: f.CWE, Confidence: f.Confidence,
		Source: "gored-nosqli", Evidence: f.Evidence, Rung: core.LadderExploitable, Exploitable: true,
		Repro: fmt.Sprintf("POST %s with a JSON body injecting operators (%s) — authenticates where wrong credentials do not", f.Path, f.Vector)}
	return p, true
}

// ProofFromGraphQL normalizes an introspected GraphQL surface into a Proof. A surface recovered at
// all means introspection is enabled — a real information-disclosure misconfiguration (CWE-200) that
// hands an attacker the full schema. It is confirmed present on real bytes (the endpoint answered the
// introspection query), so it sits at the present rung with medium confidence; it is never
// exploitable on its own. The id-taking operations are recorded as the IDOR/BAC candidates to drive.
func ProofFromGraphQL(s ingest.GraphQLSurface, app, locus string) (core.Proof, bool) {
	if len(s.Ops) == 0 {
		return core.Proof{}, false
	}
	if locus == "" {
		locus = "/graphql"
	}
	l, _ := core.NormLocus(locus)
	ev := fmt.Sprintf("GraphQL introspection enabled: %d operations disclosed", len(s.Ops))
	if ids := s.IDOps(); len(ids) > 0 {
		var names []string
		for _, o := range ids {
			names = append(names, o.Name)
		}
		ev += fmt.Sprintf("; id-taking operations (IDOR/BAC candidates): %s", strings.Join(names, ", "))
	}
	p := core.Proof{App: app, Locus: l, Kind: "GraphQL introspection enabled (schema disclosure)", CWE: "CWE-200",
		Rung: core.LadderPresent, Confidence: core.ConfMedium, Source: "gored-graphql", Evidence: ev,
		Repro: fmt.Sprintf("POST %s with a GraphQL introspection query ({__schema{queryType{name fields{name}}}}) — the full schema is returned", locus)}
	return p, true
}

// ProofFromMassAssign normalizes a mass-assignment finding. Certain means the probe wrote
// a privileged field and read it back changed — an executed privilege escalation, so
// exploitable; high (reflected only) is triggerable.
func ProofFromMassAssign(f MassAssignFinding, app string) (core.Proof, bool) {
	if !f.Flagged() {
		return core.Proof{}, false
	}
	locus, kind := core.NormLocus(f.WritePath)
	p := core.Proof{App: app, Locus: locus, Kind: kind, CWE: f.CWE, Confidence: f.Confidence,
		Source: "gored-massassign", Evidence: f.Evidence}
	if f.Confidence == core.ConfCertain {
		p.Rung, p.Exploitable = core.LadderExploitable, true
		p.Repro = fmt.Sprintf("%s %s with {\"%s\":%v} as the low-priv identity; read it back changed", f.Method, f.WritePath, f.Field, f.SentValue)
	} else {
		p.Rung = core.LadderTriggerable
	}
	return p, true
}

// ProofFromJWT normalizes a JWT finding. Certain means a forged token was accepted on
// replay — an executed authentication bypass, so exploitable; high (forgeable, replay
// not confirmed) is triggerable. locus is the protected path the token unlocks.
func ProofFromJWT(f JWTFinding, app, locus string) (core.Proof, bool) {
	if !f.Flagged() {
		return core.Proof{}, false
	}
	l, kind := core.NormLocus(locus)
	p := core.Proof{App: app, Locus: l, Kind: kind, CWE: f.CWE, Confidence: f.Confidence,
		Source: "gored-jwt", Evidence: f.Evidence}
	if f.Confidence == core.ConfCertain {
		p.Rung, p.Exploitable = core.LadderExploitable, true
		p.Repro = fmt.Sprintf("forge a %s token (vector %s) and replay it on %s", f.Alg, f.Vector, locus)
	} else {
		p.Rung = core.LadderTriggerable
	}
	return p, true
}
