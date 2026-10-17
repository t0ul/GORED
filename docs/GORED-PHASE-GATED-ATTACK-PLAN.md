# GORED — phase-gated, ambiguity-reduced attack (implementation plan)

Status: APPROVED plan, NOT yet built. Date: 2026-10-17. Owner: t.
Prereq landed: the recon-contract stack (PRs #119–#123, on main) — typed `EndpointContract`,
`recon` tool, OpenAPI ingest, active headers + per-endpoint auth map, contract pre-fill into the
focused exploit prompt.

## Context

The recon stack works: on a live RiskRancher sweep it put typed contracts on 61/64 endpoints and an
auth map on 20, and pre-filled the contract into the focused exploit prompt. But two qwen-3b sweeps
(same model, same recon) both landed **0 confirmed** — the bottleneck is **tool-selection
ambiguity**, not recon:

- **all-tools:** the model crawled (`discover`) and hammered the generic `api_request`, barely
  touched the specialized confirmers; attempted 2–3 endpoints; 0 confirmed.
- **attack-only** (env `GORED_ATTACK_ONLY`, dropped recon/crawl tools): `discover` gone and it
  engaged `recon`+`mass_assign`, but `api_request` still dominated (337 calls across 9 endpoints);
  0 confirmed.

So: reduce the small model's decision space to near-zero by **scoping each endpoint's attack run to
only that endpoint's class tool(s)**, sharpening tool names/prompts, and capping churn — then
**measure** with an A/B/C matrix. Recall is honestly **1/15**; this plan is judged solely by
whether it moves that number. Bigger attack model + GBNF constrained decoding are a separate,
later axis.

Note: `GORED_ATTACK_ONLY` is a throwaway experimental toggle (uncommitted edit in
`internal/appsweep/apiexploit.go`); S1 supersedes and removes it.

## Approach (staged; each stage its own PR, branch per phase, commits as `t`, no attribution)

### S1 — Per-endpoint-class tool scoping (the core)
Give each focused exploit run ONLY the tools its endpoint class routes to — no generic escape hatch.
- `internal/tools/tools.go`: add `func (b *Toolbox) Restrict(names []string)` — keep only the named
  tools, preserve order; no-op on empty.
- `internal/appsweep/appsweep.go`: add `WithAllowedTools(names ...string)` option; after
  `tb := st.BuildTools(gate, base)` + `tb.Add(o.extraTools...)` (≈line 192), call
  `tb.Restrict(o.allowedTools)` when set.
- `internal/eva/model.go`: add `allowedTools []string` to `run`.
- `internal/eva/campaign.go` (`launchCampaignRunInst` / `runExploitPhase`): set `rn.allowedTools`
  from the endpoint's class tool hint — parse `classifyEndpoint(ep).tool` (e.g.
  `"mass_assign / body_limit"`, `"nosqli / jwt_forge / throttle_probe / password_policy"`) into
  tool names (split on `/` + spaces; names already match the registered `Name()`s).
- `internal/eva/eva.go` (`runStage`): when `rn.allowedTools` is non-empty (endpoint phase), append
  `appsweep.WithAllowedTools(rn.allowedTools...)`, and gate the injected `surfaceSaveTool`/`recon`
  tools OFF for scoped attack runs (contract is pre-filled, so they are ambiguity sinks).
- `internal/appsweep/apiexploit.go`: remove the `GORED_ATTACK_ONLY` block and its `os` import.
Reuse: `classifyEndpoint` hints (`internal/eva/prioritize.go`), the `WithExtraTools` pattern,
`endpointPhase()`.

### S2 — Action-named tools + imperative, single-purpose descriptions
- Alias the confirmers to action names (`test_login_throttle`, `check_weak_password`,
  `try_mass_assignment`, `test_body_limit`) via `Name()`/`Describe()` in `internal/probes/*.go`;
  keep `Toolbox.Resolve` tolerant so old names still work.
- Rewrite each `Describe()` to one imperative line with the exact args — no "optional"/alternatives.
- Collapse overlap: a scoped run never carries two interchangeable request primitives.

### S3 — Few-shot example + per-endpoint step cap in the focused prompt
- `internal/eva/campaign.go` `exploitInstruction`: append a concrete one-line example of the exact
  call for this endpoint's tool (e.g. `try_mass_assignment {"path":"/api/adapters"}`), built from
  the contract; strip the now-moot "do NOT crawl" wording.
- Tighten the per-endpoint run budget (`bench.Flags` MaxSteps/MaxStall for scoped exploit runs, set
  in `launchCampaignRunInst`) to ~3–5 calls so a run commits instead of churning.
- Short-circuit: end the endpoint's run the instant a `*-CONFIRMED` sentinel appears.

### S4 — A/B/C evaluation matrix (measure, don't guess)
Run the SAME endpoint set across {all-tools, class-scoped, one-tool} × {qwen-3b, granite-8b,
ministral-8b} and emit recall + per-run tool-histogram. Reuse the matrix/leaderboard seam
(`internal/core/matrix.go`, the leaderboard JSON) — a thin `cmd/` or an eva campaign mode that sets
scoping + model per cell. This is how we learn which lever actually moves recall.

### S5 — Later / separate axis (not in the first build)
Phased hexagon runs (recon → classify → attack as distinct tool-scoped runs, UI later); a bigger
model for the attack phase; a `classify` run (tiny decision space) between recon and attack; a
single `attack` dispatcher tool per class; GBNF / JSON-schema **constrained decoding** at the
goserve layer. Plus: score "adaptation" as its own metric ([[gored-self-correct]]); decoy/hardened
ruler endpoints for false-positive discipline; per-model prompt style in the registry; map
models→phases (cheap for recon/classify, bigger for attack).

## Verification
- **Unit:** `Toolbox.Restrict` keeps only named tools (order preserved); `WithAllowedTools` filters
  the assembled toolbox; the `classifyEndpoint.tool`→names parser; `exploitInstruction` renders the
  few-shot example for a class.
- **Live (RR, the real test):** re-run the sweep with S1–S3 (qwen-3b, held constant) and read the
  **per-run tool-histogram** — each run should use ONLY its class tool(s), no `api_request` crutch
  on write/auth endpoints — then whether any `*-CONFIRMED` lands. Reset `eva2.db`; RR on `:8082`
  (creds via `rrhash/reset.sql`); cockpit on `:4100`.
- **Matrix (S4):** the A/B/C run comparing recall + tool-histograms across scoping × model.
- `go build/vet ./...` + `go test ./internal/... ./store/` green per PR; files gofmt-clean; honest
  corner list per [[go-code-standards]].

## Honesty boundary (binding — [[gored-no-cheating-science]])
Scoping shrinks tool-SELECTION noise only. The model still decides WHICH endpoint and WHETHER to
fire; the oracle still confirms on real bytes. Deterministic routing must never become "the harness
found it." Recall moves only on a model-fired, oracle-confirmed finding on the real app.
