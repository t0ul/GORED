# GORED

An OSS-model **red-team agent** framework — it gores your own web apps. Part of
*the fleet* — build-your-own Go security tools.

GORED drives an open-source model (model + signed skills + sandboxed primitives +
an outward objective loop) to capture-the-flag against a controlled local build
of **your own** app, then scores and persists how well each model did. The point
is to measure whether tuned and combined OSS models rival a single frontier model
at agentic red-teaming — without sending private code to a third party.

## GORED vs gorauder

They are opposite directions, and GORED composes gorauder when it helps:

- [`gorauder`](https://github.com/t0ul/gorauder) attacks a **model**: it fires a
  seed corpus at an LLM and scores jailbreak/injection ASR. The model is the
  *victim under test*.
- **GORED** attacks an **app**: it hands a model a toolbox and a goal and sees if
  it breaks the app. The model is the *weapon*.

When a target app exposes its own LLM surface (a chat, an ingestion endpoint),
GORED picks up gorauder as a tool — the app's embedded model becomes a
sub-target.

## Status

Early, built in phases (target + oracle → single-agent MVP → model × skill
leaderboard → combos → ADD integration). Done:

- **Phase 0 — target + oracle.** A benign demo target (`demotarget`) with a
  planted IDOR and a loopback-scoped SSRF, each guarding an unforgeable flag held
  by a server-side `Oracle`; a strict manifest loader.
- **Phase 1 — MVP agent.** An objective loop driving a local OSS model (booted via
  goserve) with `http_request`/`exec` primitives behind an egress allowlist, a
  typed blackboard (scrubbed via goflage), a cold and a warm skill, and a SQLite
  run store; the per-step trace goes to a gledger audit log. Capture is detected
  only by the oracle, never by the model's self-report.
- **Phase 2 — matrix + leaderboard.** A `Matrix` runner loops models × {cold,warm}
  × flags × N trials (booting one model at a time), and a leaderboard aggregation
  reports capture rate (with N and standard error), efficiency medians among
  captures, and the cold→warm lift per model and difficulty.
- **Phase 3 — combos.** Planner/executor and self-consistency are `ModelClient`
  wrappers over base models, so a combo is scored as just another contestant on the
  same board, with a "keep only combos beating the best solo" verdict.

Expect the interfaces (`ModelClient`, `Tool`, `Skill`, `Target`, `Blackboard`,
`RunStore`) to keep moving until the ADD/factory integration in phase 4.

## Scope & safety

GORED is for **authorized** testing of the author's own applications on local
hosts, with flags the author planted. It is contained by construction — the
detonation chamber's egress allowlist is set to the target address only, so an
agent cannot pivot off the target. Skills and target manifests are offensive
content about the author's own apps; keep them private.

## License

MIT — see [LICENSE](LICENSE).
