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

Early. Design lives with the author; the runtime is being built in phases
(target + oracle → single-agent MVP → model × skill leaderboard → combos → ADD
integration). Expect the interfaces (`ModelClient`, `Sandbox`, `Tool`, `Skill`,
`Target`, `Scorer`, `Blackboard`, `RunStore`) to move until phase 2.

## Scope & safety

GORED is for **authorized** testing of the author's own applications on local
hosts, with flags the author planted. It is contained by construction — the
detonation chamber's egress allowlist is set to the target address only, so an
agent cannot pivot off the target. Skills and target manifests are offensive
content about the author's own apps; keep them private.

## License

MIT — see [LICENSE](LICENSE).
