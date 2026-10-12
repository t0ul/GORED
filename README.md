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

## Hunt your own app (quickstart)

`gored-hunt` is the generic end-to-end tool: point it at any local web app you own,
give it two test identities, and it maps the authenticated surface, flags broken
access control by differential comparison (and object-level IDOR by id-swapping),
has a **local** model write a repro the system executes to confirm each finding, and
writes a JSON report plus a replayable trace. No app-specific code — the app is named
only by the URL, the identities, and the login shape.

**1. Make two test accounts** in your app (an owner and a second user). This is the
only per-app setup, and it is not code.

**2. Run it.** Cookie-login apps:

```
gored-hunt -url http://127.0.0.1:8080 \
  -priv owner@app:pw -low other@app:pw \
  -login-path /api/auth/login -seed
```

Token/header apps (bearer or session header — works for any auth you can put in a
header):

```
gored-hunt -url http://127.0.0.1:8080 \
  -priv-header 'Authorization: Bearer <A>' \
  -low-header  'Authorization: Bearer <B>' -seed
```

Logins that aren't JSON `email`/`password` are covered by flags:

```
-login-type form          # application/x-www-form-urlencoded instead of json
-login-user username       # field name for the username/email (default: email)
-login-pass pass           # field name for the password      (default: password)
```

`-seed` plants canaries through your app's own create endpoints so real leaks come
back `certain`; drop it to run canary-free (findings are then ranked `high`/`medium`/
`low` by false-positive likelihood). `-no-verify` skips the model and reports flags
`UNVERIFIED`.

**What you get.** A report separating `certain` findings (a planted marker was
disclosed to the low-privilege identity — zero false positive) from heuristic flags,
each `certain` one carrying a model-written repro the system ran, plus a `gored-replay`
trace.

**Containment.** Every request goes through an egress allowlist set to the target host
only, so the agent cannot pivot off your app; it reads by default (the one write is the
privileged identity planting canaries).

**Limits (honest).** Login must be a JSON/form POST or a static header — OAuth
redirects, CSRF-token flows, and multi-step logins need a small extension. Static
discovery can miss SPA routes built dynamically, and file-upload (multipart) resources
aren't seeded yet. See the per-app harness pattern (`cmd/gored-riskrancher`, kept local)
for scripting account/data setup on an app you benchmark repeatedly.

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
- **Phase 4 — ADD + factory seam.** `addcase.AutonomousAdversary` runs the live
  agent against a vulnerable and a hardened build and reports an `add.Outcome`, so
  the agentic adversary joins the ADD coverage grid (live-tagged, skipped offline,
  so the scorecard keeps its determinism). `gored-leaderboard` exports the board as
  JSON for the factory's model-select to read.

## Scope & safety

GORED is for **authorized** testing of the author's own applications on local
hosts, with flags the author planted. It is contained by construction — the
detonation chamber's egress allowlist is set to the target address only, so an
agent cannot pivot off the target. Skills and target manifests are offensive
content about the author's own apps; keep them private.

## License

MIT — see [LICENSE](LICENSE).
