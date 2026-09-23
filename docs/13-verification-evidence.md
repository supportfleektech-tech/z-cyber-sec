# 13 — Verification & Evidence Log

Discipline: every claim carries command, environment, timestamp, result,
and limitation. Labels: **Verified** (observed this turn), **Previously
reported** (observed in an earlier turn, re-check before relying),
**Proposed** (not yet done).

## Environment

- Host: Arena.ai sandbox (Linux), repo `supportfleektech-tech/z-cyber-sec`,
  branch `arena/01a0c152-z-cyber-sec` (branched from `main` @
  `72633702551d6857b02bb1a680054b766fa07b5c`).
- Python 3.11 (`app/backend/.venv`, deps from pinned
  `requirements.txt`); Node 20 + npm (frontend, `package-lock.json`
  committed); SQLite (stdlib); all timestamps UTC.
- Date: 2026-09-21. Environment labeled `LOCAL`; all data synthetic
  (`data_class='synthetic'`, seeded by `app/backend/app/seed/seed_demo.py`).

## Backend test suite — Verified

```
$ cd app/backend && .venv/bin/python -m pytest
97 passed, 4 warnings in 67.05s (0:01:07)     # 2026-09-21 ~05:22 UTC (post capacity test added)
96 passed, 4 warnings in 83.52s (0:01:23)     # 2026-09-21 ~04:19 UTC (post ruff E741 fix)
96 passed, 4 warnings in 83.80s (0:01:23)     # 2026-09-21 ~04:15 UTC (pre-ruff-fix run)
```
Also **Previously reported**: 4 consecutive green runs of 96/96 before the
`intel.py` status-patch change; the runs above are the post-change
confirmation. Coverage notes: auth (oracle-free login, session revocation),
RBAC permission matrices per domain, detection engine (threshold/timeframe/
entity, dry-run, backfill), STIX subset parser, audit chain verify,
evidence permission split, agents (allowlist deny, approval gate, evals),
automation (dry-run executes nothing), reports (provenance fields),
backup/restore round-trip.

## Lint — Verified

```
$ .venv/bin/ruff check app/          # 2026-09-21 ~04:16 UTC (after fix)
All checks passed!
```
(Fix applied same day: `app/routers/grc.py` E741 — renamed `l`/`i` to
`lik`/`imp` in the risk-score recompute block.)

## Frontend build — Verified

```
$ cd app/frontend && npm run build    # 2026-09-21, earlier cycle
✓ built in ~1.5s
dist/assets/index-BYlOEAjU.css   7.95 kB
dist/assets/index-C6Fo0R9B.js 259.33 kB  (73.59 kB gzip)
```
`dist/` is served by the backend (single origin). SPA assets live-checked
this cycle: `GET /assets/index-C6Fo0R9B.js` → 200,
`GET /assets/index-BYlOEAjU.css` → 200 (2026-09-21 ~04:14 UTC).

## Live server — Verified

```
$ .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8080
$ curl -s localhost:8080/api/healthz
{"ok":true,"env":"LOCAL","version":"1.0.0"}
$ curl -s -X POST localhost:8080/api/auth/login -d '{"username":"admin","password":"***"}'
HTTP 200 (cookie session)
$ curl -s localhost:8080/            # SPA index.html served
$ curl -s -b <jar> localhost:8080/api/overview/stats
{"events_total":342,"alerts":{"total":6,"critical":1,"high":4,"medium":1},
 "cases":{"total":1,"investigating":1},"vulns":{"total":8,"open":6}, ...}
```

## Module smoke (new pages' endpoints) — Verified, 2026-09-21 (this session)

- `GET /api/agents/approvals?status=pending` → `{"items":[],"total":0}`
- `POST /api/automation/1/run` `{"dry_run":true,"note":"smoke"}` →
  `{"run_id":7,"dry_run":true,"plan":{"status":"pending","reasons":[],
  "steps":[{"tool":"summarize_alerts","args":{}},
           {"tool":"get_alerts","args":{"status":"new"}}]}}` — dry run
  returned a plan and executed nothing.
- `POST /api/reports` `{"kind":"overview"}` →
  `{"id":1,"path":".../data/reports/overview-1.html","input_rows":349,
   "input_sha256":"47830bfa4a5cfbb00e0f2a543c051ba123d693e97dbed3d627cdfc1d5a02d8cd"}`

## Capacity / load test (SEC-043) — Verified, 2026-09-21 ~05:20 UTC

`app/backend/scripts/load_test.py` drives the real ASGI app (API + detection
engine + SQLite) with a synthetic stream (~85% benign + concentrated SSH
brute-force / login-storm patterns so detection work is representative).
Runs use a throwaway data dir and a runtime-generated load-test user (no
credential literals in source, ADR-006).

```
$ .venv/bin/python -m scripts.load_test --events 20000 --batch 250   # → GATE: PASS
events_per_second: 3903.2    batch p50 64ms / p95 97ms / p99 134ms / max 134ms
detections_fired: 251 (→ 8 alerts after per-rule/entity dedupe)
db_size_bytes: 360448 → 6082560   (~275 B/event incl. WAL)

$ .venv/bin/python -m scripts.load_test --events 50000 --batch 500   # → GATE: PASS
events_per_second: 6722.4    batch p50 72ms / p95 107ms / max 112ms
db_size_bytes: 360448 → 14548992
```

- Bounded regression guard in the fast suite: `tests/test_capacity.py`
  (2,000 events / 8 batches, <20s floor, detection must fire) — 1.05s
  locally, part of the suite.
- **Live-uvicorn HTTP mode — Verified 2026-09-21 ~08:35 UTC** (was the last
  pending part of SEC-043): `--mode http` against a real `uvicorn` instance
  on 127.0.0.1:8081 with a throwaway seeded DATA_DIR (preview DB untouched):
  20,000 events → **4,501.2 ev/s** (wall 4.44s), batch p50/p95/p99/max
  57/90/101/101 ms, 251 detections → 8 alerts, GATE PASS. The network path
  matches/exceeds the in-process ceiling; `scripts/load_test.py` httpx call
  fixed for 0.28 keyword-only API.
- Multi-client concurrency: not exercised (single-client sequential batches
  already saturate the measured ceiling; revisit only if a concurrency
  requirement appears — ADR-008 trigger list).

## CI on GitHub Actions — Verified (2026-09-21 ~04:22 UTC)

First run of `.github/workflows/ci.yml` (PR #1, run 35560868111):

- `backend — ruff + pytest`: **pass** (1m19s)
- `frontend — typecheck + build`: **pass** (25s)

Push and pull_request triggers both fired; both green.

## SEC-050/056/071/072 extension block — Verified, 2026-09-21 ~06:00 UTC

Environment: same sandbox, backend venv (py3.11), branch
`arena/01a0c152-z-cyber-sec` (uncommitted at time of writing).

| Item | Command | Result |
|---|---|---|
| Lint | `ruff check app/ scripts/` | All checks passed |
| Full test suite | `pytest -q` | 110 passed (97 prior + 13 new in `tests/test_extensions.py`), exit 0, ~74s |
| New tests | `pytest tests/test_extensions.py` | 13 passed — purple-team pass + rerun dedupe (created→updated) + 404 + audit rows in `audit_events`; coverage `never_fired` flips; saved-search owner scoping (403 cross-owner delete, 400 bad module); schedule lifecycle (create → force-due via `next_run_at` UPDATE → run-due builds 1 report → `last_run_at`/`next_run_at` advance → pause → 400 bogus status → delete); retention report (`due_count`, `legal_hold`, evidence with retention `1d` from 2000); adapters (builtin+prompt→400 "no brain", bad adapter→400, `openai_compat` via monkeypatched `httpx.post` asserting URL + allowlisted tools only, completed+truthful, **bypass attempt denied** — model proposes `create_case` while allowlist has only `summarize_alerts` → status `denied`, "allowlist" in reason, `cli` roundtrip via real subprocess, malformed output→400) |
| Migration | boot with `0002_extensions.sql` | auto-applied (tests run against it; scheduler tables + adapter columns present) |
| Frontend build | `npm run build` | `tsc -b && vite build` ✓ 50 modules, `dist/assets/index-Cuz-NSpu.js` 270.09 kB (gzip 75.94 kB) |
| Backup rehearsal | `python -m scripts.backup_rehearsal` (in-process) | **DRILL: PASS** — backup created, sha256 verified, live DB wiped, production `restore_from` applied, **342/342 events** match baseline, audit chain ok both sides, RTO 0.01s (in-process; live-mode path documented, unrun in sandbox) |
| Live server smoke (post-restart, migration 0002 auto-applied) | `uvicorn app.main:app` on :8080, cookie-authed curl/python probes | healthz 200; coverage 200 (100%, 0 gaps); PT scenarios listed; **pt-001/002/003 × 3 rounds all HTTP 200, passed=true**; schedule create 201 (`active`); retention report 200 (nested `evidence{}` shape); saved-searches owner-scoped (sasha sees 0 of admin's); SPA serves rebuilt bundle `index-Cuz-NSpu.js` |
| Bug found by smoke → fixed | pt-003 returned 500: `sqlite3.ProgrammingError … created in a thread can only be used in that same thread` in `db.get_conn` teardown. Root cause: FastAPI runs sync dependency setup/teardown via anyio's LIFO worker pool; a background scheduler tick between a request's work and its teardown moves the teardown to a different worker. Fix: `sqlite3.connect(..., check_same_thread=False)` in `app/db.py` (per-request usage is sequential; WAL + busy_timeout serialize writers). Re-verified: full suite 110 passed + PT ×3×3 all 200. |
| Docker image build | `docker build -f app/backend/Dockerfile` | **Proposed/unrun** — no docker daemon in this sandbox. COPY paths verified to exist; compose context = repo root (fixed from `infra/`); YAML valid. |
| CI | pending this block's push | — |

New/changed files: `app/backend/app/migrations/0002_extensions.sql`,
`app/services/{purple_team,agent_adapters,scheduler,backup,report_builder}.py`,
`app/routers/{soc,agents,reports,admin}.py`, `app/config.py`, `app/main.py`,
`app/backend/scenarios/pt-00{1,2,3}-*.yaml`,
`app/backend/scripts/{backup_rehearsal,load_test}.py`,
`app/backend/tests/test_extensions.py`, `app/backend/Dockerfile`,
`infra/prod/{docker-compose.yml,Caddyfile,.env.example.prod}`,
`infra/network/{nftables.conf,validate_flows.sh}`,
`.github/workflows/ci.yml` (+supply-chain job, npm audit step),
`app/frontend/src/{api.ts,pages/{Soc,Reports,Agents}.tsx}`,
`docs/{12-api-reference,13-verification-evidence}.md`, `gitleaks.toml`.

## SEC-060/061/064/070 completion block — Verified, 2026-09-21 ~07:30 UTC

Environment: same sandbox, backend venv (py3.11), branch
`arena/01a0c152-z-cyber-sec`.

| Item | Command | Result |
|---|---|---|
| Lint | `ruff check app/ scripts/ tests/` | All checks passed |
| Full test suite | `pytest -q` | **115 passed** (110 prior + 2 forwarded-headers + 2 release-gate + 1 boot-guard), exit 0, ~88s |
| SEC-061 boot guard hardened (self-caught footgun) | new test `test_boot_guard_rejects_placeholder_secrets` | The guard only rejected the dev default — an operator copying `.env.example` unedited would boot on `__SET__`. Now STAGING/PROD also reject template placeholders + keys <32 chars (ADR-006 updated; LOCAL stays permissive) |
| Backup rehearsal | `python -m scripts.backup_rehearsal` (in-process) | **DRILL: PASS** — 342/342 events, sha256 ok, chain ok both sides, RTO 0.01s |
| Frontend build | `npm run build` | `tsc -b && vite build` ✓ 50 modules, `dist/assets/index-yPnJV00W.js` 274.36 kB (gzip 76.89 kB) |
| SEC-061 edge trust (real bug found & fixed) | new `app/middleware.py` `ForwardedHeadersMiddleware` + 2 tests | The installed starlette build (1.6.0) ships **no** `ProxyHeadersMiddleware` — a naive `request.url.scheme` would never be `https` behind Caddy (no Secure cookie, client IP = proxy). Middleware implements one-hop trust (X-Forwarded-Proto → scheme; last XFF entry / X-Real-IP → client). Tests: cookie gains `Secure` behind edge + session records `198.51.100.7` (forged leading XFF entries ignored); direct connection keeps local behavior (no Secure, `testclient` IP) |
| SEC-064 release gate (live smoke) | cookie-authed probes on :8080 after restart (migration 0003 auto-applied) | gate `no_decision` → record `rejected` (201) → gate `blocked` → record `approved` (201) → gate `approved` (v1.1.0); history `['approved','rejected']`; sasha (soc_analyst) record → **403**; bad commit sha → 422; audit rows `release.approved`/`release.rejected` present; chain verify ok (35 rows) |
| SEC-061 Secure cookie (live smoke) | login with `X-Forwarded-Proto: https` | Set-Cookie contains `secure` ✓ |
| SPA | `GET /` | serves rebuilt bundle `index-yPnJV00W.js` |
| Compose/YAML | python yaml parse + `bash -n` | `infra/staging/docker-compose.yml`, `infra/prod/docker-compose.yml`, `infra/compose/compose.yaml` valid; `validate_flows.sh` syntax OK |
| Docker image build | `docker build` | **Proposed/unrun** — no docker daemon in sandbox (COPY paths verified to exist) |
| CI | pending this block's push | — |

New/changed files: `app/backend/app/middleware.py` (NEW),
`app/backend/app/migrations/0003_releases.sql` (NEW),
`app/backend/app/{main,security,config}.py` (middleware registration; `release.read`/`release.write` perms; boot-guard hardening),
`app/backend/app/routers/admin.py` (releases endpoints),
`app/backend/tests/{test_security,test_extensions}.py` (+4 tests; +2 ruff auto-fixes in test_capacity.py),
`app/frontend/src/pages/Admin.tsx` (Releases tab),
`infra/staging/{docker-compose.yml,.env.example}` (NEW, SEC-060),
`docs/14-release-checklist.md` (NEW), `docs/adr/008-capacity-based-extraction.md` (NEW, SEC-070 decision),
`docs/{09-production,12-api-reference,13-verification-evidence}.md`,
`infra/README.md`, `planning/backlog.md` (44/44), `README.md` (docs index).

## SEC-063 live-mode drill — Verified, 2026-09-21 ~08:10 UTC

Live mode of `scripts/backup_rehearsal.py` executed against the real
preview server (real uvicorn stop/start):

- `--url http://127.0.0.1:8080 --restart-cmd ".venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080"`
- **DRILL: PASS** — backup `cybersec-20260921T08092.tar.gz` (sha256
  verified), server SIGTERMed, live DB files moved to `data.lost-1789978185`
  (preserved), production `restore_from` applied, server restarted
  (`start_new_session` so it outlives the drill), **423/423 events** match,
  audit chain ok both sides, **RTO 16.68s** (real stop+restore+start).
- Post-drill live check: 423 events, both release decisions present, gate
  `approved`, chain verify ok (41 rows).

Bugs found & fixed by the live run: `httpx.Client(base_url=…)` (0.28.x
keyword-only API), and `pgrep -f uvicorn` matching the drill's own argv
(self-kill) → replaced with a /proc cmdline scan that excludes the drill
process + its ancestor chain.

## SEC-073 API surface hardening — Verified, 2026-09-22

Post-build audit of the running app (not the test suite): every `/api` route
was inspected for an auth dependency, and the live server was probed
unauthenticated. Four findings, all fixed, each pinned by a test in
`tests/test_api_surface_hardening.py` (14 tests).

| # | Finding (as found) | Fix |
|---|---|---|
| 1 | Unknown `/api/*` returned the SPA shell: **`200 text/html`** for a typo'd path, contradicting the docs/12 error contract | explicit `/api` + `/api/{rest}` catch-alls → `404 {detail:{code:"not_found"}}`, registered after real routers so nothing is shadowed |
| 2 | `/metrics` (open-alert counts by severity, DB size, session counts) had no auth option and, in prod, would be proxied by Caddy on the **public** edge | Caddyfile `respond @metrics 403` + optional `METRICS_TOKEN` bearer gate (constant-time compare) |
| 3 | Login brute-force limiting existed **only** as a Caddy `rate_limit` directive — not part of the standard build, so the pinned `caddy:2` image rejects such a file ("unknown directive: rate_limit"). The control existed nowhere. | limiter enforced in the app (`app/ratelimit.py`): 50/10s per IP, on by default in STAGING/PROD, `429` + `Retry-After`, one `auth.rate_limited` audit event per window, bounded key map. Caddyfile rewritten with stock directives only; the optional custom-image layer is documented in `infra/README.md`. |
| 4 | `infra/README.md` + prod compose instruct `cp .env.example.prod .env`, but the template **did not exist** — and `.gitignore` (`.env.*`) would have silently ignored it if created | added `infra/prod/.env.example.prod`; `.gitignore` negates `!.env.example.*` (verified: template committable, real `.env` / `.env.prod` still ignored) |

Route audit method: walk `app.routes` → `_IncludedRouter.original_router.routes`
(the pinned FastAPI wraps included routers, so top-level iteration alone sees
only 21 entries and **zero** `/api/*` — the earlier attempt that reported
"missing endpoints" was measuring the wrapper, not the app).

Results: **111 `/api` routes audited — 0 without authentication**; the only
session-auth-without-permission route is `GET /api/auth/me` (correct: any
authenticated user reads their own identity). The live 200s that triggered
the audit (`/api/overview`, `/api/admin/users`) were the SPA fallback, not
data — now they are JSON 404s.

Full suite after the change: **129 passed** (115 + 14 new), `ruff` clean. Live
checks on a throwaway STAGING instance (`ENV_NAME=STAGING`,
`LOGIN_RATE_LIMIT=3/60s`, `METRICS_TOKEN` set, seeded temp `DATA_DIR`):
`/metrics` 401 / 401 (wrong token) / 200 (correct token); logins 401, 401,
401, then **429** with `Retry-After: 60` and `{"detail":{"code":"rate_limited"}}`;
exactly one `auth.rate_limited` audit row (`seq 7`, target `ip:127.0.0.1`,
detail `{limit:3, retry_after_s:60, window_s:60}`) beside the 3 `auth.failed`
rows. The LOCAL preview is unchanged by design: `/metrics` open, five bad
logins → five `401`s (no limiter locally).

**Evidence level for finding 3's edge claim** (per the repo's labeling rule):
*Verified by external sources* — the `rate_limit` directive is supplied by the
community `mholt/caddy-ratelimit` module, not the standard build, and a stock
`caddy:2` container rejects a Caddyfile using it. *Not load-tested here*
(**Blocked**): `caddy validate` needs the binary, and this sandbox has no
Docker daemon and blocks `release-assets.githubusercontent.com` (two download
attempts, `curl` and `gh release download`, both failed). The rewritten
Caddyfile therefore uses only stock directives (`encode`, `header`, `respond`,
`reverse_proxy`, `@matcher`) — correct by inspection, to be confirmed by
`caddy validate` on the target host before go-live.

## SEC-074 inert-rule blind spot — Verified, 2026-09-22

Closes the gap this file itself recorded ("the engine is a documented subset;
no linter for out-of-subset rules yet").

**Defect as found:** `app/routers/soc.py` skipped a non-compiling rule with a
bare `except RuleError: continue` — no log, no audit, no counter — while
`GET /rules` still listed it as `active` and `/rules/coverage` showed it as a
"gap" (indistinguishable from "no matching traffic yet"). `_seed_rules` also
inserted `rules/*.yaml` into the database **without compiling them**. Net
effect: a rule ported from a full Sigma pack, or invalidated by a grammar
change, became a permanent silent blind spot — the operator would believe they
had coverage that could never fire.

Reproduced before fixing: a rule using the common `action|contains|all` +
`condition: 1 of selection*` raised `RuleError: Cannot parse condition at: '*'`
and was dropped silently (verified directly against `compile_rule`).

**Fix (four layers):**

| Layer | Change |
|---|---|
| Engine | `detection.rule_health(spec)` returns `{compiles, error, rule}` instead of raising — one implementation for every surface |
| Runtime | the skip is logged (`WARNING cybersec.detection: detection rule <uid> cannot compile and is INERT: <reason>`), throttled to once per rule per process |
| API | `GET /rules` adds `compiles`/`error` per rule + `summary{ok,broken,broken_uids}`; `GET /rules/coverage` adds `inert_rules` + `broken_rules`, keeps inert rules **out** of `gaps`, and counts only runnable rules in `coverage_pct` |
| Seed + CI | `_seed_rules` compiles every shipped rule and raises `RuntimeError` naming the file; `scripts/lint_rules.py` validates `rules/*.yaml` (or a named ported file) with porting advice, run in the CI backend job |

**Verified live** (preview server, rule inserted directly into SQLite to
simulate one that became invalid after an engine change — the case no
write-time check can catch):

- `GET /api/soc/rules` → `summary: {"ok": 6, "broken": 1, "broken_uids":
  ["legacy-inert-1"]}`; the inert rule reports `compiles: false`,
  `error: Cannot parse condition at: '*'`, `status: active`.
- `GET /api/soc/rules/coverage` → `inert_rules: 1`, `broken_rules:
  [("legacy-inert-1", …)]`, `gaps: []`, `coverage_pct: 100.0` (of the 6
  runnable rules) — previously this read 6/7 with the rule listed as a gap.
- Two ingest batches → the INERT warning appeared **exactly once** in the
  server log (throttle confirmed).
- `python -m scripts.lint_rules` on the 6 shipped rules → exit 0, all compile.
  On a verbatim SigmaHQ rule → exit 1 with `title`/`id`/`level` mapping advice
  and the field-modifier explanation.
- Frontend: SOC page renders a `live`/`inert` marker per rule plus a banner
  listing inert rules and reasons (build verified; `inert-warn`/`st.inert`
  present in the shipped bundle).

The grammar claims in `docs/15-detection-rules.md` were established by probing
the compiler, not by reading it: `a`, `a and b`, `a or b`, `not a`,
`(a or b) and c`, `all`, `any`, `2 of` compile; `1 of a`, `2 of (a, b)`,
`all of (a,b)`, `1 of a*`, `all of them` do **not**. `N of` counts terms
matched by a single event.

Suite: **145 passed** (129 + 16 new in `tests/test_rule_health.py`), ruff clean
on `app/ scripts/ tests/`.

## SEC-075 adversary tradecraft (The-Xploiter) — Verified, 2026-09-22

Requested integration: an offensive-security persona (pentest/bug bounty/red
team tradecraft, exploitability validation, attack chaining, triage-ready
reporting) inside the platform. Integration point is the **existing governed
agent gateway** (docs/06) plus the **existing authorization model**
(`exercises`), not a parallel subsystem — so the guardrails are the ones the
platform already enforces and tests, extended to the new capability.

**Safety architecture (what makes an offensive capability acceptable here):**

| Control | Enforcement |
|---|---|
| Authorization | A target must appear in `exercises.targets` for an exercise in status `authorized`/`running`; `planned` grants nothing (verified live: `lab-ctf-target-01` ∈ a *planned* CTF exercise → `in_scope: false`) |
| Deny by default | No authorized engagement ⇒ no target authorizes anything |
| Over-broad scope | `0.0.0.0/0`, `::/0`, `*`, `any`, `all` are surfaced in `ignored_entries` with reasons and authorize **nothing** |
| Refusals are audited | Out-of-scope attempts write `tradecraft.out_of_scope` (target + reason) to the hash-chained log — for top-level targets *and* per-step chain targets |
| No weaponisation | The agent tool registry contains no shell/exec/scan tool (14 tools, asserted by test); the module records judgements, it does not send traffic |
| Agent writes gated | `record_exploitability_review` and `propose_attack_chain` are consequential → human approval; read-only `list_scope_targets`/`get_finding` auto-run |
| Persona ≠ permission | `adapter_config.persona` only edits the system prompt; unknown names refused (`400 bad_persona`) |

**Two real bugs found and fixed while building it:**

1. **Scope widening via `@`.** `_normalize_target` stripped everything before
   `@` unconditionally (userinfo stripping meant for URLs). A legitimate
   account-style scope entry — the seeded phish-sim drill authorizes
   `test1@test.local` — collapsed to `test.local`, silently authorizing the
   **entire domain**. Fixed: userinfo is stripped only in URL form
   (`scheme://…`); verified live that `test1@test.local` authorizes itself and
   not the domain.
2. **Unaudited step targeting.** `validate_chain` scope-checked per-step
   targets but did not report them in `out_of_scope`, so a chain step aimed at
   an un-authorized host produced a 400 with **no audit event**. Fixed: step
   violations are collected into `out_of_scope` and audited like top-level
   ones (test asserts the audit row).

**Verified live** (preview server, seeded data):

- Persona: 8 focus areas, 5 principles, 6 use cases, 6 guardrails,
  eJPT/OSCP/CRTO mapping.
- Scope: `test1@test.local` → in scope (exercise 1); `lab-ctf-target-01`,
  `10.42.0.10`, `evil.example.org`, `production-db-01` → all refused.
- Review policy: out-of-scope → `400` + audit row; `exploitable` without
  evidence → `400` listing all three missing requirements; `theoretical` →
  recorded with `triage_ready: false` and the rejection note; a complete
  review → `201`, `triage_ready: true`, scope `authorized by exercise 1`.
- Chains: flat low→low → refused ("does not escalate"); escalating 3-step
  chain → `201 draft`, combined impact `critical`; step-level `vuln_id` links
  the chain into the finding's report.
- Triage report: `READY FOR SUBMISSION` with why-it-works, preconditions,
  reproduction, evidence, impact, attack paths, remediation, confidence.
- Agent tools: 14 registered; the four tradecraft tools show
  `read_only` / `requires_approval` correctly; an agent recording a review
  against an out-of-scope target is refused by the same validator.
- RBAC: viewer reads (200), viewer writes (403 `tradecraft.write`).
- Audit: `tradecraft.review_recorded` ×2, `tradecraft.chain_recorded` ×2,
  `tradecraft.out_of_scope` ×1 (target `production-db-01`); chain verify
  `ok: true` afterwards — the tamper-evident log still validates.

Suite: **191 passed** (145 + 46 new in `tests/test_tradecraft.py`), ruff clean;
frontend typecheck + build green (288.15 kB / 80.33 kB gzip). Docs: `docs/16`
(new), `docs/12` (endpoints), `docs/06` (personas), README index.

## SEC-076 tradecraft follow-ups — Verified, 2026-09-22

Three items found by **using** SEC-075 rather than shipping it. The first is a
defect that broke the feature's own workflow.

**Defect: the injection heuristic rejected legitimate engagement prose.**
`policy.validate_args` applied `_SHELLISH_RE` to every argument field, so an
agent recording a reproduction step reading "run
``curl -s http://target/api``" was refused as "possible injection". A pentest
tool that cannot record a command line is broken for the thing it is for. The
filter was also inconsistent (`"id; whoami"` passed, `"id;whoami"` did not),
because the pattern requires a letter straight after the semicolon.

Fix: tools declare `text_fields` (prose stored as data, never interpreted).
The heuristic is skipped for exactly those fields; they are length-capped
instead (8000 chars/entry, 50 entries/field), and every other field keeps the
strict check unchanged. Verified that the relaxation is **per-tool**, not
global: the same args are still refused for `propose_attack_chain` (which does
not declare `reproduction`), for `create_case`, and for the no-tool default;
injection in an identifier field (`target: "$(rm -rf /)"`) is still refused.

**Gap: no deliverable.** `POST /api/reports {kind: "tradecraft"}` now renders
the engagement report — summary, findings ready for submission, chains as
paths, and the rejected/disproven list. Live: report id 1, 349 input rows,
sha256 recorded, `Engagement summary / Findings ready for submission / Attack
chains / Rejected` all present in the HTML; empty-state renders "None — no
review has met the evidence standard".

**Gap: not discoverable.** The seed now ships `the-xploiter` (adapter
`openai_compat`, local Ollama endpoint, `persona: the-xploiter`, the four
tradecraft tools) so a fresh install exposes the persona; a test asserts the
shipped example contains no execution primitive.

**Full agent path verified live** (not just planned): a read-only task
auto-executed (`list_scope_targets` returned the authorized targets, allowed
only because exercise 1 is `authorized`); a consequential task returned
`awaiting_approval` — proving the prose fix did not weaken the gate — and after
`POST /approvals/1/decide {decision: "approve", comment: …}` the task executed
and wrote review id 3 with `reviewed_by: agent`, verdict `exploitable`, and the
backticks **preserved intact** in the stored reproduction text. The approval
vocabulary is `approve`/`reject` (`bad_decision` on anything else).

**Defect found by auditing a claim in the new code:** `_fingerprint`'s
docstring promised that URL/port noise and severity wording would not change
the dedupe key, but it only lower-cased the target and kept severity words —
so the same finding submitted as ``https://lab-web-01:8443/x "SQL Injection
(critical)"`` and ``lab-web-01 "sql injection"`` landed in **two** clusters,
i.e. the signal-to-noise feature silently did nothing for the most common
re-submission. Fixed: the target is normalised exactly as scope matching
normalises it, and severity vocabulary (`critical`…`info`, `severity`) is
dropped from the title words. Five cases verified: scheme/port/path,
severity wording and word order all collapse to one key, while a different
host, a different weakness or a different CVE stay separate.

**Stale release gate found and corrected:** `docs/14` still instructed the
approver to verify "Login rate limit … at the edge (Caddyfile: 50r/10s per
IP)" — a control SEC-073 moved into the application. An approver following the
checklist would have looked for it in the Caddyfile, not found it, and either
ticked the box anyway or blocked the release. The checklist now carries the
command-level in-app check, plus the SEC-073/074/075 gates (Caddyfile loads on
the stock image, `/metrics` 403 on the edge, JSON 404 for unknown API paths,
`lint_rules` exit 0, tradecraft scope + audit check).

**Reports UI gap:** the kind dropdown was hardcoded to the five original kinds,
so the new engagement deliverable was API-only. `Reports.tsx` now lists
`tradecraft`.

### SEC-077 — authorization windows are enforced (not decorative)

**Defect found in the course of SEC-076 verification.** Exercised the scope guard
against the seeded engagement and found the authorization window was never
evaluated: `10.42.0.10` was listed as *usable* on **2026-09-22** from an
engagement whose window had ended **2026-09-13**. The guard rested on
`status IN ('authorized','running')` alone, so a written authorization silently
outlived the permission it rests on — the one bound a pentest engagement
actually turns on. The seed made it invisible by carrying an already-lapsed
window (09-12 → 09-13).

Fixed in `app/services/tradecraft.py`:

- `_window_state(starts_at, ends_at, today)` → `expired` / `not_started` /
  `active` / `open`. Missing dates = `open` (no window claimed, reported as
  open-ended rather than quietly trusted). Inclusive of the last day.
- `authorized_targets()` marks entries of a lapsed or not-yet-started
  engagement unusable and carries `starts_at`/`ends_at`/`window_state` per row.
- `check_target()` refuses with the **real cause**: *"target matches exercise 1
  (Synthetic Phish Drill Q3), but that engagement does not authorize work right
  now: authorization window ended 2020-01-31 — renew the engagement"*. The old
  generic "not listed in any exercise" would have sent an operator hunting for a
  missing entry when the fix is to renew the engagement.
- `scope_summary()` adds `expired_engagements`; the rule text states the window
  requirement. `/tradecraft` shows a **window_state** column, an explicit
  lapsed-engagement warning block, and the stat card now reads "in-force
  authorization windows".
- Seed: the demo engagement's window now extends 30 days past today, with a
  comment explaining why an example must not be born expired (a test asserts it).

Verified (live, preview server on :8080, DB window set to expire 2026-09-01):

| # | Check | Result |
|---|-------|--------|
| 1 | `GET /api/tradecraft/scope` before fix | `10.42.0.10` usable on 09-22 despite window ending 09-13 — **BUG** |
| 2 | Review against lapsed engagement | `400 bad_review`; refusal names exercise, window and fix |
| 3 | Same review after renewal (window to 11-21) | `201` recorded, `window_state: active` |
| 4 | `expired_engagements` in scope summary | `[[1, "Synthetic Phish Drill Q3", "authorization window ended 2026-09-01 — renew the engagement"]]` |
| 5 | Future window (2099) | refused, reason "not in force yet", not usable |
| 6 | No window recorded | `window_state: open`, usable — and labelled as open-ended |
| 7 | Over-broad entry (`0.0.0.0/0`) | refused with "over-broad scope entry authorizes nothing" |
| 8 | Unrelated host | generic "not listed in any exercise" message retained |

Also in this pass: the `exploitable` refusal now states the reproduction minimum
("at least 20 characters") — the previous wording rejected an undersized
reproduction without saying what size was expected, which reads as a false
negative to the person who just wrote it.

Suite 214 → **222 passed**, ruff clean, `lint_rules` 6/6 compile, frontend
typecheck + build green (290.66 kB / 81.07 kB gzip).

### SEC-078 — the approval gate could execute one task twice

**Defect found by auditing the approval guard rather than assuming it.** The
decision handler read the approval, checked `status != 'pending'` in Python, and
then wrote `UPDATE approvals SET status = ... WHERE id = ?` — a read followed by
an unguarded write. Under the interleaving two concurrent approves produce, both
requests pass the check and both proceed:

```
request A reads status: pending
request B reads status: pending
B's UPDATE ... WHERE id=1 affected rows: 1  -> B believes it decided the approval
pending left: 0                             -> both requests conclude "execute the tool"
decided_by ends as: B                       -> A's decision is silently overwritten
```

The consequence is a governance failure, not a cosmetic one: the
consequential tool runs **twice** (one approved action executed twice), and the
recorded approver becomes whichever request wrote last.

Fixed with guarded transitions (`app/routers/agents.py`):

- The decision is a compare-and-set: `UPDATE ... WHERE id = ? AND status =
  'pending'`; `rowcount != 1` ⇒ `409 already_decided`. Exactly one caller can
  move an approval out of `pending`.
- The task is claimed atomically: `UPDATE agent_tasks SET status='running' ...
  WHERE id = ? AND status = 'awaiting_approval'`. Only the claimer executes. A
  second approval on a claimed task is approved but audited
  `{"executed": false, "note": "task already claimed by another approval"}` —
  visible, rather than a silent second run.

Verified live (preview :8080, six simultaneous approves of one approval):

| # | Check | Result |
|---|-------|--------|
| 1 | 6 concurrent `POST /approvals/3/decide` | `req4:200`, other five `409 already_decided` |
| 2 | Cases created for that task | **1** (count 1 → 2 overall, one title match) |
| 3 | `approval.executed` audit rows for the approval | exactly **1** (`{"errors":[],"task_id":5}`) |
| 4 | Task status | `completed` |
| 5 | A second approval (id 4) for the same, already-claimed task | `200 approved`, audited `executed:false`, cases stayed at 2 |

Note the two-layer behaviour visible in the live run: four of the losers were
stopped by the cheap pre-check, one reached the compare-and-set and was stopped
there — the guard no longer depends on timing luck.

Tests: `test_stale_read_cannot_double_decide` drives the exact stale-read
interleaving (approval committed behind the caller's back, stale snapshot
returned) and asserts `409` plus *no* side effect; 
`test_second_approval_on_claimed_task_does_not_reexecute` asserts the second
approver is audited `executed:false` and the case count is unchanged.

Suite 222 → **224 passed**, ruff clean.

### SEC-079 — the SPA offered statuses the API rejects, and hid the real ones

**Defect class found by sweeping every picker in the SPA against the API's
accepted values** (the same class that produced the missing `tradecraft` report
kind in SEC-076). Silently, three screens were wrong in both directions — they
offered values the API refuses and omitted values it accepts, so the omission
looked like a broken feature:

| Screen | Offered by the UI, rejected by the API | Accepted by the API, unreachable in the UI |
|--------|----------------------------------------|--------------------------------------------|
| `/soc` triage | `false_positive` → live `400 bad_status` | `dismissed` — **the way a false positive is actually recorded** |
| `/incidents` case status | `containment`, `recovered` → live `400 bad_status` | `contained`, `mitigated` (also unfilterable) |
| `/incidents` task status | — | `canceled` |
| `/cloud` posture | — (the API validated nothing at all) | — |

The first row is the serious one: an analyst following the UI to dismiss an
alert as a false positive got a `400`, and there was no way to record the
outcome the platform actually supports.

Fixes:
- `Soc.tsx`, `Incidents.tsx` pickers now carry the API's exact vocabulary;
  `Incidents.tsx` task statuses gained `canceled`.
- `routers/cloud.py` gained the validation it never had: posture `status` and
  `severity` are checked on create and update (`400 bad_status` /
  `bad_severity` with the allowed list). The existing test asserted the old
  behaviour with a third vocabulary — `status: "remediated"`, a word the UI
  (`resolved`) and the seed (`open`) never used — which is precisely how the
  drift survived; it now asserts `400` for the unknown value and `200` for
  `resolved`.
- **`tests/test_enum_parity.py` (new, 10 tests)** reads the SPA source and
  compares every named picker list with the set the API accepts — alerts,
  cases, case tasks, GRC controls, GRC risks, cloud posture, vulns, report
  kinds, roles — plus the inline severity lists. Drift now fails in CI with the
  two-way diff in the message. Verified non-vacuous: reintroducing
  `false_positive` fails with *"offered by the UI but rejected by the API:
  ['false_positive'] / accepted by the API but unreachable in the UI:
  ['dismissed']"*, and the suite passes again once restored.

Suite 224 → **234 passed**, ruff clean, frontend typecheck + build green
(290.67 kB / 81.08 kB gzip).

### SEC-080 — the documented error envelope was not the real one

**Defect found by testing a documented claim instead of the code.** docs/12
states: *"non-2xx bodies carry `detail = {code, message}` … Clients key off
`code`"*. Application errors do. FastAPI's request-validation failures did not:

```
POST /api/cases {"title": "x"}  ->  422
{"detail":[{"type":"string_too_short","loc":["body","title"],"msg":"String should have
 at least 3 characters","input":"x","ctx":{"min_length":3}}]}
```

`detail` is a **list**, so a client written against the documented contract reads
`detail.code` → `undefined` (the SPA already branched on the array shape, which
is how the inconsistency stayed invisible in the UI while remaining wrong for
every other consumer).

Fixed in `app/main.py`: a `RequestValidationError` handler keeps the correct
`422` status and returns the documented envelope, preserving the field-level
detail:

```json
{"detail": {"code": "invalid_request",
            "message": "title: String should have at least 3 characters",
            "errors": [{"field": "title", "msg": "...", "type": "string_too_short"}]}}
```

`message` names the first three offending fields (then `(+N more)`), and no
internals (`Traceback`, module paths, submitted values beyond the field name)
appear in the response. docs/12 now documents the 422 shape and the new codes.

Verified live: `{"title":"x"}` → `422 invalid_request` with
`errors[0].field == "title"`; the same request previously returned a bare list.

Suite 234 → **235 passed**, ruff clean.

Suite: **235 passed** (191 + 21 new in `tests/test_hardening_followups.py` plus
the replaced fingerprint tests), ruff clean; frontend typecheck + build green
(290.07 kB / 80.89 kB gzip). Duplicate clusters have a UI panel on
`/tradecraft`, and a "generate report" button wired to the deliverable.

## Known limitations & blocked items
- **Capacity (SEC-043)**: fully measured — in-process (3.9k/6.7k ev/s) and
  live-uvicorn HTTP (4,501 ev/s @20k, p95 90ms). Multi-client concurrency
  remains unexercised (no requirement today; ADR-008 trigger list governs).
- **Restore rehearsal (SEC-063)**: **both modes verified** — in-process
  (342/342, RTO 0.01s) and live (423/423, RTO 16.68s, real server
  stop/start). Live-mode RTO on this host, small dataset; production RTO
  scales with DB size (see ADR-005/007).
- **Production deployment (ADR-007)**: compose/Caddyfile/env templates +
  Dockerfile + supply-chain CI now exist; the actual staging/production
  bring-up is **Proposed** (roadmap Phases 8–9) — not exercised here.
- **Network isolation (SEC-040)**: `infra/network/nftables.conf` +
  `validate_flows.sh` encode the docs/03 flow matrix; they are for the target
  host and **unapplied** here (no authorized target host in this sandbox) —
  treat enforcement as **Proposed/Blocked on a real host**.
- **Real-Sigma-pack porting**: the engine is a documented subset and porting
  is deliberately manual (docs/15); `scripts/lint_rules.py` + the seed guard +
  `/rules` health reporting now catch out-of-subset rules (SEC-074), so an
  inert rule can no longer hide. What remains unbuilt: an **automatic
  translator** from full Sigma to this subset (judged not worth building — a
  silently mistranslated regex/`|all` is worse than a hand rewrite).
- **Agent LLM adapters (SEC-050)**: now wired (builtin/openai_compat/cli) and
  tested with a stubbed LLM + real subprocess; a live local model end-to-end
  (e.g. Ollama) is not exercised in this sandbox — **Proposed**.
- Sandbox workspace restores wipe excluded dirs (`.venv`, `data/`,
  `node_modules`, `dist`); recovery is documented in this file's
  environment section and takes < 5 minutes (venv + pip install +
  `npm install && npm run build` + `python -m app.seed.seed_demo`).
  Happened twice (03:48 and 05:07 UTC); the second also reset the local
  branch pointer to the base commit — fixed with
  `git fetch origin <branch> && git reset --soft FETCH_HEAD`
  (working tree untouched), verified via `git status` before continuing.
