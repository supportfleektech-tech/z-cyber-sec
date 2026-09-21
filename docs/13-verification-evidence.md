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
  locally, part of the 97-test run.
- `--mode http` measures a live server end-to-end (needs
  `LOAD_TEST_USER` / `LOAD_TEST_PASSWORD` env vars); not run here.
- Single-process, single-core-equivalent, in-process (no uvicorn network
  hop); the in-process ceiling, not the network ceiling, is measured.

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

## Known limitations & blocked items
- **Capacity (SEC-043)**: measured in-process (see section above); a
  live-uvicorn `--mode http` run and multi-client concurrency are not yet
  exercised.
- **Restore rehearsal (SEC-063)**: in-process drill PASSes (backup → wipe →
  production restore → 342/342 events + chain intact, RTO 0.01s). The **live**
  mode (real uvicorn stop/start + `--restart-cmd`) is coded but unrun in this
  sandbox (needs a live server + server-control env); treat live RTO as
  **Proposed**.
- **Production deployment (ADR-007)**: compose/Caddyfile/env templates +
  Dockerfile + supply-chain CI now exist; the actual staging/production
  bring-up is **Proposed** (roadmap Phases 8–9) — not exercised here.
- **Network isolation (SEC-040)**: `infra/network/nftables.conf` +
  `validate_flows.sh` encode the docs/03 flow matrix; they are for the target
  host and **unapplied** here (no authorized target host in this sandbox) —
  treat enforcement as **Proposed/Blocked on a real host**.
- **Real-Sigma-pack porting**: the engine is a documented subset; no
  linter for out-of-subset rules yet (backlog P2).
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
