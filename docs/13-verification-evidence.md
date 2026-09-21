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

## Known limitations & blocked items
- **Capacity (SEC-043)**: measured in-process (see section above); a
  live-uvicorn `--mode http` run and multi-client concurrency are not yet
  exercised.
- **Restore rehearsal under load (SEC-063)**: backup/restore round-trip is
  covered by tests; a timed RTO/RPO rehearsal is **Proposed** (Phase 8).
- **Production deployment (ADR-007)**: all swap boundaries documented, none
  exercised; staging/production are **Proposed** (roadmap Phases 8–9).
- **Real-Sigma-pack porting**: the engine is a documented subset; no
  linter for out-of-subset rules yet (backlog P2).
- **Agent real-LLM adapters**: the agent gateway currently executes
  deterministic local tool steps; OpenCode/OpenClaw/Hermes adapters are
  scoped (docs/06) but not wired (backlog SEC-050/051).
- Sandbox workspace restores wipe excluded dirs (`.venv`, `data/`,
  `node_modules`, `dist`); recovery is documented in this file's
  environment section and takes < 5 minutes (venv + pip install +
  `npm install && npm run build` + `python -m app.seed.seed_demo`).
  Happened twice (03:48 and 05:07 UTC); the second also reset the local
  branch pointer to the base commit — fixed with
  `git fetch origin <branch> && git reset --soft FETCH_HEAD`
  (working tree untouched), verified via `git status` before continuing.
