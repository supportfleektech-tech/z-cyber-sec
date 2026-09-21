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
96 passed, 4 warnings in 83.80s (0:01:23)     # 2026-09-21 ~04:15 UTC (pre-ruff-fix run)
```
Ruff fix applied ~04:16 UTC (grc.py E741). Post-fix confirmation runs:

```
$ .venv/bin/python -m pytest -q        # ~04:17 UTC: exit 0, 96/96 progress dots, no F/E
$ .venv/bin/python -m pytest -v
================== 96 passed, 4 warnings in 83.52s (0:01:23) ===================   # ~04:19 UTC
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

## Known limitations & blocked items

- **CI workflow** (`.github/workflows/ci.yml`) added this turn but **not yet
  executed on GitHub Actions** — first run happens on push; treat as
  **Proposed until the check is green**.
- **Load/capacity test (SEC-043)**: not performed; SQLite in-process
  engine limits are estimated, not measured.
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
