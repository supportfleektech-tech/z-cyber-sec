# Final Status Report

**Date:** 2026-09-26 · **Build:** v1.0.0, branch `arena/01a0c152-z-cyber-sec` ·
**Environment of record:** the build sandbox (Linux, Python 3.11, Node 20, SQLite;
no Docker daemon, no root, no target host).

This is the report `agents/MASTER_BUILD_PROMPT.md` asks for ("final status report with
exact paths"), written the way that document demands: every claim carries the command
that produced it, and anything that could not be run here is marked **host-ops** or
**human** rather than folded into "done". The detailed, timestamped evidence log is
`docs/13-verification-evidence.md`; the phase table is `planning/roadmap.md`.

## 1. Verdict

| Question | Answer |
|---|---|
| Is there a working cyber-sec lab platform here? | **Yes** — `make lab`, then `make run`; UI at `http://localhost:8080` |
| Is it complete against the plan's own scope? | **Yes for code**: 11 capability areas, 19 docs, 317 tests, 7 migrations, 5 CI jobs |
| Is it production-deployed? | **No, deliberately** — production is a separate hardened deployment (ADR-007); nothing here has been exposed, and the acts that need a real host are listed in §5 |
| Is anything broken that I know of? | No. Live smoke 214 checks / 0 failures, acceptance 10 demonstrated / 2 host-ops / 0 failed, doctor verdict `ok` |

## 2. What exists (exact paths)

| Artifact | Path |
|---|---|
| Application (FastAPI modular monolith) | `app/backend/app/` — `main.py`, 15 routers, services, migrations 0001–0007 |
| Frontend (React + TS + Vite, served by the backend) | `app/frontend/src/` — 16 pages incl. `pages/Lab.tsx`, `pages/Admin.tsx` |
| Synthetic dataset (complete demo, one command) | `app/backend/app/seed/seed_demo.py` → `seed_full()` |
| Tests | `app/backend/tests/` — 317 tests; `tests/test_lab_range_infra.py` pins the range's isolation rules |
| Operator tools | `app/backend/scripts/` — `smoke_check.py`, `acceptance_check.py`, `doctor_report.py`, `lint_rules.py`, `backup_rehearsal.py`, `load_test.py` |
| One entry point | `Makefile` (`make help`) |
| CI/CD | `.github/workflows/ci.yml` — secrets, backend, live, frontend, supply-chain |
| Infrastructure | `infra/compose/` (local), `infra/lab/` (training range), `infra/staging/`, `infra/prod/` (+ Caddy edge), `infra/network/` (nftables matrix + validator) |
| Documentation | `docs/00`–`docs/18` + `docs/adr/` |
| Planning authority | `planning/plan.md`, `acceptance-criteria.md`, `roadmap.md`, `backlog.md`, `risk-register.md` |

## 3. Verification performed in this build (all re-runnable)

| Command | Result |
|---|---|
| `cd app/backend && .venv/bin/python -m pytest -q` | **310 passed** (≈4 min) |
| `.venv/bin/ruff check app/ scripts/ tests/` | clean |
| `.venv/bin/python -m scripts.lint_rules` | every detection rule can fire |
| `npm run build` (app/frontend) | `tsc -b && vite build` clean |
| `.venv/bin/python -m scripts.smoke_check` (live, seeded) | **SMOKE OK** — 214 checks, surface 102 paths / 136 operations |
| `.venv/bin/python -m scripts.acceptance_check` (live, seeded) | **10 demonstrated · 2 host-ops · 0 failed** |
| `.venv/bin/python -m scripts.doctor_report` | `verdict: OK (11 ok, 0 warn, 0 fail)` |
| `.venv/bin/python -m scripts.backup_rehearsal` | PASS, both modes |
| GitHub Actions `ci` on the pushed commits | success (backend, frontend, secrets, supply-chain, live) |

## 4. The twelve acceptance clauses

| # | Clause | Status | Evidence |
|---|---|---|---|
| 1 | Environment and version recorded | demonstrated | `/api/healthz` (`LOCAL`, `1.0.0`), `X-Environment`/`X-Data-Class` headers, release record v1.0.0 |
| 2 | Core user flows pass automated tests | demonstrated | 317 tests; `acceptance_check` probes 12 module endpoints live |
| 3 | RBAC enforced server-side and tested | demonstrated | anonymous 401 on every route, viewer 403 on 14 consequential writes, per-role tests in `tests/` |
| 4 | Lab-to-management prohibited paths shown blocked | **host-ops** | rules pinned by `tests/test_lab_range_infra.py` (internal network, loopback-only publishes); the nftables matrix is applied and validated on the target host: `sudo infra/network/validate_flows.sh` |
| 5 | Integrations expose health, errors, provenance | demonstrated | 4 integrations with `status`/`last_run_at`/`last_status`/`provenance`; probe results recorded via `/api/admin/integrations/{id}/health` |
| 6 | Synthetic events produce expected alert/case behaviour | demonstrated | 342 events → 6 alerts, 1 linked case; a second detection pass creates 0 duplicates |
| 7 | Agent actions scoped, auditable, approval-gated | demonstrated | 4 agents with tool allowlists, approval queue, eval harness `POST /api/agents/evals/run`; gate tests in `tests/test_agents.py` |
| 8 | No secrets committed or exposed | demonstrated | gitleaks over full history in CI; `.env` ignored; boot guard refuses dev `SECRET_KEY` outside `LOCAL`/`LAB`; app-level fail-fast on weak STAGING/PROD config |
| 9 | Backup and restore demonstrated | demonstrated | bundle created + verified (`/api/admin/backup`, `/backup/verify`), `scripts/backup_rehearsal.py` PASS, doctor `backup.freshness: ok` |
| 10 | Deployment and rollback work on a clean target | **host-ops** | `infra/prod/docker-compose.yml` + Caddyfile + `docs/09-production.md` rollback steps; needs a clean host |
| 11 | Documentation matches implementation | demonstrated | 19 docs, all linked from the README; the discrepancy hunt is recorded as SEC-093…SEC-123 in `docs/13`; `scripts/lint_docs.py` checks 181 invariants (index, test count, migrations, SPA pages, CI jobs, `make` targets, paths) |
| 12 | Unresolved risks and limitations accepted by an owner | **human** | `planning/risk-register.md` is complete and residual risks are listed there; the release decision is recorded through `/api/admin/releases` with the approver, the comment and the hash of `docs/14-release-checklist.md` — the demo row is seeded, a real go-live approval is a human act |

## 5. The acts that are deliberately not done here

Each needs something this environment does not have (a real host, root, a domain, or a
human decision). None of them is hidden behind a green check.

1. **Apply and verify the network matrix on the target host** — `sudo infra/network/validate_flows.sh`
   (needs root and the host's interfaces; the rules and the validator are built and reviewed).
2. **Deploy staging, then production** — `docker compose -f infra/staging/docker-compose.yml up -d`,
   then `infra/prod/` with TLS via the Caddy edge; the go-live gate is Phase 8 + the release
   decision recorded through the API (docs/14).
3. **Run the range against real containers** — `make lab-up` needs a Docker daemon; the
   compose file, the isolation rules and the registry consistency are tested statically.
4. **The recurring operational cadence** — `docs/10-operations-runbook.md` (daily/weekly/
   monthly) is written for a named owner; establishing that ownership is human.
5. **Rotating the lab credentials** — documented; the demo logins are synthetic and
   labeled.

## 6. Known limitations and residual risks (accepted, not discovered)

- **SQLite, single node.** Chosen for a local-first lab; ADR-007 names PostgreSQL and a
  split of the monolith as the production path, with `app/db.py` as the single swap point.
- **The range runs third-party vulnerable images** (Juice Shop, DVWA) plus our own
  `lab-api-01`. They are unpatched *on purpose*, isolated to an `internal: true` network
  with loopback-only publishes, and never reachable from the platform network.
- **Detection is a documented Sigma subset** (`docs/15`), not a SIEM. Rules that the engine
  cannot fire are refused at load time rather than stored inert.
- **The Caddy edge uses stock directives only** — no `rate_limit` plugin (SEC-073); the
  application carries its own login limiter, and the Caddyfile is required to load on the
  stock image for exactly that reason.
- **Agents are a governed gateway, not an autonomous fleet**: out-of-allowlist tools are
  denied, consequential tools need a human approval, and the eval harness scores claims
  against evidence.

## 7. Where to start reading

`README.md` (2-minute overview) → `docs/13-verification-evidence.md` (what was run and
observed, in order, including every defect found and fixed) → `docs/17-lab-range.md`
(the training range) → `planning/roadmap.md` (phase truth) →
`planning/acceptance-criteria.md` (the clauses above).
