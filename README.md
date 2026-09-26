# CYBER-SEC — Cybersecurity Engineering & Intelligence Lab

**Status:** Implemented v1.0 (modular monolith + React SPA), local-first, zero-budget.
**Verified:** 110/110 backend tests, ruff clean, SPA builds + served, live smoke checks,
backup/restore rehearsal PASS — see `docs/13-verification-evidence.md` for the full
evidence log (commands, timestamps, limitations).

> All data in this repository and its default runtime is **synthetic**
> (`data_class='synthetic'`). No real credentials, real targets, or real
> telemetry. Production is a separately hardened deployment (ADR-007), not
> this host.

## Mission

A modular, secure, reproducible local cybersecurity lab and operations
platform, with a documented path to a separately hardened production
deployment.

## Capability scope (all implemented as modules)

SOC & Blue Team · Incident Response & Forensics · Threat Intelligence ·
Application Security · Cloud Security · Network Security (design) ·
Vulnerability Management · GRC & Compliance · Authorized Red Team / CTF
(exercises) · Security Engineering & Automation · Cybersecurity AI Agents
(governed gateway)

## Quick start (local, ~3 minutes)

```bash
# Backend (Python 3.11)
cd app/backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m app.seed.seed_demo        # synthetic users, events, findings
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080

# Frontend (Node 20) — optional; backend serves dist/ when present
cd app/frontend
npm install && npm run build
```

Open `http://localhost:8080/` — default lab login **admin /
`CyberSecAdmin1!`** (synthetic; rotate before any non-LOCAL environment).
Interactive API docs: `/api/docs`.

## Layout

```
app/backend/
  app/main.py            # FastAPI app: API routers + SPA serving (single origin)
  app/config.py          # env-driven settings; refuses dev SECRET_KEY in STAGING/PROD
  app/db.py              # single data-access boundary (SQLite WAL; PG swap point, ADR-007)
  app/security.py        # PBKDF2 passwords, server-side sessions, cookie policy
  app/audit.py           # append-only hash-chained audit log + chain verify
  app/deps.py            # require("<permission>") RBAC dependency
  app/routers/           # one module per domain (soc, cases, intel, vulns, appsec,
                         # cloud, grc, exercises, agents, automation, reports, admin, ...)
  app/services/          # detection engine (Sigma-subset), STIX subset parser,
                         # backup, policy, report builder
  app/migrations/        # 0001_init.sql (full schema) + 0002_extensions.sql (auto-applied)
  app/seed/              # synthetic demo data (explicitly labeled)
  scripts/               # load_test.py (SEC-043), backup_rehearsal.py (SEC-063 drill)
  scenarios/             # purple-team synthetic-attack scenarios (pt-*.yaml, SEC-072)
  tests/                 # 110 tests: auth, RBAC, detection, intel, agents, e2e, extensions, ...
  Dockerfile             # multi-stage prod image (non-root, pinned deps, healthcheck)
app/frontend/            # React 18 + TS + Vite SPA (served by backend)
docs/                    # 00–10 design/ops, 11 frontend, 12 API reference, 13 evidence
docs/adr/                # 001–007 architecture decisions
planning/                # roadmap, backlog, threat scope, workflow
infra/                   # README + local compose, target-host network matrix, prod/Caddy edge
```

## Operating rules (carried into the platform)

- **Synthetic data by default**; real data only behind explicit labeling.
- **Least privilege RBAC**: 5 roles, named permissions per endpoint;
  viewers cannot download reports/evidence; `agent_service` is scoped.
- **Agents cannot waive their own guardrails**: read-only tools run
  immediately, consequential tools require a human approval (queue +
  comment), out-of-allowlist tools are denied, and every tool call is
  audited (docs/06, `/api/agents/evals/run` harness).
- **Audit is hash-chained and append-only**; `GET /api/admin/audit/verify`
  proves the chain.
- **Human approval gates** for production changes, destructive operations,
  containment, and external testing — the UI enforces confirm text
  (e.g. restore requires typing `RESTORE`).
- **Secrets** never in repo/prompts/logs: `.env` gitignored,
  `.env.example` committed, boot guard refuses dev defaults outside
  `LOCAL`/`LAB` (ADR-006).

## Tests & CI

```bash
cd app/backend && .venv/bin/python -m pytest -q          # 289 tests
cd app/backend && .venv/bin/ruff check app/ scripts/ tests/
cd app/backend && .venv/bin/python -m scripts.lint_rules # every rule can fire
cd app/frontend && npm run build                         # tsc -b && vite build
```

GitHub Actions (`.github/workflows/ci.yml`) runs four jobs on every push/PR:
secrets (gitleaks), backend (ruff + rule lint + pytest), frontend
(typecheck + build), supply-chain (SBOM + pip-audit + npm audit).

## Documentation index

| Doc | Content |
|---|---|
| [00](docs/00-source-and-status.md) | Source basis, provenance labels, status |
| [01](docs/01-host-audit.md) | Host audit (pre-change baseline) |
| [02](docs/02-architecture.md) | Architecture overview |
| [03](docs/03-network-design.md) | Network zones & flow matrix |
| [04](docs/04-data-model.md) | Data model |
| [05](docs/05-threat-model.md) | Threat model & authorized scope |
| [06](docs/06-agent-governance.md) | Agent governance & guardrails |
| [07](docs/07-testing.md) | Testing strategy |
| [08](docs/08-deployment-local.md) | Local deployment |
| [09](docs/09-production.md) | Production path |
| [10](docs/10-operations-runbook.md) | Operations runbook |
| [11](docs/11-frontend-spa.md) | Frontend SPA |
| [12](docs/12-api-reference.md) | API reference (all endpoints, error model, audit) |
| [13](docs/13-verification-evidence.md) | Verification & evidence log |
| [14](docs/14-release-checklist.md) | Release checklist & human approval gate (SEC-064) |
| [15](docs/15-detection-rules.md) | Detection rule subset, validation & Sigma porting guide (SEC-074) |
| [16](docs/16-adversary-tradecraft.md) | Adversary tradecraft — The-Xploiter persona, scope guard, chains, triage reporting (SEC-075) |
| [ADR 001–008](docs/adr/) | Framework, auth, SIEM, schema/contracts, evidence, secrets, production, capacity/extraction |

Roadmap & phase gates: [`planning/roadmap.md`](planning/roadmap.md) ·
Backlog: [`planning/backlog.md`](planning/backlog.md)
