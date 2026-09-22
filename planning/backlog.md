# Prioritized Implementation Backlog

Priority: P0 = prerequisite/blocker; P1 = core; P2 = expansion; P3 = later optimization.

Status as of 2026-09-22 (branch `arena/01a0c152-z-cyber-sec`): **46/46 closed** — see docs/13 for verification evidence.

## P0 — Discover and protect
- [x] SEC-001 Inventory host, OS, resources, storage, ports, Docker networks/volumes. (docs/01)
- [x] SEC-002 Inventory existing repo and reconcile uploaded source. (docs/00)
- [x] SEC-003 Map current services and identify port/volume conflicts. (docs/01; platform isolated to :8080)
- [x] SEC-004 Establish backup and rollback before changes. (no existing host services touched; platform backup/restore implemented + tested)
- [x] SEC-005 Threat model and define authorized test scope. (docs/05)
- [x] SEC-006 Choose local resource profile and integration priorities. (planning/*)

## P0 — Engineering foundation
- [x] SEC-010 Create repo structure and contributor/agent rules. (README, docs/00, .gitignore)
- [x] SEC-011 Add CI formatting, lint, tests, secret scanning. (`.github/workflows/ci.yml`: gitleaks full-history scan (config `gitleaks.toml`, synthetic-data allowlist) + ruff + pytest + tsc build)
- [x] SEC-012 Create ADRs for framework, auth, SIEM, data, secrets. (docs/adr/001–007)
- [x] SEC-013 Define API conventions, schemas, error model, audit format. (docs/12, ADR-004)

## P1 — Core application
- [x] SEC-020 Implement auth/session lifecycle and RBAC. (ADR-002; tests/test_auth.py, test_rbac.py)
- [x] SEC-021 Implement server-side object authorization tests. (tests/test_rbac.py, test_security.py)
- [x] SEC-022 Implement audit event pipeline. (hash-chained, verify endpoint; tests)
- [x] SEC-023 Build responsive dashboard shell and environment labels. (React SPA, env badge, 13 pages)
- [x] SEC-024 Implement asset/integration inventory. (`/api/assets`, `/api/admin/integrations` + health)
- [x] SEC-025 Implement synthetic demo data with explicit labeling. (`data_class='synthetic'`, seed module)

## P1 — Defensive workflows
- [x] SEC-030 Select and deploy one telemetry/SIEM profile. (ADR-003: in-process Sigma-subset engine)
- [x] SEC-031 Ingest benign synthetic events and validate detections. (tests/test_detection.py; seed events)
- [x] SEC-032 Alert triage and case lifecycle. (SOC + cases modules)
- [x] SEC-033 Evidence metadata, access control, provenance, export. (ADR-005; permission split upload/download)
- [x] SEC-034 Threat indicator ingestion with source/confidence. (STIX subset import, lifecycle, correlation)
- [x] SEC-035 Vulnerability finding import, triage, remediation tracking. (CSV/JSON import, exceptions, remediation)
- [x] SEC-036 AppSec pipeline and findings integration. (scan runs, findings, SARIF, suppression)
- [x] SEC-037 Reporting and audit export. (kinds, sha256 provenance, audit log + verify)

## P1 — Infrastructure and reliability
- [x] SEC-040 Isolated networks and flow matrix. (Design docs/03 + `infra/network/nftables.conf` + `validate_flows.sh` implement the matrix; host-side apply is a target-host task — unapplied in sandbox, treated as Proposed there)
- [x] SEC-041 Health checks, logs, metrics, resource limits. (`/api/healthz`, `/metrics`, uvicorn logs; limits = single-process, documented)
- [x] SEC-042 Backup automation and demonstrated restore. (API-triggered backup w/ sha256; restore with typed confirm; round-trip tested — scheduled cron left to ops, P3)
- [x] SEC-043 Capacity/load test with expected event volume. (`scripts/load_test.py`: in-process 3.9k ev/s @20k, 6.7k ev/s @50k; **live-uvicorn HTTP mode verified: 4,501 ev/s @20k (p95 90ms), GATE PASS**; `tests/test_capacity.py` fast-suite floor)
- [x] SEC-044 Local deployment/rollback runbook. (docs/08, docs/10)

## P2 — AI and advanced modules
- [x] SEC-050 Inventory actual OpenCode/OpenClaw/Hermes capabilities. (Capability contract wired: builtin + openai_compat (local LLM, key-by-env-name) + cli adapters in `services/agent_adapters.py`; prompt→plan through the gateway; allowlist/bypass tested in test_extensions.py. Live local-model E2E = Proposed)
- [x] SEC-051 Build scoped agent gateway and tool allowlist. (read-only auto-run, consequential = approval, out-of-allowlist denied)
- [x] SEC-052 Add approval queue and immutable audit events. (approvals endpoint + decide; hash-chained audit)
- [x] SEC-053 Agent evals: prompt injection, scope, timeout, truthful status. (`POST /api/agents/evals/run`; tests/test_agents.py)
- [x] SEC-054 Add cloud posture and GRC modules. (cloud + grc routers/pages)
- [x] SEC-055 Add isolated CTF/exercise orchestration. (authorized lifecycle, reason-on-complete, run log)
- [x] SEC-056 Add detection coverage and purple-team validation. (`GET /api/soc/rules/coverage` + `scenarios/pt-00{1,2,3}-*.yaml` replayed through live detection (`POST /api/soc/purple-team/run`); UI panel on /soc; rerun dedupe + audit verified)

## P2 — Production readiness
- [x] SEC-060 Provision separate staging. (`infra/staging/` compose + env: separate volume/network/secret, HTTP-only on staging LAN, same image as prod, synthetic-labeled; actual host provisioning = ops task)
- [x] SEC-061 Production secrets, TLS, ingress, access controls. (Boot guard; Caddy ACME TLS + security headers; `ForwardedHeadersMiddleware` → Secure cookie + real client IP behind the edge; env templates. Edge rate limiting was replaced by the in-app limiter in SEC-073 — the stock `caddy:2` image cannot load `rate_limit`, so it would have been a control that existed nowhere. Actual deployment = ops task on the target host)
- [x] SEC-062 SBOM, dependency/image scanning, release provenance. (CI `supply-chain` job: CycloneDX SBOM from pinned requirements + pip-audit + npm audit; gitleaks secret scan; image scan/signed releases = Proposed for the registry stage)
- [x] SEC-063 RTO/RPO, backup isolation, restore/rollback rehearsal. (`scripts/backup_rehearsal.py`: in-process drill PASS (342/342, RTO 0.01s) AND live drill PASS (real uvicorn stop/start: 423/423 events, chain intact, RTO 16.68s; lost files preserved in data.lost-*)
- [x] SEC-064 Production acceptance and human release approval. (Release gate built: `POST/GET /api/admin/releases` + `/latest` gate view (admin-only, audit-chained, append-only) + Admin UI + `docs/14` checklist. The human approval act itself is recorded at deploy time by an admin — the platform enforces the gate, it does not simulate the human)

## P3 — Optimization
- [x] SEC-070 Capacity-based service extraction if justified. (ADR-008 decision: do NOT extract — measured 3.9k/6.7k ev/s single-process vs. expected volume; quantified revisit triggers; extraction seams already in place (db.py, `_run_detections`, scheduler `tick()`, stateless report builder))
- [x] SEC-071 Advanced dashboards, saved searches, scheduled reports. (Coverage + purple-team + saved-search panels on /soc; report schedules CRUD + in-process scheduler daemon; retention report on /admin)
- [x] SEC-072 Cost/resource optimization and retention tuning. (Retention labels + `GET /api/admin/retention/report` report-only per ADR-005; resource limits in compose. Service-extraction cost model = SEC-070, Proposed)
- [x] SEC-074 Inert-rule blind spot: rule validation across the whole lifecycle. (Was: `except RuleError: continue` skipped a non-compiling rule silently while `/rules` showed it `active`; `rules/*.yaml` were seeded uncompiled. Now: `detection.rule_health`; loud throttled warning; `/rules` → `compiles`/`error` + `broken` summary; `/coverage` → `inert_rules`/`broken_rules` separate from gaps; seed refuses a broken shipped rule; `scripts/lint_rules.py` in CI with porting advice; SOC page `live`/`inert` markers + banner. docs/15 = subset + porting guide (grammar verified by probing). 16 new tests)
- [x] SEC-073 API surface hardening from a post-build audit. (4 findings fixed + tested: unknown `/api/*` → JSON 404 not SPA HTML; `/metrics` denied on the public edge + optional `METRICS_TOKEN`; login brute-force limiting moved into the app (`app/ratelimit.py`, 50/10s per IP, on in STAGING/PROD, audited) because the stock `caddy:2` image cannot load `rate_limit`; `infra/prod/.env.example.prod` added + `.gitignore` negation so env templates are committable. Route audit: 111 `/api` routes, 0 unauthenticated. Suite 115 → 129. See docs/13)
