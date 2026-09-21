# Prioritized Implementation Backlog

Priority: P0 = prerequisite/blocker; P1 = core; P2 = expansion; P3 = later optimization.

Status as of 2026-09-21 (branch `arena/01a0c152-z-cyber-sec`): see docs/13 for verification evidence.

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
- [ ] SEC-040 Isolated networks and flow matrix. (Design complete — docs/03; host-side firewall/zone enforcement is a target-host task, not exercisable in the sandbox)
- [x] SEC-041 Health checks, logs, metrics, resource limits. (`/api/healthz`, `/metrics`, uvicorn logs; limits = single-process, documented)
- [x] SEC-042 Backup automation and demonstrated restore. (API-triggered backup w/ sha256; restore with typed confirm; round-trip tested — scheduled cron left to ops, P3)
- [x] SEC-043 Capacity/load test with expected event volume. (`scripts/load_test.py`: 3.9k ev/s @20k, 6.7k ev/s @50k in-process; `tests/test_capacity.py` fast-suite floor; live-uvicorn http mode pending)
- [x] SEC-044 Local deployment/rollback runbook. (docs/08, docs/10)

## P2 — AI and advanced modules
- [ ] SEC-050 Inventory actual OpenCode/OpenClaw/Hermes capabilities. (Gateway is built around the capability contract; real adapters pending)
- [x] SEC-051 Build scoped agent gateway and tool allowlist. (read-only auto-run, consequential = approval, out-of-allowlist denied)
- [x] SEC-052 Add approval queue and immutable audit events. (approvals endpoint + decide; hash-chained audit)
- [x] SEC-053 Agent evals: prompt injection, scope, timeout, truthful status. (`POST /api/agents/evals/run`; tests/test_agents.py)
- [x] SEC-054 Add cloud posture and GRC modules. (cloud + grc routers/pages)
- [x] SEC-055 Add isolated CTF/exercise orchestration. (authorized lifecycle, reason-on-complete, run log)
- [ ] SEC-056 Add detection coverage and purple-team validation. (Dry-run + backfill exist; coverage metrics + purple-team schedule pending)

## P2 — Production readiness
- [ ] SEC-060 Provision separate staging. (ADR-007 boundaries documented)
- [ ] SEC-061 Production secrets, TLS, ingress, access controls. (Boot guard + Secure-cookie flip ready; deployment pending)
- [ ] SEC-062 SBOM, dependency/image scanning, release provenance. (CI lint/test/build first; gitleaks + SBOM step in hardening pass)
- [ ] SEC-063 RTO/RPO, backup isolation, restore/rollback rehearsal. (API round-trip tested; timed rehearsal pending)
- [ ] SEC-064 Production acceptance and human release approval.

## P3 — Optimization
- [ ] SEC-070 Capacity-based service extraction if justified. (Extraction points named in ADR-001/007)
- [ ] SEC-071 Advanced dashboards, saved searches, scheduled reports.
- [ ] SEC-072 Cost/resource optimization and retention tuning. (Retention labels exist (ADR-005); automation pending)
