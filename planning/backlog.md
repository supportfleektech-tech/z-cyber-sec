# Prioritized Implementation Backlog

Priority: P0 = prerequisite/blocker; P1 = core; P2 = expansion; P3 = later optimization.

## P0 — Discover and protect
- [ ] SEC-001 Inventory host, OS, resources, storage, ports, Docker networks/volumes.
- [ ] SEC-002 Inventory existing repo and reconcile uploaded source.
- [ ] SEC-003 Map current services and identify port/volume conflicts.
- [ ] SEC-004 Establish backup and rollback before changes.
- [ ] SEC-005 Threat model and define authorized test scope.
- [ ] SEC-006 Choose local resource profile and integration priorities.

## P0 — Engineering foundation
- [ ] SEC-010 Create repo structure and contributor/agent rules.
- [ ] SEC-011 Add CI formatting, lint, tests, secret scanning.
- [ ] SEC-012 Create ADRs for framework, auth, SIEM, data, secrets.
- [ ] SEC-013 Define API conventions, schemas, error model, audit format.

## P1 — Core application
- [ ] SEC-020 Implement auth/session lifecycle and RBAC.
- [ ] SEC-021 Implement server-side object authorization tests.
- [ ] SEC-022 Implement audit event pipeline.
- [ ] SEC-023 Build responsive dashboard shell and environment labels.
- [ ] SEC-024 Implement asset/integration inventory.
- [ ] SEC-025 Implement synthetic demo data with explicit labeling.

## P1 — Defensive workflows
- [ ] SEC-030 Select and deploy one telemetry/SIEM profile.
- [ ] SEC-031 Ingest benign synthetic events and validate detections.
- [ ] SEC-032 Alert triage and case lifecycle.
- [ ] SEC-033 Evidence metadata, access control, provenance, export.
- [ ] SEC-034 Threat indicator ingestion with source/confidence.
- [ ] SEC-035 Vulnerability finding import, triage, remediation tracking.
- [ ] SEC-036 AppSec pipeline and findings integration.
- [ ] SEC-037 Reporting and audit export.

## P1 — Infrastructure and reliability
- [ ] SEC-040 Isolated networks and flow matrix.
- [ ] SEC-041 Health checks, logs, metrics, resource limits.
- [ ] SEC-042 Backup automation and demonstrated restore.
- [ ] SEC-043 Capacity/load test with expected event volume.
- [ ] SEC-044 Local deployment/rollback runbook.

## P2 — AI and advanced modules
- [ ] SEC-050 Inventory actual OpenCode/OpenClaw/Hermes capabilities.
- [ ] SEC-051 Build scoped agent gateway and tool allowlist.
- [ ] SEC-052 Add approval queue and immutable audit events.
- [ ] SEC-053 Agent evals: prompt injection, scope, timeout, truthful status.
- [ ] SEC-054 Add cloud posture and GRC modules.
- [ ] SEC-055 Add isolated CTF/exercise orchestration.
- [ ] SEC-056 Add detection coverage and purple-team validation.

## P2 — Production readiness
- [ ] SEC-060 Provision separate staging.
- [ ] SEC-061 Production secrets, TLS, ingress, access controls.
- [ ] SEC-062 SBOM, dependency/image scanning, release provenance.
- [ ] SEC-063 RTO/RPO, backup isolation, restore/rollback rehearsal.
- [ ] SEC-064 Production acceptance and human release approval.

## P3 — Optimization
- [ ] SEC-070 Capacity-based service extraction if justified.
- [ ] SEC-071 Advanced dashboards, saved searches, scheduled reports.
- [ ] SEC-072 Cost/resource optimization and retention tuning.
