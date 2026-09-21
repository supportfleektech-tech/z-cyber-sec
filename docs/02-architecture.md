# Target Architecture

## Design goals
Modular, local-first, reproducible, observable, least-privilege, replaceable integrations, and a clear path to separate production infrastructure.

## Logical layers
1. **User experience:** SOC console, engineering console, admin.
2. **Application:** frontend, API, background worker, integration adapters.
3. **Security workflows:** alert triage, cases/evidence, threat intel, vulnerabilities, AppSec, cloud, GRC, exercises, reports.
4. **Data:** relational records, event/index store, object/evidence store, audit events, metrics/logs.
5. **Infrastructure:** Linux host, containers, isolated networks, backup target.
6. **Agent gateway:** policy checks, scoped adapters, approvals, audit, evaluation.

## Suggested initial stack (subject to compatibility and resource validation)
- Frontend: TypeScript + React-based framework
- API: TypeScript service or Python FastAPI; choose one after a short ADR
- Database: PostgreSQL
- Background jobs: lightweight queue only when required
- Local orchestration: Docker Compose
- Metrics: Prometheus + Grafana when resource budget permits
- Detection: begin with one selected SIEM/telemetry stack; avoid deploying overlapping heavy stacks
- IaC/configuration: Ansible; OpenTofu for cloud later
- CI: GitHub Actions or a self-hosted runner with restricted permissions
- Secrets: `.env` only for local development and excluded from Git; encrypted secrets/config for shared environments

## Key boundaries
- Web/API must not directly execute arbitrary shell commands.
- Agent tools go through allowlisted adapters.
- Lab target network is separate from management and application networks.
- Evidence storage has restricted access and audit logging.
- Production is separate from the laptop lab.

## Architecture decisions required
- ADR-001 frontend/backend framework
- ADR-002 identity provider vs application-managed auth
- ADR-003 SIEM and telemetry choice
- ADR-004 event schema and integration contracts
- ADR-005 evidence storage and retention
- ADR-006 local secrets strategy
- ADR-007 deployment target for production
