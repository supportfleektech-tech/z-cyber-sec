# Roadmap & Phase Gates

Status legend: **Done** = exit gate met with evidence (docs/13) ·
**Code-complete** = all code/config/docs built + tested; the remaining step
is an ops act on a real host (not possible in the sandbox) · **Human** = a
genuinely human act (cannot be simulated).

| Phase | Deliverable | Exit gate | Status |
|---|---|---|---|
| 0 Audit | Host, repo, source, services, capacity, risks | Inventory reviewed; no destructive changes | Done (docs/01) |
| 1 Foundation | Repo, docs, ADRs, CI baseline | Required docs and workflow merged | Done (docs/00–14, ADR-001–008, CI 4 jobs) |
| 2 Isolation | Network zones, firewall plan, Compose profiles | Isolation tests pass | Code-complete (nftables matrix + validator built; host apply pending — no authorized target host in sandbox) |
| 3 Core platform | Auth, RBAC, API, DB, audit, dashboard shell | Core E2E and access tests pass | Done (115-test suite, RBAC tested) |
| 4 Defensive telemetry | Selected SIEM/agent telemetry and synthetic events | Events ingest; detections validated | Done (ingest contract, 3 purple-team scenarios validated) |
| 5 Modules | Cases, intel, vuln, AppSec, cloud, GRC, reports | Module acceptance tests pass | Done (module tests + scheduled reports + retention report) |
| 6 Agent gateway | Scoped adapters with approvals | Evaluations and approvals pass | Done (builtin/openai_compat/cli adapters, allowlist-bypass denied, evals, approval queue) |
| 7 Hardening | Security review, restore, capacity, regression | No unresolved release-blocking issue | Done (gitleaks, boot guard, restore drills PASS both modes, capacity measured in-process + live-HTTP, supply-chain CI, SEC-073 API-surface audit: 111 routes / 0 unauthenticated) |
| 8 Staging | Production-like deploy and acceptance | Release candidate approved | Code-complete (infra/staging stack built; deploy + acceptance on a real staging host pending) |
| 9 Production | Separate hardened deployment | Go-live evidence and rollback verified | Code-complete (infra/prod + Caddy TLS + release gate + committed `.env.example.prod`; go-live is the ops act, gated by Phase 8 + the SEC-064 gate) |
| 10 Operations | Patching, monitoring, review, restore drills | Recurring ownership established | Human (runbook docs/10 + drill tooling in place; recurring ownership is an org decision) |

Timing is intentionally not promised until Phase 0 confirms capacity,
existing workload, and scope.
