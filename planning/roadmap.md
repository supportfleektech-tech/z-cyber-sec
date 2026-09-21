# Roadmap & Phase Gates

| Phase | Deliverable | Exit gate |
|---|---|---|
| 0 Audit | Host, repo, source, services, capacity, risks | Inventory reviewed; no destructive changes |
| 1 Foundation | Repo, docs, ADRs, CI baseline | Required docs and workflow merged |
| 2 Isolation | Network zones, firewall plan, Compose profiles | Isolation tests pass |
| 3 Core platform | Auth, RBAC, API, DB, audit, dashboard shell | Core E2E and access tests pass |
| 4 Defensive telemetry | Selected SIEM/agent telemetry and synthetic events | Events ingest; detections validated |
| 5 Modules | Cases, intel, vuln, AppSec, cloud, GRC, reports | Module acceptance tests pass |
| 6 Agent gateway | OpenCode/OpenClaw/Hermes scoped adapters | Evaluations and approvals pass |
| 7 Hardening | Security review, restore, capacity, regression | No unresolved release-blocking issue |
| 8 Staging | Production-like deploy and acceptance | Release candidate approved |
| 9 Production | Separate hardened deployment | Go-live evidence and rollback verified |
| 10 Operations | Patching, monitoring, review, restore drills | Recurring ownership established |

Timing is intentionally not promised until Phase 0 confirms capacity, existing workload, and scope.
