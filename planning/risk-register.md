# Risk Register

| ID | Risk | Impact | Mitigation | Status |
|---|---|---|---|---|
| R-01 | Existing laptop overloaded | Service instability | Audit capacity; small profile; offload heavy indexing | Open |
| R-02 | Port/volume collision with existing Docker stacks | Outage/data loss | Inventory; unique names; backups; no global prune | Open |
| R-03 | Vulnerable target reaches trusted network | Host/LAN compromise | Isolated network; deny-by-default; verify routes | Open |
| R-04 | Agent prompt injection or excessive permissions | Unauthorized actions/data exposure | Allowlist, scoped identities, approval, evals | Open |
| R-05 | Secrets leak through prompts/logs/Git | Account compromise | Secret scanning, redaction, rotation, secure storage | Open |
| R-06 | SIEM storage growth exhausts disk | Host failure | Retention, quotas, monitoring, capacity tests | Open |
| R-07 | Backup exists but cannot restore | Extended outage/data loss | Scheduled restore drills and evidence | Open |
| R-08 | Unverified integration API assumptions | Build delays/failures | Contract tests; verify docs and credentials | Open |
| R-09 | Local lab accidentally treated as production | Exposure/data loss | Separate environments and explicit banners | Open |
| R-10 | Source attachment details not reconciled | Scope mismatch | Phase 0 source review and change log | Open |
