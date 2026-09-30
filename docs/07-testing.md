# Testing & Verification Strategy

## Test layers
1. Static: formatting, lint, type checks, secret scanning.
2. Unit: domain logic, validation, authorization helpers.
3. Integration: database, queue, adapter contracts, migrations.
4. E2E: login, role restrictions, create alert/case, attach evidence, report export.
5. Security: access-control matrix, injection defenses, dependency/container/IaC scans.
6. Infrastructure: service health, network isolation, backup restore, rollback.
7. Agent evaluation: allowlist, approval, untrusted-input, no-claim-without-evidence tests.

## Required quality gates
- No known critical exploitable finding without documented decision and mitigation.
- Tests run in CI and results retained.
- Migrations tested against disposable data.
- Restore drill demonstrated for persistent services.
- Production deployment approval is human-controlled.

## Assembled-app checks (beyond pytest)

`pytest` exercises the FastAPI app in-process against a temp database. Two scripts cover
what that cannot: the app as it actually runs, over HTTP, against the seeded demo dataset.

| Script | Answers | Evidence |
|---|---|---|
| `python -m scripts.smoke_check` | Is the live surface up and locked down? | 214 checks: every read route 2xx for an admin, every route 401 unauthenticated, fourteen consequential writes 403 for a viewer, no write 5xx/401 for a viewer; surface 102 paths / 136 operations |
| `python -m scripts.acceptance_check` | Does this build satisfy the release clauses? | One line per clause of `planning/acceptance-criteria.md`: `pass` with the values behind it, `host-ops` with the exact command to run on the target host, or `fail` (exit 1). Currently 10 demonstrated · 2 host-ops · 0 failed |
| `GET /api/admin/doctor` | Is this install healthy right now? | Eleven checks aggregated into one `ok`/`warn`/`fail` verdict with fix hints (SEC-116) |

Both scripts run in CI's `live` job against a freshly seeded instance, and both appear as
gates in `docs/14-release-checklist.md`. They write only what a release check must: the
smoke check performs logins and refused writes; the acceptance check records integration
probe results and takes one backup.

## Truthful status
Report tests as Passed only with command, environment, timestamp, and observed result. Distinguish Not run, Blocked, Failed, and Passed.
