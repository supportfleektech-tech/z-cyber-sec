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

## Truthful status
Report tests as Passed only with command, environment, timestamp, and observed result. Distinguish Not run, Blocked, Failed, and Passed.
