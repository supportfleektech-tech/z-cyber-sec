# Local Deployment Runbook

## Before deployment
- Complete host audit and capacity check.
- Identify conflicts with existing ports, networks, volumes, and containers.
- Back up existing project data before changes.
- Select a small service profile.
- Review Compose file and pin image versions.
- Configure `.env` from `.env.example`; never commit secrets.
- Confirm services bind only to intended interfaces.

## Deployment sequence
1. Create a dedicated project directory and Git branch.
2. Validate Compose syntax: `docker compose config`.
3. Review resolved configuration for secret leakage and unexpected published ports.
4. Start only foundational services.
5. Verify health checks and logs.
6. Run migrations and smoke tests.
7. Add telemetry integrations incrementally.
8. Record actual versions, ports, volumes, and test results.

## Rollback
Stop only the CYBER-SEC Compose project. Preserve volumes unless a separately approved recovery procedure says otherwise. Restore from verified backup if needed. Never run global Docker prune as routine rollback.
