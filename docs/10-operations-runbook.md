# Operations Runbook

## Daily
- Check service health, disk headroom, failed jobs, ingestion gaps, and alert pipeline.
- Review admin and agent audit events.
- Confirm backup job status.

## Weekly
- Review access changes, agent permissions, open critical findings, image/dependency updates.
- Inspect resource trends and retention growth.
- Verify integration credentials remain valid without exposing them.

## Monthly
- Test a restore for at least one persistent service.
- Review threat model, risk register, RTO/RPO, and stale accounts.
- Patch through a staged, reversible release.

## Incident
1. Preserve relevant logs and evidence.
2. Isolate affected lab segment when needed.
3. Revoke exposed credentials.
4. Identify blast radius and persistence.
5. Recover from known-good state.
6. Verify service and detection health.
7. Document timeline, root cause, corrective actions.
