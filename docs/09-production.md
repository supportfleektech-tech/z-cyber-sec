# Production Deployment & Operations

## Production is separate
Do not expose the laptop lab as production. Provision a separate hardened host or cloud environment after local acceptance and capacity review.

## Readiness requirements
- Approved domain/DNS and TLS
- Restricted ingress and administrative access
- MFA and tested RBAC
- Secrets manager or approved encrypted secret delivery
- Reviewed database migration and backup strategy
- Monitoring, alerting, log retention, and incident ownership
- Vulnerability review and SBOM
- Privacy, legal, data retention, and jurisdiction review
- CI/CD with immutable versioned artifacts and approval gates
- Rollback rehearsal and documented RTO/RPO
- Operational handover and support ownership

## Release flow
Commit -> CI quality/security gates -> reviewed artifact -> staging -> acceptance tests -> human approval -> production rollout -> health checks -> release record. Roll back on failed health criteria.
