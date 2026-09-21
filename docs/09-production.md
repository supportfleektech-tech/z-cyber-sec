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

## Staging (SEC-060)

Provisioned as a **separate** stack in `infra/staging/`: its own compose
project, its own named volume, its own network, HTTP-only on the staging
LAN (no public DNS), running the **same image** as production. Secrets are
environment-specific (the staging `SECRET_KEY` must differ from prod's).
Checklist acceptance (docs/14, "Safety gates" rollout section) runs here
against the exact candidate build before approval.

## Access controls behind the TLS edge (SEC-061)

- TLS terminates at Caddy (ACME automatic, HSTS, `nosniff`, `no-referrer`);
  the app is bound to an internal address only.
- The app trusts exactly one proxy hop (`app/middleware.py`,
  `ForwardedHeadersMiddleware`): `X-Forwarded-Proto` flips the session
  cookie to `Secure=`, and the last `X-Forwarded-For` entry (or
  `X-Real-IP`) is recorded as the client IP for login attribution and
  per-IP session logging.
- Login rate limiting at the edge: 50 req / 10 s per IP on
  `/api/auth/login` (Caddyfile).
- RBAC is enforced server-side on every endpoint (`require("<perm>")`);
  the Admin page's Release tab records the human release decision
  (admin-only, `release.write`).

## Release record (SEC-064)

The final step of the release flow is machine-checked: an admin records
the decision via `POST /api/admin/releases`, bound to the exact commit and
the sha256 of the signed checklist (docs/14). `GET /api/admin/releases/latest`
answers `approved | blocked | no_decision` — operators and rollout tooling
must see `approved` for the version being promoted. The record is
append-only and lives in the hash-chained audit log.
