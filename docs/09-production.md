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
- Login rate limiting: **enforced in the app**, 50 attempts / 10 s per IP by
  default in STAGING/PROD (`app/ratelimit.py`, SEC-073) → `429
  {detail:{code:"rate_limited"}}` + `Retry-After`, with one `auth.rate_limited`
  audit event per window. It is *not* a Caddy directive: `rate_limit` is not
  part of the standard Caddy build, and the pinned `caddy:2` image rejects a
  Caddyfile containing it — so the control lives where it is testable and
  always loadable. An optional second edge layer is documented in
  `infra/README.md` (custom `xcaddy` image).
- The `Caddyfile` uses **stock directives only** and must be validated on the
  target host before go-live: `docker compose --profile prod run --rm caddy
  caddy validate --config /etc/caddy/Caddyfile` (this sandbox has no Docker
  daemon and blocks the caddy release asset, so it is unvalidated here —
  docs/13).
- `/metrics` is **refused on the public edge** (`Caddyfile` → `403`). Scrape
  the internal bind instead (`curl -s http://127.0.0.1:8080/metrics`); set
  `METRICS_TOKEN` to require `Authorization: Bearer <token>` if anything
  beyond the host can reach that port.
- Unknown `/api/*` paths return JSON `404` (`not_found`), not the SPA shell —
  API clients never parse HTML as a successful response (SEC-073).
- Environment templates are committed and committable: `infra/prod/.env.example.prod`
  (`.gitignore` negates `.env.example.*`; real `.env` files stay ignored).
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
