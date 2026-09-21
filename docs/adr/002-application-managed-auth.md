# ADR-002: Application-managed auth (no external IdP) with RBAC

**Status:** Accepted
**Date:** 2026-09-21

## Context

The lab is local-first and often offline; an external identity provider
(Okta/Keycloak/etc.) would add a dependency, a network exposure, and a
failure mode the lab does not need at this phase. Production (ADR-007) may
swap the identity source later; the decision now is what the platform itself
manages.

## Decision

**Application-managed accounts and sessions** (`app/security.py`,
`app/routers/auth.py`), deliberately boring, stdlib-only:

- **Passwords:** PBKDF2-HMAC-SHA256, 390,000 iterations (OWASP 2023
  minimum), 16-byte random salt, `pbkdf2_sha256$iter$salt$hash` format,
  constant-time compare.
- **Sessions:** opaque 32-byte random tokens; **only SHA-256(token) stored**
  server-side with user, IP, user-agent, created/expires; single-session
  revocation on logout.
- **Cookie:** `HttpOnly`, `SameSite=Strict`, `Secure` when served over
  HTTPS, `max_age` = configured token TTL.
- **Login errors are generic** (`invalid_credentials`) — no user-existence
  oracle; every login attempt (success or failure) is an audit event.
- **RBAC:** fixed roles (`admin`, `ir_lead`, `soc_analyst`, `viewer`,
  `agent_service`) mapped to a named permission set; every endpoint declares
  `require("<permission>")` — there is no anonymous API surface except
  `/api/healthz` and login. Least privilege: viewers cannot download
  reports or evidence; `agent_service` gets scoped read/execute grants only.

## Consequences

- Zero external dependencies; identity data lives in the same audited store
  as everything else, and is covered by the same backup/restore.
- Password storage and session logic are ~100 lines of stdlib Python that
  the test suite pins (timing oracle, session revocation, permission
  matrices in `tests/test_auth.py`, `tests/test_rbac.py`).
- Known limitation: no MFA/SSO in the lab phase; if production needs SSO,
  the swap point is `get_current_user` (dependency injection boundary), so
  an OIDC adapter can replace the local table without touching routers.
