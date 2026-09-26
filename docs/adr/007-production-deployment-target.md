# ADR-007: Production deployment target

**Status:** Accepted
**Date:** 2026-09-21

## Context

The lab runs on the operator's own host, single process, SQLite, dev
defaults that are safe *because* the box is offline-bound. Production must
be a **separate** deployment — "promote the laptop" is explicitly not an
option (data classes, blast radius, and the threat model all depend on it).

## Decision

- **Target:** a separate, hardened host (VM or small server), not the lab
  machine. The lab stays a lab; production is provisioned from this repo
  as its own deployment (roadmap Phases 8–9: staging first, then
  production, each with a human release approval gate).
- **What changes at the swap, by boundary:**
  1. **Storage:** all data access goes through `app/db.py`
     (one module owns every query helper); the stated swap is to a
     PostgreSQL driver behind the same helper surface. The schema is
     portable SQL where the engine allows it; SQLite-specific spots are
     listed in docs/04.
  2. **Secrets:** `SECRET_KEY` and any credentials come from the host
     secret store, injected as environment — enforced by the existing boot
     guard (dev default refuses to start in `STAGING`/`PROD`, ADR-006).
  3. **Transport:** TLS terminated at the ingress; the app already flips
     the session cookie to `Secure` when served over HTTPS, and the SPA is
     served same-origin, so no CORS surface is introduced.
  4. **Telemetry scale:** if production event volume exceeds the
     in-process engine (SEC-043 load gate), the event store is the first
     component to externalize — the detection API and rule language stay
     unchanged (ADR-003/004).
  5. **Evidence:** `data/evidence` filesystem → object storage behind the
     same directory abstraction (`settings.evidence_dir`), ADR-005.
- **What does NOT change:** the RBAC model, audit chain, agent governance
  gates, and the human-approval rule for production changes, destructive
  operations, containment, and external testing carry over verbatim.
- **Backups/restore:** production RTO/RPO targets, backup isolation, and a
  rehearsed restore are release gates (SEC-063), documented in docs/09 and
  the runbook (docs/10).

## Consequences

- Staging and production share code with the lab (same repo, `ENV_NAME`
  label) — behavior differences come from config and the boundaries above,
  not from forks.
- The swap boundaries are code-visible (one module per concern), so "how
  hard is production" has a concrete answer: db.py, config.py, ingress,
  evidence store — and nothing else.
- Known risk: the SQLite→PostgreSQL swap is the largest single change in
  the plan; it is deliberately deferred until Phase 8 and protected by the
  existing 96-test suite plus a restore rehearsal.
