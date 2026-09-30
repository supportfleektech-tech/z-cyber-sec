# ADR-004: Event schema and integration contracts

**Status:** Accepted
**Date:** 2026-09-21

## Context

Multiple producers (seed, lab targets, agents, future log shippers) must
write events into one store, and external formats (STIX bundles, scanner
CSV) must import cleanly — without a schema migration every time a producer
changes.

## Decision

- **Core event schema** (flat, `app/migrations/0001_init.sql`):
  `ts` (ISO-8601 UTC), `source_type`, `source_name`, `host`, `user`,
  `action`, `outcome`, `severity`, `msg`, plus an **opaque `data` JSON
  column** for producer-specific fields. New producers add fields inside
  `data` — no migration required. `data_class` (default `synthetic`) marks
  provenance honesty at the row level.
- **Ingest contract:** `POST /api/soc/events` accepts a batch
  `{events: [...], idempotency_key?}`; duplicate `idempotency_key` returns
  skipped, not an error (replay-safe for agents and lab targets).
  Ingest runs the active detection rules in the same call, so detection
  latency is ingest-time, not polling-time.
- **STIX:** `POST /api/intel/stix` accepts a STIX **2.1 bundle subset**
  (indicator + observed-data objects) via a stdlib-only parser
  (`app/services/stix.py`); unsupported object types are reported, not
  silently dropped. Indicators land with source, confidence, and status
  lifecycle (`active`/`expired`/`revoked`) and can be correlated against
  stored events (`GET /api/intel/indicators/correlate`).
- **Scanner import:** vulnerability findings import as CSV with column
  mapping validation; rows fail loudly with per-row errors rather than
  partial silent import.
- **API error model:** non-2xx responses carry `detail = {code, message}`
  with stable machine-readable `code` strings (`bad_status`,
  `not_found`, ...); the SPA and any client code key off `code`, never off
  message text.
- **Audit contract:** every state-changing call appends an append-only
  audit row (actor, action, target, detail JSON, seq, hash-chained for
  verification — `GET /api/admin/audit/verify`). Audit rows are the
  platform's integration contract for "what did who do".

## Consequences

- Producers evolve inside `data` JSON without touching the engine; the
  engine only depends on the named flat columns it indexes.
- External formats have bounded, documented surface (STIX subset, CSV
  mapping) — full-format support is a backlog item, not a silent TODO.
- The hash-chained audit table is append-only by construction (no
  update/delete API), which is what makes `audit/verify` meaningful.
