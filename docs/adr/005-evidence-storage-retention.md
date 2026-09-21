# ADR-005: Evidence storage and retention

**Status:** Accepted
**Date:** 2026-09-21

## Context

Incident response needs files (pcaps, logs, artifacts) attached to cases
with integrity and access control — but the lab is local-first, and
evidence content is the one class of data that must never leak into
general list/export surfaces.

## Decision

- **Two-layer split:** content lives on the filesystem under
  `data/evidence/` (gitignored, outside the API response surface);
  **metadata** lives in the `evidence` table (`name`, `sha256`, `size`,
  `classification`, `retention`, `uploaded_by`, `created_at`).
- **Integrity:** SHA-256 is computed at upload and is part of the metadata
  record — it is the basis for provenance in case exports and for verifying
  the file has not changed.
- **Access control:** upload requires `evidence.upload`; **download
  requires `evidence.download`** (a separate, narrower permission — an
  analyst can attach, not exfiltrate). The case list endpoint returns
  evidence **metadata only**; content is served exclusively by the
  download endpoint, and **every access is audit-logged**.
- **Retention:** each file carries an explicit `retention` label
  (e.g. `retain-case-close`, `30d`, `legal-hold`); retention is metadata
  the runbook (docs/10) acts on, not an automatic purger — deletion is a
  human, audited operation. `legal-hold` files are flagged and the
  backup/restore runbook treats them as pinned.
- **Classification:** `classification` (e.g. `synthetic`, `internal`) is
  set at upload; the default lab data is `synthetic` end-to-end, so the
  honest answer to "is this real" is always in the metadata.

## Consequences

- Case JSON exports remain shareable (metadata + sha256) without moving
  content; content movement is always a controlled, audited download.
- Filesystem storage is a named production-swap boundary (object store) in
  ADR-007; only `evidence_dir` handling changes, the API does not.
- No automatic deletion = nothing gets destroyed by a bug, at the cost of
  manual retention hygiene, which the runbook assigns as a recurring task.
