# ADR-003: SIEM & telemetry — in-process Sigma-subset engine, no external SIEM

**Status:** Accepted
**Date:** 2026-09-21

## Context

A real SIEM (Wazuh, Elastic, Graylog) is free software, but at lab scale it
means extra containers, extra networks, extra failure modes, and a second
system to keep running while the platform under test is the point. The
zero-budget rule allows *ideas* to be borrowed from existing projects —
not services to depend on.

## Decision

**No external SIEM.** Telemetry is:

- **Event store:** the platform's own `events` table (flat, indexed on
  `ts`/`action`/`host`). Ingest is a batched, **idempotent** API
  (`POST /api/soc/events`, `idempotency_key` → duplicate = skipped, not
  error) so agents and lab targets can replay safely.
- **Detection engine:** a deliberately small, auditable **Sigma-subset**
  interpreter in stdlib Python (`app/services/detection.py`). Rules are
  YAML/JSON files: `detection` terms with exact/list/numeric(`gt`,`lt`,
  `ge`,`le`)/`contains` values, a `condition` grammar (`all`, `any`, `not`,
  `and`, `or`, `N of`), optional `timeframe` + `threshold` with `entity`
  grouping. Design borrowed from Sigma's rule model, Wazuh's alerting, and
  elastic-detection; implemented natively (the "outsource = reuse ideas"
  rule).
- **Operations:** rule dry-run against stored events, backfill re-evaluation
  of existing events when rules change, and per-rule `dry_run`/disabled
  states so a bad rule can never fire unreviewed.
- **Data honesty:** every event carries `data_class` (default
  `synthetic`) — detections fire on synthetic lab data by default, and the
  UI labels the environment.

## Consequences

- One moving part: ingest → detect → alert → case is a single-process,
  in-transaction path; the whole pipeline is exercised by
  `tests/test_detection.py` with no external process.
- Rule language is a documented subset, not full Sigma — porting real Sigma
  packs requires the subset linter (backlog), which is intentional scope.
- Throughput limit is the SQLite event table; at lab volumes (tens of
  thousands of events) this is fine and is a named gate for the production
  swap (ADR-007).
