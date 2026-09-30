# ADR-008: Capacity-based service extraction decision

**Status:** Accepted
**Date:** 2026-09-21

## Context

Backlog item SEC-070 asks: extract services out of the modular monolith
**if justified by capacity**. The measured facts (SEC-043, in-process,
single process, SQLite/WAL; see docs/13 for the full run):

| Load | Throughput | Batch latency p50/p95/p99 |
|---|---|---|
| 20,000 events | 3,903 ev/s | 64 / 97 / 134 ms |
| 50,000 events | 6,722 ev/s | 72 / 107 / 112 ms |

The fast suite pins a bounded regression floor (2,000 events / 8 batches in
<20s with detection firing), so capacity cannot silently rot.

The platform's expected event volume is **not** a continuous high-rate
stream. It is an operations platform driven by (a) operator/agent actions,
(b) scheduled report builds, and (c) batched ingest from authorized
sources, each bounded by API limits and per-rule dedupe. Even an aggressive
lab exercise (a concentrated brute-force storm) is the kind of burst the
50k load test models, and it completes in ~7.5s of in-process work.

## Candidates considered

1. **Extract the detection engine** to a worker/queue (e.g. a separate
   process consuming an event queue).
2. **Extract the report/scheduler** service.
3. **Extract the storage layer** to PostgreSQL behind `app/db.py`.
4. **Do not extract** — keep the modular monolith; revisit only on a
   measured trigger.

## Decision

**Do not extract.** The single process meets expected volume with large
headroom, and every extraction adds an operational surface (another
service, a queue or a second datastore, another failure mode, more
secrets, more deployment steps) that a zero-budget local-first platform
should not pay for until it is demonstrably needed.

The seams for a later extraction are **already in place and tested**, so a
future extraction is a refactor, not a rewrite:

- **Storage** — all data access goes through `app/db.py`; the PostgreSQL
  swap is a single-module change (ADR-007 boundary 1).
- **Detection** — `_run_detections` is a pure function of `(conn, events)`
  with an injectable `threshold_context`; it can move to a worker without
  touching the API (it is already called from both the ingest path and the
  backfill/purple-team paths).
- **Scheduler** — `services/scheduler.py` is an in-process daemon with a
  `tick()` seam and persisted `next_run_at`; a separate process would call
  the same `tick()`.
- **Report build** — `services/report_builder.py` is stateless given a
  snapshot.

## Revisit triggers (quantified)

Extract only when **measured**, not anticipated:

1. Sustained ingest > **~50% of the 50k-run throughput** (≈3,300 ev/s) for
   an extended period, **or** batch p99 > 250ms under expected load.
2. A single component (detection or report build) becomes the bottleneck
   for **another** component's latency (evidence: correlated latency
   spikes, not intuition).
3. The deployment requires more than one node, or the storage swap to
   PostgreSQL (ADR-007) is taken — at which point a separate detection
   worker becomes comparatively cheap.

Until one of these is measured and recorded in docs/13, the monolith stays.

## Consequences

- No new services, queues, or datastores; ops stay single-image.
- Extraction is deferred but cheap when triggered (seams above).
- Capacity regression stays covered by `tests/test_capacity.py` and the
  periodic `scripts/load_test.py` gate.
