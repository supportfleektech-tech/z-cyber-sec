"""In-process report scheduler (SEC-071) — stdlib threading, no extra deps.

One daemon thread wakes every `tick_seconds`, finds active schedules whose
next_run_at has passed, generates the report (same builder as the API), and
advances next_run_at. Each generated run is audit-logged with actor
type='system'. A restart simply resumes from the persisted next_run_at —
at-most-once per interval, which is the right semantics for reports.
"""
from __future__ import annotations

import threading
from datetime import UTC

from .. import db
from ..audit import record_audit
from .report import ReportBuilder

_thread: threading.Thread | None = None
_stop = threading.Event()


def _run_due(conn, now: str) -> int:
    due = db.q(conn, "SELECT * FROM report_schedules WHERE status = 'active' "
                     "AND next_run_at IS NOT NULL AND next_run_at <= ? ORDER BY next_run_at", (now,))
    built = 0
    for s in due:
        try:
            builder = ReportBuilder(conn)
            builder.build(s["kind"], db.jload(s.get("filters"), {}) or {}, f"scheduler:{s['created_by']}")
            built += 1
        except Exception:  # one bad schedule must not starve the others
            continue
        nxt = s["interval_minutes"]
        conn.execute("UPDATE report_schedules SET last_run_at = ?, next_run_at = ? WHERE id = ?",
                     (now, _plus_minutes(now, nxt), s["id"]))
        conn.commit()
        record_audit(conn, {"type": "system", "id": None, "name": "scheduler"},
                     "report.scheduled_run", target_type="report_schedule",
                     target_id=str(s["id"]), detail={"kind": s["kind"], "title": s["title"]})
    return built


def _plus_minutes(ts: str, minutes: int) -> str:
    from datetime import datetime, timedelta
    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return (dt + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def tick() -> int:
    """One scheduler pass (also the unit-tested seam)."""
    conn = db.raw_connection()
    try:
        return _run_due(conn, db.utcnow())
    finally:
        conn.close()


def _loop(tick_seconds: int) -> None:
    while not _stop.is_set():
        try:
            tick()
        except Exception:
            pass
        _stop.wait(tick_seconds)


def start(tick_seconds: int = 30) -> None:
    """Idempotent: starts the daemon thread once per process."""
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(tick_seconds,), name="report-scheduler", daemon=True)
    _thread.start()


def stop() -> None:
    _stop.set()
