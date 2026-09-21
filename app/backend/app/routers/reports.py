"""Reports (SEC-037): generation, listing, export with provenance."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..config import settings
from ..deps import require
from ..services.report import ReportBuilder

router = APIRouter(prefix="/api/reports", tags=["reports"])

KINDS = ["overview", "soc", "cases", "intel", "vulns"]


class ReportIn(BaseModel):
    kind: str
    title: str | None = None
    filters: dict | None = None


@router.post("", status_code=201)
def generate(body: ReportIn, conn: sqlite3.Connection = Depends(db.get_conn),
             user: dict = Depends(require("reports.generate"))):
    if body.kind not in KINDS:
        raise HTTPException(400, {"code": "bad_kind", "message": f"kind must be one of {KINDS}"})
    builder = ReportBuilder(conn)
    return builder.build(body.kind, body.filters or {}, user["username"])


@router.get("")
def list_reports(conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("reports.read")),
                 kind: str | None = None,
                 page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    where, params = ["1=1"], []
    if kind:
        where.append("kind = ?")
        params.append(kind)
    sql = "SELECT * FROM reports WHERE " + " AND ".join(where)
    out = db.paged(conn, sql, tuple(params), "ORDER BY id DESC", page, page_size)
    for it in out["items"]:
        it["meta"] = db.jload(it.get("meta"), {})
        it["filters"] = db.jload(it.get("filters"), {})
        it["path_exists"] = Path(it["path"]).exists()
    return out


@router.get("/{report_id}/download")
def download(report_id: int, conn: sqlite3.Connection = Depends(db.get_conn),
             user: dict = Depends(require("reports.generate"))):
    r = db.one(conn, "SELECT * FROM reports WHERE id = ?", (report_id,))
    if not r:
        raise HTTPException(404, {"code": "not_found"})
    path = Path(r["path"])
    if not path.exists() or not str(path).startswith(str(settings.reports_dir)):
        raise HTTPException(410, {"code": "missing"})
    from ..audit import record_audit
    record_audit(conn, {"type": "user", "id": str(user["user_id"]), "name": user["username"]},
                 "report.downloaded", target_type="report", target_id=str(report_id))
    return FileResponse(path, filename=path.name, media_type="text/html")


# ------------------------------------------------------- scheduled reports
# SEC-071: in-process scheduler (services/scheduler.py) generates due reports.

from ..services.scheduler import tick as _scheduler_tick  # noqa: E402

SCHEDULE_STATUSES = {"active", "paused"}


class ScheduleIn(BaseModel):
    kind: str
    title: str | None = None
    filters: dict | None = None
    interval_minutes: int = Field(default=1440, ge=5, le=525600)


class ScheduleUpdate(BaseModel):
    status: str | None = None
    interval_minutes: int | None = Field(default=None, ge=5, le=525600)


@router.get("/schedules")
def list_schedules(conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("reports.read"))):
    rows = db.q(conn, "SELECT * FROM report_schedules ORDER BY id DESC")
    for r in rows:
        r["filters"] = db.jload(r.get("filters"), {}) or {}
    return {"items": rows, "total": len(rows)}


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleIn, conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("reports.generate"))):
    if body.kind not in KINDS:
        raise HTTPException(400, {"code": "bad_kind", "message": f"kind must be one of {KINDS}"})
    from ..services.scheduler import _plus_minutes
    now = db.utcnow()
    title = body.title or f"Scheduled {body.kind} report"
    cur = conn.execute(
        "INSERT INTO report_schedules (kind, title, filters, interval_minutes, last_run_at, next_run_at, status, created_by, created_at) "
        "VALUES (?, ?, ?, ?, NULL, ?, 'active', ?, ?)",
        (body.kind, title, db.jdump(body.filters), body.interval_minutes,
         _plus_minutes(now, body.interval_minutes), user["username"], now))
    conn.commit()
    record_audit(conn, {"type": "user", "id": str(user["user_id"]), "name": user["username"]},
                 "report_schedule.created", target_type="report_schedule",
                 target_id=str(cur.lastrowid), detail={"kind": body.kind, "interval_minutes": body.interval_minutes})
    return db.one(conn, "SELECT * FROM report_schedules WHERE id = ?", (cur.lastrowid,))


@router.patch("/schedules/{sched_id}")
def update_schedule(sched_id: int, body: ScheduleUpdate,
                    conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("reports.generate"))):
    s = db.one(conn, "SELECT * FROM report_schedules WHERE id = ?", (sched_id,))
    if not s:
        raise HTTPException(404, {"code": "not_found"})
    fields, params = [], []
    if body.status is not None:
        if body.status not in SCHEDULE_STATUSES:
            raise HTTPException(400, {"code": "bad_status"})
        fields.append("status = ?")
        params.append(body.status)
    if body.interval_minutes is not None:
        from ..services.scheduler import _plus_minutes
        fields.append("interval_minutes = ?")
        params.append(body.interval_minutes)
        if s["status"] == "active":
            fields.append("next_run_at = ?")
            params.append(_plus_minutes(db.utcnow(), body.interval_minutes))
    if not fields:
        raise HTTPException(400, {"code": "no_changes"})
    params.append(sched_id)
    conn.execute(f"UPDATE report_schedules SET {', '.join(fields)} WHERE id = ?", tuple(params))
    conn.commit()
    record_audit(conn, {"type": "user", "id": str(user["user_id"]), "name": user["username"]},
                 "report_schedule.updated", target_type="report_schedule",
                 target_id=str(sched_id), detail={"fields": fields})
    return db.one(conn, "SELECT * FROM report_schedules WHERE id = ?", (sched_id,))


@router.delete("/schedules/{sched_id}")
def delete_schedule(sched_id: int, conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("reports.generate"))):
    s = db.one(conn, "SELECT * FROM report_schedules WHERE id = ?", (sched_id,))
    if not s:
        raise HTTPException(404, {"code": "not_found"})
    conn.execute("DELETE FROM report_schedules WHERE id = ?", (sched_id,))
    conn.commit()
    record_audit(conn, {"type": "user", "id": str(user["user_id"]), "name": user["username"]},
                 "report_schedule.deleted", target_type="report_schedule", target_id=str(sched_id))
    return {"ok": True}


@router.post("/schedules/run-due")
def run_due_now(conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("reports.generate"))):
    """Manual trigger (also the test seam): run all due schedules now."""
    built = _scheduler_tick()
    record_audit(conn, {"type": "user", "id": str(user["user_id"]), "name": user["username"]},
                 "report_schedule.run_due", target_type="report_schedule", detail={"built": built})
    return {"built": built}
