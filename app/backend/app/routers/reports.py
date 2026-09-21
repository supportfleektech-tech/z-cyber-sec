"""Reports (SEC-037): generation, listing, export with provenance."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .. import db
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
