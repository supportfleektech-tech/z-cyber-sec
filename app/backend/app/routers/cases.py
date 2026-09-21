"""Incident Response: case lifecycle, tasks, timeline, evidence (SEC-032/033).

Evidence: files on disk (0600, never publicly mounted); metadata in DB with
sha256, classification, retention; every access audited.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..config import settings
from ..deps import require

router = APIRouter(prefix="/api/cases", tags=["cases"])

CASE_STATUSES = {"open", "investigating", "contained", "mitigated", "closed"}
TASK_STATUSES = {"open", "in_progress", "done", "canceled"}
CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}
MAX_EVIDENCE_BYTES = 25 * 1024 * 1024


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


def _next_number(conn) -> str:
    year = db.utcnow()[:4]
    r = db.one(conn, "SELECT COUNT(*) c FROM cases WHERE number LIKE ?", (f"CASE-{year}-%",))
    n = (int(r["c"]) + 1 if r else 1)
    return f"CASE-{year}-{n:04d}"


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    priority: str | None = None
    severity: str | None = None
    assigned_to: str | None = Field(default=None, max_length=100)
    source: str | None = None
    alert_id: int | None = None


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    status: str | None = None
    priority: str | None = None
    severity: str | None = None
    assigned_to: str | None = Field(default=None, max_length=100)
    notes: str | None = Field(default=None, max_length=2000)


@router.post("", status_code=201)
def create_case(body: CaseIn, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("cases.write"))):
    if body.priority and body.priority not in {"low", "medium", "high", "critical"}:
        raise HTTPException(400, {"code": "bad_priority"})
    now = db.utcnow()
    number = _next_number(conn)
    source = body.source
    alert_row = None
    if body.alert_id:
        alert_row = db.one(conn, "SELECT * FROM alerts WHERE id = ?", (body.alert_id,))
        if not alert_row:
            raise HTTPException(404, {"code": "alert_not_found"})
        source = "alert"
    cur = conn.execute(
        "INSERT INTO cases (number, title, description, status, priority, severity, assigned_to, source, "
        "created_at, updated_at) VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)",
        (number, body.title, body.description, body.priority, body.severity, body.assigned_to,
         source, now, now),
    )
    case_id = int(cur.lastrowid)
    conn.execute("INSERT INTO case_timeline (case_id, ts, actor, entry_type, message) VALUES (?, ?, ?, 'status', ?)",
                 (case_id, now, user["username"], f"Case opened: {body.title}"))
    if alert_row:
        conn.execute("UPDATE alerts SET case_id = ?, status = 'confirmed', updated_at = ? WHERE id = ?",
                     (case_id, now, alert_row["id"]))
        conn.execute("INSERT INTO case_timeline (case_id, ts, actor, entry_type, message, meta) "
                     "VALUES (?, ?, ?, 'alert', ?, ?)",
                     (case_id, now, "system", f"Linked alert #{alert_row['id']}: {alert_row['title']}",
                      db.jdump({"alert_id": alert_row["id"]})))
    conn.commit()
    record_audit(conn, _actor(user), "case.created", target_type="case", target_id=str(case_id),
                 detail={"number": number, "alert_id": body.alert_id})
    return db.one(conn, "SELECT * FROM cases WHERE id = ?", (case_id,))


@router.get("")
def list_cases(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("cases.read")),
               status: str | None = None, severity: str | None = None,
               assigned_to: str | None = None, q: str | None = None,
               page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    where, params = [], []
    if status:
        where.append("status = ?")
        params.append(status)
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if assigned_to:
        where.append("assigned_to = ?")
        params.append(assigned_to)
    if q:
        where.append("(title LIKE ? OR number LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    sql = "SELECT * FROM cases"
    if where:
        sql += " WHERE " + " AND ".join(where)
    return db.paged(conn, sql, tuple(params), "ORDER BY updated_at DESC, id DESC", page, page_size)


@router.get("/{case_id}")
def get_case(case_id: int, conn: sqlite3.Connection = Depends(db.get_conn),
             user: dict = Depends(require("cases.read"))):
    c = db.one(conn, "SELECT * FROM cases WHERE id = ?", (case_id,))
    if not c:
        raise HTTPException(404, {"code": "not_found"})
    c["tasks"] = db.q(conn, "SELECT * FROM case_tasks WHERE case_id = ? ORDER BY id", (case_id,))
    c["timeline"] = db.q(conn, "SELECT * FROM case_timeline WHERE case_id = ? ORDER BY ts DESC LIMIT 200",
                         (case_id,))
    # Evidence: metadata only — content requires evidence.download (checked at /evidence/{id}/download)
    c["evidence"] = db.q(conn, "SELECT id, name, sha256, size, classification, retention, uploaded_by, created_at "
                               "FROM evidence WHERE case_id = ? ORDER BY id", (case_id,))
    return c


@router.patch("/{case_id}")
def update_case(case_id: int, body: CaseUpdate, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("cases.write"))):
    c = db.one(conn, "SELECT * FROM cases WHERE id = ?", (case_id,))
    if not c:
        raise HTTPException(404, {"code": "not_found"})
    if body.status and body.status not in CASE_STATUSES:
        raise HTTPException(400, {"code": "bad_status"})
    fields, params = [], []
    for f in ("title", "description", "status", "priority", "severity", "assigned_to"):
        v = getattr(body, f)
        if v is not None:
            fields.append(f"{f} = ?")
            params.append(v)
    if not fields and body.notes is None:
        raise HTTPException(400, {"code": "no_changes"})
    fields.append("updated_at = ?")
    params.append(db.utcnow())
    params.append(case_id)
    conn.execute(f"UPDATE cases SET {', '.join(fields)} WHERE id = ?", params)
    if body.status == "closed":
        conn.execute("UPDATE cases SET closed_at = ? WHERE id = ?", (db.utcnow(), case_id))
    now = db.utcnow()
    if body.status:
        conn.execute("INSERT INTO case_timeline (case_id, ts, actor, entry_type, message) "
                     "VALUES (?, ?, ?, 'status', ?)", (case_id, now, user["username"], f"Status → {body.status}"))
    if body.notes:
        conn.execute("INSERT INTO case_timeline (case_id, ts, actor, entry_type, message) "
                     "VALUES (?, ?, ?, 'note', ?)", (case_id, now, user["username"], body.notes))
    conn.commit()
    record_audit(conn, _actor(user), "case.updated", target_type="case", target_id=str(case_id),
                 detail={k: v for k, v in body.model_dump().items() if v is not None})
    return db.one(conn, "SELECT * FROM cases WHERE id = ?", (case_id,))


# ------------------------------------------------------------------- tasks

class TaskIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    assigned_to: str | None = Field(default=None, max_length=100)
    due: str | None = Field(default=None, max_length=40)


@router.post("/{case_id}/tasks", status_code=201)
def add_task(case_id: int, body: TaskIn, conn: sqlite3.Connection = Depends(db.get_conn),
             user: dict = Depends(require("cases.write"))):
    if not db.one(conn, "SELECT id FROM cases WHERE id = ?", (case_id,)):
        raise HTTPException(404, {"code": "not_found"})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO case_tasks (case_id, title, status, assigned_to, due, created_at, updated_at) "
        "VALUES (?, ?, 'open', ?, ?, ?, ?)",
        (case_id, body.title, body.assigned_to, body.due, now, now),
    )
    conn.execute("INSERT INTO case_timeline (case_id, ts, actor, entry_type, message) VALUES (?, ?, ?, 'task', ?)",
                 (case_id, now, user["username"], f"Task added: {body.title}"))
    conn.commit()
    return db.one(conn, "SELECT * FROM case_tasks WHERE id = ?", (cur.lastrowid,))


@router.patch("/tasks/{task_id}")
def update_task(task_id: int, body: dict, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("cases.write"))):
    t = db.one(conn, "SELECT * FROM case_tasks WHERE id = ?", (task_id,))
    if not t:
        raise HTTPException(404, {"code": "not_found"})
    allowed = {"status", "assigned_to", "due"}
    fields, params = [], []
    for k, v in (body or {}).items():
        if k in allowed and v is not None:
            if k == "status" and v not in TASK_STATUSES:
                raise HTTPException(400, {"code": "bad_status"})
            fields.append(f"{k} = ?")
            params.append(v)
    if not fields:
        raise HTTPException(400, {"code": "no_changes"})
    fields.append("updated_at = ?")
    params.append(db.utcnow())
    params.append(task_id)
    conn.execute(f"UPDATE case_tasks SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()
    record_audit(conn, _actor(user), "case_task.updated", target_type="case_task", target_id=str(task_id),
                 detail={k: v for k, v in (body or {}).items() if k in allowed})
    return db.one(conn, "SELECT * FROM case_tasks WHERE id = ?", (task_id,))


# ------------------------------------------------------------------ evidence

@router.post("/{case_id}/evidence", status_code=201)
def upload_evidence(case_id: int, file: UploadFile,
                    classification: str = Form("internal"),
                    retention: str | None = Form(None),
                    conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("evidence.upload"))):
    if not db.one(conn, "SELECT id FROM cases WHERE id = ?", (case_id,)):
        raise HTTPException(404, {"code": "not_found"})
    if classification not in CLASSIFICATIONS:
        raise HTTPException(400, {"code": "bad_classification"})
    content = file.file.read()
    if len(content) > MAX_EVIDENCE_BYTES:
        raise HTTPException(413, {"code": "too_large", "message": f"max {MAX_EVIDENCE_BYTES} bytes"})
    sha = hashlib.sha256(content).hexdigest()
    safe_name = "".join(c for c in (file.filename or "upload") if c.isalnum() or c in ".-_")[:160] or "upload"
    fname = f"{secrets.token_hex(6)}-{safe_name}"
    path = settings.evidence_dir / fname
    path.write_bytes(content)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO evidence (case_id, name, path, sha256, size, classification, retention, uploaded_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (case_id, file.filename or safe_name, str(path), sha, len(content), classification,
         retention, user["username"], now),
    )
    conn.execute("INSERT INTO case_timeline (case_id, ts, actor, entry_type, message, meta) "
                 "VALUES (?, ?, ?, 'evidence', ?, ?)",
                 (case_id, now, user["username"], f"Evidence attached: {file.filename}",
                  db.jdump({"evidence_id": int(cur.lastrowid), "sha256": sha})))
    conn.commit()
    record_audit(conn, _actor(user), "evidence.uploaded", target_type="evidence",
                 target_id=str(cur.lastrowid), detail={"name": file.filename, "sha256": sha,
                                                       "classification": classification})
    return db.one(conn, "SELECT * FROM evidence WHERE id = ?", (cur.lastrowid,))


@router.get("/{case_id}/evidence")
def list_evidence(case_id: int, conn: sqlite3.Connection = Depends(db.get_conn),
                  user: dict = Depends(require("cases.read"))):
    if not db.one(conn, "SELECT id FROM cases WHERE id = ?", (case_id,)):
        raise HTTPException(404, {"code": "not_found"})
    rows = db.q(conn, "SELECT * FROM evidence WHERE case_id = ? ORDER BY id", (case_id,))
    for r in rows:
        r["path_exists"] = Path(r["path"]).exists()
    return {"items": rows, "total": len(rows)}


@router.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id: int, conn: sqlite3.Connection = Depends(db.get_conn),
                      user: dict = Depends(require("evidence.download"))):
    e = db.one(conn, "SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not e:
        raise HTTPException(404, {"code": "not_found"})
    path = Path(e["path"])
    if not path.exists():
        raise HTTPException(410, {"code": "missing", "message": "Evidence file missing from store."})
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != e["sha256"]:
        record_audit(conn, _actor(user), "evidence.integrity_failure",
                     target_type="evidence", target_id=str(evidence_id),
                     detail={"expected": e["sha256"], "actual": actual})
        raise HTTPException(500, {"code": "integrity_mismatch"})
    record_audit(conn, _actor(user), "evidence.downloaded", target_type="evidence",
                 target_id=str(evidence_id), detail={"name": e["name"], "sha256": e["sha256"]})
    return FileResponse(path, filename=e["name"], media_type="application/octet-stream")
