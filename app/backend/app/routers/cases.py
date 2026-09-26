"""Incident Response: case lifecycle, tasks, timeline, evidence (SEC-032/033).

Evidence: files on disk (0600, never publicly mounted); metadata in DB with
sha256, classification, retention; every access audited.
"""
from __future__ import annotations

import hashlib
import re
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
# The SPA's New-case form offers exactly these (Incidents.tsx), and they are the
# standard five used by alerts and vulns (SEC-079/082) — a case's triage fields are
# not free text (SEC-110).
CASE_PRIORITIES = {"low", "medium", "high", "critical"}
CASE_SEVERITIES = {"critical", "high", "medium", "low", "info"}
TASK_STATUSES = {"open", "in_progress", "done", "canceled"}
CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}
# Evidence retention is a *control*, not a note (SEC-112): the retention report only
# understands `<n><d|w|m|y>` and the sentinels below, and its `_retention_due` returns
# None for anything else — which the report then counted as `within_retention`. A typo
# ("banana", "90 days") therefore produced evidence that never came due for review
# while the operator's report said it was fine.
RETENTION_SENTINELS = {"legal-hold", "legal_hold", "retain-case-close", "indefinite"}
RETENTION_RE = re.compile(r"^(\d{1,5})\s*([dwmy])$", re.IGNORECASE)
MAX_EVIDENCE_BYTES = 25 * 1024 * 1024


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


def _validate_triage(priority: str | None, severity: str | None) -> None:
    """Refuse a triage value outside the documented set (SEC-110).

    `None` is allowed: severity is optional (the SPA sends `undefined` for its blank
    option) and, since SEC-111, a *sent* null clears a nullable column.
    """
    if priority is not None and priority not in CASE_PRIORITIES:
        raise HTTPException(400, {"code": "bad_priority", "allowed": sorted(CASE_PRIORITIES),
                                  "message": f"priority must be one of {sorted(CASE_PRIORITIES)}"})
    if severity is not None and severity not in CASE_SEVERITIES:
        raise HTTPException(400, {"code": "bad_severity", "allowed": sorted(CASE_SEVERITIES),
                                  "message": f"severity must be one of {sorted(CASE_SEVERITIES)}"})


def _validate_retention(retention: str | None) -> str | None:
    """Normalise a retention label, or refuse it (SEC-112).

    Returns the canonical label (`90d`, `legal-hold`, …) or None for "no label".
    """
    if retention is None or not retention.strip():
        return None
    label = retention.strip().lower()
    if label in RETENTION_SENTINELS:
        return label
    m = RETENTION_RE.match(label)
    if not m:
        raise HTTPException(400, {
            "code": "bad_retention",
            "message": ("retention must be a window like 90d, 4w, 6m or 12y — or one of "
                        f"{sorted(RETENTION_SENTINELS)}"),
            "allowed": sorted(RETENTION_SENTINELS) + ["<n>d", "<n>w", "<n>m", "<n>y"]})
    return f"{int(m.group(1))}{m.group(2)}"


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
    # SEC-110: `if body.priority and …` let an empty string through ("" is falsy and
    # not in the set), and `severity` was never validated at all on create or update,
    # so a case could be filed as `severity: "banana"` — invisible to every count that
    # groups by the standard five.
    _validate_triage(body.priority, body.severity)
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
    # SEC-110: `if body.status and …` skipped the check for an empty string, which is
    # falsy — `PATCH {"status": ""}` was accepted and stored a case with no status,
    # which then appeared as its own bucket in every `GROUP BY status` count.
    if body.status is not None and body.status not in CASE_STATUSES:
        raise HTTPException(400, {"code": "bad_status", "allowed": sorted(CASE_STATUSES),
                                  "message": f"status must be one of {sorted(CASE_STATUSES)}"})
    _validate_triage(body.priority, body.severity)
    # SEC-111: same rule as alerts — a field the caller *sent* is written (an
    # explicit null clears a nullable column, RFC 7396), an omitted field is left
    # alone, and a sent null for a NOT NULL column is refused by name.
    provided = body.model_fields_set
    if not provided:
        raise HTTPException(400, {"code": "no_changes"})
    for f in ("title", "status"):
        if f in provided and getattr(body, f) is None:
            raise HTTPException(400, {"code": "missing_field", "message": f"{f} must not be null."})
    fields, params = [], []
    for f in ("title", "description", "status", "priority", "severity", "assigned_to"):
        if f in provided:
            fields.append(f"{f} = ?")
            params.append(getattr(body, f))
    fields.append("updated_at = ?")
    params.append(db.utcnow())
    params.append(case_id)
    conn.execute(f"UPDATE cases SET {', '.join(fields)} WHERE id = ?", params)
    now = db.utcnow()
    # SEC-092: `closed_at` was set when a case closed and never cleared, so a
    # reopened case still reported a closure time — the case report (an evidence
    # artefact) and the SPA's "created → closed" line presented an active case as
    # closed. It is now cleared on the way out of `closed`, and re-closing keeps
    # the original timestamp instead of quietly rewriting it.
    reopened = body.status is not None and body.status != "closed" and c["status"] == "closed"
    if body.status == "closed" and (c["status"] != "closed" or not c["closed_at"]):
        conn.execute("UPDATE cases SET closed_at = ? WHERE id = ?", (now, case_id))
    elif reopened:
        conn.execute("UPDATE cases SET closed_at = NULL WHERE id = ?", (case_id,))
    if body.status:
        conn.execute("INSERT INTO case_timeline (case_id, ts, actor, entry_type, message) "
                     "VALUES (?, ?, ?, 'status', ?)",
                     (case_id, now, user["username"],
                      f"Status → {body.status}" + (" (reopened from closed)" if reopened else "")))
    if body.notes:
        conn.execute("INSERT INTO case_timeline (case_id, ts, actor, entry_type, message) "
                     "VALUES (?, ?, ?, 'note', ?)", (case_id, now, user["username"], body.notes))
    conn.commit()
    detail = {k: v for k, v in body.model_dump().items() if k in provided}  # SEC-111
    if body.status is not None and body.status != c["status"]:
        detail["from_status"], detail["to_status"] = c["status"], body.status
        detail["reopened"] = reopened
    record_audit(conn, _actor(user), "case.updated", target_type="case", target_id=str(case_id),
                 detail=detail)
    return db.one(conn, "SELECT * FROM cases WHERE id = ?", (case_id,))


# ------------------------------------------------------------------- tasks

class TaskIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    assigned_to: str | None = Field(default=None, max_length=100)
    due: str | None = Field(default=None, max_length=40)


class TaskUpdate(BaseModel):
    """SEC-110: the task PATCH took a raw `dict` and wrote any of its keys, so the
    create-side bounds (`assigned_to` ≤100, `due` ≤40) did not apply here and the
    endpoint had no schema in `/api/openapi.json` at all."""
    status: str | None = None
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
def update_task(task_id: int, body: TaskUpdate, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("cases.write"))):
    t = db.one(conn, "SELECT * FROM case_tasks WHERE id = ?", (task_id,))
    if not t:
        raise HTTPException(404, {"code": "not_found"})
    if body.status is not None and body.status not in TASK_STATUSES:
        raise HTTPException(400, {"code": "bad_status", "allowed": sorted(TASK_STATUSES),
                                  "message": f"status must be one of {sorted(TASK_STATUSES)}"})
    fields, params = [], []
    for k, v in body.model_dump().items():
        if v is not None:
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
                 detail={k: v for k, v in body.model_dump().items() if v is not None})
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
    retention = _validate_retention(retention)
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
                                                       "classification": classification,
                                                       "retention": retention})
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
