"""GRC & Compliance: frameworks/controls, risks, audit evidence (SEC-054).

Default framework data (NIST CSF 2.0 subset, CIS top controls) is free public
information; evidence is attached to controls with sha256 provenance.
"""
from __future__ import annotations

import hashlib
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require

router = APIRouter(prefix="/api/grc", tags=["grc"])

CONTROL_STATUSES = {"not_started", "in_progress", "met", "gap"}
RISK_STATUSES = {"open", "mitigating", "accepted", "closed"}


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


class ControlIn(BaseModel):
    framework: str = Field(min_length=2, max_length=80)
    code: str = Field(min_length=2, max_length=40)
    title: str = Field(min_length=3, max_length=300)
    category: str | None = Field(default=None, max_length=120)
    owner: str | None = Field(default=None, max_length=100)
    status: str = "not_started"
    next_review: str | None = Field(default=None, max_length=40)


@router.post("/controls", status_code=201)
def create_control(body: ControlIn, conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("grc.write"))):
    if body.status not in CONTROL_STATUSES:
        raise HTTPException(400, {"code": "bad_status"})
    if db.one(conn, "SELECT id FROM controls WHERE framework = ? AND code = ?", (body.framework, body.code)):
        raise HTTPException(409, {"code": "exists"})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO controls (framework, code, title, category, owner, status, next_review, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (body.framework, body.code, body.title, body.category, body.owner, body.status,
         body.next_review, now, now))
    conn.commit()
    record_audit(conn, _actor(user), "grc.control.created", target_type="control",
                 target_id=str(cur.lastrowid), detail={"framework": body.framework, "code": body.code})
    return db.one(conn, "SELECT * FROM controls WHERE id = ?", (cur.lastrowid,))


@router.get("/controls")
def list_controls(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("grc.read")),
                  framework: str | None = None, status: str | None = None,
                  page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    where, params = ["1=1"], []
    if framework:
        where.append("framework = ?")
        params.append(framework)
    if status:
        where.append("status = ?")
        params.append(status)
    sql = "SELECT * FROM controls WHERE " + " AND ".join(where)
    return db.paged(conn, sql, tuple(params), "ORDER BY framework, code", page, page_size)


class ControlUpdate(BaseModel):
    status: str | None = None
    owner: str | None = Field(default=None, max_length=100)
    next_review: str | None = Field(default=None, max_length=40)


@router.patch("/controls/{cid}")
def update_control(cid: int, body: ControlUpdate, conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("grc.write"))):
    c = db.one(conn, "SELECT * FROM controls WHERE id = ?", (cid,))
    if not c:
        raise HTTPException(404, {"code": "not_found"})
    if body.status and body.status not in CONTROL_STATUSES:
        raise HTTPException(400, {"code": "bad_status"})
    fields, params = [], []
    for k in ("status", "owner", "next_review"):
        if getattr(body, k) is not None:
            fields.append(f"{k} = ?")
            params.append(getattr(body, k))
    if not fields:
        raise HTTPException(400, {"code": "no_changes"})
    fields.append("updated_at = ?")
    params.append(db.utcnow())
    params.append(cid)
    conn.execute(f"UPDATE controls SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()
    record_audit(conn, _actor(user), "grc.control.updated", target_type="control", target_id=str(cid),
                 detail={k: v for k, v in body.model_dump().items() if v is not None})
    return db.one(conn, "SELECT * FROM controls WHERE id = ?", (cid,))


@router.post("/controls/{cid}/evidence", status_code=201)
def attach_evidence(cid: int, file: UploadFile,
                    conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("grc.write"))):
    if not db.one(conn, "SELECT id FROM controls WHERE id = ?", (cid,)):
        raise HTTPException(404, {"code": "not_found"})
    content = file.file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(413, {"code": "too_large"})
    sha = hashlib.sha256(content).hexdigest()
    cur = conn.execute(
        "INSERT INTO audit_evidence (control_id, name, path, sha256, created_at) VALUES (?, ?, ?, ?, ?)",
        (cid, file.filename or "evidence", None, sha, db.utcnow()))
    conn.commit()
    record_audit(conn, _actor(user), "grc.evidence.attached", target_type="control", target_id=str(cid),
                 detail={"name": file.filename, "sha256": sha})
    return db.one(conn, "SELECT * FROM audit_evidence WHERE id = ?", (cur.lastrowid,))


@router.get("/controls/{cid}/evidence")
def list_control_evidence(cid: int, conn: sqlite3.Connection = Depends(db.get_conn),
                          user: dict = Depends(require("grc.read"))):
    rows = db.q(conn, "SELECT * FROM audit_evidence WHERE control_id = ? ORDER BY id", (cid,))
    return {"items": rows, "total": len(rows)}


class RiskIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    likelihood: int = Field(default=3, ge=1, le=5)
    impact: int = Field(default=3, ge=1, le=5)
    status: str = "open"
    owner: str | None = Field(default=None, max_length=100)
    mitigations: list[str] | None = None


@router.post("/risks", status_code=201)
def create_risk(body: RiskIn, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("grc.write"))):
    if body.status not in RISK_STATUSES:
        raise HTTPException(400, {"code": "bad_status"})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO risks (title, description, likelihood, impact, score, status, owner, mitigations, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (body.title, body.description, body.likelihood, body.impact, body.likelihood * body.impact,
         body.status, body.owner, db.jdump(body.mitigations), now, now))
    conn.commit()
    record_audit(conn, _actor(user), "grc.risk.created", target_type="risk", target_id=str(cur.lastrowid))
    return db.one(conn, "SELECT * FROM risks WHERE id = ?", (cur.lastrowid,))


@router.get("/risks")
def list_risks(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("grc.read")),
               status: str | None = None):
    sql, params = "SELECT * FROM risks", ()
    if status:
        sql += " WHERE status = ?"
        params = (status,)
    rows = db.q(conn, f"{sql} ORDER BY score DESC, id DESC", params)
    for r in rows:
        r["mitigations"] = db.jload(r.get("mitigations"), [])   # SEC-091
    return {"items": rows, "total": len(rows)}


class RiskUpdate(BaseModel):
    status: str | None = None
    owner: str | None = Field(default=None, max_length=100)
    likelihood: int | None = Field(default=None, ge=1, le=5)
    impact: int | None = Field(default=None, ge=1, le=5)
    mitigations: list[str] | None = None


@router.patch("/risks/{risk_id}")
def update_risk(risk_id: int, body: RiskUpdate, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("grc.write"))):
    r = db.one(conn, "SELECT * FROM risks WHERE id = ?", (risk_id,))
    if not r:
        raise HTTPException(404, {"code": "not_found"})
    if body.status and body.status not in RISK_STATUSES:
        raise HTTPException(400, {"code": "bad_status"})
    fields, params = [], []
    for k in ("status", "owner"):
        if getattr(body, k) is not None:
            fields.append(f"{k} = ?")
            params.append(getattr(body, k))
    if body.likelihood is not None or body.impact is not None:
        lik = body.likelihood if body.likelihood is not None else r["likelihood"]
        imp = body.impact if body.impact is not None else r["impact"]
        fields.append("likelihood = ?")
        fields.append("impact = ?")
        fields.append("score = ?")
        params += [lik, imp, lik * imp]
    if body.mitigations is not None:
        fields.append("mitigations = ?")
        params.append(db.jdump(body.mitigations))
    if not fields:
        raise HTTPException(400, {"code": "no_changes"})
    fields.append("updated_at = ?")
    params.append(db.utcnow())
    params.append(risk_id)
    conn.execute(f"UPDATE risks SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()
    record_audit(conn, _actor(user), "grc.risk.updated", target_type="risk", target_id=str(risk_id),
                 detail={k: v for k, v in body.model_dump().items() if v is not None})
    return db.decode_json(db.one(conn, "SELECT * FROM risks WHERE id = ?", (risk_id,)),
                          "mitigations", default=[])   # SEC-091
