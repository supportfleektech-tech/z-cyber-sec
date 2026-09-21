"""Cloud Security: cloud asset inventory + posture findings (SEC-054).

Local-first: posture checks are evaluated from imported/synthetic resource
state (no cloud credentials needed); a free scanner (e.g. Prowler in
local/offline mode) can feed the same schema.
"""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require

router = APIRouter(prefix="/api/cloud", tags=["cloud"])


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


class CloudAssetIn(BaseModel):
    provider: str | None = Field(default=None, max_length=60)
    account: str | None = Field(default=None, max_length=120)
    region: str | None = Field(default=None, max_length=60)
    type: str = Field(min_length=2, max_length=60)
    name: str = Field(min_length=1, max_length=200)
    status: str = "active"
    meta: dict | None = None


@router.post("/assets", status_code=201)
def create_asset(body: CloudAssetIn, conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("cloud.write"))):
    cur = conn.execute(
        "INSERT INTO cloud_assets (provider, account, region, type, name, status, meta, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (body.provider, body.account, body.region, body.type, body.name, body.status,
         db.jdump(body.meta), db.utcnow()))
    conn.commit()
    record_audit(conn, _actor(user), "cloud.asset.created", target_type="cloud_asset",
                 target_id=str(cur.lastrowid), detail={"name": body.name, "type": body.type})
    return db.one(conn, "SELECT * FROM cloud_assets WHERE id = ?", (cur.lastrowid,))


@router.get("/assets")
def list_assets(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("cloud.read")),
                provider: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    sql, params = "SELECT * FROM cloud_assets", ()
    if provider:
        sql += " WHERE provider = ?"
        params = (provider,)
    return db.paged(conn, sql, params, "ORDER BY name", page, page_size)


class PostureIn(BaseModel):
    asset_id: int
    rule_id: str = Field(min_length=2, max_length=120)
    title: str = Field(min_length=3, max_length=300)
    severity: str = "medium"
    status: str = "open"
    detail: str | None = Field(default=None, max_length=4000)
    meta: dict | None = None


@router.post("/posture", status_code=201)
def create_posture(body: PostureIn, conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("cloud.write"))):
    if not db.one(conn, "SELECT id FROM cloud_assets WHERE id = ?", (body.asset_id,)):
        raise HTTPException(400, {"code": "bad_asset"})
    cur = conn.execute(
        "INSERT INTO posture_findings (asset_id, rule_id, title, severity, status, detail, checked_at, meta) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (body.asset_id, body.rule_id, body.title, body.severity, body.status, body.detail,
         db.utcnow(), db.jdump(body.meta)))
    conn.commit()
    record_audit(conn, _actor(user), "cloud.posture.created", target_type="posture_finding",
                 target_id=str(cur.lastrowid), detail={"rule_id": body.rule_id})
    return db.one(conn, "SELECT * FROM posture_findings WHERE id = ?", (cur.lastrowid,))


@router.get("/posture")
def list_posture(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("cloud.read")),
                 asset_id: int | None = None, status: str | None = None,
                 page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    where, params = ["1=1"], []
    if asset_id is not None:
        where.append("p.asset_id = ?")
        params.append(asset_id)
    if status:
        where.append("p.status = ?")
        params.append(status)
    sql = ("SELECT p.*, ca.name AS asset_name, ca.provider FROM posture_findings p "
           "JOIN cloud_assets ca ON ca.id = p.asset_id WHERE " + " AND ".join(where))
    return db.paged(conn, sql, tuple(params), "ORDER BY p.id DESC", page, page_size)


@router.patch("/posture/{finding_id}")
def update_posture(finding_id: int, body: PostureIn, conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("cloud.write"))):
    p = db.one(conn, "SELECT * FROM posture_findings WHERE id = ?", (finding_id,))
    if not p:
        raise HTTPException(404, {"code": "not_found"})
    conn.execute(
        "UPDATE posture_findings SET status = ?, severity = ?, detail = ?, checked_at = ? WHERE id = ?",
        (body.status, body.severity, body.detail, db.utcnow(), finding_id))
    conn.commit()
    record_audit(conn, _actor(user), "cloud.posture.updated", target_type="posture_finding",
                 target_id=str(finding_id), detail={"status": body.status})
    return db.one(conn, "SELECT * FROM posture_findings WHERE id = ?", (finding_id,))
