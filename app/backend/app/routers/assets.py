"""Asset inventory (SEC-024): on-prem assets with environment + group boundaries."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require

router = APIRouter(prefix="/api/assets", tags=["assets"])

ASSET_TYPES = {"server", "workstation", "container", "cloud", "network", "application", "iot"}
STATUSES = {"active", "decommissioned", "quarantined", "in_maintenance"}


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


class AssetIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    type: str
    environment: str | None = Field(default=None, max_length=40)
    owner: str | None = Field(default=None, max_length=100)
    group_name: str | None = Field(default=None, max_length=120)
    status: str = "active"
    meta: dict | None = None


@router.post("", status_code=201)
def create_asset(body: AssetIn, conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("assets.write"))):
    if body.type not in ASSET_TYPES:
        raise HTTPException(400, {"code": "bad_type", "message": f"type must be one of {sorted(ASSET_TYPES)}"})
    if body.status not in STATUSES:
        raise HTTPException(400, {"code": "bad_status"})
    if db.one(conn, "SELECT id FROM assets WHERE name = ?", (body.name,)):
        raise HTTPException(409, {"code": "exists"})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO assets (name, type, environment, owner, group_name, status, meta, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (body.name, body.type, body.environment, body.owner, body.group_name, body.status,
         db.jdump(body.meta), now, now))
    conn.commit()
    record_audit(conn, _actor(user), "asset.created", target_type="asset", target_id=str(cur.lastrowid),
                 detail={"name": body.name, "type": body.type, "environment": body.environment})
    return db.one(conn, "SELECT * FROM assets WHERE id = ?", (cur.lastrowid,))


@router.get("")
def list_assets(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("assets.read")),
                type: str | None = None, environment: str | None = None, status: str | None = None,
                q: str | None = None,
                page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    where, params = ["1=1"], []
    if type:
        where.append("type = ?")
        params.append(type)
    if environment:
        where.append("environment = ?")
        params.append(environment)
    if status:
        where.append("status = ?")
        params.append(status)
    if q:
        where.append("name LIKE ?")
        params.append(f"%{q}%")
    sql = "SELECT * FROM assets WHERE " + " AND ".join(where)
    return db.paged(conn, sql, tuple(params), "ORDER BY name", page, page_size)


@router.patch("/{asset_id}")
def update_asset(asset_id: int, body: AssetIn, conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("assets.write"))):
    a = db.one(conn, "SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not a:
        raise HTTPException(404, {"code": "not_found"})
    if body.type not in ASSET_TYPES or body.status not in STATUSES:
        raise HTTPException(400, {"code": "bad_value"})
    conn.execute(
        "UPDATE assets SET type=?, environment=?, owner=?, group_name=?, status=?, meta=?, updated_at=? WHERE id=?",
        (body.type, body.environment, body.owner, body.group_name, body.status,
         db.jdump(body.meta), db.utcnow(), asset_id))
    conn.commit()
    record_audit(conn, _actor(user), "asset.updated", target_type="asset", target_id=str(asset_id),
                 detail={"status": body.status})
    return db.one(conn, "SELECT * FROM assets WHERE id = ?", (asset_id,))
