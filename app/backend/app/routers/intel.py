"""Threat Intelligence (SEC-034): sources, indicators, STIX import, correlation."""
from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require
from ..services.stix import parse_bundle

router = APIRouter(prefix="/api/intel", tags=["intel"])

IND_TYPES = {"ip", "domain", "url", "sha256", "file", "email"}
RELIABILITY = {"a", "b", "c", "d", "e", "f"}


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


class SourceIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: str = "osint"
    reliability: str = "c"
    description: str | None = Field(default=None, max_length=500)


@router.post("/sources", status_code=201)
def create_source(body: SourceIn, conn: sqlite3.Connection = Depends(db.get_conn),
                  user: dict = Depends(require("intel.write"))):
    if body.reliability.lower() not in RELIABILITY:
        raise HTTPException(400, {"code": "bad_reliability"})
    if db.one(conn, "SELECT id FROM intel_sources WHERE name = ?", (body.name,)):
        raise HTTPException(409, {"code": "exists"})
    cur = conn.execute(
        "INSERT INTO intel_sources (name, kind, reliability, description, created_at) VALUES (?, ?, ?, ?, ?)",
        (body.name, body.kind, body.reliability.lower(), body.description, db.utcnow()))
    conn.commit()
    record_audit(conn, _actor(user), "intel.source.created", target_type="intel_source",
                 target_id=str(cur.lastrowid), detail={"name": body.name})
    return db.one(conn, "SELECT * FROM intel_sources WHERE id = ?", (cur.lastrowid,))


@router.get("/sources")
def list_sources(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("intel.read"))):
    rows = db.q(conn, "SELECT * FROM intel_sources ORDER BY name")
    return {"items": rows, "total": len(rows)}


class IndicatorIn(BaseModel):
    type: str
    value: str = Field(min_length=1, max_length=500)
    confidence: int | None = Field(default=None, ge=0, le=100)
    source_id: int | None = None
    ttl_hours: int | None = Field(default=None, gt=0)
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
    notes: str | None = Field(default=None, max_length=1000)
    status: str | None = None  # active | expired | revoked (update path)


@router.post("/indicators", status_code=201)
def create_indicator(body: IndicatorIn, conn: sqlite3.Connection = Depends(db.get_conn),
                     user: dict = Depends(require("intel.write"))):
    if body.type not in IND_TYPES:
        raise HTTPException(400, {"code": "bad_type", "message": f"type must be one of {sorted(IND_TYPES)}"})
    if body.source_id and not db.one(conn, "SELECT id FROM intel_sources WHERE id = ?", (body.source_id,)):
        raise HTTPException(400, {"code": "bad_source"})
    now = db.utcnow()
    existing = db.one(conn, "SELECT id FROM threat_indicators WHERE type = ? AND value = ?",
                      (body.type, body.value))
    if existing:
        conn.execute(
            "UPDATE threat_indicators SET confidence = COALESCE(?, confidence), last_seen = ?, updated_at = ? WHERE id = ?",
            (body.confidence, now, now, existing["id"]))
        conn.commit()
        return {"id": existing["id"], "created": False, "updated": True}
    cur = conn.execute(
        "INSERT INTO threat_indicators (type, value, confidence, source_id, status, ttl_hours, first_seen, "
        "last_seen, mitre_tactics, mitre_techniques, notes, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?)",
        (body.type, body.value, body.confidence, body.source_id, body.ttl_hours, now, now,
         db.jdump(body.mitre_tactics), db.jdump(body.mitre_techniques), body.notes, now, now))
    conn.commit()
    record_audit(conn, _actor(user), "intel.indicator.created", target_type="threat_indicator",
                 target_id=str(cur.lastrowid), detail={"type": body.type, "value": body.value})
    return db.one(conn, "SELECT * FROM threat_indicators WHERE id = ?", (cur.lastrowid,))


@router.get("/indicators")
def list_indicators(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("intel.read")),
                    type: str | None = None, status: str | None = None,
                    min_confidence: int | None = Query(default=None, ge=0, le=100),
                    q: str | None = None,
                    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    where, params = [], []
    if type:
        where.append("i.type = ?")
        params.append(type)
    if status:
        where.append("i.status = ?")
        params.append(status)
    if min_confidence is not None:
        where.append("i.confidence >= ?")
        params.append(min_confidence)
    if q:
        where.append("i.value LIKE ?")
        params.append(f"%{q}%")
    sql = ("SELECT i.*, s.name AS source_name FROM threat_indicators i "
           "LEFT JOIN intel_sources s ON s.id = i.source_id")
    if where:
        sql += " WHERE " + " AND ".join(where)
    return db.paged(conn, sql, tuple(params), "ORDER BY i.confidence DESC, i.id DESC", page, page_size)


class StixImportIn(BaseModel):
    bundle: dict[str, Any]
    source_id: int | None = None
    default_confidence: int = Field(default=50, ge=0, le=100)


@router.post("/indicators/stix", status_code=201)
def import_stix(body: StixImportIn, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("intel.write"))):
    """Import a STIX 2.1 bundle (subset parser, ADR-004)."""
    if body.source_id and not db.one(conn, "SELECT id FROM intel_sources WHERE id = ?", (body.source_id,)):
        raise HTTPException(400, {"code": "bad_source"})
    try:
        parsed = parse_bundle(body.bundle)
    except ValueError as e:
        raise HTTPException(400, {"code": "bad_stix", "message": str(e)}) from e
    now = db.utcnow()
    created = updated = 0
    for ind in parsed:
        conf = ind.get("confidence") or body.default_confidence
        existing = db.one(conn, "SELECT id FROM threat_indicators WHERE type = ? AND value = ?",
                          (ind["type"], ind["value"]))
        if existing:
            conn.execute("UPDATE threat_indicators SET last_seen = ?, updated_at = ? WHERE id = ?",
                         (now, now, existing["id"]))
            updated += 1
        else:
            conn.execute(
                "INSERT INTO threat_indicators (type, value, confidence, source_id, status, first_seen, "
                "last_seen, notes, created_at, updated_at) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)",
                (ind["type"], ind["value"], conf, body.source_id, now, now,
                 f"imported via STIX: {ind.get('name', '')}"[:1000], now, now))
            created += 1
    conn.commit()
    record_audit(conn, _actor(user), "intel.stix.imported", target_type="intel",
                 detail={"created": created, "updated": updated})
    return {"created": created, "updated": updated, "total_parsed": len(parsed)}


@router.get("/indicators/correlate")
def correlate(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("intel.read")),
              window_hours: int = Query(default=72, ge=1, le=24 * 30)):
    """Cross-reference active indicators with recent event data (host/ip/user fields + data JSON)."""
    inds = db.q(conn, "SELECT id, type, value, confidence FROM threat_indicators WHERE status = 'active'")
    hits: list[dict] = []
    recent = db.q(conn, "SELECT id, ts, host, user, action, severity, msg, data FROM events ORDER BY ts DESC LIMIT 5000")
    for ev in recent:
        blob = f"{ev['host'] or ''} {ev['user'] or ''} {ev['msg'] or ''} {ev['data'] or ''}"
        for ind in inds:
            if ind["value"].lower() in blob.lower():
                hits.append({"event_id": ev["id"], "event_ts": ev["ts"], "event_action": ev["action"],
                             "indicator_id": ind["id"], "indicator_type": ind["type"],
                             "indicator_value": ind["value"], "confidence": ind["confidence"]})
                if len(hits) >= 500:
                    return {"hits": hits, "truncated": True}
    return {"hits": hits, "truncated": False, "indicators_checked": len(inds),
            "events_checked": len(recent)}


@router.patch("/indicators/{ind_id}")
def update_indicator(ind_id: int, body: IndicatorIn, conn: sqlite3.Connection = Depends(db.get_conn),
                     user: dict = Depends(require("intel.write"))):
    i = db.one(conn, "SELECT * FROM threat_indicators WHERE id = ?", (ind_id,))
    if not i:
        raise HTTPException(404, {"code": "not_found"})
    if body.status and body.status not in {"active", "expired", "revoked"}:
        raise HTTPException(400, {"code": "bad_status"})
    status = body.status or i["status"]
    fields = ("confidence = ?, source_id = ?, ttl_hours = ?, status = ?, mitre_tactics = ?, "
              "mitre_techniques = ?, notes = ?, updated_at = ?")
    conn.execute(
        f"UPDATE threat_indicators SET {fields} WHERE id = ?",
        (body.confidence, body.source_id, body.ttl_hours, status,
         db.jdump(body.mitre_tactics), db.jdump(body.mitre_techniques), body.notes, db.utcnow(), ind_id))
    conn.commit()
    record_audit(conn, _actor(user), "intel.indicator.updated", target_type="threat_indicator",
                 target_id=str(ind_id), detail={"status": status})
    return db.one(conn, "SELECT * FROM threat_indicators WHERE id = ?", (ind_id,))
