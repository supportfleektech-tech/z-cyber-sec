"""Threat Intelligence (SEC-034): sources, indicators, STIX import, correlation."""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require
from ..services.stix import parse_bundle

router = APIRouter(prefix="/api/intel", tags=["intel"])

IND_TYPES = {"ip", "domain", "url", "sha256", "file", "email"}
IND_STATUSES = {"active", "expired", "revoked"}
RELIABILITY = {"a", "b", "c", "d", "e", "f"}


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


class SourceIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: str = "osint"
    reliability: str = "c"
    description: str | None = Field(default=None, max_length=500)


def _shape(row: dict | None) -> dict | None:
    """Decode the two JSON list columns for API consumers.

    SEC-089: `mitre_tactics`/`mitre_techniques` were returned as raw JSON text
    (`'["T1041"]'`), which is why the SPA's MITRE column rendered that literal
    and why its create form — written against the column, not the model — sent a
    bare string and got a 422 (`Input should be a valid list`), so the field
    could never be filled in from the UI.
    """
    if row is None:
        return None
    out = dict(row)
    for col in ("mitre_tactics", "mitre_techniques"):
        if col in out:
            out[col] = db.jload(out.get(col), None)
    return out


def _parse_ts(ts: str | None):
    """Parse our stored ISO-8601 ("2026-09-23T02:21:58Z") into a datetime."""
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def _stix_window(first_seen: str, valid_until: str | None, now: str) -> tuple[int | None, str, str | None]:
    """Map a STIX validity window onto (ttl_hours, status, expires_at).

    An indicator whose `valid_until` has already passed is imported `expired`
    rather than `active`; one still in the future gets a TTL so it expires on
    time even if no later bundle ever mentions it again.
    """
    if not valid_until:
        return None, "active", None
    start, end = _parse_ts(first_seen), _parse_ts(valid_until)
    if start is None or end is None:
        return None, "active", None
    if end <= _parse_ts(now):
        return None, "expired", valid_until
    hours = max(1, int((end - start).total_seconds() // 3600))
    return hours, "active", valid_until


def expires_at(first_seen: str | None, ttl_hours: int | None) -> str | None:
    """When an indicator's TTL elapses, or None if it does not expire."""
    start = _parse_ts(first_seen)
    if start is None or not ttl_hours:
        return None
    return (start + timedelta(hours=ttl_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def expire_due(conn: sqlite3.Connection) -> list[int]:
    """SEC-087: honour `ttl_hours` — flip active indicators past their TTL to
    `expired`.

    This is lazy (run on the read paths that consume indicators) rather than a
    scheduled job, so it needs no extra thread and cannot drift from the data.
    `expires_at` was computed, stored and shown to operators, and the UI
    advertised "confidence, expiry, and cross-correlation" — but nothing ever
    read it, so a stale IOC stayed `active` forever and `correlate` kept
    matching it. Idempotent: only rows still `active` are touched, and the
    audit entry is written only when at least one row actually changed.
    """
    rows = db.q(conn, "SELECT id, first_seen, ttl_hours FROM threat_indicators "
                      "WHERE status = 'active' AND ttl_hours IS NOT NULL")
    now = datetime.now(UTC)
    due = []
    for r in rows:
        deadline = expires_at(r["first_seen"], r["ttl_hours"])
        if deadline and _parse_ts(deadline) <= now:
            due.append(r["id"])
    if not due:
        return []
    marks = ",".join("?" * len(due))
    conn.execute(f"UPDATE threat_indicators SET status = 'expired', updated_at = ? "
                 f"WHERE id IN ({marks}) AND status = 'active'", (db.utcnow(), *due))
    record_audit(conn, {"type": "system", "id": None, "name": "intel-expiry"},
                 "intel.indicators.expired", target_type="threat_indicator",
                 detail={"count": len(due), "ids": due[:20], "reason": "ttl_elapsed"})
    conn.commit()
    return due


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
    status: str | None = None  # active | expired | revoked


class IndicatorUpdateIn(BaseModel):
    """True partial update (SEC-088).

    The update route used to take `IndicatorIn`: `type`/`value` were *required*
    but never written, while every other column was set from the body, so
    omitting a field silently NULLed it. A UI status change therefore erased the
    indicator's source, TTL, MITRE mappings and notes, and `PATCH {"confidence":
    10}` wiped them again. Every field is optional now and only the ones the
    caller actually sent are written.
    """
    type: str | None = None
    value: str | None = Field(default=None, min_length=1, max_length=500)
    confidence: int | None = Field(default=None, ge=0, le=100)
    source_id: int | None = None
    ttl_hours: int | None = Field(default=None, gt=0)
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
    notes: str | None = Field(default=None, max_length=1000)
    status: str | None = None


@router.post("/indicators", status_code=201)
def create_indicator(body: IndicatorIn, conn: sqlite3.Connection = Depends(db.get_conn),
                     user: dict = Depends(require("intel.write"))):
    if body.type not in IND_TYPES:
        raise HTTPException(400, {"code": "bad_type", "message": f"type must be one of {sorted(IND_TYPES)}"})
    if body.source_id and not db.one(conn, "SELECT id FROM intel_sources WHERE id = ?", (body.source_id,)):
        raise HTTPException(400, {"code": "bad_source"})
    # SEC-087: `status` was silently ignored on create (POST with
    # status:"revoked" returned 201 and stored an *active* indicator, which
    # `correlate` then matched). Validate it and store what was asked for.
    status = body.status or "active"
    if status not in IND_STATUSES:
        raise HTTPException(400, {"code": "bad_status",
                                  "message": f"status must be one of {sorted(IND_STATUSES)}"})
    now = db.utcnow()
    # A re-sighting is judged against the *current* lifecycle state, so bring
    # any due TTLs up to date first — otherwise a stale row still reads
    # `active` and the revival below never triggers.
    expire_due(conn)
    existing = db.one(conn, "SELECT id, status FROM threat_indicators WHERE type = ? AND value = ?",
                      (body.type, body.value))
    if existing:
        # SEC-087: this upsert changed confidence/last_seen with no audit entry,
        # while docs/12 promises one per state change. A re-sighting of an
        # `expired` indicator also revives it (fresh evidence), but a human
        # `revoked` retraction is never undone by a feed.
        revived = existing["status"] == "expired"
        new_status = "active" if revived else existing["status"]
        conn.execute(
            "UPDATE threat_indicators SET confidence = COALESCE(?, confidence), last_seen = ?, "
            "updated_at = ?, status = ? WHERE id = ?",
            (body.confidence, now, now, new_status, existing["id"]))
        record_audit(conn, _actor(user), "intel.indicator.reseen", target_type="threat_indicator",
                     target_id=str(existing["id"]),
                     detail={"type": body.type, "value": body.value, "confidence": body.confidence,
                             "revived": revived, "status": new_status})
        conn.commit()
        return {"id": existing["id"], "created": False, "updated": True, "revived": revived,
                "status": new_status}
    cur = conn.execute(
        "INSERT INTO threat_indicators (type, value, confidence, source_id, status, ttl_hours, first_seen, "
        "last_seen, mitre_tactics, mitre_techniques, notes, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (body.type, body.value, body.confidence, body.source_id, status, body.ttl_hours, now, now,
         db.jdump(body.mitre_tactics), db.jdump(body.mitre_techniques), body.notes, now, now))
    conn.commit()
    record_audit(conn, _actor(user), "intel.indicator.created", target_type="threat_indicator",
                 target_id=str(cur.lastrowid),
                 detail={"type": body.type, "value": body.value, "status": status,
                         "ttl_hours": body.ttl_hours})
    return _shape(db.one(conn, "SELECT * FROM threat_indicators WHERE id = ?", (cur.lastrowid,)))


@router.get("/indicators")
def list_indicators(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("intel.read")),
                    type: str | None = None, status: str | None = None,
                    min_confidence: int | None = Query(default=None, ge=0, le=100),
                    q: str | None = None,
                    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    expire_due(conn)      # SEC-087: TTL is enforced on read
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
    out = db.paged(conn, sql, tuple(params), "ORDER BY i.confidence DESC, i.id DESC", page, page_size)
    for idx, it in enumerate(out["items"]):
        out["items"][idx] = _shape(it)
        out["items"][idx]["expires_at"] = expires_at(it.get("first_seen"), it.get("ttl_hours"))
    return out


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
    expired_on_arrival = 0
    for ind in parsed:
        conf = ind.get("confidence") or body.default_confidence
        first_seen = ind.get("valid_from") or now
        # SEC-087: translate the bundle's validity window into the local model.
        ttl_hours, status, _ = _stix_window(first_seen, ind.get("valid_until"), now)
        if status == "expired":
            expired_on_arrival += 1
        existing = db.one(conn, "SELECT id, status FROM threat_indicators WHERE type = ? AND value = ?",
                          (ind["type"], ind["value"]))
        if existing:
            revived = existing["status"] == "expired" and status == "active"
            new_status = "active" if revived else existing["status"]
            conn.execute("UPDATE threat_indicators SET last_seen = ?, updated_at = ?, status = ?, "
                         "ttl_hours = COALESCE(?, ttl_hours) WHERE id = ?",
                         (now, now, new_status, ttl_hours, existing["id"]))
            updated += 1
        else:
            conn.execute(
                "INSERT INTO threat_indicators (type, value, confidence, source_id, status, ttl_hours, "
                "first_seen, last_seen, notes, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ind["type"], ind["value"], conf, body.source_id, status, ttl_hours, first_seen, now,
                 f"imported via STIX: {ind.get('name', '')}"[:1000], now, now))
            created += 1
    conn.commit()
    record_audit(conn, _actor(user), "intel.stix.imported", target_type="intel",
                 detail={"created": created, "updated": updated,
                         "expired_on_arrival": expired_on_arrival})
    return {"created": created, "updated": updated, "total_parsed": len(parsed),
            "expired_on_arrival": expired_on_arrival}


@router.get("/indicators/correlate")
def correlate(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("intel.read")),
              window_hours: int = Query(default=72, ge=1, le=24 * 30)):
    """Cross-reference active indicators with recent event data (host/ip/user fields + data JSON)."""
    expire_due(conn)      # SEC-087: never correlate against a stale IOC
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
def update_indicator(ind_id: int, body: IndicatorUpdateIn, conn: sqlite3.Connection = Depends(db.get_conn),
                     user: dict = Depends(require("intel.write"))):
    i = db.one(conn, "SELECT * FROM threat_indicators WHERE id = ?", (ind_id,))
    if not i:
        raise HTTPException(404, {"code": "not_found"})
    # SEC-088: only the fields the caller actually sent are written.
    provided = body.model_fields_set
    if not provided:
        raise HTTPException(400, {"code": "no_changes",
                                  "message": "Send at least one field to update."})
    if "type" in provided and body.type not in IND_TYPES:
        raise HTTPException(400, {"code": "bad_type", "message": f"type must be one of {sorted(IND_TYPES)}"})
    if "status" in provided and body.status not in IND_STATUSES:
        raise HTTPException(400, {"code": "bad_status",
                                  "message": f"status must be one of {sorted(IND_STATUSES)}"})
    if "source_id" in provided and body.source_id and \
            not db.one(conn, "SELECT id FROM intel_sources WHERE id = ?", (body.source_id,)):
        raise HTTPException(400, {"code": "bad_source"})
    new_type = body.type if "type" in provided else i["type"]
    new_value = body.value if "value" in provided else i["value"]
    if (new_type, new_value) != (i["type"], i["value"]):
        # create() dedupes on (type, value); an edit must not smuggle in a pair
        # that already exists, or the dedupe invariant breaks via the back door.
        if db.one(conn, "SELECT id FROM threat_indicators WHERE type = ? AND value = ? AND id <> ?",
                  (new_type, new_value, ind_id)):
            raise HTTPException(409, {"code": "duplicate_indicator",
                                      "message": f"{new_type} {new_value} already exists"})
    columns = {"type": new_type, "value": new_value, "confidence": body.confidence,
               "source_id": body.source_id, "ttl_hours": body.ttl_hours,
               "mitre_tactics": db.jdump(body.mitre_tactics),
               "mitre_techniques": db.jdump(body.mitre_techniques), "notes": body.notes,
               "status": body.status}
    sets = [f"{c} = ?" for c in columns if c in provided]
    params = [columns[c] for c in columns if c in provided]
    conn.execute(f"UPDATE threat_indicators SET {', '.join(sets)}, updated_at = ? WHERE id = ?",
                 (*params, db.utcnow(), ind_id))
    conn.commit()
    record_audit(conn, _actor(user), "intel.indicator.updated", target_type="threat_indicator",
                 target_id=str(ind_id),
                 detail={"changed": sorted(provided), "status": i["status"] if "status" not in provided
                         else body.status})
    return _shape(db.one(conn, "SELECT * FROM threat_indicators WHERE id = ?", (ind_id,)))
