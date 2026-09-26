"""Local training range registry (SEC-115).

The lab half of "cyber-sec lab": the platform already had exercises (written
authorization), the tradecraft scope guard (authorization enforced on evidence)
and synthetic telemetry — but no record of the *targets* those exercises point
at. An authorization could name a host that no container ever served, and
nothing in the platform could tell the difference between "authorized and
running", "authorized but not up" (a session that will fail), and "up but not
authorized" (scope drift, the dangerous one).

This module is the registry of range targets plus the cross-checks the UI and
the scope guard need. It stores metadata only: the containers themselves are
defined in `infra/lab/docker-compose.yml` on an isolated docker network
(`lab_range`, `internal: true`), never on the platform network.
"""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require

router = APIRouter(prefix="/api/lab", tags=["lab"])

KINDS = {"web", "api", "network", "host", "cloud"}
EXPOSURES = {"critical", "high", "medium", "low"}
STATUSES = {"registered", "running", "stopped", "retired"}


def _looks_like_lab_target(name: str) -> bool:
    """Only *range* targets are the registry's business.

    An exercise may legitimately authorize things that are not containers — the
    demo phishing drill authorizes two mailbox addresses, an external engagement
    authorizes a vendor's hostname. Flagging those as "dangling" would make the
    check cry wolf until someone turned it off, which is how scope checks die. So
    the cross-check applies to names that read like range targets (`lab-*`,
    `*.lab`, or anything carrying a port); anything else is listed separately as
    `other_authorized_targets` — visible, but not an error.
    """
    text = (name or "").strip()
    return bool(text) and (text.startswith("lab-") or text.endswith(".lab") or ":" in text)


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


class TargetIn(BaseModel):
    name: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    kind: str = "web"
    endpoint: str = Field(min_length=3, max_length=200)
    image: str | None = Field(default=None, max_length=200)
    exposure: str = "medium"
    purpose: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=1000)


class TargetUpdate(BaseModel):
    kind: str | None = None
    endpoint: str | None = Field(default=None, min_length=3, max_length=200)
    image: str | None = Field(default=None, max_length=200)
    exposure: str | None = None
    status: str | None = None
    purpose: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=1000)


def _validate(kind=None, exposure=None, status=None) -> None:
    for value, allowed, code in ((kind, KINDS, "bad_kind"),
                                 (exposure, EXPOSURES, "bad_exposure"),
                                 (status, STATUSES, "bad_status")):
        if value is not None and value not in allowed:
            raise HTTPException(400, {"code": code, "allowed": sorted(allowed),
                                      "message": f"must be one of {sorted(allowed)}"})


def _normalise_endpoint(endpoint: str) -> str:
    """A lab endpoint is inside the lab: a bare host[:port]. Refuse a scheme, a
    public address or a path, so `https://evil.example/` can never be registered
    as a range target and then matched by an exercise."""
    text = endpoint.strip().strip("/")
    if "://" in text or "/" in text:
        raise HTTPException(400, {"code": "bad_endpoint",
                                  "message": "endpoint must be host[:port] inside the lab network "
                                             "(no scheme, no path)"})
    host = text.split(":")[0]
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or host.endswith(".local"):
        raise HTTPException(400, {"code": "bad_endpoint",
                                  "message": "endpoint must be a lab-network hostname, not the platform host"})
    if "." in host and not host.endswith(".lab"):
        raise HTTPException(400, {"code": "bad_endpoint",
                                  "message": "external names are not range targets — use a lab-network "
                                             "name (or a .lab name)"})
    return text


@router.get("/targets")
def list_targets(conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("lab.read")),
                 status: str | None = None, kind: str | None = None):
    where, params = [], []
    if status:
        where.append("status = ?")
        params.append(status)
    if kind:
        where.append("kind = ?")
        params.append(kind)
    sql = "SELECT * FROM lab_targets"
    if where:
        sql += " WHERE " + " AND ".join(where)
    rows = db.q(conn, sql + " ORDER BY name", tuple(params))
    return {"items": rows, "total": len(rows)}


@router.post("/targets", status_code=201)
def register_target(body: TargetIn, conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("lab.write"))):
    _validate(kind=body.kind, exposure=body.exposure)
    endpoint = _normalise_endpoint(body.endpoint)
    if db.one(conn, "SELECT id FROM lab_targets WHERE name = ?", (body.name,)):
        raise HTTPException(409, {"code": "duplicate", "message": f"{body.name} is already registered"})
    if db.one(conn, "SELECT id FROM lab_targets WHERE endpoint = ?", (endpoint,)):
        raise HTTPException(409, {"code": "duplicate_endpoint",
                                  "message": f"{endpoint} is already a registered target"})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO lab_targets (name, kind, endpoint, image, exposure, status, purpose, notes, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'registered', ?, ?, ?, ?)",
        (body.name, body.kind, endpoint, body.image, body.exposure, body.purpose, body.notes, now, now))
    conn.commit()
    record_audit(conn, _actor(user), "lab.target_registered", target_type="lab_target",
                 target_id=str(cur.lastrowid),
                 detail={"name": body.name, "endpoint": endpoint, "exposure": body.exposure})
    return db.one(conn, "SELECT * FROM lab_targets WHERE id = ?", (cur.lastrowid,))


@router.patch("/targets/{target_id}")
def update_target(target_id: int, body: TargetUpdate,
                  conn: sqlite3.Connection = Depends(db.get_conn),
                  user: dict = Depends(require("lab.write"))):
    row = db.one(conn, "SELECT * FROM lab_targets WHERE id = ?", (target_id,))
    if not row:
        raise HTTPException(404, {"code": "not_found"})
    provided = body.model_fields_set
    if not provided:
        raise HTTPException(400, {"code": "no_changes", "message": "Send at least one field to update."})
    _validate(kind=body.kind if "kind" in provided else None,
              exposure=body.exposure if "exposure" in provided else None,
              status=body.status if "status" in provided else None)
    # Retiring a target that an active exercise still authorizes would leave that
    # authorization pointing at nothing (the defect this feature exists to catch),
    # so it is refused while a live exercise lists it.
    if body.status == "retired":
        holders = db.q(conn, "SELECT name, status, targets FROM exercises "
                             "WHERE status IN ('authorized', 'running')")
        for ex in holders:
            if row["name"] in (db.jload(ex["targets"], []) or []):
                raise HTTPException(409, {
                    "code": "target_in_use",
                    "message": f"exercise '{ex['name']}' ({ex['status']}) still authorizes "
                               f"{row['name']}; close it or remove the target from its scope first"})
    columns = {"kind": body.kind, "endpoint": body.endpoint, "image": body.image,
               "exposure": body.exposure, "status": body.status, "purpose": body.purpose,
               "notes": body.notes}
    if "endpoint" in provided:
        columns["endpoint"] = _normalise_endpoint(body.endpoint or "")
    sets = [f"{c} = ?" for c in columns if c in provided]
    params = [columns[c] for c in columns if c in provided]
    conn.execute(f"UPDATE lab_targets SET {', '.join(sets)}, updated_at = ? WHERE id = ?",
                 (*params, db.utcnow(), target_id))
    conn.commit()
    record_audit(conn, _actor(user), "lab.target_updated", target_type="lab_target",
                 target_id=str(target_id), detail={k: v for k, v in columns.items() if k in provided})
    return db.one(conn, "SELECT * FROM lab_targets WHERE id = ?", (target_id,))


@router.get("/coverage")
def range_coverage(conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("lab.read"))):
    """Cross-check the range against the authorizations: what is authorized but
    not up (a session that will fail), and what is up but authorized by nobody
    (scope drift — the one that matters)."""
    targets = db.q(conn, "SELECT * FROM lab_targets ORDER BY name")
    exercises = db.q(conn, "SELECT id, name, status, owner, starts_at, ends_at, targets FROM exercises "
                           "ORDER BY id")
    by_name = {t["name"]: t for t in targets}
    authorized: dict[str, list[dict]] = {}
    dangling: list[dict] = []
    other: list[dict] = []
    for ex in exercises:
        names = db.jload(ex["targets"], []) or []
        if ex["status"] not in ("authorized", "running"):
            continue
        for name in names:
            if name in by_name:
                authorized.setdefault(name, []).append(
                    {"exercise_id": ex["id"], "name": ex["name"], "status": ex["status"],
                     "owner": ex["owner"], "ends_at": ex["ends_at"]})
            elif _looks_like_lab_target(name):
                dangling.append({"exercise_id": ex["id"], "exercise": ex["name"],
                                 "target": name, "status": ex["status"]})
            else:
                other.append({"exercise_id": ex["id"], "exercise": ex["name"], "target": name})
    out, unavailable, unauthorized = [], [], []
    for target in targets:
        holders = authorized.get(target["name"], [])
        entry = {**target, "authorized_by": holders, "in_scope": bool(holders)}
        out.append(entry)
        if holders and target["status"] not in ("running",):
            unavailable.append({"name": target["name"], "status": target["status"],
                                "exercises": [h["name"] for h in holders]})
        if not holders and target["status"] == "running":
            unauthorized.append({"name": target["name"], "endpoint": target["endpoint"]})
    return {
        "targets": out,
        "counts": {"registered": len(targets),
                   "running": sum(1 for t in targets if t["status"] == "running")},
        "authorized_but_not_running": unavailable,
        "running_but_not_authorized": unauthorized,
        "authorizations_with_no_target": dangling,
        "other_authorized_targets": other,
        "note": ("authorizations_with_no_target counts names that read like range targets "
                 "(lab-*, *.lab, host:port) but are not registered; other_authorized_targets "
                 "(mailboxes, vendor hosts) is informational and does not affect ok"),
        "ok": not (unauthorized or dangling),
    }
