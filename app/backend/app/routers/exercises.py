"""Authorized Red Team / CTF exercises (SEC-055).

Scope is mandatory written text; targets are inventory only — the platform
never initiates network action against targets (see threat model + ADR-003).
Status flow enforces authorization BEFORE running.
"""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require

router = APIRouter(prefix="/api/exercises", tags=["exercises"])

# NOTE: must be a tuple (ordered) — a set here would make ORDER depend on
# per-process hash randomization (PYTHONHASHSEED), breaking the state machine.
STATUSES = ("planned", "authorized", "running", "completed", "aborted")
ORDER = {s: i for i, s in enumerate(STATUSES)}


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


class ExerciseIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    scope: str = Field(min_length=20, max_length=4000,
                       description="Written, explicit authorization scope (mandatory).")
    owner: str | None = Field(default=None, max_length=100)
    starts_at: str | None = Field(default=None, max_length=40)
    ends_at: str | None = Field(default=None, max_length=40)
    targets: list[str] | None = None
    meta: dict | None = None


@router.post("", status_code=201)
def create_exercise(body: ExerciseIn, conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("exercises.write"))):
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO exercises (name, scope, status, owner, starts_at, ends_at, targets, meta, created_at, updated_at) "
        "VALUES (?, ?, 'planned', ?, ?, ?, ?, ?, ?, ?)",
        (body.name, body.scope, body.owner, body.starts_at, body.ends_at,
         db.jdump(body.targets), db.jdump(body.meta), now, now))
    conn.commit()
    record_audit(conn, _actor(user), "exercise.created", target_type="exercise", target_id=str(cur.lastrowid),
                 detail={"name": body.name})
    return db.one(conn, "SELECT * FROM exercises WHERE id = ?", (cur.lastrowid,))


@router.get("")
def list_exercises(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("exercises.read")),
                   status: str | None = None):
    sql, params = "SELECT * FROM exercises", ()
    if status:
        sql += " WHERE status = ?"
        params = (status,)
    rows = db.q(conn, f"{sql} ORDER BY updated_at DESC, id DESC", params)
    for r in rows:
        r["targets"] = db.jload(r.get("targets"), [])
        r["meta"] = db.jload(r.get("meta"), {})
    return {"items": rows, "total": len(rows)}


@router.get("/{ex_id}")
def get_exercise(ex_id: int, conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("exercises.read"))):
    e = db.one(conn, "SELECT * FROM exercises WHERE id = ?", (ex_id,))
    if not e:
        raise HTTPException(404, {"code": "not_found"})
    e["runs"] = db.q(conn, "SELECT * FROM exercise_runs WHERE exercise_id = ? ORDER BY id DESC", (ex_id,))
    return e


class ExerciseUpdate(BaseModel):
    status: str | None = None
    owner: str | None = Field(default=None, max_length=100)
    starts_at: str | None = Field(default=None, max_length=40)
    ends_at: str | None = Field(default=None, max_length=40)
    targets: list[str] | None = None
    meta: dict | None = None
    reason: str | None = Field(default=None, max_length=500)


@router.patch("/{ex_id}")
def update_exercise(ex_id: int, body: ExerciseUpdate, conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("exercises.write"))):
    e = db.one(conn, "SELECT * FROM exercises WHERE id = ?", (ex_id,))
    if not e:
        raise HTTPException(404, {"code": "not_found"})
    if body.status:
        if body.status not in STATUSES:
            raise HTTPException(400, {"code": "bad_status"})
        # Guard: cannot run or complete an exercise that is not authorized.
        if ORDER.get(body.status, 0) >= ORDER["running"] and e["status"] not in {"authorized", "running"}:
            raise HTTPException(409, {"code": "not_authorized",
                                      "message": "Exercise must be in 'authorized' status before running."})
        if body.status == "running":
            cur = conn.execute(
                "INSERT INTO exercise_runs (exercise_id, started_at, result, detail) VALUES (?, ?, 'running', ?)",
                (ex_id, db.utcnow(), db.jdump({"triggered_by": user["username"]})))
            e["run_id"] = int(cur.lastrowid)
    fields, params = [], []
    for k in ("status", "owner", "starts_at", "ends_at"):
        if getattr(body, k) is not None:
            fields.append(f"{k} = ?")
            params.append(getattr(body, k))
    if body.targets is not None:
        fields.append("targets = ?")
        params.append(db.jdump(body.targets))
    if body.meta is not None:
        fields.append("meta = ?")
        params.append(db.jdump(body.meta))
    if not fields:
        raise HTTPException(400, {"code": "no_changes"})
    fields.append("updated_at = ?")
    params.append(db.utcnow())
    params.append(ex_id)
    conn.execute(f"UPDATE exercises SET {', '.join(fields)} WHERE id = ?", params)
    if body.status in {"completed", "aborted"}:
        run = db.one(conn, "SELECT id FROM exercise_runs WHERE exercise_id = ? AND result = 'running' "
                           "ORDER BY id DESC LIMIT 1", (ex_id,))
        if run:
            result = "completed" if body.status == "completed" else "aborted"
            conn.execute("UPDATE exercise_runs SET finished_at = ?, result = ?, detail = ? WHERE id = ?",
                         (db.utcnow(), result, db.jdump({"reason": body.reason}), run["id"]))
    conn.commit()
    record_audit(conn, _actor(user), "exercise.updated", target_type="exercise", target_id=str(ex_id),
                 detail={"status": body.status, "reason": body.reason})
    return db.one(conn, "SELECT * FROM exercises WHERE id = ?", (ex_id,))
