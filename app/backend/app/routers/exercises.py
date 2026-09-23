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

# SEC-083: an engagement's lifecycle is one-way.
#
# The status is not a label — it is the authority the scope guard reads, the
# trigger that starts a run, and the record of whether offensive work was ever
# permitted. Before this table, `running -> planned` was accepted silently
# (authorization evaporated mid-engagement: 2 authorized targets became 0, and
# in-flight tradecraft started being refused and audited as out-of-scope
# attempts) and `aborted -> authorized` was accepted too, quietly restoring the
# authority of an engagement that had been explicitly stopped. Going forward
# means a new engagement with its own authorization; it must never be a quiet
# reversal of this one.
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "planned": {"authorized", "aborted"},
    "authorized": {"running", "completed", "aborted"},
    "running": {"completed", "aborted"},
    "completed": set(),
    "aborted": set(),
}
TERMINAL_STATUSES = {"completed", "aborted"}


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
    if body.status and body.status != e["status"]:
        if body.status not in STATUSES:
            raise HTTPException(400, {"code": "bad_status"})
        # Guard: cannot run or complete an exercise that is not authorized.
        if body.status in {"running", "completed"} and e["status"] == "planned":
            raise HTTPException(409, {"code": "not_authorized",
                                      "message": "Exercise must be in 'authorized' status before running."})
        # SEC-083: no backwards or post-terminal moves (see ALLOWED_TRANSITIONS).
        if body.status not in ALLOWED_TRANSITIONS[e["status"]]:
            # Refusals are visible, like an out-of-scope targeting attempt: a
            # request to withdraw an engagement's authority or reopen a closed
            # one is a governance signal, not just a 409.
            record_audit(conn, _actor(user), "exercise.transition_denied",
                         target_type="exercise", target_id=str(ex_id),
                         detail={"from": e["status"], "to": body.status,
                                 "allowed": sorted(ALLOWED_TRANSITIONS[e["status"]])})
            conn.commit()
            raise HTTPException(409, {
                "code": "illegal_transition",
                "message": (f"an engagement's lifecycle is one-way: "
                            f"{e['status']} -> {body.status} is not a valid transition"),
                "from": e["status"], "to": body.status,
                "allowed": sorted(ALLOWED_TRANSITIONS[e["status"]])})
        # SEC-083: closing an engagement ends an authorization other people and
        # processes depend on, so the closing reason is part of the record (the
        # API previously accepted `aborted` with no reason at all).
        if body.status in TERMINAL_STATUSES and len((body.reason or "").strip()) < 10:
            raise HTTPException(400, {
                "code": "reason_required",
                "message": (f"'{body.status}' closes an engagement — record the outcome "
                            "(at least 10 characters)")})
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
