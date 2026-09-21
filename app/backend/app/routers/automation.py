"""Automation: playbooks, triggers, dry-run, execution history (SEC-056).

Playbook steps use the SAME policy engine as the agent gateway: every step is
tool-allowlisted, injection-checked, and consequential steps need approval.
Dry-run returns the validated plan without executing anything.
"""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require
from ..services import policy

router = APIRouter(prefix="/api/automation", tags=["automation"])

# Automation runs as the 'internal-automation' agent identity (allowlisted).
AUTOMATION_AGENT_NAME = "internal-automation"


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


def _automation_agent(conn) -> dict | None:
    return db.one(conn, "SELECT * FROM agents WHERE name = ?", (AUTOMATION_AGENT_NAME,))


class PlaybookIn(BaseModel):
    name: str = Field(min_length=2, max_length=120, pattern=r"^[a-z0-9._-]+$")
    description: str | None = Field(default=None, max_length=500)
    trigger: str = "manual"  # manual | on_alert:critical | on_alert:high | on_alert:medium
    steps: list[dict] = Field(min_length=1, description="[{'tool': str, 'args': object}]")
    auto_run: bool = False


@router.post("", status_code=201)
def create_playbook(body: PlaybookIn, conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("automation.write"))):
    if body.trigger != "manual" and not body.trigger.startswith("on_alert:"):
        raise HTTPException(400, {"code": "bad_trigger",
                                  "message": "trigger must be 'manual' or 'on_alert:<severity>'"})
    if db.one(conn, "SELECT id FROM playbooks WHERE name = ?", (body.name,)):
        raise HTTPException(409, {"code": "exists"})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO playbooks (name, description, trigger, steps, status, auto_run, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 'active', ?, ?, ?)",
        (body.name, body.description, body.trigger, db.jdump(body.steps), int(body.auto_run), now, now))
    conn.commit()
    record_audit(conn, _actor(user), "playbook.created", target_type="playbook",
                 target_id=str(cur.lastrowid), detail={"name": body.name, "trigger": body.trigger})
    return db.one(conn, "SELECT * FROM playbooks WHERE id = ?", (cur.lastrowid,))


@router.get("")
def list_playbooks(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("automation.read"))):
    rows = db.q(conn, "SELECT * FROM playbooks ORDER BY name")
    for r in rows:
        r["steps"] = db.jload(r.get("steps"), [])
    return {"items": rows, "total": len(rows)}


class RunIn(BaseModel):
    dry_run: bool = False
    note: str | None = Field(default=None, max_length=300)


@router.post("/{pb_id}/run")
def run_playbook(pb_id: int, body: RunIn, conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("automation.run"))):
    pb = db.one(conn, "SELECT * FROM playbooks WHERE id = ?", (pb_id,))
    if not pb:
        raise HTTPException(404, {"code": "not_found"})
    steps = db.jload(pb["steps"], [])
    agent = _automation_agent(conn)
    if not agent:
        raise HTTPException(503, {"code": "automation_agent_missing",
                                  "message": f"agent '{AUTOMATION_AGENT_NAME}' not registered"})

    plan = policy.plan_task(conn, agent, {"steps": steps}, _actor(user))
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO playbook_runs (playbook_id, trigger, status, started_at, result) VALUES (?, ?, ?, ?, ?)",
        (pb_id, "manual", "pending", now, None))
    run_id = int(cur.lastrowid)

    if body.dry_run:
        conn.execute("UPDATE playbook_runs SET status = 'completed', finished_at = ?, result = ? WHERE id = ?",
                     (now, db.jdump({"dry_run": True, "plan": plan, "executed": False}), run_id))
        conn.commit()
        record_audit(conn, _actor(user), "playbook.dry_run", target_type="playbook", target_id=str(pb_id),
                     detail={"run_id": run_id})
        return {"run_id": run_id, "dry_run": True, "plan": plan}

    if plan["status"] == "denied":
        conn.execute("UPDATE playbook_runs SET status = 'failed', finished_at = ?, result = ? WHERE id = ?",
                     (now, db.jdump({"error": "denied", "reasons": plan["reasons"]}), run_id))
        conn.commit()
        record_audit(conn, _actor(user), "playbook.failed", target_type="playbook", target_id=str(pb_id),
                     detail={"reasons": plan["reasons"][:5]})
        return {"run_id": run_id, "status": "denied", "reasons": plan["reasons"]}

    if plan["status"] == "awaiting_approval":
        for step in plan["steps"]:
            if not policy.TOOL_REGISTRY[step["tool"]]["read_only"]:
                conn.execute("INSERT INTO approvals (task_id, action, status, requested_by, created_at) "
                             "VALUES (?, ?, 'pending', ?, ?)",
                             (0, f"playbook:{pb['name']}:{step['tool']}", user["username"], now))
        conn.execute("UPDATE playbook_runs SET status = 'pending', result = ? WHERE id = ?",
                     (db.jdump({"awaiting_approval": True, "plan": plan}), run_id))
        conn.commit()
        record_audit(conn, _actor(user), "playbook.awaiting_approval", target_type="playbook",
                     target_id=str(pb_id), detail={"run_id": run_id})
        return {"run_id": run_id, "status": "awaiting_approval", "reasons": plan["reasons"]}

    # Execute read-only steps.
    task = {"id": run_id, "request": db.jdump({"steps": plan["steps"]})}
    result = policy.execute_task(conn, task, agent)
    status = "completed" if not result.get("errors") else "failed"
    conn.execute("UPDATE playbook_runs SET status = ?, finished_at = ?, result = ? WHERE id = ?",
                 (status, db.utcnow(), db.jdump(result), run_id))
    conn.commit()
    record_audit(conn, _actor(user), f"playbook.{status}", target_type="playbook", target_id=str(pb_id),
                 detail={"run_id": run_id, "errors": result.get("errors", [])[:5]})
    return {"run_id": run_id, "status": status, "result": result}


@router.get("/runs")
def list_runs(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("automation.read")),
              playbook_id: int | None = None, status: str | None = None):
    where, params = ["1=1"], []
    if playbook_id is not None:
        where.append("playbook_id = ?")
        params.append(playbook_id)
    if status:
        where.append("status = ?")
        params.append(status)
    rows = db.q(conn, "SELECT * FROM playbook_runs WHERE " + " AND ".join(where) +
                " ORDER BY id DESC LIMIT 200", tuple(params))
    for r in rows:
        r["result"] = db.jload(r.get("result"))
    return {"items": rows, "total": len(rows)}


# Hook used by the SOC ingest path (trigger: on_alert:<severity>).
def _trigger_on_alert(conn, raised_alerts: list[dict]) -> None:
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for a in raised_alerts:
        if a.get("status") != "created":
            continue  # only NEW alerts trigger playbooks (no re-runs on refresh)
        plays = db.q(conn, "SELECT * FROM playbooks WHERE status = 'active' AND trigger LIKE 'on_alert:%'")
        for p in plays:
            need = p["trigger"].split(":", 1)[1].lower()
            if sev_rank.get(a.get("severity", "info"), 0) >= sev_rank.get(need, 99):
                conn.execute(
                    "INSERT INTO playbook_runs (playbook_id, trigger, status, started_at) VALUES (?, ?, 'pending', ?)",
                    (p["id"], f"on_alert:{a['id']}", db.utcnow()))
                conn.commit()
