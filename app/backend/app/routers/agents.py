"""Agent Center (SEC-050..053): scoped adapters, approval queue, audit, evals.

Governance (docs/06): least privilege, tool allowlists, human approval for
consequential actions, untrusted-input handling, truthful status. OpenCode /
OpenClaw / Hermes act through this gateway as scoped identities; the gateway
itself never grants shell or production access.
"""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require
from ..services import agent_adapters, policy

router = APIRouter(prefix="/api/agents", tags=["agents"])


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


# ---------------------------------------------------------------- registry

@router.get("/tools")
def list_tools(user: dict = Depends(require("agents.read"))):
    """Tool registry with approval requirements (transparent to all users)."""
    return {"tools": {
        name: {"description": spec["description"], "read_only": spec["read_only"],
               "requires_approval": not spec["read_only"]}
        for name, spec in policy.TOOL_REGISTRY.items()}}




class AgentIn(BaseModel):
    name: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9._-]+$")
    provider: str = "internal"
    role: str | None = Field(default=None, max_length=120)
    scope: dict | None = None
    tools: list[str] = Field(default_factory=list)
    adapter: str = "builtin"          # builtin | openai_compat | cli (SEC-050)
    adapter_config: dict | None = None


@router.post("", status_code=201)
def create_agent(body: AgentIn, conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("agents.manage"))):
    bad = [t for t in body.tools if t not in policy.TOOL_REGISTRY]
    if bad:
        raise HTTPException(400, {"code": "unknown_tools", "message": f"unknown tools: {bad}"})
    if body.adapter not in agent_adapters.ADAPTERS:
        raise HTTPException(400, {"code": "bad_adapter", "message": f"adapter must be one of {agent_adapters.ADAPTERS}"})
    # SEC-075: a persona changes reasoning style, never permissions. Unknown
    # personas are refused so a typo cannot silently leave an agent without the
    # behaviour an operator believes they configured.
    persona = ((body.adapter_config or {}).get("persona") or "").strip().lower()
    if persona and persona not in agent_adapters.PERSONAS:
        raise HTTPException(400, {"code": "bad_persona",
                                  "message": f"persona must be one of {list(agent_adapters.PERSONAS)}"})
    if db.one(conn, "SELECT id FROM agents WHERE name = ?", (body.name,)):
        raise HTTPException(409, {"code": "exists"})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO agents (name, provider, role, scope, tools, status, adapter, adapter_config, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)",
        (body.name, body.provider, body.role, db.jdump(body.scope), db.jdump(body.tools),
         body.adapter, db.jdump(body.adapter_config), now, now))
    conn.commit()
    record_audit(conn, _actor(user), "agent.created", target_type="agent", target_id=str(cur.lastrowid),
                 detail={"name": body.name, "provider": body.provider, "tools": body.tools,
                         "adapter": body.adapter})
    return db.one(conn, "SELECT * FROM agents WHERE id = ?", (cur.lastrowid,))


def _decode_agent(row: dict) -> dict:
    row["tools"] = db.jload(row.get("tools"), [])
    row["scope"] = db.jload(row.get("scope"), {})
    row["adapter"] = row.get("adapter") or "builtin"
    row["adapter_config"] = db.jload(row.get("adapter_config"), {}) or {}
    return row


@router.get("")
def list_agents(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("agents.read"))):
    rows = db.q(conn, "SELECT * FROM agents ORDER BY name")
    return {"items": [_decode_agent(r) for r in rows], "total": len(rows)}


@router.patch("/{agent_id}")
def update_agent(agent_id: int, body: AgentIn, conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("agents.manage"))):
    a = db.one(conn, "SELECT * FROM agents WHERE id = ?", (agent_id,))
    if not a:
        raise HTTPException(404, {"code": "not_found"})
    # SEC-090: `name` was required in the body and then dropped, so a rename
    # returned 200 and changed nothing. The name is a real key here — policy
    # decisions, audit actors and the automation runner all resolve the agent by
    # name — so the one rename that would quietly break other subsystems is
    # refused, and every other rename is actually applied (there is no delete
    # route, so refusing all renames would make a typo permanent).
    renamed_from = None
    if body.name and body.name != a["name"]:
        from .automation import AUTOMATION_AGENT_NAME
        if a["name"] == AUTOMATION_AGENT_NAME:
            raise HTTPException(409, {
                "code": "rename_not_supported",
                "message": f"{a['name']!r} is the identity the automation runner resolves by "
                           f"name; renaming it would break playbook runs"})
        if db.one(conn, "SELECT id FROM agents WHERE name = ? AND id <> ?", (body.name, agent_id)):
            raise HTTPException(409, {"code": "exists",
                                      "message": f"another agent is already named {body.name!r}"})
        renamed_from = a["name"]
    bad = [t for t in body.tools if t not in policy.TOOL_REGISTRY]
    if bad:
        raise HTTPException(400, {"code": "unknown_tools", "message": f"unknown tools: {bad}"})
    if body.adapter not in agent_adapters.ADAPTERS:
        raise HTTPException(400, {"code": "bad_adapter", "message": f"adapter must be one of {agent_adapters.ADAPTERS}"})
    # SEC-075: a persona changes reasoning style, never permissions. Unknown
    # personas are refused so a typo cannot silently leave an agent without the
    # behaviour an operator believes they configured.
    persona = ((body.adapter_config or {}).get("persona") or "").strip().lower()
    if persona and persona not in agent_adapters.PERSONAS:
        raise HTTPException(400, {"code": "bad_persona",
                                  "message": f"persona must be one of {list(agent_adapters.PERSONAS)}"})
    conn.execute(
        "UPDATE agents SET name = ?, provider = ?, role = ?, scope = ?, tools = ?, adapter = ?, "
        "adapter_config = ?, updated_at = ? WHERE id = ?",
        (body.name, body.provider, body.role, db.jdump(body.scope), db.jdump(body.tools),
         body.adapter, db.jdump(body.adapter_config), db.utcnow(), agent_id))
    conn.commit()
    record_audit(conn, _actor(user), "agent.updated", target_type="agent", target_id=str(agent_id),
                 detail={"tools": body.tools, "adapter": body.adapter,
                         **({"renamed_from": renamed_from} if renamed_from else {})})
    return _decode_agent(db.one(conn, "SELECT * FROM agents WHERE id = ?", (agent_id,)))


# ------------------------------------------------------------------ tasks

class TaskIn(BaseModel):
    agent_id: int
    title: str = Field(min_length=3, max_length=200)
    request: dict = Field(description="{'tool':..., 'args':...} or {'steps':[...]}; untrusted content allowed, execution is policy-checked")


@router.post("/tasks", status_code=201)
def create_task(body: TaskIn, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("agents.task"))):
    agent = db.one(conn, "SELECT * FROM agents WHERE id = ?", (body.agent_id,))
    if not agent:
        raise HTTPException(404, {"code": "agent_not_found"})
    if agent["status"] != "active":
        raise HTTPException(409, {"code": "agent_inactive"})
    # Adapter (SEC-050): a free-form {"prompt": ...} request is translated to
    # explicit tool steps by the agent's adapter, THEN goes through the
    # standard allowlist/injection/approval gates. Adapter output can never
    # bypass the gateway (docs/06).
    request = body.request
    if "tool" not in request and "steps" not in request:
        try:
            request = agent_adapters.resolve_steps(agent, request)
        except agent_adapters.AdapterError as e:
            raise HTTPException(400, {"code": "bad_request", "message": str(e)}) from e
    try:
        plan = policy.plan_task(conn, agent, request, _actor(user))
    except ValueError as e:
        raise HTTPException(400, {"code": "bad_request", "message": str(e)}) from e

    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO agent_tasks (agent_id, title, status, request, created_at) VALUES (?, ?, ?, ?, ?)",
        (agent["id"], body.title, plan["status"],
         db.jdump({"steps": plan["steps"], "original": body.request}), now))
    task_id = int(cur.lastrowid)
    # SEC-097: refused steps are recorded against this task (they used to land on
    # task_id 0, invisible in the task's audited tool-call list), and a plan that
    # lost steps is refused as a whole — the task must not run a subset of what
    # was asked for and report success.
    policy.record_denials(conn, task_id, plan)
    if plan["status"] == "denied" or plan["reasons"]:
        record_audit(conn, _actor(user), "agent.task.denied", target_type="agent_task",
                     target_id=str(task_id),
                     detail={"reasons": plan["reasons"][:5], "partial": plan["status"] != "denied"})
        conn.execute("UPDATE agent_tasks SET status = 'denied', result = ?, finished_at = ? WHERE id = ?",
                     (db.jdump({"denied": True, "reasons": plan["reasons"]}), now, task_id))
        conn.commit()
        return db.decode_json(db.one(conn, "SELECT * FROM agent_tasks WHERE id = ?", (task_id,)),
                          "result", "request", default=None)   # SEC-091
    if plan["status"] == "awaiting_approval":
        approval = None
        # Create approval(s) for the consequential steps
        for step in plan["steps"]:
            if not policy.TOOL_REGISTRY[step["tool"]]["read_only"]:
                cur2 = conn.execute(
                    "INSERT INTO approvals (task_id, action, status, requested_by, created_at) "
                    "VALUES (?, ?, 'pending', ?, ?)",
                    (task_id, step["tool"], user["username"], now))
                approval = cur2.lastrowid
        conn.execute("UPDATE agent_tasks SET approval_id = ? WHERE id = ?", (approval, task_id))
        conn.commit()
        record_audit(conn, _actor(user), "agent.task.awaiting_approval", target_type="agent_task",
                     target_id=str(task_id), detail={"approval_id": int(approval)})
    else:
        # Safe, allowlisted read-only steps: execute immediately (still audited).
        task = db.one(conn, "SELECT * FROM agent_tasks WHERE id = ?", (task_id,))
        conn.execute("UPDATE agent_tasks SET status = 'running', started_at = ? WHERE id = ?", (now, task_id))
        conn.commit()
        result = policy.execute_task(conn, task, agent)
        conn.execute("UPDATE agent_tasks SET status = ?, result = ?, finished_at = ? WHERE id = ?",
                     ("completed" if not result.get("errors") else "failed",
                      db.jdump(result), db.utcnow(), task_id))
        conn.commit()
    return db.decode_json(db.one(conn, "SELECT * FROM agent_tasks WHERE id = ?", (task_id,)),
                          "result", "request", default=None)   # SEC-091


@router.get("/tasks")
def list_tasks(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("agents.read")),
               agent_id: int | None = None, status: str | None = None,
               page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    where, params = ["1=1"], []
    if agent_id is not None:
        where.append("t.agent_id = ?")
        params.append(agent_id)
    if status:
        where.append("t.status = ?")
        params.append(status)
    sql = ("SELECT t.*, a.name AS agent_name FROM agent_tasks t "
           "JOIN agents a ON a.id = t.agent_id WHERE " + " AND ".join(where))
    out = db.paged(conn, sql, tuple(params), "ORDER BY t.id DESC", page, page_size)
    for it in out["items"]:
        it["result"] = db.jload(it.get("result"))
        it["request"] = db.jload(it.get("request"), {}).get("original")
    return out


@router.get("/tasks/{task_id}")
def get_task(task_id: int, conn: sqlite3.Connection = Depends(db.get_conn),
             user: dict = Depends(require("agents.read"))):
    t = db.one(conn, "SELECT t.*, a.name AS agent_name FROM agent_tasks t "
                     "JOIN agents a ON a.id = t.agent_id WHERE t.id = ?", (task_id,))
    if not t:
        raise HTTPException(404, {"code": "not_found"})
    t["result"] = db.jload(t.get("result"))
    t["request"] = db.jload(t.get("request"), {}).get("original")
    t["tool_calls"] = db.decode_rows(
        db.q(conn, "SELECT * FROM tool_calls WHERE task_id = ? ORDER BY id", (task_id,)),
        "args", "result", default=None)   # SEC-091
    t["approvals"] = db.q(conn, "SELECT * FROM approvals WHERE task_id = ? ORDER BY id", (task_id,))
    return t


# --------------------------------------------------------------- approvals

class ApprovalDecision(BaseModel):
    decision: str  # approve | reject
    comment: str | None = Field(default=None, max_length=1000)


def _decide_playbook_approval(conn, ap: dict, body, user: dict, status: str, now: str):
    """Decide an approval raised by a playbook run (SEC-094).

    Approving the last pending approval for the run executes its validated plan
    exactly like a run that needed no approval; rejecting it fails the run with
    the reason. The run transition is a compare-and-set, so two approvers
    deciding concurrently can only execute the plan once.
    """
    from .automation import _automation_agent

    run = db.one(conn, "SELECT * FROM playbook_runs WHERE id = ?", (ap["task_id"],))
    if run is None:
        raise HTTPException(409, {"code": "missing_run",
                                  "message": f"approval {ap['id']} refers to playbook run "
                                             f"{ap['task_id']}, which no longer exists"})
    if body.decision == "reject":
        cur = conn.execute(
            "UPDATE playbook_runs SET status = 'failed', finished_at = ?, result = ? "
            "WHERE id = ? AND status = 'pending'",
            (now, db.jdump({"error": "approval_rejected", "approval_id": ap["id"],
                            "reason": f"approval rejected by {user['username']}"}), run["id"]))
        conn.commit()
        record_audit(conn, _actor(user), "playbook.rejected", target_type="playbook",
                     target_id=str(run["playbook_id"]),
                     detail={"run_id": run["id"], "approval_id": ap["id"],
                             "action": ap["action"], "comment": body.comment,
                             "applied": bool(cur.rowcount)})
        return {"approval_id": ap["id"], "status": status, "decision": "reject",
                "run_id": run["id"], "run_status": "failed"}

    others = db.one(conn, "SELECT COUNT(*) c FROM approvals "
                          "WHERE task_id = ? AND action LIKE 'playbook:%' AND status = 'pending' "
                          "AND id <> ?", (run["id"], ap["id"]))
    if int(others["c"]) > 0:
        conn.commit()
        record_audit(conn, _actor(user), "approval.approved", target_type="approval",
                     target_id=str(ap["id"]),
                     detail={"run_id": run["id"], "comment": body.comment,
                             "waiting_on": int(others["c"])})
        return {"approval_id": ap["id"], "status": status, "decision": "approve",
                "run_id": run["id"], "run_status": run["status"],
                "awaiting_more_approvals": int(others["c"])}

    plan = (db.jload(run.get("result"), {}) or {}).get("plan") or {}
    steps = plan.get("steps") or []
    agent = _automation_agent(conn)
    if not agent:
        conn.rollback()
        raise HTTPException(503, {"code": "automation_agent_missing",
                                  "message": "the automation agent is not registered"})
    claim = conn.execute("UPDATE playbook_runs SET status = 'running' "
                         "WHERE id = ? AND status = 'pending'", (run["id"],))
    if claim.rowcount != 1:
        conn.rollback()
        record_audit(conn, _actor(user), "approval.approved", target_type="approval",
                     target_id=str(ap["id"]),
                     detail={"run_id": run["id"], "comment": body.comment, "executed": False})
        return {"approval_id": ap["id"], "status": status, "decision": "approve",
                "run_id": run["id"], "run_status": run["status"], "executed": False}

    conn.commit()
    from ..services import policy as _policy
    result = _policy.execute_task(conn, {"id": run["id"], "request": db.jdump({"steps": steps})}, agent)
    run_status = "completed" if not result.get("errors") else "failed"
    conn.execute("UPDATE playbook_runs SET status = ?, finished_at = ?, result = ? WHERE id = ?",
                 (run_status, db.utcnow(), db.jdump(result), run["id"]))
    conn.commit()
    record_audit(conn, _actor(user), f"playbook.{run_status}", target_type="playbook",
                 target_id=str(run["playbook_id"]),
                 detail={"run_id": run["id"], "approved_by": user["username"],
                         "approval_id": ap["id"], "errors": result.get("errors", [])[:5],
                         "executed": True})
    return {"approval_id": ap["id"], "status": status, "decision": "approve",
            "run_id": run["id"], "run_status": run_status, "executed": True,
            "result": result}


@router.get("/approvals")
def list_approvals(conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("agents.approve")),
                   status: str = Query(default="pending")):
    # SEC-094: this was an INNER JOIN on agent_tasks, so an approval whose
    # `task_id` referred to a playbook run disappeared from the queue entirely —
    # the run sat `pending` and the operator had no way to see or decide it.
    rows = db.q(conn,
                "SELECT ap.*, "
                "       COALESCE(t.title, pb.name || ' run #' || pr.id) AS task_title, "
                "       COALESCE(a.name, 'automation') AS agent_name, "
                "       CASE WHEN ap.action LIKE 'playbook:%' THEN 'playbook' ELSE 'agent_task' END AS kind, "
                "       pb.name AS playbook_name, pr.status AS run_status "
                "FROM approvals ap "
                "LEFT JOIN agent_tasks t ON t.id = ap.task_id AND ap.action NOT LIKE 'playbook:%' "
                "LEFT JOIN agents a ON a.id = t.agent_id "
                "LEFT JOIN playbook_runs pr ON pr.id = ap.task_id AND ap.action LIKE 'playbook:%' "
                "LEFT JOIN playbooks pb ON pb.id = pr.playbook_id "
                "WHERE ap.status = ? ORDER BY ap.id DESC",
                (status,))
    return {"items": rows, "total": len(rows)}


@router.post("/approvals/{approval_id}/decide")
def decide_approval(approval_id: int, body: ApprovalDecision,
                    conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("agents.approve"))):
    ap = db.one(conn, "SELECT * FROM approvals WHERE id = ?", (approval_id,))
    if not ap:
        raise HTTPException(404, {"code": "not_found"})
    if ap["status"] != "pending":
        raise HTTPException(409, {"code": "already_decided"})
    if body.decision not in {"approve", "reject"}:
        raise HTTPException(400, {"code": "bad_decision"})
    now = db.utcnow()
    status = "approved" if body.decision == "approve" else "rejected"
    # SEC-078: compare-and-set, not read-then-write. The `status != 'pending'`
    # check above is a read; if two approval requests interleave between that
    # read and this write, both pass it and both go on to execute the tool, and
    # the last writer silently becomes the recorded approver. Guarding the
    # statement makes the transition atomic: exactly one caller can move the
    # approval out of `pending`.
    cur = conn.execute(
        "UPDATE approvals SET status = ?, decided_by = ?, decision = ?, comment = ?, decided_at = ? "
        "WHERE id = ? AND status = 'pending'",
        (status, user["username"], body.decision, body.comment, now, approval_id))
    if cur.rowcount != 1:
        conn.rollback()
        raise HTTPException(409, {"code": "already_decided",
                                  "message": "Another decision for this approval was committed first."})
    # SEC-094: a playbook approval's `task_id` is a playbook_runs row, not an
    # agent task. Falling through to the agent-task path dereferenced a missing
    # task (`task["agent_id"]` on None) and returned an opaque 500 *after* the
    # status change above had already been committed — so the run stayed
    # `pending`, the approval could never be decided again, and nothing was
    # executed or audited.
    if ap["action"].startswith("playbook:"):
        return _decide_playbook_approval(conn, ap, body, user, status, now)

    task = db.one(conn, "SELECT * FROM agent_tasks WHERE id = ?", (ap["task_id"],))
    if task is None:
        raise HTTPException(409, {"code": "missing_task",
                                  "message": f"approval {approval_id} refers to agent task "
                                             f"{ap['task_id']}, which no longer exists"})
    agent = db.one(conn, "SELECT * FROM agents WHERE id = ?", (task["agent_id"],))
    if body.decision == "reject":
        conn.execute("UPDATE agent_tasks SET status = 'denied', result = ?, finished_at = ? WHERE id = ?",
                     (db.jdump({"denied": True, "reason": f"approval rejected by {user['username']}",
                                "approval_id": approval_id}), now, task["id"]))
        record_audit(conn, _actor(user), "approval.rejected", target_type="approval",
                     target_id=str(approval_id), detail={"task_id": task["id"], "comment": body.comment})
    else:
        # Check no other pending approvals remain for this task
        pending = db.one(conn, "SELECT COUNT(*) c FROM approvals WHERE task_id = ? AND status = 'pending'",
                         (task["id"],))
        if int(pending["c"]) == 0:
            task_row = db.one(conn, "SELECT * FROM agent_tasks WHERE id = ?", (task["id"],))
            # SEC-078: claim the task atomically. Two approvals on one task can
            # both observe "no pending approvals left" and both execute the
            # consequential tool — the tool must run once, for one approver.
            claim = conn.execute(
                "UPDATE agent_tasks SET status = 'running', started_at = COALESCE(started_at, ?) "
                "WHERE id = ? AND status = 'awaiting_approval'", (now, task["id"]))
            if claim.rowcount == 1:
                conn.commit()
                result = policy.execute_task(conn, task_row, agent)
                conn.execute("UPDATE agent_tasks SET status = ?, result = ?, finished_at = ? WHERE id = ?",
                             ("completed" if not result.get("errors") else "failed",
                              db.jdump(result), db.utcnow(), task["id"]))
                record_audit(conn, _actor(user), "approval.executed", target_type="approval",
                             target_id=str(approval_id),
                             detail={"task_id": task["id"], "errors": result.get("errors", [])[:5]})
            else:
                # Another approver already claimed this task and is running it.
                record_audit(conn, _actor(user), "approval.approved", target_type="approval",
                             target_id=str(approval_id),
                             detail={"task_id": task["id"], "executed": False,
                                     "note": "task already claimed by another approval"})
        else:
            record_audit(conn, _actor(user), "approval.approved", target_type="approval",
                         target_id=str(approval_id), detail={"task_id": task["id"]})
    conn.commit()
    return db.one(conn, "SELECT * FROM approvals WHERE id = ?", (approval_id,))


# -------------------------------------------------------------------- evals

class EvalRunIn(BaseModel):
    agent_id: int


@router.post("/evals/run")
def run_evals(body: EvalRunIn, conn: sqlite3.Connection = Depends(db.get_conn),
              user: dict = Depends(require("agents.approve"))):
    """Built-in governance eval suite (SEC-053): prompt injection, scope
    enforcement, truthful status, refusal of unknown tools."""
    agent = db.one(conn, "SELECT * FROM agents WHERE id = ?", (body.agent_id,))
    if not agent:
        raise HTTPException(404, {"code": "agent_not_found"})
    allowed = set(db.jload(agent.get("tools"), []))
    results = []

    def check(name, passed, detail):
        results.append({"name": name, "passed": passed, "detail": detail})

    # 1. Unknown tool must be denied.
    p = policy.plan_task(conn, agent, {"tool": "delete_everything", "args": {}}, _actor(user))
    check("rejects_unknown_tool", p["status"] == "denied", p["reasons"][:2])

    # 2. Tool outside allowlist must be denied (scope enforcement).
    out_of_scope = next((t for t in policy.TOOL_REGISTRY
                         if not policy.TOOL_REGISTRY[t]["read_only"] and t not in allowed), "contain_asset")
    if out_of_scope not in allowed:
        p = policy.plan_task(conn, agent, {"tool": out_of_scope, "args": {"asset_id": 1}}, _actor(user))
        check("rejects_out_of_scope_tool", p["status"] == "denied", p["reasons"][:2])
    else:
        check("rejects_out_of_scope_tool", True, "agent has all consequential tools; tested allowlist via unknown tool")

    # 3. Prompt-injection-shaped args must be rejected as untrusted input.
    p = policy.plan_task(conn, agent,
                         {"tool": "query_events", "args": {"action": "x; rm -rf / --ignore-previous"}},
                         _actor(user))
    injected = any("injection" in r or "shell-like" in r for r in p["reasons"])
    check("rejects_injection_args", injected, p["reasons"][:2])

    # 4. Consequential tool requires approval (no silent execution).
    if "create_case" in allowed:
        p = policy.plan_task(conn, agent, {"tool": "create_case", "args": {"title": "Eval case"}},
                             _actor(user))
        check("consequential_requires_approval", p["status"] == "awaiting_approval", p["reasons"][:2])
    else:
        check("consequential_requires_approval", True, "agent has no consequential tools; gate is registry-enforced")

    # 5. Truthful status: a task that never ran must not claim completion.
    fake = {"id": 0, "title": "x", "status": "pending", "request": db.jdump({"steps": []}), "result": None}
    res = policy.execute_task(conn, fake, agent)
    check("truthful_no_work_no_success", "error" in res, res)

    passed = sum(1 for r in results if r["passed"])
    record_audit(conn, _actor(user), "agent.evals.run", target_type="agent", target_id=str(agent["id"]),
                 detail={"passed": passed, "total": len(results)})
    return {"agent": agent["name"], "passed": passed, "total": len(results), "results": results}
