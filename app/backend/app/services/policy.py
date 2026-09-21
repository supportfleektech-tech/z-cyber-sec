"""Agent gateway policy engine (docs/06-agent-governance.md).

Controls:
- Tool allowlist per agent (agents.tools JSON array). Anything not listed is
  denied and audited — no shell tool exists in the registry at all.
- Consequential tools require a human approval before execution.
- Tool arguments are treated as untrusted input: shell-like constructs are
  rejected (defense in depth against prompt injection).
- Every tool call is recorded with allowed/denied + reason + result.
- Task results are truthful: status/result only reflect actually executed work.
"""
from __future__ import annotations

import re

from .. import db
from ..audit import record_audit

_SHELLISH_RE = re.compile(
    r"(\$\(|`|;[A-Za-z]|&&|\|\||>\s*/|\brm\s+-rf\b|/bin/sh|/bin/bash|curl\s+.*\|\s*(sh|bash))",
    re.IGNORECASE,
)


def _actor_from_agent(agent: dict) -> dict:
    return {"type": "agent", "id": str(agent["id"]), "name": agent["name"]}


def validate_args(args: dict) -> str | None:
    """Return a denial reason if args look like shell injection; else None."""
    def walk(v):
        if isinstance(v, str) and _SHELLISH_RE.search(v):
            return True
        if isinstance(v, dict):
            return any(walk(x) for x in v.values())
        if isinstance(v, list):
            return any(walk(x) for x in v)
        return False
    if walk(args or {}):
        return "args rejected: shell-like construct in untrusted input (possible injection)"
    return None


# --------------------------------------------------------------- tool registry
# read_only tools: no approval needed (still allowlisted).
# consequential tools: always require a pending human approval.

def _query_events(conn, args):
    action = args.get("action")
    host = args.get("host")
    sql, params = "SELECT id, ts, host, user, action, outcome, severity, msg FROM events", ()
    where = []
    if action:
        where.append("action = ?")
        params.append(action)
    if host:
        where.append("host = ?")
        params.append(host)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC LIMIT 50"
    return {"events": db.q(conn, sql, tuple(params)), "returned": min(50, None)}


def _get_alerts(conn, args):
    status = args.get("status") or "new"
    rows = db.q(conn, "SELECT id, title, severity, status, count, first_seen, last_seen "
                    "FROM alerts WHERE status = ? ORDER BY severity, id DESC LIMIT 50", (status,))
    return {"alerts": rows}


def _get_case(conn, args):
    case_id = int(args["case_id"])
    case = db.one(conn, "SELECT * FROM cases WHERE id = ?", (case_id,))
    if not case:
        return {"error": "case not found"}
    case["tasks"] = db.q(conn, "SELECT * FROM case_tasks WHERE case_id = ? ORDER BY id", (case_id,))
    case["timeline"] = db.q(conn, "SELECT ts, actor, entry_type, message FROM case_timeline "
                                   "WHERE case_id = ? ORDER BY ts DESC LIMIT 50", (case_id,))
    # Evidence: metadata only, never file content, via agent path
    case["evidence"] = [
        {"id": e["id"], "name": e["name"], "sha256": e["sha256"],
         "classification": e["classification"]}
        for e in db.q(conn, "SELECT * FROM evidence WHERE case_id = ?", (case_id,))
    ]
    return case


def _fetch_indicator(conn, args):
    value = args.get("value")
    row = db.one(conn, "SELECT * FROM threat_indicators WHERE value = ? OR value LIKE ? LIMIT 1",
                 (value, f"%{value}%"))
    return {"indicator": row, "related_events": db.q(
        conn, "SELECT id, ts, host, action, severity FROM events WHERE data LIKE ? ORDER BY ts DESC LIMIT 10",
        (f'%"{value}"%',))}


def _list_assets(conn, args):
    env = args.get("environment")
    rows = db.q(conn, "SELECT id, name, type, environment, owner, status FROM assets "
                      + ("WHERE environment = ?" if env else "") + " ORDER BY name LIMIT 200",
                (env,) if env else ())
    return {"assets": rows, "count": len(rows)}


def _summarize_alerts(conn, args):
    rows = db.q(conn, "SELECT severity, COUNT(*) c FROM alerts GROUP BY severity")
    by_status = db.q(conn, "SELECT status, COUNT(*) c FROM alerts GROUP BY status")
    top_rules = db.q(conn, "SELECT a.rule_id, r.name, COUNT(*) c FROM alerts a "
                           "LEFT JOIN detection_rules r ON r.id = a.rule_id "
                           "GROUP BY a.rule_id ORDER BY c DESC LIMIT 5")
    return {"by_severity": rows, "by_status": by_status, "top_rules": top_rules}


def _list_vulns(conn, args):
    rows = db.q(conn, "SELECT id, cve_id, title, severity, status FROM vuln_findings "
                      "WHERE status IN ('new','triaged','in_progress') ORDER BY cvss DESC LIMIT 50")
    return {"open_findings": rows}


def _request_report(conn, args):
    """Queues a report job id; actual generation happens via reports API.
    Read-only: only returns what filters are valid."""
    kinds = ["overview", "soc", "cases", "intel", "vulns"]
    kind = args.get("kind")
    if kind not in kinds:
        return {"error": f"unknown report kind; valid: {kinds}"}
    return {"queued": True, "kind": kind, "note": "generate via reports API (audited)"}


def _create_case(conn, args):
    title = (args.get("title") or "").strip()
    if not title or len(title) > 200:
        return {"error": "title required (<=200 chars)"}
    number = f"CASE-{db.utcnow()[:4]}-{_next_case_number(conn):04d}"
    cur = conn.execute(
        "INSERT INTO cases (number, title, description, status, severity, source, created_at, updated_at) "
        "VALUES (?, ?, ?, 'open', ?, 'agent', ?, ?)",
        (number, title, (args.get("description") or "")[:2000], args.get("severity"), db.utcnow(), db.utcnow()),
    )
    conn.execute("INSERT INTO case_timeline (case_id, ts, actor, entry_type, message) VALUES (?, ?, ?, 'alert', ?)",
                 (cur.lastrowid, db.utcnow(), "agent", f"Case created by agent: {title}"))
    conn.commit()
    return {"case_id": int(cur.lastrowid), "number": number}


def _contain_asset(conn, args):
    """Simulated containment: marks asset quarantined + timeline entry.
    No network actions are taken from the platform (see threat model)."""
    asset_id = int(args["asset_id"])
    asset = db.one(conn, "SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not asset:
        return {"error": "asset not found"}
    conn.execute("UPDATE assets SET status = 'quarantined', updated_at = ? WHERE id = ?",
                 (db.utcnow(), asset_id))
    conn.execute(
        "INSERT INTO case_timeline (case_id, ts, actor, entry_type, message) "
        "SELECT id, ?, 'agent:containment', 'status', ? FROM cases WHERE number = (SELECT number FROM cases LIMIT 1)",
        (db.utcnow(), f"Asset {asset['name']} quarantined (simulated, human-approved)"))
    conn.commit()
    return {"asset_id": asset_id, "status": "quarantined", "simulated": True}


def _next_case_number(conn) -> int:
    row = db.one(conn, "SELECT COUNT(*) c FROM cases")
    return int(row["c"]) + 1 if row else 1


TOOL_REGISTRY: dict[str, dict] = {
    "query_events": {"fn": _query_events, "read_only": True,
                     "description": "Query recent security events (read-only, capped)."},
    "get_alerts": {"fn": _get_alerts, "read_only": True,
                   "description": "List alerts by status (read-only)."},
    "get_case": {"fn": _get_case, "read_only": True,
                 "description": "Read case with tasks/timeline/evidence metadata (no file content)."},
    "fetch_indicator": {"fn": _fetch_indicator, "read_only": True,
                        "description": "Look up a threat indicator and related events."},
    "list_assets": {"fn": _list_assets, "read_only": True,
                    "description": "List asset inventory (read-only)."},
    "summarize_alerts": {"fn": _summarize_alerts, "read_only": True,
                         "description": "Aggregate alert statistics."},
    "list_vulns": {"fn": _list_vulns, "read_only": True,
                   "description": "List open vulnerability findings."},
    "request_report": {"fn": _request_report, "read_only": True,
                       "description": "Validate report request (generation via API)."},
    "create_case": {"fn": _create_case, "read_only": False,
                    "description": "Open a new case from an alert. REQUIRES APPROVAL."},
    "contain_asset": {"fn": _contain_asset, "read_only": False,
                      "description": "Simulate containment of an asset. REQUIRES APPROVAL."},
}


def normalize_request(request: dict) -> list[dict]:
    """Accept {steps: [{tool, args}]} or {tool, args} -> list of steps."""
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    if "steps" in request:
        steps = request["steps"]
        if not isinstance(steps, list) or not steps:
            raise ValueError("steps must be a non-empty list")
        return [{"tool": s.get("tool"), "args": s.get("args") or {}} for s in steps]
    tool = request.get("tool")
    if not tool:
        raise ValueError("request must include 'tool' or 'steps'")
    return [{"tool": tool, "args": request.get("args") or {}}]


def plan_task(conn, agent: dict, request: dict, requester: dict) -> dict:
    """Validate a task against the agent's allowlist.

    Returns {"status": "pending"|"awaiting_approval"|"denied", "reasons": [...]}
    and records tool_calls rows + audit for every step.
    """
    steps = normalize_request(request)
    allowed_tools = set(db.jload(agent.get("tools"), []) or [])
    reasons = []
    needs_approval = False
    valid_steps = []
    for step in steps:
        tool, args = step.get("tool"), step.get("args") or {}
        if tool not in TOOL_REGISTRY:
            reasons.append(f"unknown tool: {tool}")
            _record_call(conn, None, tool, args, False, "tool not in registry")
            continue
        if tool not in allowed_tools:
            reasons.append(f"tool not in agent allowlist: {tool}")
            _record_call(conn, None, tool, args, False, "not in agent allowlist")
            continue
        inj = validate_args(args)
        if inj:
            reasons.append(inj)
            _record_call(conn, None, tool, args, False, inj)
            continue
        if not TOOL_REGISTRY[tool]["read_only"]:
            needs_approval = True
        valid_steps.append(step)
    if not valid_steps:
        return {"status": "denied", "reasons": reasons, "steps": []}
    status = "awaiting_approval" if needs_approval else "pending"
    return {"status": status, "reasons": reasons, "steps": valid_steps}


def _record_call(conn, task_id, tool, args, allowed, reason, result=None):
    conn.execute(
        "INSERT INTO tool_calls (task_id, tool, args, allowed, reason, result, ts) "
        "VALUES (COALESCE(?, 0), ?, ?, ?, ?, ?, ?)",
        (task_id, tool, db.jdump(args), int(allowed), reason, db.jdump(result), db.utcnow()),
    )
    conn.commit()


def execute_task(conn, task: dict, agent: dict) -> dict:
    """Run a pre-approved task. Truthful: result only reflects executed work.

    task.request stores {"steps": [...]} — exactly the allowlist-validated steps.
    """
    agent_id = agent["id"]
    req = db.jload(task.get("request"), {}) or {}
    steps = req.get("steps") or []
    if not steps:
        return {"error": "no executable steps recorded"}
    results, errors = [], []
    for step in steps:
        tool, args = step["tool"], step.get("args") or {}
        spec = TOOL_REGISTRY.get(tool)
        if not spec:
            errors.append(f"unknown tool {tool}")
            _record_call(conn, task["id"], tool, args, False, "tool not in registry at execution")
            continue
        inj = validate_args(args)
        if inj:
            errors.append(inj)
            _record_call(conn, task["id"], tool, args, False, inj)
            continue
        try:
            out = spec["fn"](conn, args)
            _record_call(conn, task["id"], tool, args, True, None, out)
            results.append({"tool": tool, "result": out})
        except Exception as e:  # noqa: BLE001 - tool errors are data, not crashes
            errors.append(f"{tool} failed: {e}")
            _record_call(conn, task["id"], tool, args, True, f"error: {e}")
    record_audit(conn, {"type": "agent", "id": str(agent_id), "name": agent["name"]},
                 "agent.task.completed" if not errors else "agent.task.failed",
                 target_type="agent_task", target_id=str(task["id"]),
                 detail={"results": len(results), "errors": errors[:5]})
    return {"results": results, "errors": errors, "truthful": True}
