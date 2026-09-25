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

# Caps for declared free-text argument fields (SEC-076): the heuristic is
# skipped for these, so they need a bound of their own.
_TEXT_FIELD_LIMITS = {"max_chars": 8000, "max_items": 50}


def _actor_from_agent(agent: dict) -> dict:
    return {"type": "agent", "id": str(agent["id"]), "name": agent["name"]}


def validate_args(args: dict, tool: str | None = None) -> str | None:
    """Return a denial reason if args look like shell injection; else None.

    Scope matters (SEC-076). The shell-construct heuristic exists to stop
    injection reaching some *other* tool's semantics — nothing here executes
    anything. Applied to every field it produced false positives that broke the
    product's own workflow: a reproduction step reading "run
    ``curl -s http://target/api``" is normal pentest prose, not an attack, and
    a tool that refuses to record it is unusable for the thing it is for.

    So tools may declare ``text_fields``: free text that is stored as data and
    never interpreted (reproduction steps, rationale, evidence, notes). Those
    are length-capped here and skipped by the shell heuristic; every other
    field keeps the strict check exactly as before.
    """
    prose = set((TOOL_REGISTRY.get(tool or "", {}) or {}).get("text_fields") or ())
    limits = _TEXT_FIELD_LIMITS

    def check_text(value, name: str) -> str | None:
        items = value if isinstance(value, list) else [value]
        if len(items) > limits["max_items"]:
            return f"{name}: too many entries (max {limits['max_items']})"
        for item in items:
            if not isinstance(item, str):
                return f"{name}: entries must be strings"
            if len(item) > limits["max_chars"]:
                return f"{name}: entry exceeds {limits['max_chars']} characters"
        return None

    def walk(v, name: str = ""):
        if name in prose:
            return check_text(v, name)
        if isinstance(v, str) and _SHELLISH_RE.search(v):
            return "shell-like construct in untrusted input (possible injection)"
        if isinstance(v, dict):
            for k, x in v.items():
                err = walk(x, str(k))
                if err:
                    return err
        if isinstance(v, list):
            for x in v:
                err = walk(x, name)
                if err:
                    return err
        return None

    err = walk(args or {})
    if err:
        prefix = "args rejected: "
        return err if err.startswith(prefix) else prefix + err
    return None


# --------------------------------------------------------------- tool registry
# read_only tools: no approval needed (still allowlisted).
# consequential tools: always require a pending human approval.

def _query_events(conn, args):
    """Recent events, optionally filtered by action/host (max 50).

    SEC-095: this tool was broken on both paths — `params` was a *tuple*, so any
    filter raised `AttributeError: 'tuple' object has no attribute 'append'`, and
    the unfiltered path raised `TypeError` from `min(50, None)` while reporting
    `returned` as that expression. Every agent task and playbook step that queried
    events failed; the seeded `exfil-response-check` playbook's first step was one.
    """
    action = args.get("action")
    host = args.get("host")
    sql, params = "SELECT id, ts, host, user, action, outcome, severity, msg FROM events", []
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
    rows = db.q(conn, sql, tuple(params))
    return {"events": rows, "returned": len(rows), "limit": 50}


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


# --- SEC-075 adversary tradecraft (The-Xploiter) -----------------------------
# The read-only tools let an agent reason about what it may touch and what is
# actually known about a finding. The consequential ones write assessment
# records and are therefore approval-gated, like every other write here.

def _list_scope_targets(conn, args):
    """Authorized targets only. An agent cannot enumerate anything else."""
    from . import tradecraft as tc
    summary = tc.scope_summary(conn)
    return {"authorized_targets": summary["authorized"], "rule": summary["rule"],
            "ignored_overbroad_entries": summary["ignored_entries"]}


def _get_finding(conn, args):
    from . import tradecraft as tc
    try:
        vuln_id = int(args["vuln_id"])
    except (KeyError, TypeError, ValueError):
        return {"error": "vuln_id (int) is required"}
    ctx = tc.vuln_context(conn, vuln_id)
    if not ctx:
        return {"error": "finding not found"}
    f = ctx["finding"]
    return {"finding": {k: f.get(k) for k in ("id", "title", "severity", "cvss", "status",
                                              "cve_id", "asset_id", "description")},
            "reviews": [{"verdict": r["verdict"], "triage_ready": r["triage_ready"],
                         "rationale": r["rationale"], "target": r["target"]}
                        for r in ctx["reviews"]],
            "chains": [{"id": c["id"], "title": c["title"], "status": c["status"]}
                       for c in ctx["chains"]]}


def _record_exploitability_review(conn, args):
    """Consequential: writes an assessment record. Approval-gated."""
    from . import tradecraft as tc
    decision = tc.validate_review(conn, args or {})
    if not decision["ok"]:
        return {"error": "review rejected", "errors": decision["errors"]}
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO exploitability_reviews (vuln_id, exercise_id, target, verdict, trust_boundary, "
        "impact_before, impact_after, preconditions, evidence, reproduction, rationale, triage_ready, "
        "policy_note, dedupe_key, reviewed_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (args.get("vuln_id"), (decision["scope"] or {}).get("exercise_id"), args.get("target"),
         args.get("verdict"), args.get("trust_boundary"), args.get("impact_before"),
         args.get("impact_after"), db.jdump(args.get("preconditions") or []),
         db.jdump(args.get("evidence") or []), args.get("reproduction"), args.get("rationale"),
         1 if decision["triage_ready"] else 0, decision["policy_note"],
         tc._fingerprint(args.get("target"), None, None), "agent", now))
    conn.commit()
    return {"review_id": cur.lastrowid, "triage_ready": decision["triage_ready"],
            "policy_note": decision["policy_note"]}


def _propose_attack_chain(conn, args):
    """Consequential: writes a chain record. Approval-gated."""
    from . import tradecraft as tc
    decision = tc.validate_chain(conn, args or {})
    if not decision["ok"]:
        return {"error": "chain rejected", "errors": decision["errors"]}
    steps = [{**s, "order": s.get("order") or i} for i, s in enumerate(args.get("steps") or [], 1)]
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO attack_chains (exercise_id, title, entry_point, trust_boundary, steps, "
        "combined_impact, status, escalation_note, rationale, meta, created_by, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?, 'draft', ?, ?, ?, 'agent', ?, ?)",
        (args.get("exercise_id"), args.get("title"), args.get("entry_point"),
         args.get("trust_boundary"), db.jdump(steps), args.get("combined_impact"),
         args.get("escalation_note"), args.get("rationale"),
         db.jdump({"targets": args.get("targets") or []}), now, now))
    conn.commit()
    return {"chain_id": cur.lastrowid, "status": "draft", "steps": len(steps)}


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
    # SEC-075 — tradecraft. Note there is still no shell/scanning tool: an agent
    # reasons over authorized scope and recorded findings; it does not attack.
    "list_scope_targets": {"fn": _list_scope_targets, "read_only": True,
                           "description": "List targets authorized by an active engagement (read-only)."},
    "get_finding": {"fn": _get_finding, "read_only": True,
                    "description": "Read one finding with its exploitability reviews and chains."},
    "record_exploitability_review": {
        "fn": _record_exploitability_review, "read_only": False,
        "text_fields": ("rationale", "reproduction", "evidence", "preconditions",
                        "impact_before", "impact_after"),
        "description": "Record an exploitability verdict with evidence. REQUIRES APPROVAL."},
    "propose_attack_chain": {
        "fn": _propose_attack_chain, "read_only": False,
        "text_fields": ("rationale", "escalation_note", "title", "steps"),
        "description": "Propose a multi-step attack chain. REQUIRES APPROVAL."},
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
        inj = validate_args(args, tool)
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
        inj = validate_args(args, tool)
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
