"""SOC: event ingestion (idempotent), alert triage, detection rules.

SEC-022 audit pipeline, SEC-030/031 telemetry+detections, SEC-032 triage.
"""
from __future__ import annotations

import logging
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from .. import db
from ..audit import record_audit
from ..deps import require
from ..services.detection import RuleError, compile_rule, evaluate_batch, rule_health

log = logging.getLogger("cybersec.detection")

# Rules already reported as non-compiling in this process (avoid log spam on
# every ingest batch). Keyed by rule uid.
_reported_broken: set[str] = set()

router = APIRouter(prefix="/api/soc", tags=["soc"])

SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALERT_STATUSES = {"new", "triaging", "confirmed", "dismissed", "closed"}


class EventIn(BaseModel):
    ts: str = Field(min_length=4, max_length=40)
    source_type: str | None = None
    source_name: str | None = None
    host: str | None = None
    user: str | None = None
    action: str | None = None
    outcome: str | None = None
    severity: str | None = None
    msg: str | None = Field(default=None, max_length=2000)
    data: dict[str, Any] | None = None
    data_class: str = "synthetic"
    idempotency_key: str | None = Field(default=None, max_length=160)

    @field_validator("data_class")
    @classmethod
    def _dc(cls, v):
        if v not in {"synthetic", "verified"}:
            raise ValueError("data_class must be synthetic|verified")
        return v

    @field_validator("severity")
    @classmethod
    def _sev(cls, v):
        if v is not None and v.lower() not in SEVERITIES:
            raise ValueError("bad severity")
        return v.lower() if v else v


class BatchIn(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=5000)


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


@router.post("/events", status_code=201)
def ingest_events(batch: BatchIn, conn: sqlite3.Connection = Depends(db.get_conn),
                  user: dict = Depends(require("soc.write"))):
    """Idempotent batch ingest. Duplicate idempotency_key -> skipped, not error."""
    inserted, skipped = 0, 0
    new_events: list[dict] = []
    for e in batch.events:
        d = e.model_dump()
        if d["idempotency_key"] and db.one(conn, "SELECT id FROM events WHERE idempotency_key = ?",
                                           (d["idempotency_key"],)):
            skipped += 1
            continue
        cur = conn.execute(
            "INSERT INTO events (idempotency_key, ts, source_type, source_name, host, user, action, "
            "outcome, severity, msg, data, data_class, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (d["idempotency_key"], d["ts"], d["source_type"], d["source_name"], d["host"], d["user"],
             d["action"], d["outcome"], d["severity"], d["msg"], db.jdump(d["data"]), d["data_class"],
             db.utcnow()),
        )
        d["id"] = int(cur.lastrowid)
        new_events.append(d)
        inserted += 1
    conn.commit()

    alerts = _run_detections(conn, new_events)
    record_audit(conn, _actor(user), "soc.events.ingested", target_type="events",
                 detail={"inserted": inserted, "skipped": skipped, "alerts": len(alerts)})
    return {"inserted": inserted, "skipped": skipped, "alerts": alerts}


def _run_detections(conn: sqlite3.Connection, events: list[dict],
                    threshold_context: list[dict] | None = None) -> list[dict]:
    """Evaluate active rules. `events` are the candidate events for non-threshold
    rules; `threshold_context` is the window used for threshold rules.

    A rule that cannot compile is skipped — but never silently (SEC-074): it is
    logged once per process, and `GET /rules` + `GET /rules/coverage` report it
    as broken with the compiler's reason. Skipping quietly would mean an
    operator believes they have coverage they do not have.
    """
    if not events:
        return []
    rules = db.q(conn, "SELECT * FROM detection_rules WHERE status = 'active'")
    raised = []
    for r in rules:
        spec = db.jload(r["spec"], {})
        health = rule_health(spec)
        if not health["compiles"]:
            if r["uid"] not in _reported_broken:
                _reported_broken.add(r["uid"])
                log.warning("detection rule %s cannot compile and is INERT: %s",
                            r["uid"], health["error"])
            continue
        rule = health["rule"]
        if rule.requires_threshold:
            ctx = threshold_context if threshold_context is not None else db.q(
                conn, "SELECT id, ts, host, user, action, outcome, severity, source_name, source_type, data FROM events "
                      "ORDER BY ts DESC LIMIT 5000")
            recent = ctx
        else:
            recent = events
        for group in evaluate_batch(rule, recent, new_ids={e["id"] for e in events}):
            # Dedupe: one open alert per (rule, entity) — entity encoded in title.
            entity = group.get("entity")
            title = f"{rule.name}" + (f" — {entity}" if entity else "")
            existing = db.one(conn, "SELECT id FROM alerts WHERE rule_id = ? AND title = ? "
                                    "AND status IN ('new','triaging','confirmed') "
                                    "ORDER BY last_seen DESC LIMIT 1",
                              (r["id"], title))
            if existing:
                cur = db.one(conn, "SELECT * FROM alerts WHERE id = ?", (existing["id"],))
                merged = list(dict.fromkeys((db.jload(cur["event_ids"], []) or []) + group["event_ids"]))[:500]
                conn.execute(
                    "UPDATE alerts SET count = ?, last_seen = ?, event_ids = ?, updated_at = ? WHERE id = ?",
                    (group["count"], group["last_seen"], db.jdump(merged), db.utcnow(), existing["id"]),
                )
                conn.commit()
                raised.append({"id": cur["id"], "title": title, "severity": cur["severity"],
                               "status": "updated", "count": group["count"]})
            else:
                cur = conn.execute(
                    "INSERT INTO alerts (rule_id, uid, title, severity, status, event_ids, first_seen, "
                    "last_seen, count, created_at, updated_at) VALUES (?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?)",
                    (r["id"], rule.uid, title, rule.severity, db.jdump(group["event_ids"]),
                     group["first_seen"], group["last_seen"], group["count"], db.utcnow(), db.utcnow()),
                )
                conn.commit()
                raised.append({"id": int(cur.lastrowid), "title": title, "severity": rule.severity,
                               "status": "created", "count": group["count"]})
    if raised:
        # Hook automation playbooks (trigger: on_alert:<severity>)
        try:
            from .automation import _trigger_on_alert
            _trigger_on_alert(conn, raised)
        except Exception:  # automation must never break ingest
            pass
    return raised


@router.get("/events")
def list_events(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("soc.read")),
                host: str | None = None, user_name: str | None = None, action: str | None = None,
                from_ts: str | None = None, to_ts: str | None = None,
                data_class: str | None = None,
                page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    where, params = ["1=1"], []
    if host:
        where.append("host = ?")
        params.append(host)
    if user_name:
        where.append("user = ?")
        params.append(user_name)
    if action:
        where.append("action = ?")
        params.append(action)
    if from_ts:
        where.append("ts >= ?")
        params.append(from_ts)
    if to_ts:
        where.append("ts <= ?")
        params.append(to_ts)
    if data_class:
        where.append("data_class = ?")
        params.append(data_class)
    sql = ("SELECT id, ts, source_type, source_name, host, user, action, outcome, severity, msg, "
           "data, data_class FROM events WHERE " + " AND ".join(where))
    return db.paged(conn, sql, tuple(params), "ORDER BY ts DESC, id DESC", page, page_size)


class AlertUpdate(BaseModel):
    status: str | None = None
    assigned_to: str | None = Field(default=None, max_length=100)
    notes: str | None = Field(default=None, max_length=4000)


@router.get("/alerts")
def list_alerts(conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("soc.read")),
                status: str | None = Query(default=None), severity: str | None = None,
                q: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    where, params = [], []
    if status:
        where.append("a.status = ?")
        params.append(status)
    if severity:
        where.append("a.severity = ?")
        params.append(severity)
    if q:
        where.append("(a.title LIKE ? OR r.name LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    sql = ("SELECT a.id, a.title, a.severity, a.status, a.count, a.first_seen, a.last_seen, "
           "a.assigned_to, r.name AS rule_name, r.uid AS rule_uid, a.case_id "
           "FROM alerts a LEFT JOIN detection_rules r ON r.id = a.rule_id")
    if where:
        sql += " WHERE " + " AND ".join(where)
    return db.paged(conn, sql, tuple(params), "ORDER BY a.first_seen DESC, a.id DESC", page, page_size)


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, conn: sqlite3.Connection = Depends(db.get_conn),
              user: dict = Depends(require("soc.read"))):
    a = db.one(conn, "SELECT * FROM alerts WHERE id = ?", (alert_id,))
    if not a:
        raise HTTPException(404, {"code": "not_found"})
    events = db.q(conn, "SELECT id, ts, host, user, action, outcome, severity, msg, data "
                        "FROM events WHERE id IN (%s) ORDER BY ts" %
                        ",".join("?" * len(db.jload(a["event_ids"], []))),
                        tuple(db.jload(a["event_ids"], [])))
    return {"alert": a, "events": events[:100]}


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, body: AlertUpdate, conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("soc.write"))):
    a = db.one(conn, "SELECT * FROM alerts WHERE id = ?", (alert_id,))
    if not a:
        raise HTTPException(404, {"code": "not_found"})
    if body.status is not None and body.status not in ALERT_STATUSES:
        raise HTTPException(400, {"code": "bad_status"})
    # SEC-081: dismissing an alert is a false-positive judgement, and it is the
    # highest-volume analyst call in a SOC. Everywhere else on this platform a
    # judgement records its reason (chain status needs a rationale, a release
    # needs its checklist, a verdict needs its mechanism); an alert dismissal
    # previously wrote nothing at all, so "why was this critical alert closed
    # without action?" had no answer. Require the reason.
    if body.status == "dismissed" and not (body.notes or "").strip():
        raise HTTPException(400, {"code": "note_required",
                                  "message": "dismissing an alert records a false-positive "
                                             "judgement — add a note saying why"})
    fields, params = [], []
    if body.status is not None:
        fields.append("status = ?")
        params.append(body.status)
    if body.assigned_to is not None:
        fields.append("assigned_to = ?")
        params.append(body.assigned_to)
    if body.notes is not None:
        fields.append("notes = ?")
        params.append(body.notes)
    if not fields:
        raise HTTPException(400, {"code": "no_changes"})
    fields.append("updated_at = ?")
    params.append(db.utcnow())
    params.append(alert_id)
    conn.execute(f"UPDATE alerts SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()
    record_audit(conn, _actor(user), "alert.updated", target_type="alert", target_id=str(alert_id),
                 detail={k: v for k, v in body.model_dump().items() if v is not None})
    return db.one(conn, "SELECT * FROM alerts WHERE id = ?", (alert_id,))


# ------------------------------------------------------------- detection rules

class RuleIn(BaseModel):
    uid: str = Field(min_length=3, max_length=64)
    name: str = Field(min_length=3, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    severity: str = "medium"
    status: str = "active"
    spec: dict[str, Any]


@router.post("/rules", status_code=201)
def create_rule(body: RuleIn, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("rules.write"))):
    spec = {**body.spec, "uid": body.uid, "name": body.name,
            "description": body.description, "severity": body.severity, "status": body.status}
    try:
        compile_rule(spec)
    except RuleError as e:
        raise HTTPException(400, {"code": "bad_rule", "message": str(e)}) from e
    if db.one(conn, "SELECT id FROM detection_rules WHERE uid = ?", (body.uid,)):
        raise HTTPException(409, {"code": "exists"})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO detection_rules (uid, name, description, severity, status, spec, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (body.uid, body.name, body.description, body.severity, body.status, db.jdump(spec), now, now),
    )
    conn.commit()
    record_audit(conn, _actor(user), "rule.created", target_type="detection_rule",
                 target_id=str(cur.lastrowid), detail={"uid": body.uid, "severity": body.severity})
    return db.one(conn, "SELECT * FROM detection_rules WHERE id = ?", (cur.lastrowid,))


@router.get("/rules")
def list_rules(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("soc.read"))):
    """Rules with compile health (SEC-074).

    `compiles: false` means the rule is stored but **inert** — detection will
    never fire it. `error` carries the compiler's reason (e.g. an unsupported
    condition construct when porting a rule from a full Sigma pack).
    """
    rows = db.q(conn, "SELECT id, uid, name, description, severity, status, spec, updated_at "
                      "FROM detection_rules ORDER BY uid")
    items = []
    for r in rows:
        health = rule_health(db.jload(r["spec"], {}) or {})
        r.pop("spec", None)
        r["compiles"] = health["compiles"]
        r["error"] = health["error"]
        items.append(r)
    broken = [i["uid"] for i in items if not i["compiles"]]
    return {
        "items": items,
        "total": len(items),
        "summary": {"ok": len(items) - len(broken), "broken": len(broken), "broken_uids": broken},
    }


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: int, body: RuleIn, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("rules.write"))):
    r = db.one(conn, "SELECT * FROM detection_rules WHERE id = ?", (rule_id,))
    if not r:
        raise HTTPException(404, {"code": "not_found"})
    spec = {**body.spec, "uid": body.uid, "name": body.name,
            "description": body.description, "severity": body.severity, "status": body.status}
    try:
        compile_rule(spec)
    except RuleError as e:
        raise HTTPException(400, {"code": "bad_rule", "message": str(e)}) from e
    conn.execute("UPDATE detection_rules SET name=?, description=?, severity=?, status=?, spec=?, updated_at=? WHERE id=?",
                 (body.name, body.description, body.severity, body.status, db.jdump(spec), db.utcnow(), rule_id))
    conn.commit()
    record_audit(conn, _actor(user), "rule.updated", target_type="detection_rule", target_id=str(rule_id))
    return db.one(conn, "SELECT * FROM detection_rules WHERE id = ?", (rule_id,))


@router.post("/detections/backfill")
def backfill_detections(conn: sqlite3.Connection = Depends(db.get_conn),
                        user: dict = Depends(require("rules.write"))):
    """Re-run active rules over all stored events (e.g. after adding a rule).
    Open-alert dedup prevents duplicate alert spam."""
    events = db.q(conn, "SELECT id, ts, host, user, action, outcome, severity, source_name, source_type, data FROM events "
                        "ORDER BY ts LIMIT 20000")
    raised = _run_detections(conn, events, threshold_context=events)
    created = [a for a in raised if a["status"] == "created"]
    updated = [a for a in raised if a["status"] == "updated"]
    record_audit(conn, _actor(user), "detections.backfilled", target_type="detections",
                 detail={"events": len(events), "created": len(created), "updated": len(updated)})
    # Backfill surfaces NEW alerts only; refreshes of existing open alerts are
    # reported in the count, not re-raised (prevents alert spam on re-runs).
    return {"events_checked": len(events), "alerts": created, "updated": len(updated)}


class RuleDryRun(BaseModel):
    rule_id: int
    event_ids: list[int] = Field(min_length=1, max_length=1000)


@router.post("/rules/dry-run")
def rule_dry_run(body: RuleDryRun, conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("soc.read"))):
    r = db.one(conn, "SELECT * FROM detection_rules WHERE id = ?", (body.rule_id,))
    if not r:
        raise HTTPException(404, {"code": "not_found"})
    try:
        rule = compile_rule(db.jload(r["spec"], {}))
    except RuleError as e:
        raise HTTPException(400, {"code": "bad_rule", "message": str(e)}) from e
    events = db.q(conn, "SELECT id, ts, host, user, action, outcome, severity, source_name, source_type, data FROM events "
                        "WHERE id IN (%s)" % ",".join("?" * len(body.event_ids)), tuple(body.event_ids))
    groups = evaluate_batch(rule, events)
    return {"rule_uid": r["uid"], "events_checked": len(events), "alert_groups": groups}


# ---------------------------------------------------------------- coverage
# SEC-056: detection coverage — which rules have ever fired, which are gaps.

@router.get("/rules/coverage")
def rules_coverage(conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("soc.read"))):
    rules = db.q(conn, "SELECT * FROM detection_rules ORDER BY uid")
    per_rule = []
    gaps = []
    broken_rules = []
    for r in rules:
        alert = db.one(conn,
            "SELECT COUNT(*) AS n, MAX(last_seen) AS last_seen FROM alerts WHERE rule_id = ?",
            (r["id"],))
        n = alert["n"] if alert else 0
        last = alert["last_seen"] if alert else None
        active = r["status"] == "active"
        never_fired = n == 0
        # SEC-074: distinguish "has not fired yet" from "can never fire".
        health = rule_health(db.jload(r["spec"], {}) or {})
        per_rule.append({
            "rule_id": r["id"], "uid": r["uid"], "name": r["name"],
            "severity": r["severity"], "status": r["status"],
            "alerts_total": n, "last_alert_at": last,
            "never_fired": never_fired,
            "compiles": health["compiles"], "error": health["error"],
        })
        if not health["compiles"]:
            broken_rules.append({"uid": r["uid"], "name": r["name"],
                                 "severity": r["severity"], "status": r["status"],
                                 "error": health["error"]})
        # A broken rule is a configuration fault, not a coverage gap: it is
        # reported separately so the gap list stays actionable.
        elif active and never_fired:
            gaps.append({"uid": r["uid"], "name": r["name"], "severity": r["severity"]})
    # Coverage counts only rules that *can* run; counting inert rules as
    # "unfired" would understate coverage for a reason nobody can act on.
    active_rules = [p for p in per_rule if p["status"] == "active" and p["compiles"]]
    fired = [p for p in active_rules if not p["never_fired"]]
    coverage_pct = round(100.0 * len(fired) / len(active_rules), 1) if active_rules else 100.0
    return {
        "total_rules": len(rules),
        "active_rules": len(active_rules),
        "inert_rules": len(broken_rules),
        "fired_rules": len(fired),
        "coverage_pct": coverage_pct,
        "gaps": gaps,
        "broken_rules": broken_rules,
        "rules": per_rule,
    }


# ------------------------------------------------------------ purple team
# SEC-056: recorded synthetic attack sequences validated against live rules.

class PurpleRunIn(BaseModel):
    scenario: str = Field(min_length=2, max_length=64)


@router.get("/purple-team/scenarios")
def purple_scenarios(user: dict = Depends(require("soc.read"))):
    from ..services import purple_team
    return {"scenarios": purple_team.list_scenarios()}


@router.post("/purple-team/run")
def purple_run(body: PurpleRunIn, conn: sqlite3.Connection = Depends(db.get_conn),
               user: dict = Depends(require("soc.write"))):
    from ..services import purple_team
    try:
        return purple_team.run_scenario(conn, body.scenario, _actor(user))
    except ValueError as e:
        raise HTTPException(404, {"code": "not_found", "message": str(e)}) from e


# -------------------------------------------------------- saved searches
# SEC-071: named, user-scoped filter sets for event/alert queries.

class SavedSearchIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    module: str = "soc"          # 'events' | 'alerts'
    params: dict = Field(default_factory=dict)


@router.get("/saved-searches")
def list_saved_searches(conn: sqlite3.Connection = Depends(db.get_conn),
                        user: dict = Depends(require("soc.read")),
                        module: str | None = None):
    where, params = ["owner = ?"], [user["username"]]
    if module:
        where.append("module = ?")
        params.append(module)
    rows = db.q(conn, "SELECT * FROM saved_searches WHERE " + " AND ".join(where)
                + " ORDER BY id DESC", tuple(params))
    for r in rows:
        r["params"] = db.jload(r.get("params"), {})
    return {"items": rows, "total": len(rows)}


@router.post("/saved-searches", status_code=201)
def save_search(body: SavedSearchIn, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("soc.write"))):
    if body.module not in ("events", "alerts"):
        raise HTTPException(400, {"code": "bad_module", "message": "module must be 'events' or 'alerts'"})
    cur = conn.execute(
        "INSERT INTO saved_searches (name, owner, module, params, created_at) VALUES (?, ?, ?, ?, ?)",
        (body.name, user["username"], body.module, db.jdump(body.params), db.utcnow()))
    conn.commit()
    record_audit(conn, _actor(user), "saved_search.created", target_type="saved_search",
                 target_id=str(cur.lastrowid), detail={"name": body.name, "module": body.module})
    return db.one(conn, "SELECT * FROM saved_searches WHERE id = ?", (cur.lastrowid,))


@router.delete("/saved-searches/{ss_id}")
def delete_saved_search(ss_id: int, conn: sqlite3.Connection = Depends(db.get_conn),
                        user: dict = Depends(require("soc.write"))):
    row = db.one(conn, "SELECT * FROM saved_searches WHERE id = ?", (ss_id,))
    if not row:
        raise HTTPException(404, {"code": "not_found"})
    if row["owner"] != user["username"]:
        raise HTTPException(403, {"code": "forbidden", "message": "not your saved search"})
    conn.execute("DELETE FROM saved_searches WHERE id = ?", (ss_id,))
    conn.commit()
    record_audit(conn, _actor(user), "saved_search.deleted", target_type="saved_search",
                 target_id=str(ss_id), detail={"name": row["name"]})
    return {"ok": True}
