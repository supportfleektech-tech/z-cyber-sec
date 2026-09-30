"""Purple-team validation (SEC-056) — offense and defense in one, on demand.

A scenario is a recorded, fully synthetic attack sequence (attacker side)
paired with the detection rule that MUST fire (defender side). Running a
scenario injects its events through the real ingest path (same code as
production), lets the detection engine evaluate, and reports pass/fail with
evidence (the raised/updated alert rows).

Scenarios live in `scenarios/*.yaml` (repo = code, synthetic by definition).
Hosts/users are purple-team-dedicated (pt-*) so results never collide with
seed data, and every run is audited.
"""
from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta

import yaml

from .. import db
from ..audit import record_audit
from ..config import settings

SCENARIO_FIELDS = ("offset", "host", "user", "action", "outcome", "severity",
                   "source_name", "msg", "data")


def list_scenarios() -> list[dict]:
    out = []
    if not settings.scenarios_dir.exists():
        return out
    for f in sorted(settings.scenarios_dir.glob("*.yaml")):
        spec = yaml.safe_load(f.read_text()) or {}
        if not spec.get("uid") or not spec.get("events"):
            continue
        out.append({
            "uid": spec["uid"], "name": spec.get("name", spec["uid"]),
            "description": spec.get("description", ""),
            "expected_rule": spec.get("expected_rule"),
            "events": len(spec["events"]),
        })
    return out


def _load(spec_uid: str) -> dict:
    if not settings.scenarios_dir.exists():
        return {}
    for f in sorted(settings.scenarios_dir.glob("*.yaml")):
        spec = yaml.safe_load(f.read_text()) or {}
        if spec.get("uid") == spec_uid:
            return spec
    return {}


def run_scenario(conn, spec_uid: str, actor: dict) -> dict:
    """Run one scenario end-to-end. Returns {passed, run_id, evidence...}."""
    spec = _load(spec_uid)
    if not spec:
        raise ValueError(f"unknown scenario: {spec_uid}")

    run_id = uuid.uuid4().hex[:10]
    tag = f"purple-{run_id}"
    now = datetime.now(UTC)
    t0 = time.monotonic()

    # ---- attacker side: inject the recorded sequence through the real path
    new_events = []
    for i, e in enumerate(spec["events"]):
        ts = (now + timedelta(seconds=e.get("offset", 0))).strftime("%Y-%m-%dT%H:%M:%SZ")
        row = {
            "idempotency_key": f"{tag}-{i}",
            "ts": ts,
            "source_type": "purple-team",
            "source_name": e.get("source_name", "purple-team"),
            "host": e.get("host"),
            "user": e.get("user"),
            "action": e.get("action"),
            "outcome": e.get("outcome"),
            "severity": (e.get("severity") or "info").lower(),
            "msg": f"[{tag}] {e.get('msg', '')}",
            "data": e.get("data") or {},
        }
        cur = conn.execute(
            "INSERT INTO events (idempotency_key, ts, source_type, source_name, host, user, action, "
            "outcome, severity, msg, data, data_class, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (row["idempotency_key"], ts, row["source_type"], row["source_name"], row["host"],
             row["user"], row["action"], row["outcome"], row["severity"], row["msg"],
             db.jdump(row["data"]), "synthetic", db.utcnow()))
        row["id"] = int(cur.lastrowid)
        new_events.append(row)
    conn.commit()

    # ---- defender side: real detection engine over the new events
    from ..routers.soc import _run_detections
    raised = _run_detections(conn, new_events)

    expected_rule = spec.get("expected_rule")
    fired = [a for a in raised if a.get("status") in ("created", "updated")]
    match = None
    if expected_rule:
        rule = db.one(conn, "SELECT name FROM detection_rules WHERE uid = ?", (expected_rule,))
        if rule:
            match = next((a for a in fired if a.get("title", "").startswith(rule["name"])), None)

    passed = match is not None
    duration_ms = int((time.monotonic() - t0) * 1000)
    record_audit(conn, actor, "purple_team.run", target_type="scenario",
                 target_id=spec_uid, detail={
                     "run_id": run_id, "passed": passed,
                     "events_injected": len(new_events),
                     "alert_id": match["id"] if match else None,
                     "duration_ms": duration_ms})
    return {
        "run_id": run_id, "scenario": spec_uid, "name": spec.get("name"),
        "passed": passed, "expected_rule": expected_rule,
        "events_injected": len(new_events),
        "alerts_raised": fired,
        "matched_alert": match,
        "duration_ms": duration_ms,
        "evidence": {
            "tag": tag,
            "note": "Events remain in the store labeled source_type=purple-team for review.",
        },
    }
