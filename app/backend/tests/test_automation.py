"""Automation: playbooks, triggers, dry-run, policy reuse (SEC-056)."""
from __future__ import annotations

from app import db


def test_playbook_dry_run_does_not_execute(client, seeded):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    r = client.get("/api/automation")
    assert r.json()["total"] >= 3
    pb = next(p for p in r.json()["items"] if p["name"] == "daily-standup-brief")
    r = client.post(f"/api/automation/{pb['id']}/run", json={"dry_run": True})
    assert r.status_code == 200
    body = r.json()
    assert body["dry_run"] is True
    assert body["plan"]["status"] == "pending"
    # nothing executed (list endpoint returns `result` already decoded)
    runs = client.get("/api/automation/runs").json()["items"]
    assert runs[0]["status"] == "completed"
    assert runs[0]["result"]["executed"] is False


def test_playbook_execution(client, seeded, conn):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    pb = next(p for p in client.get("/api/automation").json()["items"]
              if p["name"] == "daily-standup-brief")
    r = client.post(f"/api/automation/{pb['id']}/run", json={})
    assert r.status_code == 200
    assert r.json()["status"] == "completed"
    result = r.json()["result"]
    assert len(result["results"]) == 2  # summarize_alerts + list_vulns
    assert result["errors"] == []
    rows = db.q(conn, "SELECT tool FROM tool_calls WHERE allowed=1 ORDER BY id DESC LIMIT 2")
    assert {r_["tool"] for r_ in rows} == {"summarize_alerts", "list_vulns"}


def test_playbook_consequential_step_awaits_approval(client, seeded):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    pb = next(p for p in client.get("/api/automation").json()["items"]
              if p["name"] == "exfil-response-check")
    before = db.one(seeded, "SELECT COUNT(*) c FROM cases")["c"]
    r = client.post(f"/api/automation/{pb['id']}/run", json={})
    assert r.status_code == 200
    assert r.json()["status"] == "awaiting_approval"
    # the consequential create_case step did NOT run
    after = db.one(seeded, "SELECT COUNT(*) c FROM cases")["c"]
    assert after == before


def test_playbook_denied_when_tool_missing(client, seeded):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    r = client.post("/api/automation", json={
        "name": "bad-pb", "trigger": "manual",
        "steps": [{"tool": "not_a_tool", "args": {}}]})
    assert r.status_code == 201
    pb_id = r.json()["id"]
    r = client.post(f"/api/automation/{pb_id}/run", json={})
    assert r.json()["status"] == "denied"
    # bad trigger rejected
    r = client.post("/api/automation", json={"name": "bad-trigger", "steps": [
        {"tool": "query_events", "args": {}}], "trigger": "sometimes"})
    assert r.status_code == 400


def test_on_alert_trigger_creates_pending_run(client, seeded, conn):
    """A high+ NEW alert raise should queue a pending run for on_alert:high playbooks.

    Uses a fresh host so the raised alert is new (not an update of the seeded
    lab-jump-01 alert, which is already open).
    """
    conn.execute("DELETE FROM playbook_runs")
    conn.commit()
    now_ts = db.utcnow()
    for i in range(6):
        conn.execute(
            "INSERT INTO events (idempotency_key, ts, source_type, source_name, host, user, action, "
            "outcome, severity, msg, data, data_class, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (f"trig-{i}", now_ts, "syslog", "sshd", "lab-bastion-02", "admin",
             "ssh_failed_login", "failure", "low", "trigger test", None, "synthetic", db.utcnow()))
    conn.commit()
    # now ingest ONE more via API so detection runs (threshold 5 in window)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    assert r.status_code == 200
    r = client.post("/api/soc/events", json={"events": [{
        "ts": db.utcnow(), "host": "lab-bastion-02", "user": "admin", "action": "ssh_failed_login",
        "outcome": "failure", "severity": "low", "source_name": "sshd",
        "idempotency_key": "trig-final"}]})
    assert r.status_code == 201
    runs = db.q(conn, "SELECT * FROM playbook_runs WHERE trigger LIKE 'on_alert:%'")
    assert runs, "expected a pending playbook run from on_alert:high"
    assert all(run["status"] == "pending" for run in runs)
