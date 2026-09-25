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


def test_playbook_approval_is_visible_decidable_and_executes(client, seeded):
    """SEC-094: the approval gate for playbooks was broken end to end.

    `run_playbook` wrote `approvals.task_id = 0` even though the schema documents
    the column as "agent_tasks(id) for agent approvals, or a playbook_runs(id) for
    automation"; the queue used an INNER JOIN on agent_tasks, so the approval never
    appeared; and deciding it by id dereferenced the missing task and returned an
    opaque 500 after the status change had already been committed — leaving the run
    `pending`, the approval undecidable, and nothing executed or audited.
    """
    from app import db as dbmod

    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    pb = next(p for p in client.get("/api/automation").json()["items"]
              if p["name"] == "exfil-response-check")

    r = client.post(f"/api/automation/{pb['id']}/run", json={})
    assert r.status_code == 200 and r.json()["status"] == "awaiting_approval"
    run_id = r.json()["run_id"]

    # 1. the approval is in the queue (it used to be invisible)
    queue = client.get("/api/agents/approvals", params={"status": "pending"}).json()["items"]
    ap = next(a for a in queue if a["task_id"] == run_id)
    assert ap["kind"] == "playbook" and ap["playbook_name"] == "exfil-response-check"
    assert ap["run_status"] == "pending"
    assert ap["task_id"] != 0        # the run id, as the schema documents

    # 2. approving executes the plan and completes the run
    cases_before = client.get("/api/cases").json()["total"]
    r = client.post(f"/api/agents/approvals/{ap['id']}/decide",
                    json={"decision": "approve", "comment": "reviewed the plan"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["executed"] is True and body["run_status"] == "completed"
    run = next(x for x in client.get("/api/automation/runs").json()["items"] if x["id"] == run_id)
    assert run["status"] == "completed" and run["result"]["results"]
    assert client.get("/api/cases").json()["total"] == cases_before + 1

    # 3. it is no longer pending, and a second decision is refused
    assert not [a for a in client.get("/api/agents/approvals", params={"status": "pending"}).json()["items"]
                if a["id"] == ap["id"]]
    r = client.post(f"/api/agents/approvals/{ap['id']}/decide", json={"decision": "approve"})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "already_decided"

    # 4. the audit trail records what happened
    actions = [r["action"] for r in dbmod.q(seeded, "SELECT action FROM audit_events "
                                                    "ORDER BY seq DESC LIMIT 8")]
    assert "playbook.completed" in actions
    detail = dbmod.jload(dbmod.q(seeded, "SELECT detail FROM audit_events "
                                         "WHERE action = 'playbook.completed' ORDER BY seq DESC LIMIT 1")[0]["detail"])
    assert detail["executed"] is True and detail["approved_by"] == "admin"
    assert detail["run_id"] == run_id


def test_playbook_approval_rejection_fails_the_run(client, seeded):
    """The reject half of the same gate (SEC-094): the run must end as failed with
    the reason, and the consequential step must not run."""
    from app import db as dbmod

    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    pb = next(p for p in client.get("/api/automation").json()["items"]
              if p["name"] == "exfil-response-check")
    run_id = client.post(f"/api/automation/{pb['id']}/run", json={}).json()["run_id"]
    ap = next(a for a in client.get("/api/agents/approvals", params={"status": "pending"}).json()["items"]
              if a["task_id"] == run_id)

    cases_before = client.get("/api/cases").json()["total"]
    r = client.post(f"/api/agents/approvals/{ap['id']}/decide",
                    json={"decision": "reject", "comment": "not enough evidence"})
    assert r.status_code == 200 and r.json()["run_status"] == "failed"
    run = next(x for x in client.get("/api/automation/runs").json()["items"] if x["id"] == run_id)
    assert run["status"] == "failed" and run["result"]["error"] == "approval_rejected"
    assert "not enough evidence" in run["result"]["reason"] or "rejected by" in run["result"]["reason"]
    assert client.get("/api/cases").json()["total"] == cases_before

    detail = dbmod.jload(dbmod.q(seeded, "SELECT detail FROM audit_events "
                                         "WHERE action = 'playbook.rejected' ORDER BY seq DESC LIMIT 1")[0]["detail"])
    assert detail["run_id"] == run_id and detail["applied"] is True
