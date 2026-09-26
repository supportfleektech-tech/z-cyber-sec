"""End-to-end user flows (test layer 5 in docs/07-testing.md).

Flow: login -> ingest attack -> alert -> case -> evidence -> closure -> report.
Plus the IR lead flow and the agent-assisted flow.
"""
from __future__ import annotations

import io

from app import db


def test_full_incident_flow(client, seeded, conn):
    # 1. Analyst logs in
    r = client.post("/api/auth/login", json={"username": "sasha", "password": "SashaSocPass1!"})
    assert r.status_code == 200

    # 2. Ingest a fresh attack pattern (login storm)
    events = [{"ts": "2026-09-21T12:00:%02dZ" % i, "host": "lab-web-01", "user": "svc_ci",
               "action": "login_failed", "outcome": "failure", "severity": "low",
               "source_name": "web", "data": {"src_ip": "192.0.2.99"},
               "idempotency_key": f"e2e-storm-{i}"} for i in range(11)]
    r = client.post("/api/soc/events", json={"events": events})
    assert r.status_code == 201
    assert r.json()["inserted"] == 11
    raised = r.json()["alerts"]
    assert any("Login Storm" in a["title"] for a in raised)

    # 3. Alert appears in queue
    alerts = client.get("/api/soc/alerts", params={"status": "new"}).json()["items"]
    alert = next(a for a in alerts if "Login Storm" in a["title"] and "svc_ci" in a["title"])

    # 4. Triage
    r = client.patch(f"/api/soc/alerts/{alert['id']}", json={"status": "triaging",
                                                             "assigned_to": "sasha"})
    assert r.status_code == 200

    # 5. Open case from alert
    r = client.post("/api/cases", json={"title": "Credential stuffing (e2e)",
                                        "alert_id": alert["id"], "priority": "high"})
    assert r.status_code == 201
    case = r.json()

    # 6. Add task + timeline note
    client.post(f"/api/cases/{case['id']}/tasks", json={"title": "Reset credentials"})
    client.patch(f"/api/cases/{case['id']}", json={"status": "investigating",
                                                   "notes": "Confirming with asset owner"})

    # 7. Attach + verify evidence
    files = {"file": ("storm-events.txt", io.BytesIO(b"e2e synthetic evidence"), "text/plain")}
    r = client.post(f"/api/cases/{case['id']}/evidence", files=files,
                    data={"classification": "internal", "retention": "90d"})
    assert r.status_code == 201
    ev = r.json()

    # 8. IR lead downloads evidence (different role)
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "iris", "password": "IrisLeadPass1!"})
    assert r.status_code == 200
    r = client.get(f"/api/cases/evidence/{ev['id']}/download")
    assert r.status_code == 200
    assert r.content == b"e2e synthetic evidence"
    # analyst (sasha) may NOT download
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "sasha", "password": "SashaSocPass1!"})
    r = client.get(f"/api/cases/evidence/{ev['id']}/download")
    assert r.status_code == 403

    # 9. Close case
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "iris", "password": "IrisLeadPass1!"})
    client.patch(f"/api/cases/{case['id']}", json={"status": "closed"})
    closed = client.get(f"/api/cases/{case['id']}").json()
    assert closed["status"] == "closed" and closed["closed_at"]

    # 10. Report with provenance
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    r = client.post("/api/reports", json={"kind": "cases"})
    assert r.status_code == 201
    html = r.json()
    from pathlib import Path
    assert "Credential stuffing (e2e)" in Path(html["path"]).read_text()

    # 11. Audit chain is intact through all of this
    r = client.get("/api/admin/audit/verify")
    assert r.json()["ok"] is True
    actions = {x["action"] for x in client.get("/api/admin/audit",
                                               params={"page_size": 500}).json()["items"]}
    for expected in ("auth.login", "soc.events.ingested", "alert.updated", "case.created",
                     "evidence.uploaded", "evidence.downloaded", "report.generated"):
        assert expected in actions


def test_agent_assisted_triage_flow(client, seeded, conn):
    """IR lead uses the agent gateway to summarize, then approves a case creation."""
    r = client.post("/api/auth/login", json={"username": "iris", "password": "IrisLeadPass1!"})
    assert r.status_code == 200
    agent = next(a for a in client.get("/api/agents").json()["items"] if a["name"] == "openclaw-ops")
    # read-only summary (no approval needed)
    r = client.post("/api/agents/tasks", json={
        "agent_id": agent["id"], "title": "Morning summary",
        "request": {"tool": "summarize_alerts", "args": {}}})
    assert r.json()["status"] == "completed"
    # consequential case creation (approval required)
    r = client.post("/api/agents/tasks", json={
        "agent_id": agent["id"], "title": "Create response case",
        "request": {"tool": "create_case",
                    "args": {"title": "Agent-created response case", "severity": "high"}}})
    task = r.json()
    assert task["status"] == "awaiting_approval"
    ap = client.get("/api/agents/approvals", params={"status": "pending"}).json()["items"]
    ap = next(a for a in ap if a["task_id"] == task["id"])
    r = client.post(f"/api/agents/approvals/{ap['id']}/decide", json={"decision": "approve"})
    assert r.status_code == 200
    assert db.one(conn, "SELECT id FROM cases WHERE title='Agent-created response case'") is not None
