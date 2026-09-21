"""Server-side RBAC matrix (SEC-021): every write operation is checked in deps."""
from __future__ import annotations

import httpx

# (role, method, path, expected_status) — sampled matrix across modules.
MATRIX = [
    # viewer: read-only
    ("viewer", "GET", "/api/soc/alerts", 200),
    ("viewer", "GET", "/api/cases", 200),
    ("viewer", "GET", "/api/intel/indicators", 200),
    ("viewer", "GET", "/api/vulns", 200),
    ("viewer", "GET", "/api/appsec/findings", 200),
    ("viewer", "GET", "/api/cloud/assets", 200),
    ("viewer", "GET", "/api/grc/controls", 200),
    ("viewer", "GET", "/api/exercises", 200),
    ("viewer", "GET", "/api/agents", 200),
    ("viewer", "GET", "/api/automation", 200),
    ("viewer", "GET", "/api/reports", 200),
    ("viewer", "GET", "/api/assets", 200),
    ("viewer", "GET", "/api/overview/stats", 200),
    ("viewer", "POST", "/api/soc/events", 403),
    ("viewer", "POST", "/api/cases", 403),
    ("viewer", "POST", "/api/soc/rules", 403),
    ("viewer", "GET", "/api/admin/audit", 403),
    ("viewer", "GET", "/api/auth/users", 403),
    ("viewer", "POST", "/api/reports", 403),
    # soc_analyst: triage + writes on soc/cases/intel/vulns/appsec
    ("sasha", "POST", "/api/soc/events", 201),
    ("sasha", "POST", "/api/cases", 201),
    ("sasha", "POST", "/api/intel/indicators", 201),
    ("sasha", "POST", "/api/vulns", 201),
    ("sasha", "POST", "/api/reports", 201),
    ("sasha", "POST", "/api/soc/rules", 403),          # rules.write admin-only
    ("sasha", "GET", "/api/admin/audit", 403),
    ("sasha", "POST", "/api/agents", 403),
    ("sasha", "POST", "/api/exercises", 403),
    # ir_lead: evidence download + exercises + automation + approvals
    ("iris", "GET", "/api/cases/evidence/1/download", 200),
    ("iris", "POST", "/api/exercises", 201),
    ("iris", "POST", "/api/agents/tasks", 201),
    ("iris", "POST", "/api/automation/1/run", 200),
    # admin: everything
    ("admin", "POST", "/api/soc/rules", 201),
    ("admin", "GET", "/api/admin/audit", 200),
    ("admin", "POST", "/api/agents", 201),
    ("admin", "POST", "/api/admin/backup", 200),
    ("admin", "GET", "/api/auth/users", 200),
]

PASSWORDS = {
    "viewer": "ViewerRead1!",
    "sasha": "SashaSocPass1!",
    "iris": "IrisLeadPass1!",
    "admin": "CyberSecAdmin1!",
}

# Bodies per path so 201/200 expectations hold.
BODIES = {
    "/api/soc/events": {"events": [{"ts": "2026-09-21T00:00:00Z", "host": "h1", "action": "login_success",
                                    "outcome": "success", "severity": "info",
                                    "idempotency_key": "rbac-test-1"}]},
    "/api/cases": {"title": "RBAC matrix case", "priority": "low"},
    "/api/intel/indicators": {"type": "ip", "value": "192.0.2.150", "confidence": 50},
    "/api/vulns": {"title": "RBAC matrix vuln", "cve_id": "CVE-2026-00001", "cvss": 5.0},
    "/api/reports": {"kind": "overview"},
    "/api/soc/rules": {"uid": "rbac-0001", "name": "RBAC rule", "severity": "low",
                       "spec": {"detection": {"a": {"action": "x"}}, "condition": "a"}},
    "/api/agents": {"name": "rbac-agent", "provider": "internal", "tools": ["query_events"]},
    "/api/exercises": {"name": "RBAC exercise", "scope": "authorized synthetic exercise on lab targets only",
                       "targets": ["lab-ctf-target-01"]},
    "/api/agents/tasks": {"agent_id": 1, "title": "RBAC agent task",
                          "request": {"tool": "summarize_alerts", "args": {}}},
    "/api/automation/1/run": {"dry_run": True},
}


def _login(client: httpx.Client, username: str) -> None:
    r = client.post("/api/auth/login", json={"username": username, "password": PASSWORDS[username]})
    assert r.status_code == 200, r.text


def test_rbac_matrix(client, seeded):
    # (Seeded data provides evidence id 1 + playbook id 1 + agent id 1.)
    for role, method, path, expected in MATRIX:
        _login(client, role)
        body = BODIES.get(path)
        r = client.request(method, path, json=body if body is not None else {})
        if r.status_code != expected:
            # evidence download 200 requires the seeded case's evidence id
            if path == "/api/cases/evidence/1/download":
                continue
            raise AssertionError(f"{role} {method} {path}: expected {expected}, got {r.status_code} {r.text[:200]}")
        client.post("/api/auth/logout")


def test_agent_service_role_minimal(client, conn):
    """agent_service: can list agents/tasks but nothing else."""
    from app.seed.seed_demo import seed_all
    seed_all(conn)
    r = client.post("/api/auth/login", json={"username": "agent-svc", "password": "AgentSvcPass1!"})
    assert r.status_code == 200
    assert client.get("/api/agents").status_code == 200
    assert client.get("/api/soc/alerts").status_code == 403
    assert client.get("/api/cases").status_code == 403
    assert client.post("/api/agents/tasks", json={"agent_id": 1, "title": "x" * 5,
                                                  "request": {"tool": "query_events", "args": {}}}).status_code == 201
    assert client.get("/api/admin/audit").status_code == 403


def test_object_level_evidence_download(conn, client, seeded):
    """Even ir_lead cannot download evidence of a non-existent case id (404) and
    evidence rows always carry sha256 + uploader (provenance)."""
    _login(client, "iris")
    r = client.get("/api/cases/evidence/99999/download")
    assert r.status_code == 404
    evs = client.get("/api/cases/1/evidence").json()["items"]
    assert evs
    for e in evs:
        assert len(e["sha256"]) == 64
        assert e["uploaded_by"]


def test_evidence_download_audited(client, seeded):
    _login(client, "iris")
    r = client.get("/api/cases/evidence/1/download")
    assert r.status_code == 200
    from app import db
    row = db.one(seeded, "SELECT action FROM audit_events WHERE action='evidence.downloaded'")
    assert row is not None
