"""Reports + admin (integrations, flags, audit, backup/restore) (SEC-037/042)."""
from __future__ import annotations

from pathlib import Path

from app import db


def test_report_generation_and_download(client, seeded, conn):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    for kind in ("overview", "soc", "cases", "intel", "vulns"):
        r = client.post("/api/reports", json={"kind": kind})
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["input_sha256"]
        p = Path(body["path"])
        assert p.exists()
        html = p.read_text()
        assert "SYNTHETIC DATA" in html  # demo labeling
        assert "Provenance" in html
        assert body["input_sha256"] in html
        # download works for admin
        r = client.get(f"/api/reports/{body['id']}/download")
        assert r.status_code == 200
        assert r.text == html
    # unknown kind
    r = client.post("/api/reports", json={"kind": "nope"})
    assert r.status_code == 400
    # listing
    r = client.get("/api/reports")
    assert r.json()["total"] >= 5
    # SOC report filter
    r = client.post("/api/reports", json={"kind": "soc", "filters": {"severity": "high"}})
    assert r.status_code == 201
    html = Path(r.json()["path"]).read_text()
    assert "High" in html or "high" in html


def test_report_download_permission(client, seeded):
    client.post("/api/auth/login", json={"username": "viewer", "password": "ViewerRead1!"})
    # viewer can list but not download (download requires reports.generate)
    r = client.get("/api/reports")
    assert r.status_code == 200
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    rep = client.post("/api/reports", json={"kind": "overview"}).json()
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "viewer", "password": "ViewerRead1!"})
    r = client.get(f"/api/reports/{rep['id']}/download")
    assert r.status_code == 403


def test_integration_secret_rejection(client, seeded):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    r = client.post("/api/admin/integrations", json={
        "name": "leaky", "kind": "feed",
        "config": {"endpoint": "https://x", "api_key": "sk-supersecret"}})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "secret_in_config"
    r = client.post("/api/admin/integrations", json={
        "name": "ok-int", "kind": "feed", "config": {"endpoint": "https://x", "schedule": "15m"}})
    assert r.status_code == 201
    r = client.post("/api/admin/integrations/1/health", json={"status": "degraded"})
    assert r.status_code == 200


def test_flags_and_settings(client, seeded):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    r = client.post("/api/admin/flags", json={"key": "feature_x", "value": True})
    assert r.status_code == 200
    flags = client.get("/api/admin/flags").json()["items"]
    assert any(f["key"] == "feature_x" and f["value"] == 1 for f in flags)
    r = client.put("/api/admin/settings/key1", json={"value": "v1"})
    assert r.status_code == 200
    s = client.get("/api/admin/settings").json()["items"]
    assert any(x["key"] == "key1" and x["value"] == "v1" for x in s)
    # viewer blocked
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "viewer", "password": "ViewerRead1!"})
    assert client.get("/api/admin/flags").status_code == 403


def test_audit_log_and_chain_verification(client, seeded, conn):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    r = client.get("/api/admin/audit", params={"page_size": 20})
    assert r.status_code == 200
    assert r.json()["total"] > 0
    r = client.get("/api/admin/audit", params={"action": "auth"})
    assert all(x["action"].startswith("auth") for x in r.json()["items"])
    r = client.get("/api/admin/audit/verify")
    assert r.json()["ok"] is True
    # tamper -> verification fails
    conn.execute("UPDATE audit_events SET detail = 'tampered' WHERE seq = 1")
    conn.commit()
    r = client.get("/api/admin/audit/verify")
    assert r.json()["ok"] is False
    assert r.json()["first_bad_seq"] == 1


def test_backup_and_restore_roundtrip(client, seeded, conn):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    cases_before = db.q(conn, "SELECT number FROM cases")
    r = client.post("/api/admin/backup")
    assert r.status_code == 200
    body = r.json()
    bpath = Path(body["path"])
    assert bpath.exists()
    assert len(body["sha256"]) == 64
    # tamper simulation: create a marker row, then restore overwrites it
    conn.execute("INSERT INTO cases (number, title, status, created_at, updated_at) "
                 "VALUES ('CASE-1999-9999', 'tamper marker', 'open', ?, ?)",
                 (db.utcnow(), db.utcnow()))
    conn.commit()
    assert db.one(conn, "SELECT id FROM cases WHERE number='CASE-1999-9999'") is not None
    # restore without confirm -> 400
    r = client.post("/api/admin/backup/restore", json={"path": str(bpath)})
    assert r.status_code == 400
    r = client.post("/api/admin/backup/restore", json={"path": str(bpath), "confirm": "RESTORE"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    # fresh connection to see restored state
    conn2 = db.raw_connection()
    assert db.one(conn2, "SELECT id FROM cases WHERE number='CASE-1999-9999'") is None
    restored = db.q(conn2, "SELECT number FROM cases")
    assert {c["number"] for c in restored} >= {c["number"] for c in cases_before}
    conn2.close()


def test_backup_bad_path_rejected(client, seeded):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    r = client.post("/api/admin/backup/restore", json={"path": "/etc/passwd", "confirm": "RESTORE"})
    assert r.status_code == 400


def test_metrics_endpoint(client, seeded):
    r = client.get("/metrics")
    assert r.status_code == 200
    text = r.text
    for key in ("cybersec_uptime_seconds", "cybersec_events_total", "cybersec_alerts_open",
                "cybersec_db_size_bytes"):
        assert key in text
    assert 'cybersec_alerts_open{severity="high"}' in text


def test_healthz(client, seeded):
    r = client.get("/api/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_env_banner_header(client, seeded):
    r = client.get("/api/healthz")
    assert r.headers.get("X-Environment") == "LOCAL"
