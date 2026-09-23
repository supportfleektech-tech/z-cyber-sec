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
    assert r.json()["reason"] == "linkage"


def test_truncating_the_audit_log_is_detected(client, seeded, conn):
    """SEC-084: a hash chain cannot see its own tail. Deleting the newest rows
    used to leave every remaining link valid, so verify said ok for exactly the
    tamper that erases the evidence of what someone just did."""
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    before = client.get("/api/admin/audit/verify").json()
    assert before["ok"] is True and before["anchor"]["rows"] == before["rows"]

    # delete the newest rows straight from the DB (the attacker's move)
    conn.execute("DELETE FROM audit_events WHERE seq > (SELECT MAX(seq) - 2 FROM audit_events)")
    conn.commit()

    after = client.get("/api/admin/audit/verify").json()
    assert after["ok"] is False
    assert after["reason"] == "truncated"
    assert after["anchor"]["rows"] == before["rows"]      # what history says existed
    assert after["rows"] < before["rows"]

    # ...and the export endpoint reports both sides
    r = client.get("/api/admin/audit/anchor")
    assert r.status_code == 200
    assert r.json()["verify"]["ok"] is False
    assert r.json()["anchor"]["rows"] == before["rows"]


def test_truncation_cannot_be_healed_by_later_activity(client, seeded, conn):
    """The anchor must not be re-blessed by later activity: first the count
    watermark, then the (seq, hash) pin — an attacker who deletes rows can
    otherwise replenish the count with fresh events and make verify say ok."""
    from app.audit import record_audit

    actor = {"type": "user", "id": "1", "name": "admin"}
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    before = client.get("/api/admin/audit/anchor").json()["anchor"]
    conn.execute("DELETE FROM audit_events WHERE seq > (SELECT MAX(seq) - 2 FROM audit_events)")
    conn.commit()

    # one new event: the count is still short of the watermark
    record_audit(conn, actor, "test.after_truncation")
    v = client.get("/api/admin/audit/verify").json()
    assert v["ok"] is False and v["reason"] == "truncated"
    assert v["anchor"]["rows"] == before["rows"]           # watermark held
    assert v["missing_rows"] >= 1

    # Replenish until the count AND the anchored seq are reached again. The
    # in-DB anchor advances with legitimate appends, so once enough new events
    # land it can no longer see the gap — that is the documented limit of a
    # local anchor. An anchor exported BEFORE the deletion still catches it,
    # because seq numbers are reused and the row at that seq now hashes
    # differently.
    for i in range(6):
        record_audit(conn, actor, f"test.launder{i}")

    r = client.get("/api/admin/audit/verify", params={
        "head_seq": before["head_seq"], "head_hash": before["head_hash"], "rows": before["rows"]})
    ext = r.json()["external"]
    assert ext["ok"] is False, "an exported anchor must still detect the erased history"
    assert ext["reason"] in ("missing", "replaced", "truncated")


def test_newest_rows_are_anchored_as_they_are_written(client, seeded, conn):
    """The anchor must track appends, or truncation after the last anchor is
    invisible again."""
    from app.audit import record_audit

    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    a1 = client.get("/api/admin/audit/anchor").json()["anchor"]
    record_audit(conn, {"type": "user", "id": "1", "name": "admin"}, "test.anchor_probe")
    a2 = client.get("/api/admin/audit/anchor").json()["anchor"]
    assert a2["rows"] == a1["rows"] + 1 and a2["head_hash"] != a1["head_hash"]
    # and the anchor does not live somewhere an admin can overwrite via the API
    r = client.get("/api/admin/settings")
    assert all(s["key"] != "audit.anchor" for s in r.json()["items"])


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
