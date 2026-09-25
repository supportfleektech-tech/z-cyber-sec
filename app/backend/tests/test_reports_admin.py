"""Reports + admin (integrations, flags, audit, backup/restore) (SEC-037/042)."""
from __future__ import annotations

from pathlib import Path

import pytest

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


def test_restore_path_must_really_be_in_the_backups_dir(client, seeded, tmp_path):
    """SEC-085: the guard was `"backups" not in str(path)` — a substring test —
    so any path that merely mentioned backups passed while the message claimed
    containment."""
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    outside = tmp_path / "evil-backups" / "stale.db"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"not really a bundle")

    r = client.post("/api/admin/backup/restore", json={"path": str(outside), "confirm": "RESTORE"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "bad_path"
    assert "backups directory" in r.json()["detail"]["message"]

    # a directory (not a file) inside the backups dir is refused too
    from app.config import settings
    d = settings.backups_dir / "not-a-file"
    d.mkdir(parents=True, exist_ok=True)
    r = client.post("/api/admin/backup/restore", json={"path": str(d), "confirm": "RESTORE"})
    assert r.status_code == 400

    # traversal out of the backups dir, even if it starts inside it
    sneaky = settings.backups_dir / ".." / "outside.db"
    sneaky.write_bytes(b"x")
    r = client.post("/api/admin/backup/restore", json={"path": str(sneaky), "confirm": "RESTORE"})
    assert r.status_code == 400
    sneaky.unlink(missing_ok=True)


def test_crafted_bundle_cannot_write_outside_the_evidence_store(client, seeded, tmp_path):
    """SEC-085: restore joined `evidence/<member>` onto the evidence directory,
    so `evidence/../../../../tmp/x` escaped. Verification iterated only over the
    manifest, so an unlisted member was invisible to it."""
    import io
    import tarfile
    from pathlib import Path as _Path

    from app.services.backup import contained, create_backup, restore_from, safe_member_name, verify_bundle

    good = _Path(create_backup(seeded, {"type": "user", "id": "1", "name": "admin"})["path"])
    assert verify_bundle(None, good)["ok"] is True          # legitimate bundle

    evil = tmp_path / "crafted.db"
    with tarfile.open(good, "r:gz") as src:
        members = [(m, src.extractfile(m).read() if m.isfile() else None) for m in src.getmembers()]
    with tarfile.open(evil, "w:gz") as dst:
        for m, data in members:
            dst.addfile(m, io.BytesIO(data) if data is not None else None)
        for name in ("evidence/../../../../../../tmp/cybersec_escape.txt", "/tmp/cybersec_absolute.txt"):
            info = tarfile.TarInfo(name)
            info.size = 5
            dst.addfile(info, io.BytesIO(b"PWNED"))

    v = verify_bundle(None, evil)
    assert v["ok"] is False
    assert any(x.startswith("unsafe:") for x in v["bad"])
    assert any(x.startswith("unlisted:") for x in v["bad"])

    escapees = [_Path("/tmp/cybersec_escape.txt"), _Path("/tmp/cybersec_absolute.txt")]
    for f in escapees:
        f.unlink(missing_ok=True)
    with pytest.raises(RuntimeError):
        restore_from(evil, {"type": "user", "id": "1", "name": "admin"})
    assert not any(f.exists() for f in escapees)

    # the primitives themselves
    for bad in ("evidence/../x", "../x", "/etc/passwd", "a/../../b"):
        assert safe_member_name(bad) is False
    assert safe_member_name("evidence/ok.bin") is True
    base = tmp_path / "ev"
    base.mkdir()
    assert contained(base, "sub/ok.bin") is not None
    assert contained(base, "../escape.bin") is None


def test_corrupt_bundle_is_a_clean_refusal_not_a_500(client, seeded):
    """SEC-086: `verify_bundle` raised on unreadable archives, so restoring an
    interrupted/corrupt backup returned an opaque 500 and the operator had to
    read server logs to learn their file was unreadable. It is now a 409 whose
    message names the reason, and the 409 for error-style failures no longer
    renders as "None"."""
    from app.config import settings

    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    settings.backups_dir.mkdir(parents=True, exist_ok=True)
    junk = settings.backups_dir / "corrupt-test.db"
    junk.write_bytes(b"this is not a tar.gz at all")

    r = client.post("/api/admin/backup/restore", json={"path": str(junk), "confirm": "RESTORE"})
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert detail["code"] == "verify_failed"
    assert detail["message"] != "None" and "unreadable bundle" in detail["message"]

    # truncated archive: recognisable extension, unusable content
    from app.services.backup import create_backup
    good = Path(create_backup(seeded, {"type": "user", "id": "1", "name": "admin"})["path"])
    trunc = settings.backups_dir / "truncated-test.db"
    trunc.write_bytes(good.read_bytes()[: len(good.read_bytes()) // 2])
    r = client.post("/api/admin/backup/restore", json={"path": str(trunc), "confirm": "RESTORE"})
    assert r.status_code == 409 and "unreadable bundle" in r.json()["detail"]["message"]

    # and the app is still healthy afterwards
    junk.unlink(missing_ok=True)
    trunc.unlink(missing_ok=True)
    assert client.get("/api/healthz").json()["ok"] is True


def test_deleting_the_anchor_is_tampering_not_a_pass(client, seeded, conn):
    """SEC-099: `DELETE FROM audit_anchor` used to make /audit/verify answer
    `ok: true, reason: "unanchored"` — a single row deletion turned detected
    truncation into a passing check, which is exactly the laundering path SEC-084
    set out to close. Live: on a copy of the demo DB, deleting the anchor row after
    deleting the log's tail reported ok=True (warning only)."""

    assert client.get("/api/admin/audit/verify").json()["ok"] is True

    # Delete history AND its anchor — the two things an attacker erasing activity
    # would remove together.
    conn.execute("DELETE FROM audit_events WHERE seq > 1")
    conn.execute("DELETE FROM audit_anchor")
    conn.commit()

    v = client.get("/api/admin/audit/verify").json()
    assert v["ok"] is False and v["reason"] == "anchor_missing", v
    assert "anchor" in v["detail"] and v["anchor"] is None

    # An anchor exported beforehand still says what the log claimed to contain.
    exported = {"head_seq": 1, "head_hash": conn.execute(
        "SELECT hash FROM audit_events WHERE seq = 1").fetchone()["hash"], "rows": 5}
    v2 = client.get("/api/admin/audit/verify", params=exported).json()
    assert v2["ok"] is False and v2["reason"] == "anchor_missing"
    assert v2["external"]["ok"] is False and v2["external"]["reason"] == "truncated"


def test_full_rewrite_is_caught_by_an_exported_anchor(client, seeded, conn):
    """A rewrite that recomputes the whole chain *and* the in-DB anchor is
    invisible to the in-DB check (the attacker rewrote the evidence) but must not
    be invisible to a copy kept outside the platform."""
    from app.audit import compute_hash

    before = client.get("/api/admin/audit/anchor").json()["anchor"]
    rows = [dict(r) for r in conn.execute("SELECT * FROM audit_events ORDER BY seq")]
    head = rows[-1]
    # Rewrite the tail event's content, then rebuild the chain and the anchor so
    # everything verifies in-database.
    conn.execute("DELETE FROM audit_events WHERE seq = ?", (head["seq"],))
    detail = (head["detail"] or "{}")
    forged_detail = detail.replace("admin", "someone-else")
    prev = conn.execute("SELECT hash FROM audit_events WHERE seq = ?", (head["seq"] - 1,)).fetchone()["hash"]
    forged_hash = compute_hash(head["seq"], head["ts"], head["actor_type"], head["actor_id"],
                               head["actor_name"], head["action"], head["target_type"],
                               head["target_id"], forged_detail, prev)
    conn.execute("INSERT INTO audit_events (seq, ts, actor_type, actor_id, actor_name, action,"
                 " target_type, target_id, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (head["seq"], head["ts"], head["actor_type"], head["actor_id"], head["actor_name"],
                  head["action"], head["target_type"], head["target_id"], forged_detail, prev, forged_hash))
    conn.execute("UPDATE audit_anchor SET head_hash = ? WHERE id = 1", (forged_hash,))
    conn.commit()

    assert client.get("/api/admin/audit/verify").json()["ok"] is True  # attacker: clean
    v = client.get("/api/admin/audit/verify", params=before).json()
    assert v["external"]["ok"] is False and v["external"]["reason"] == "replaced"
    assert before["head_hash"][:8] in v["external"]["detail"]
