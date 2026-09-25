"""Cloud posture + GRC + exercises (SEC-054/055)."""
from __future__ import annotations

import io


def test_cloud_assets_and_posture(client, seeded):
    r = client.post("/api/cloud/assets", json={"provider": "synthetic-cloud", "type": "bucket",
                                               "name": "syn-bucket-2"})
    assert r.status_code == 201
    aid = r.json()["id"]
    r = client.post("/api/cloud/posture", json={"asset_id": aid, "rule_id": "csp-009",
                                                "title": "Public bucket", "severity": "high"})
    assert r.status_code == 201
    r = client.get("/api/cloud/posture", params={"asset_id": aid})
    assert r.json()["total"] == 1
    r = client.post("/api/cloud/posture", json={"asset_id": 9999, "rule_id": "csp-009",
                                                "title": "Bad asset"})
    assert r.status_code == 400
    # SEC-079: posture status/severity are validated like every other audited
    # state. This test previously asserted `status: "remediated"` was stored —
    # a word no other part of the product uses (the UI offers `resolved`, the
    # seed uses `open`), which is exactly how the vocabulary drifted.
    r = client.patch("/api/cloud/posture/1", json={"asset_id": 1, "rule_id": "csp-001",
                                                    "title": "Updated", "severity": "low",
                                                    "status": "remediated"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "bad_status"
    r = client.patch("/api/cloud/posture/1", json={"asset_id": 1, "rule_id": "csp-001",
                                                    "title": "Updated", "severity": "low",
                                                    "status": "resolved"})
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"
    r = client.patch("/api/cloud/posture/1", json={"asset_id": 1, "rule_id": "csp-001",
                                                    "title": "Updated", "severity": "banana",
                                                    "status": "open"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "bad_severity"


def test_grc_controls_risks_evidence(client, seeded, conn):
    r = client.get("/api/grc/controls")
    assert r.json()["total"] >= 6
    r = client.post("/api/grc/controls", json={"framework": "ISO27001", "code": "A.5.1",
                                               "title": "Policies (synthetic)", "status": "met"})
    assert r.status_code == 201
    cid = r.json()["id"]
    r = client.post("/api/grc/controls", json={"framework": "ISO27001", "code": "A.5.1",
                                               "title": "Dup"})
    assert r.status_code == 409
    r = client.patch(f"/api/grc/controls/{cid}", json={"status": "gap"})
    assert r.status_code == 200
    r = client.patch(f"/api/grc/controls/{cid}", json={"status": "bogus"})
    assert r.status_code == 400
    # control evidence (metadata with sha256)
    files = {"file": ("policy.pdf", io.BytesIO(b"synthetic policy"), "application/pdf")}
    r = client.post(f"/api/grc/controls/{cid}/evidence", files=files)
    assert r.status_code == 201
    assert len(r.json()["sha256"]) == 64
    assert client.get(f"/api/grc/controls/{cid}/evidence").json()["total"] == 1
    # risks
    r = client.post("/api/grc/risks", json={"title": "Test risk", "likelihood": 4, "impact": 5})
    assert r.status_code == 201
    assert r.json()["score"] == 20
    r = client.get("/api/grc/risks")
    assert r.json()["items"]


def test_exercise_authorization_gate(client, seeded):
    r = client.post("/api/exercises", json={
        "name": "Gate test exercise",
        "scope": "Authorized synthetic exercise limited to lab-ctf-target-01 only.",
        "targets": ["lab-ctf-target-01"]})
    assert r.status_code == 201
    ex = r.json()
    # cannot run before authorization
    r = client.patch(f"/api/exercises/{ex['id']}", json={"status": "running"})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "not_authorized"
    r = client.patch(f"/api/exercises/{ex['id']}", json={"status": "authorized"})
    assert r.status_code == 200
    r = client.patch(f"/api/exercises/{ex['id']}", json={"status": "running"})
    assert r.status_code == 200
    ex_full = client.get(f"/api/exercises/{ex['id']}").json()
    assert ex_full["runs"]
    # SEC-083: closing an engagement records its outcome, so the reason is a
    # real sentence rather than a placeholder ("done" no longer passes).
    r = client.patch(f"/api/exercises/{ex['id']}",
                     json={"status": "completed", "reason": "synthetic range cleaned up; exercise closed"})
    assert r.status_code == 200
    ex_full = client.get(f"/api/exercises/{ex['id']}").json()
    assert ex_full["runs"][0]["result"] == "completed"
    # scope text is mandatory (min 20 chars)
    r = client.post("/api/exercises", json={"name": "No scope", "scope": "short"})
    assert r.status_code == 422


def test_control_evidence_round_trips_and_verifies(client, seeded, conn):
    """SEC-102: control evidence used to be hashed and thrown away — the row stored
    `path = NULL`, so a control's "audit evidence" was a name, a digest and a
    timestamp with no artifact behind it, and no route existed to download one.
    Uploads now land in the evidence store and download verifies the digest."""
    from pathlib import Path

    from app import db as dbmod

    r = client.post("/api/grc/controls", json={"framework": "SOC2", "code": "CC7.1",
                                              "title": "Evidence round-trip"})
    cid = r.json()["id"]
    payload = b"control evidence body"
    r = client.post(f"/api/grc/controls/{cid}/evidence",
                    files={"file": ("policy.pdf", io.BytesIO(payload), "application/pdf")})
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["path"] and Path(ev["path"]).exists()      # the bytes are really stored
    assert Path(ev["path"]).read_bytes() == payload

    listing = client.get(f"/api/grc/controls/{cid}/evidence").json()
    assert listing["total"] == 1 and listing["missing"] == 0
    assert listing["items"][0]["storage"] == "stored"

    # Download returns the artifact and audit-logs it.
    dl = client.get(f"/api/grc/evidence/{ev['id']}/download")
    assert dl.status_code == 200 and dl.content == payload

    # A file swapped in the store is refused, and the refusal is recorded.
    Path(ev["path"]).write_bytes(b"tampered")
    bad = client.get(f"/api/grc/evidence/{ev['id']}/download")
    assert bad.status_code == 500 and bad.json()["detail"]["code"] == "integrity_mismatch"
    audit = dbmod.q(seeded, "SELECT action, detail FROM audit_events "
                            "WHERE action = 'evidence.integrity_failure' ORDER BY seq DESC LIMIT 1")
    assert audit and str(ev["id"]) in audit[0]["detail"]

    # A row whose artifact is gone is reported as missing, not silently listed.
    Path(ev["path"]).unlink()
    assert client.get(f"/api/grc/evidence/{ev['id']}/download").status_code == 410
    listing = client.get(f"/api/grc/controls/{cid}/evidence").json()
    assert listing["missing"] == 1 and listing["items"][0]["storage"] == "missing"

    # A row written before the fix (no path) cannot be downloaded and says so.
    conn.execute("INSERT INTO audit_evidence (control_id, name, path, sha256, created_at) "
                 "VALUES (?, 'legacy.pdf', NULL, 'synthetic', ?)", (cid, dbmod.utcnow()))
    conn.commit()
    legacy = dbmod.one(seeded, "SELECT id FROM audit_evidence WHERE name = 'legacy.pdf'")
    r = client.get(f"/api/grc/evidence/{legacy['id']}/download")
    assert r.status_code == 410 and r.json()["detail"]["code"] == "not_stored"
    listing = client.get(f"/api/grc/controls/{cid}/evidence").json()
    assert listing["missing"] == 2
    assert {i["storage"] for i in listing["items"]} == {"missing", "not_stored"}


def test_seeded_control_evidence_points_at_a_real_file(seeded):
    """The demo used to seed a phantom: `path` NULL and the digest "synthetic" * 10.
    A seeded control now has a real artifact whose digest matches the file."""
    import hashlib
    from pathlib import Path

    row = seeded.execute("SELECT name, path, sha256 FROM audit_evidence ORDER BY id LIMIT 1").fetchone()
    assert row["path"] and Path(row["path"]).exists()
    assert row["sha256"] == hashlib.sha256(Path(row["path"]).read_bytes()).hexdigest()
    assert len(row["sha256"]) == 64
