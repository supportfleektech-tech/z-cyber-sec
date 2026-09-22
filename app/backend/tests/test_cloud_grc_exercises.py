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
    r = client.patch(f"/api/exercises/{ex['id']}", json={"status": "completed", "reason": "done"})
    assert r.status_code == 200
    ex_full = client.get(f"/api/exercises/{ex['id']}").json()
    assert ex_full["runs"][0]["result"] == "completed"
    # scope text is mandatory (min 20 chars)
    r = client.post("/api/exercises", json={"name": "No scope", "scope": "short"})
    assert r.status_code == 422
