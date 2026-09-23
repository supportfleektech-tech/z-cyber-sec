"""Case lifecycle, tasks, evidence provenance (SEC-032/033)."""
from __future__ import annotations

import io

from app import db


def test_case_full_lifecycle(client, seeded, conn):
    r = client.post("/api/cases", json={"title": "Test incident", "priority": "high",
                                        "severity": "high", "assigned_to": "iris",
                                        "description": "synthetic"})
    assert r.status_code == 201
    case = r.json()
    cid = case["id"]
    assert case["number"].startswith("CASE-")
    assert case["status"] == "open"

    # task
    r = client.post(f"/api/cases/{cid}/tasks", json={"title": "Contain", "assigned_to": "iris"})
    assert r.status_code == 201
    tid = r.json()["id"]
    r = client.patch(f"/api/cases/tasks/{tid}", json={"status": "done"})
    assert r.status_code == 200

    # evidence upload + list + download
    files = {"file": ("summary.txt", io.BytesIO(b"synthetic evidence content"), "text/plain")}
    r = client.post(f"/api/cases/{cid}/evidence", files=files,
                    data={"classification": "internal"})
    assert r.status_code == 201
    ev = r.json()
    assert len(ev["sha256"]) == 64
    assert ev["size"] == len(b"synthetic evidence content")

    r = client.get(f"/api/cases/{cid}/evidence")
    assert r.json()["total"] == 1

    r = client.get(f"/api/cases/evidence/{ev['id']}/download")
    assert r.status_code == 200
    assert r.content == b"synthetic evidence content"

    # timeline has status/task/evidence entries
    r = client.get(f"/api/cases/{cid}")
    types = {t["entry_type"] for t in r.json()["timeline"]}
    assert {"status", "task", "evidence"} <= types

    # status flow + closure
    for st in ("investigating", "contained", "mitigated", "closed"):
        r = client.patch(f"/api/cases/{cid}", json={"status": st})
        assert r.status_code == 200, r.text
    r = client.get(f"/api/cases/{cid}")
    assert r.json()["closed_at"]
    r = client.patch(f"/api/cases/{cid}", json={"status": "bogus"})
    assert r.status_code == 400


def test_case_from_alert(client, seeded):
    alert = client.get("/api/soc/alerts").json()["items"][0]
    r = client.post("/api/cases", json={"title": f"From alert {alert['id']}", "alert_id": alert["id"]})
    assert r.status_code == 201
    alert_after = client.get(f"/api/soc/alerts/{alert['id']}").json()["alert"]
    assert alert_after["status"] == "confirmed"
    assert alert_after["case_id"]
    case = client.get(f"/api/cases/{alert_after['case_id']}").json()
    assert any(t["entry_type"] == "alert" for t in case["timeline"])


def test_case_numbering_unique(client, seeded):
    for i in range(3):
        r = client.post("/api/cases", json={"title": f"Numbering case {i}"})
        assert r.status_code == 201
    nums = [c["number"] for c in client.get("/api/cases", params={"page_size": 100}).json()["items"]]
    assert len(nums) == len(set(nums))


def test_evidence_integrity_failure_detected(client, seeded, conn):
    ev = db.one(conn, "SELECT * FROM evidence LIMIT 1")
    assert ev is not None
    path = ev["path"]
    with open(path, "ab") as f:
        f.write(b"tampered")
    r = client.get(f"/api/cases/evidence/{ev['id']}/download")
    assert r.status_code == 500
    assert r.json()["detail"]["code"] == "integrity_mismatch"
    row = db.one(conn, "SELECT action FROM audit_events WHERE action='evidence.integrity_failure'")
    assert row is not None


def test_evidence_too_large_rejected(client, seeded):
    case = client.post("/api/cases", json={"title": "Big evidence case"}).json()
    big = b"x" * (26 * 1024 * 1024)
    files = {"file": ("big.bin", io.BytesIO(big), "application/octet-stream")}
    r = client.post(f"/api/cases/{case['id']}/evidence", files=files)
    assert r.status_code == 413


def test_evidence_bad_classification_rejected(client, seeded):
    case = client.post("/api/cases", json={"title": "Class case"}).json()
    files = {"file": ("a.txt", io.BytesIO(b"hi"), "text/plain")}
    r = client.post(f"/api/cases/{case['id']}/evidence", files=files, data={"classification": "topsecret"})
    assert r.status_code == 400


def test_reopening_a_case_clears_closed_at(client, seeded):
    """SEC-092: `closed_at` was stamped on close and never cleared, so a reopened
    case still reported a closure time — the case report (an evidence artefact)
    and the case detail header ("created → closed") presented an active case as
    closed. Live-verified before the fix: reopen left `closed_at` at the old
    value."""
    from app import db as dbmod

    c = client.post("/api/cases", json={"title": "Reopen me", "severity": "medium"}).json()
    cid = c["id"]

    r = client.patch(f"/api/cases/{cid}", json={"status": "closed"})
    assert r.status_code == 200
    closed_at = r.json()["closed_at"]
    assert closed_at

    # closing again does not rewrite the closure time
    r = client.patch(f"/api/cases/{cid}", json={"status": "closed"})
    assert r.json()["closed_at"] == closed_at

    # reopening clears it and says so in the timeline and the audit trail
    r = client.patch(f"/api/cases/{cid}", json={"status": "investigating", "notes": "false positive"})
    assert r.status_code == 200 and r.json()["closed_at"] is None
    entries = dbmod.q(seeded, "SELECT message FROM case_timeline WHERE case_id = ? ORDER BY id", (cid,))
    messages = [e["message"] for e in entries]
    assert any(m == "Status → closed" for m in messages)
    assert any("reopened from closed" in m for m in messages)
    ev = dbmod.jload(dbmod.q(seeded, "SELECT detail FROM audit_events WHERE action = 'case.updated' "
                                     "ORDER BY seq DESC LIMIT 1")[0]["detail"])
    assert ev["from_status"] == "closed" and ev["to_status"] == "investigating" and ev["reopened"] is True

    # closing after a reopen stamps a closure time again (>= because the
    # timestamps are second-granularity and this test runs within one second)
    r = client.patch(f"/api/cases/{cid}", json={"status": "closed"})
    assert r.json()["closed_at"] and r.json()["closed_at"] >= closed_at

    # scope check: a report of the case shows no closure for an open case
    client.patch(f"/api/cases/{cid}", json={"status": "open"})
    html = client.post("/api/reports", json={"kind": "cases"}).json()
    from pathlib import Path
    body = Path(html["path"]).read_text()
    assert "Reopen me" in body
