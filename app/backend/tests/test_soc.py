"""SOC: ingest validation, idempotency, alerts, rules (SEC-030/031/032)."""
from __future__ import annotations


def _ingest(client, ts, action="login_success", **kw):
    ev = {"ts": ts, "host": "h1", "action": action, "outcome": "success",
          "severity": "info", "data_class": "synthetic"}
    ev.update(kw)
    return client.post("/api/soc/events", json={"events": [ev]})


def test_ingest_validation(client, seeded):
    r = _ingest(client, "2026-09-21T00:00:00Z", severity="bogus")
    assert r.status_code == 422
    r = client.post("/api/soc/events", json={"events": []})
    assert r.status_code == 422
    r = client.post("/api/soc/events", json={"events": [
        {"ts": "2026-09-21T00:00:00Z", "action": "x", "data_class": "topsecret"}]})
    assert r.status_code == 422


def test_ingest_idempotency(client, seeded):
    body = {"events": [{"ts": "2026-09-21T00:00:00Z", "host": "h1", "action": "login_success",
                        "outcome": "success", "severity": "info", "idempotency_key": "idem-1"}]}
    r1 = client.post("/api/soc/events", json=body)
    r2 = client.post("/api/soc/events", json=body)
    assert r1.status_code == 201 and r1.json()["inserted"] == 1
    assert r2.status_code == 201 and r2.json()["inserted"] == 0 and r2.json()["skipped"] == 1


def test_batch_ingest_and_list(client, seeded):
    body = {"events": [
        {"ts": f"2026-09-21T00:0{i}:00Z", "host": f"h{i}", "action": "login_success",
         "outcome": "success", "severity": "info", "idempotency_key": f"batch-{i}"}
        for i in range(10)]}
    r = client.post("/api/soc/events", json=body)
    assert r.status_code == 201
    assert r.json()["inserted"] == 10
    r = client.get("/api/soc/events", params={"host": "h3", "page_size": 5})
    assert r.status_code == 200
    assert r.json()["total"] == 1


def test_alert_lifecycle(client, seeded):
    r = client.get("/api/soc/alerts")
    assert r.status_code == 200
    a = r.json()["items"][0]
    r = client.patch(f"/api/soc/alerts/{a['id']}", json={"status": "triaging", "assigned_to": "sasha",
                                                         "notes": "looking"})
    assert r.status_code == 200
    assert r.json()["status"] == "triaging"
    assert r.json()["assigned_to"] == "sasha"
    r = client.patch(f"/api/soc/alerts/{a['id']}", json={"status": "bogus"})
    assert r.status_code == 400
    r = client.get(f"/api/soc/alerts/{a['id']}")
    assert r.status_code == 200
    assert "events" in r.json()


def test_create_rule_validation_and_lifecycle(client, seeded):
    bad = {"uid": "t-bad", "name": "Bad rule", "spec": {}}
    r = client.post("/api/soc/rules", json=bad)
    assert r.status_code == 400
    r = client.post("/api/soc/rules", json={
        "uid": "t-new", "name": "New rule", "severity": "low",
        "spec": {"detection": {"sel": {"action": "weird_action"}}, "condition": "sel"}})
    assert r.status_code == 201
    rid = r.json()["id"]
    r = client.post("/api/soc/rules", json={
        "uid": "t-new", "name": "Dup", "severity": "low",
        "spec": {"detection": {"sel": {"action": "x"}}, "condition": "sel"}})
    assert r.status_code == 409
    r = client.patch(f"/api/soc/rules/{rid}", json={
        "uid": "t-new", "name": "New rule v2", "severity": "medium",
        "spec": {"detection": {"sel": {"action": "weird_action"}}, "condition": "sel"}})
    assert r.status_code == 200
    assert r.json()["name"] == "New rule v2"


def test_rule_dry_run(client, seeded):
    rules = client.get("/api/soc/rules").json()["items"]
    ssh = next(r for r in rules if r["uid"] == "cs-0001")
    # find the seeded brute-force event ids via alert
    alerts = client.get("/api/soc/alerts").json()["items"]
    alert = next(a for a in alerts if a["title"].startswith("SSH Brute Force"))
    detail = client.get(f"/api/soc/alerts/{alert['id']}").json()
    event_ids = [e["id"] for e in detail["events"][:8]]
    r = client.post("/api/soc/rules/dry-run", json={"rule_id": ssh["id"], "event_ids": event_ids})
    assert r.status_code == 200
    body = r.json()
    assert body["events_checked"] == len(event_ids)
    assert body["alert_groups"]


def test_backfill_idempotent_no_alert_spam(client, seeded):
    client.post("/api/soc/detections/backfill")
    r2 = client.post("/api/soc/detections/backfill").json()
    before = client.get("/api/soc/alerts").json()["total"]
    assert r2["alerts"] == []  # second backfill creates nothing new (dedup)
    assert client.get("/api/soc/alerts").json()["total"] == before


def test_new_rule_detected_via_backfill(client, seeded, conn):
    # new rule matching existing seeded exfil event
    r = client.post("/api/soc/rules", json={
        "uid": "t-exfil", "name": "Exfil v2", "severity": "high",
        "spec": {"detection": {"big": {"action": "network_out"}}, "condition": "big"}})
    assert r.status_code == 201
    out = client.post("/api/soc/detections/backfill").json()
    assert any(a["title"].startswith("Exfil v2") for a in out["alerts"])
