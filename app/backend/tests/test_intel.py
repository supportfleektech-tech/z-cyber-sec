"""Threat intel: sources, indicators, STIX import, correlation (SEC-034)."""
from __future__ import annotations

STIX_BUNDLE = {
    "type": "bundle",
    "id": "bundle--0001",
    "objects": [
        {"type": "indicator", "id": "indicator--1", "name": "bad ip",
         "pattern": "[ipv4-addr:value = '203.0.113.99']", "confidence": 80},
        {"type": "indicator", "id": "indicator--2", "name": "bad domain",
         "pattern": "[domain-name:value = 'bad-feed.example']"},
        {"type": "indicator", "id": "indicator--3", "name": "hash",
         "pattern": "[file:hashes.'SHA-256' = 'aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb']"},
        {"type": "malware", "id": "malware--1", "name": "ignored-not-indicator"},
    ],
}


def test_source_lifecycle(client, seeded):
    r = client.post("/api/intel/sources", json={"name": "Test Feed", "kind": "ioc_feed",
                                                "reliability": "b"})
    assert r.status_code == 201
    r = client.post("/api/intel/sources", json={"name": "Test Feed"})
    assert r.status_code == 409
    r = client.post("/api/intel/sources", json={"name": "Bad Rel", "reliability": "z"})
    assert r.status_code == 400
    assert client.get("/api/intel/sources").json()["total"] == 3  # 2 seeded + 1


def test_indicator_create_dedupe_and_update(client, seeded):
    r = client.post("/api/intel/indicators", json={"type": "ip", "value": "192.0.2.200", "confidence": 70})
    assert r.status_code == 201
    r = client.post("/api/intel/indicators", json={"type": "ip", "value": "192.0.2.200", "confidence": 90})
    assert r.status_code == 201
    body = r.json()
    assert body["updated"] is True
    ind = client.get("/api/intel/indicators", params={"q": "192.0.2.200"}).json()["items"][0]
    assert ind["confidence"] == 90
    # bad type
    r = client.post("/api/intel/indicators", json={"type": "port", "value": "80"})
    assert r.status_code == 400
    # filters
    r = client.get("/api/intel/indicators", params={"type": "ip", "min_confidence": 80})
    assert all(i["confidence"] >= 80 for i in r.json()["items"])


def test_stix_import(client, seeded):
    src = client.get("/api/intel/sources").json()["items"][0]
    r = client.post("/api/intel/indicators/stix", json={"bundle": STIX_BUNDLE, "source_id": src["id"]})
    assert r.status_code == 201
    body = r.json()
    assert body["created"] == 3  # malware object ignored
    inds = client.get("/api/intel/indicators", params={"type": "ip"}).json()["items"]
    ip = [i for i in inds if i["value"] == "203.0.113.99"]
    assert ip and ip[0]["confidence"] == 80
    # re-import: dedupe
    r = client.post("/api/intel/indicators/stix", json={"bundle": STIX_BUNDLE})
    assert r.json()["created"] == 0 and r.json()["updated"] == 3


def test_stix_bad_bundle(client, seeded):
    r = client.post("/api/intel/indicators/stix", json={"bundle": {"nope": 1}})
    assert r.status_code == 400


def test_correlation_finds_indicator_in_events(client, seeded):
    # seeded exfil event references 203.0.113.66 which is a seeded indicator
    r = client.get("/api/intel/indicators/correlate")
    assert r.status_code == 200
    hits = r.json()["hits"]
    assert any(h["indicator_value"] == "203.0.113.66" for h in hits)


def test_indicator_update(client, seeded):
    ind = client.get("/api/intel/indicators").json()["items"][0]
    r = client.patch(f"/api/intel/indicators/{ind['id']}",
                     json={"type": ind["type"], "value": ind["value"], "confidence": 10, "notes": "decayed"})
    assert r.status_code == 200
    assert r.json()["confidence"] == 10
    assert r.json()["notes"] == "decayed"
