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


def _backdate(db_conn, ind_id: int, hours: int):
    """Move an indicator's first_seen into the past (as if time had passed)."""
    from datetime import UTC, datetime, timedelta
    old = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db_conn.execute("UPDATE threat_indicators SET first_seen = ? WHERE id = ?", (old, ind_id))
    db_conn.commit()


def test_ttl_actually_expires_indicators(client, seeded):
    """SEC-087: `ttl_hours` was stored, validated and advertised ("confidence,
    expiry, and cross-correlation") but never read — nothing ever expired, so
    correlation kept matching stale IOCs."""
    from app import db as dbmod
    conn = seeded

    r = client.post("/api/intel/indicators", json={"type": "ip", "value": "198.51.100.77",
                                                   "confidence": 90, "ttl_hours": 24})
    assert r.status_code == 201
    ind_id = r.json()["id"]
    it = client.get("/api/intel/indicators", params={"q": "198.51.100.77"}).json()["items"][0]
    assert it["status"] == "active" and it["expires_at"] is not None

    # not yet due -> untouched, and no audit noise
    client.get("/api/intel/indicators")
    assert client.get("/api/intel/indicators", params={"q": "198.51.100.77"}).json()["items"][0]["status"] == "active"

    _backdate(conn, ind_id, hours=25)
    it = client.get("/api/intel/indicators", params={"q": "198.51.100.77"}).json()["items"][0]
    assert it["status"] == "expired"

    events = dbmod.q(conn, "SELECT action, detail FROM audit_events WHERE action = 'intel.indicators.expired'")
    assert len(events) == 1
    assert ind_id in dbmod.jload(events[0]["detail"])["ids"]

    # idempotent: nothing left to expire, no second entry
    client.get("/api/intel/indicators")
    client.get("/api/intel/indicators/correlate")
    assert len(dbmod.q(conn, "SELECT id FROM audit_events WHERE action = 'intel.indicators.expired'")) == 1

    # an expired indicator is no longer correlated
    client.post("/api/events", json={"action": "dns", "host": "h1", "user": "u1", "severity": "low",
                                     "msg": "resolved 198.51.100.77"})
    hits = client.get("/api/intel/indicators/correlate").json()["hits"]
    assert not any(h["indicator_value"] == "198.51.100.77" for h in hits)


def test_indicator_upsert_is_audited_and_revocation_survives(client, seeded):
    """SEC-087: re-sighting an indicator updated confidence/last_seen with no
    audit entry, though docs/12 promises one per state change."""
    from app import db as dbmod

    r = client.post("/api/intel/indicators", json={"type": "domain", "value": "reseen.example",
                                                   "confidence": 40, "ttl_hours": 24})
    ind_id = r.json()["id"]

    # re-sighting an expired indicator revives it (fresh evidence) ...
    _backdate(seeded, ind_id, hours=30)
    r = client.post("/api/intel/indicators", json={"type": "domain", "value": "reseen.example",
                                                   "confidence": 80})
    assert r.json()["revived"] is True and r.json()["status"] == "active"
    detail = dbmod.jload(dbmod.q(seeded, "SELECT detail FROM audit_events WHERE action = "
                                        "'intel.indicator.reseen'")[0]["detail"])
    assert detail["revived"] is True

    # ... but a human revocation is not undone by a feed
    client.patch(f"/api/intel/indicators/{ind_id}",
                 json={"type": "domain", "value": "reseen.example", "status": "revoked"})
    r = client.post("/api/intel/indicators", json={"type": "domain", "value": "reseen.example",
                                                   "confidence": 95})
    assert r.json()["status"] == "revoked" and r.json()["revived"] is False
    assert client.get("/api/intel/indicators", params={"q": "reseen.example"}).json()["items"][0]["status"] == "revoked"


def test_create_indicator_honours_and_validates_status(client, seeded):
    """SEC-087: POST silently ignored `status` (a "revoked" indicator came back
    active and was then matched by correlation)."""
    r = client.post("/api/intel/indicators", json={"type": "ip", "value": "203.0.113.123",
                                                   "status": "revoked"})
    assert r.status_code == 201
    assert client.get("/api/intel/indicators", params={"q": "203.0.113.123"}).json()["items"][0]["status"] == "revoked"

    r = client.post("/api/intel/indicators", json={"type": "ip", "value": "203.0.113.124",
                                                   "status": "banana"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "bad_status"
    assert client.get("/api/intel/indicators", params={"q": "203.0.113.124"}).json()["total"] == 0


def test_stix_validity_window_is_honoured(client, seeded):
    """SEC-087: the parser dropped STIX `valid_until`, so an imported expired
    IOC was stored active and matched forever."""
    from datetime import UTC, datetime, timedelta
    past = (datetime.now(UTC) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    soon = (datetime.now(UTC) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle = {
        "type": "bundle", "id": "bundle--ttl",
        "objects": [
            {"type": "indicator", "id": "indicator--old", "name": "stale",
             "pattern": "[ipv4-addr:value = '203.0.113.201']", "valid_until": past},
            {"type": "indicator", "id": "indicator--live", "name": "live",
             "pattern": "[ipv4-addr:value = '203.0.113.202']", "valid_until": soon},
        ],
    }
    r = client.post("/api/intel/indicators/stix", json={"bundle": bundle})
    assert r.status_code == 201
    assert r.json()["expired_on_arrival"] == 1

    stale = client.get("/api/intel/indicators", params={"q": "203.0.113.201"}).json()["items"][0]
    live = client.get("/api/intel/indicators", params={"q": "203.0.113.202"}).json()["items"][0]
    assert stale["status"] == "expired"
    assert live["status"] == "active" and live["ttl_hours"] and live["expires_at"]


def test_patch_preserves_fields_it_was_not_given(client, seeded):
    """SEC-088: `PATCH` overwrote every column from the body, so omitting a
    field NULLed it. Live-verified before the fix: `PATCH {"confidence": 10}`
    on a seeded indicator wiped source_id (1 -> None), mitre_tactics
    (["credential-access"] -> None) and its notes — and the UI's status
    dropdown sends exactly such a partial body, so one status change erased the
    indicator's provenance. `type`/`value` were required but never written."""
    from app import db as dbmod

    src = client.get("/api/intel/sources").json()["items"][0]
    r = client.post("/api/intel/indicators", json={
        "type": "ip", "value": "192.0.2.44", "confidence": 60, "source_id": src["id"],
        "ttl_hours": 48, "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1110"], "notes": "keep me"})
    ind_id = r.json()["id"]

    # partial update: one field
    r = client.patch(f"/api/intel/indicators/{ind_id}", json={"confidence": 10})
    assert r.status_code == 200
    kept = r.json()
    assert kept["confidence"] == 10
    assert kept["source_id"] == src["id"] and kept["ttl_hours"] == 48
    assert kept["mitre_tactics"] == ["credential-access"]      # SEC-089: arrays, not JSON text
    assert kept["mitre_techniques"] == ["T1110"]
    assert kept["notes"] == "keep me"

    # the audit entry names what changed
    ev = dbmod.q(seeded, "SELECT detail FROM audit_events WHERE action = 'intel.indicator.updated' "
                         "ORDER BY seq DESC LIMIT 1")[0]
    assert dbmod.jload(ev["detail"])["changed"] == ["confidence"]

    # status-only change (the UI path) also preserves provenance
    r = client.patch(f"/api/intel/indicators/{ind_id}", json={"status": "revoked"})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    assert r.json()["source_id"] == src["id"] and r.json()["notes"] == "keep me"

    # an empty body is a no-op error, not a silent wipe
    r = client.patch(f"/api/intel/indicators/{ind_id}", json={})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "no_changes"
    assert client.get("/api/intel/indicators", params={"q": "192.0.2.44"}).json()["items"][0]["notes"] == "keep me"

    # type/value are now honoured, validated, and cannot collide with the dedupe key
    r = client.patch(f"/api/intel/indicators/{ind_id}", json={"value": "192.0.2.45"})
    assert r.status_code == 200 and r.json()["value"] == "192.0.2.45"
    r = client.patch(f"/api/intel/indicators/{ind_id}", json={"type": "port"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "bad_type"
    other = client.post("/api/intel/indicators", json={"type": "ip", "value": "192.0.2.46"}).json()["id"]
    r = client.patch(f"/api/intel/indicators/{ind_id}", json={"value": "192.0.2.46"})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "duplicate_indicator"
    assert client.get("/api/intel/indicators", params={"q": "192.0.2.46"}).json()["total"] == 1

    # an explicit null still clears a field (how a client disables expiry)
    r = client.patch(f"/api/intel/indicators/{other}", json={"ttl_hours": None})
    assert r.status_code == 200 and r.json()["ttl_hours"] is None


def test_spa_sends_mitre_as_a_list_and_renders_it(client, seeded):
    """SEC-089: the API takes `list[str]`, but the SPA sent the raw input string
    and got `422 invalid_request` every time, so the field could never be saved
    from the UI. Guards the shape at the source so it cannot quietly regress."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "frontend" / "src" / "pages" / "Intel.tsx"
    text = src.read_text()
    assert 'mitre_tactics: mitre.split(",")' in text, "create form must send an array"
    assert "i.mitre_tactics?.length" in text and ".join(" in text, "column must render the list"
    assert "mitre_tactics: string[] | null" in text

    # and the API agrees: a bare string is rejected (documented 422 envelope),
    # a list is accepted and round-trips as a list.
    r = client.post("/api/intel/indicators", json={"type": "ip", "value": "198.51.100.9",
                                                  "mitre_tactics": "T1041"})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "invalid_request"
    r = client.post("/api/intel/indicators", json={"type": "ip", "value": "198.51.100.10",
                                                  "mitre_tactics": ["T1041", "T1110"]})
    assert r.status_code == 201 and r.json()["mitre_tactics"] == ["T1041", "T1110"]
    got = client.get("/api/intel/indicators", params={"q": "198.51.100.10"}).json()["items"][0]
    assert got["mitre_tactics"] == ["T1041", "T1110"]


def test_stix_import_validates_confidence_and_normalises_timestamps(client, seeded, conn):
    """SEC-104: values from a bundle went straight into the store. Live repro before
    the fix: `confidence: 999` was stored 999 and `confidence: "high"` was stored as
    TEXT (the manual endpoint bounds the same field 0-100 with `ge=0, le=100`), so
    `ORDER BY confidence DESC` ranked the string above every real score; and a
    spec-valid `valid_until` with milliseconds was stored verbatim, which the store's
    parsers cannot read, so the indicator got `ttl_hours: None` and never expired."""
    from app.services.stix import parse_bundle

    def bundle(objects):
        return {"type": "bundle", "objects": objects}

    # A wrong-typed or out-of-range confidence is refused, naming the object.
    r = client.post("/api/intel/indicators/stix", json={"bundle": bundle([
        {"type": "indicator", "confidence": "high", "pattern": "[ipv4-addr:value = '198.51.100.21']"}])})
    assert r.status_code == 400 and "confidence must be an integer 0-100" in r.json()["detail"]["message"]
    r = client.post("/api/intel/indicators/stix", json={"bundle": bundle([
        {"type": "indicator", "confidence": 999, "pattern": "[ipv4-addr:value = '198.51.100.22']"}])})
    assert r.status_code == 400, r.text
    # Nothing was written by the refused imports.
    assert not conn.execute("SELECT id FROM threat_indicators WHERE value LIKE '198.51.100.2%'").fetchall()

    # Fractional seconds are valid STIX and must still work — normalised, not dropped.
    r = client.post("/api/intel/indicators/stix", json={"bundle": bundle([
        {"type": "indicator", "name": "fractional", "confidence": 60,
         "valid_from": "2026-09-01T00:00:00.000Z", "valid_until": "2027-09-01T00:00:00.000Z",
         "pattern": "[ipv4-addr:value = '198.51.100.23']"}])})
    assert r.status_code == 201, r.text
    row = conn.execute("SELECT first_seen, ttl_hours, status, confidence FROM threat_indicators "
                       "WHERE value = '198.51.100.23'").fetchone()
    assert row["first_seen"] == "2026-09-01T00:00:00Z"      # store format, not the raw string
    assert row["ttl_hours"] and row["ttl_hours"] > 8000     # ~a year, so it does expire
    assert row["status"] == "active" and row["confidence"] == 60

    # An offset timestamp normalises to UTC.
    r = client.post("/api/intel/indicators/stix", json={"bundle": bundle([
        {"type": "indicator", "valid_from": "2026-09-01T12:00:00+03:00",
         "pattern": "[domain-name:value = 'offset.example']"}])})
    assert r.status_code == 201, r.text
    assert conn.execute("SELECT first_seen FROM threat_indicators WHERE value = 'offset.example'"
                        ).fetchone()["first_seen"] == "2026-09-01T09:00:00Z"

    # An unreadable timestamp is refused rather than stored as a string nobody can parse.
    r = client.post("/api/intel/indicators/stix", json={"bundle": bundle([
        {"type": "indicator", "valid_until": "next tuesday",
         "pattern": "[ipv4-addr:value = '198.51.100.24']"}])})
    assert r.status_code == 400 and "valid_until" in r.json()["detail"]["message"]

    # Objects whose pattern we do not support contribute nothing and are not judged.
    assert parse_bundle(bundle([{"type": "indicator", "confidence": "high",
                                 "pattern": "[mutex:name = 'x']"}])) == []
    # A missing confidence still falls back to the request default.
    assert parse_bundle(bundle([{"type": "indicator",
                                 "pattern": "[ipv4-addr:value = '198.51.100.25']"}]))[0]["confidence"] is None
