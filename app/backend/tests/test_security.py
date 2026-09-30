"""Security tests: injection defenses, error hygiene, transport posture."""
from __future__ import annotations

import pytest


def test_sql_injection_attempts(client, seeded):
    probes = ["' OR '1'='1", "1; DROP TABLE events;--", "%', 'x') OR ('x'", "1 UNION SELECT * FROM users"]
    for p in probes:
        r = client.get("/api/soc/events", params={"host": p})
        assert r.status_code == 200
        assert r.json()["total"] == 0
        r = client.get("/api/soc/alerts", params={"q": p})
        assert r.status_code == 200
        r = client.get("/api/cases", params={"q": p})
        assert r.status_code == 200
        r = client.get("/api/vulns", params={"q": p})
        assert r.status_code == 200
    # tables still intact
    assert client.get("/api/soc/events").json()["total"] > 0


def test_path_traversal_on_spa_and_files(client, seeded):
    for p in ("/../.env", "/..%2f.env", "/assets/../../.env", "/reports/../../.env"):
        r = client.get(p)
        # must NOT return secret content; API JSON (404/401) or safe HTML is acceptable
        assert b"SECRET" not in r.content
        assert b"pbkdf2_sha256" not in r.content


def test_error_responses_do_not_leak(client, seeded):
    # 404 shape
    r = client.get("/api/soc/alerts/999999")
    assert r.status_code == 404
    assert "Traceback" not in r.text
    # 422 shape (validation) — message must not echo server internals
    r = client.post("/api/soc/events", json={"events": [{"ts": "x"}]})
    assert r.status_code == 422
    assert "Traceback" not in r.text


def test_validation_errors_use_the_documented_envelope(client, seeded):
    """SEC-080: docs/12 promises `detail = {code, message}` for non-2xx; the
    default FastAPI 422 body is a bare list, which a client written against
    that contract renders as `undefined`."""
    r = client.post("/api/cases", json={"title": "x"})
    assert r.status_code == 422
    d = r.json()["detail"]
    assert d["code"] == "invalid_request"
    assert "title" in d["message"]                       # names the offending field
    assert d["errors"][0]["field"] == "title"
    assert "Traceback" not in r.text and "app/routers" not in r.text
    # 403 shape
    r = client.post("/api/cases", json={"title": "x" * 200 + "y", "priority": "low"})
    # over-long title -> 422 validation
    assert r.status_code == 422


def test_no_secrets_in_openapi_or_docs(client, seeded):
    r = client.get("/api/openapi.json")
    assert r.status_code == 200
    text = r.text
    for bad in ("CyberSecAdmin1!", "SashaSocPass1!", "IrisLeadPass1!", "sk-", "PRIVATE KEY"):
        assert bad not in text


def test_cookie_flags(client, seeded):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    set_cookie = r.headers.get("set-cookie", "")
    assert "httponly" in set_cookie.lower()
    assert "samesite=strict" in set_cookie.lower()
    # over plain http in tests the cookie is NOT secure (correct behavior: secure only on https)
    assert "secure" not in set_cookie.lower()


def test_cookie_secure_and_client_ip_behind_tls_edge(client, seeded):
    """SEC-061: behind Caddy, X-Forwarded-Proto/For make the cookie Secure and
    the session record the real client IP (last XFF entry, not the proxy)."""
    from app import db

    conn = db.raw_connection()
    try:
        before = int(db.one(conn, "SELECT COUNT(*) c FROM sessions")["c"])
    finally:
        conn.close()

    r = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "CyberSecAdmin1!"},
        headers={
            "X-Forwarded-Proto": "https",
            # forged leading entries must be ignored: Caddy appends the real IP last
            "X-Forwarded-For": "203.0.113.99, 198.51.100.7",
        },
    )
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "").lower()
    assert "secure" in set_cookie

    conn = db.raw_connection()
    try:
        row = db.one(conn, "SELECT * FROM sessions ORDER BY id DESC LIMIT 1")
        assert row is not None
        assert int(db.one(conn, "SELECT COUNT(*) c FROM sessions")["c"]) == before + 1
        assert row["ip"] == "198.51.100.7"
    finally:
        conn.close()


def test_boot_guard_rejects_placeholder_secrets(monkeypatch):
    """ADR-006 (hardened): STAGING/PROD refuse the dev default, unedited
    template placeholders, and low-entropy keys; LOCAL stays permissive
    (the offline lab is safe by design)."""
    from app.config import load_settings

    for bad in ("dev-only-change-me-in-staging", "__SET__", "changeme", "", "short-key"):
        monkeypatch.setenv("ENV_NAME", "STAGING")
        monkeypatch.setenv("SECRET_KEY", bad)
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            load_settings()

    monkeypatch.setenv("SECRET_KEY", "a" * 64)
    s = load_settings()
    assert s.env_name == "STAGING" and s.secret_key == "a" * 64

    # LOCAL lab: dev default is fine (network-bounded, synthetic data)
    monkeypatch.setenv("ENV_NAME", "LOCAL")
    monkeypatch.setenv("SECRET_KEY", "dev-only-change-me-in-staging")
    assert load_settings().secret_key == "dev-only-change-me-in-staging"


def test_direct_connection_keeps_local_behavior(client, seeded):
    """No forwarded headers (local lab, no edge): scheme stays http (no
    Secure cookie) and the session records the direct connection IP."""
    from app import db

    r = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    assert r.status_code == 200
    assert "secure" not in r.headers.get("set-cookie", "").lower()

    conn = db.raw_connection()
    try:
        row = db.one(conn, "SELECT * FROM sessions ORDER BY id DESC LIMIT 1")
        assert row is not None
        assert row["ip"] == "testclient"  # TestClient's direct-connection identity
    finally:
        conn.close()


def test_event_payload_limits(client, seeded):
    # msg is capped
    r = client.post("/api/soc/events", json={"events": [
        {"ts": "2026-09-21T00:00:00Z", "action": "x", "msg": "y" * 5000}]})
    assert r.status_code == 422
    # batch limit
    big = {"events": [{"ts": "2026-09-21T00:00:00Z", "action": "x"} for _ in range(5001)]}
    r = client.post("/api/soc/events", json=big)
    assert r.status_code == 422


def test_untrusted_rule_input_cannot_create_bad_rule(client, seeded):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    # unparseable condition
    r = client.post("/api/soc/rules", json={
        "uid": "bad-cond", "name": "Bad condition",
        "spec": {"detection": {"a": {"action": "x"}}, "condition": "a and"}})
    assert r.status_code == 400
    # unknown op rejected at compile time
    r = client.post("/api/soc/rules", json={
        "uid": "bad-op", "name": "Bad op",
        "spec": {"detection": {"a": {"data.x": {"op": "hack", "value": 1}}}, "condition": "a"}})
    assert r.status_code == 400


def test_idempotency_key_limits(client, seeded):
    r = client.post("/api/soc/events", json={"events": [
        {"ts": "2026-09-21T00:00:00Z", "action": "x", "idempotency_key": "k" * 200}]})
    assert r.status_code == 422
