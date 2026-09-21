"""Security tests: injection defenses, error hygiene, transport posture."""
from __future__ import annotations


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
