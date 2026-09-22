"""SEC-073 — API surface hardening, from a post-build audit of the live app.

Three findings, all fixed and pinned by tests here:

1. Unknown ``/api/*`` paths were answered by the SPA catch-all with
   ``200 text/html`` (the index.html shell). docs/12 promises
   ``404 {detail:{code:"not_found"}}``, and a client parsing HTML as JSON
   mistakes a typo for success.
2. ``/metrics`` had no optional auth path: it is posture data (open alert
   counts by severity, DB size, session counts) reachable by anything that can
   reach the app port. Now optionally gated by ``METRICS_TOKEN``.
3. Login brute-force limiting existed only as a Caddy directive
   (``rate_limit``) that the stock ``caddy:2`` image cannot load, so the
   control did not exist anywhere. Now enforced in-app and enabled by default
   in STAGING/PROD.
"""
from __future__ import annotations

import pytest

from app import ratelimit
from app.config import settings


@pytest.fixture(autouse=True)
def _clean_limiter():
    ratelimit.reset()
    yield
    ratelimit.reset()


# --------------------------------------------------------- unknown API paths

def test_unknown_api_path_is_json_404(client):
    r = client.get("/api/definitely-not-a-route")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["detail"]["code"] == "not_found"


def test_unknown_api_subpath_is_json_404(client):
    r = client.get("/api/soc/nope/123")
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "not_found"


def test_bare_api_path_is_json_404(client):
    r = client.get("/api")
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "not_found"


def test_unknown_api_post_is_json_404(client):
    r = client.post("/api/not/a/thing", json={})
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "not_found"


def test_real_api_route_not_shadowed(client):
    """The catch-all must never shadow a real endpoint."""
    r = client.get("/api/overview/stats")
    assert r.status_code == 200
    assert "events_total" in r.json()


# ------------------------------------------------------------------ /metrics

def test_metrics_open_when_no_token_configured(client, seeded, monkeypatch):
    monkeypatch.setattr(settings, "metrics_token", None)
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "cybersec_events_total" in r.text


def test_metrics_requires_token_when_configured(client, seeded, monkeypatch):
    monkeypatch.setattr(settings, "metrics_token", "test-metrics-token")
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    ok = client.get("/metrics", headers={"Authorization": "Bearer test-metrics-token"})
    assert ok.status_code == 200
    assert "cybersec_uptime_seconds" in ok.text


def test_metrics_401_shape_and_challenge(client, seeded, monkeypatch):
    monkeypatch.setattr(settings, "metrics_token", "test-metrics-token")
    r = client.get("/metrics")
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "unauthenticated"
    assert r.headers.get("www-authenticate") == "Bearer"


# -------------------------------------------------------------- login limiter

def test_login_rate_limit_blocks_after_limit(client, seeded, monkeypatch):
    monkeypatch.setattr(settings, "login_rate_limit_enabled", True)
    monkeypatch.setattr(settings, "login_rate_limit", 3)
    monkeypatch.setattr(settings, "login_rate_limit_window_s", 60)
    bad = {"username": "admin", "password": "wrong-password"}
    for _ in range(3):
        assert client.post("/api/auth/login", json=bad).status_code == 401
    r = client.post("/api/auth/login", json=bad)
    assert r.status_code == 429
    assert r.json()["detail"]["code"] == "rate_limited"
    assert int(r.headers["retry-after"]) >= 1


def test_login_rate_limit_also_stops_correct_credentials(client, seeded, monkeypatch):
    """The window is on attempts, not failures — a guesser cannot reset it by
    guessing right, and a locked-out attacker gets no oracle."""
    monkeypatch.setattr(settings, "login_rate_limit_enabled", True)
    monkeypatch.setattr(settings, "login_rate_limit", 2)
    monkeypatch.setattr(settings, "login_rate_limit_window_s", 60)
    client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    r = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    assert r.status_code == 429


def test_login_rate_limit_disabled_locally(client, seeded, monkeypatch):
    monkeypatch.setattr(settings, "login_rate_limit", 2)
    monkeypatch.setattr(settings, "login_rate_limit_enabled", False)
    bad = {"username": "admin", "password": "wrong-password"}
    for _ in range(5):
        assert client.post("/api/auth/login", json=bad).status_code == 401


def test_rate_limited_attempt_is_audited(client, seeded, conn, monkeypatch):
    monkeypatch.setattr(settings, "login_rate_limit_enabled", True)
    monkeypatch.setattr(settings, "login_rate_limit", 1)
    monkeypatch.setattr(settings, "login_rate_limit_window_s", 60)
    bad = {"username": "admin", "password": "wrong"}
    client.post("/api/auth/login", json=bad)
    assert client.post("/api/auth/login", json=bad).status_code == 429
    row = conn.execute(
        "SELECT COUNT(*) c FROM audit_events WHERE action = 'auth.rate_limited'").fetchone()
    assert row["c"] == 1  # logged once per window, not once per blocked request


def test_limiter_window_slides(monkeypatch):
    """Unit-level: attempts age out of the window rather than locking forever."""
    monkeypatch.setattr(ratelimit, "reset", ratelimit.reset)
    ratelimit.reset()
    assert ratelimit.check("k", limit=2, window_s=10, now=0.0)[0] is True
    assert ratelimit.check("k", limit=2, window_s=10, now=1.0)[0] is True
    allowed, retry = ratelimit.check("k", limit=2, window_s=10, now=2.0)
    assert allowed is False and retry > 0
    assert ratelimit.check("k", limit=2, window_s=10, now=11.0)[0] is True


def test_limiter_evicts_stale_keys():
    """Memory is bounded by *active* sources, not by every key ever seen: a
    spoofed-source flood that then goes quiet is dropped, so the map cannot
    grow without limit over the lifetime of the process."""
    ratelimit.reset()
    for i in range(ratelimit._MAX_KEYS + 50):
        ratelimit.check(f"k{i}", limit=5, window_s=10, now=0.0)
    assert len(ratelimit._hits) > ratelimit._MAX_KEYS
    # Every one of those keys is long stale by now → one call triggers the sweep.
    ratelimit.check("fresh", limit=5, window_s=10, now=3600.0)
    assert len(ratelimit._hits) == 1
