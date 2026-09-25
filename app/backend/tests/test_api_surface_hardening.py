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


def test_no_get_route_returns_json_as_text(client, seeded):
    """SEC-091: JSON columns are stored as text and routes decoded them
    inconsistently — the same field was an array in one response and a JSON
    string in another. Clients read the structured shape, so a forgotten decode
    hands them a string: `mitigations?.join("; ")` does not degrade, it throws,
    which blanked the GRC and Exercises pages in the SPA (live-verified before
    the fix: `[\"Tool allowlist\", ...]` as a string, and `.join` raising
    `TypeError: ... .join is not a function`).

    This walks every GET route in the OpenAPI schema and asserts no string value
    is really a JSON list/object. It is the check that would have caught the
    original bug: it fails on the next route that forgets to decode.
    """
    import json
    import re

    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    spec = client.get("/api/openapi.json").json()

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                yield from walk(v, f"{path}.{k}" if path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node[:20]):
                yield from walk(v, f"{path}[{i}]")
        else:
            yield path, node

    leaks, checked = [], 0
    for path, methods in spec["paths"].items():
        if "get" not in methods or "download" in path or "export" in path:
            continue
        url = re.sub(r"\{[^}]+\}", "1", path)
        r = client.get(url)
        if r.status_code != 200 or "json" not in r.headers.get("content-type", ""):
            continue
        checked += 1
        for field, value in walk(r.json()):
            if isinstance(value, str) and len(value) > 2 and value[0] in "[{" and value[-1] in "]}":
                try:
                    parsed = json.loads(value)
                except ValueError:
                    continue
                if isinstance(parsed, (list, dict)):
                    leaks.append(f"{url} -> {field} = {value[:60]}")
    assert checked > 40, f"expected to exercise the API surface, only checked {checked} routes"
    assert not leaks, "JSON returned as text:\n" + "\n".join(leaks)


def test_spa_renders_decoded_json_through_fmtjson(client, seeded):
    """SEC-091: decoding JSON fields turns them into objects, and rendering an
    object as a React child throws — so the two places that used to print the raw
    string must go through `fmtJson` (which stringifies objects and passes
    strings through). Without this the fix would swap one blank page for
    another."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "frontend" / "src"
    admin = (src / "pages" / "Admin.tsx").read_text()
    exercises = (src / "pages" / "Exercises.tsx").read_text()
    components = (src / "components.tsx").read_text()

    assert "export function fmtJson" in components
    assert "fmtJson(r.detail)" in admin and "title={fmtJson(r.detail)}" in admin
    assert "fmtJson(r.detail)" in exercises
    # audit detail comes back structured now, and the pages type it accordingly
    assert "string | Record<string, unknown> | null" in admin
    assert "string | Record<string, unknown> | null" in exercises


def _metric(text, name):
    for line in text.splitlines():
        if line.startswith(name + " ") or line.startswith(name + "{"):
            return line.rsplit(" ", 1)[1]
    return None


def test_metrics_severity_series_counts_only_open_alerts(client, seeded, conn):
    """SEC-105: `cybersec_alerts_open{severity=…}` counted *every* alert of that
    severity, so an alerting rule on it never cleared. Live repro before the fix:
    closing a high alert dropped `cybersec_alerts_open` 6 → 5 while
    `cybersec_alerts_open{severity="high"}` stayed 4."""
    total = int(_metric(client.get("/metrics").text, "cybersec_alerts_open"))
    sev_sum = sum(int(_metric(client.get("/metrics").text, f'cybersec_alerts_open{{severity="{s}"}}'))
                  for s in ("critical", "high", "medium", "low", "info"))
    assert sev_sum == total, "the labelled series must add up to the open total"

    # Close a high alert: both series drop together.
    alert = next(a for a in client.get("/api/soc/alerts").json()["items"] if a["severity"] == "high")
    assert client.patch(f"/api/soc/alerts/{alert['id']}", json={"status": "closed"}).status_code == 200
    text = client.get("/metrics").text
    assert int(_metric(text, "cybersec_alerts_open")) == total - 1
    assert int(_metric(text, 'cybersec_alerts_open{severity="high"}')) == \
        int(_metric(client.get("/metrics").text, 'cybersec_alerts_open{severity="high"}'))
    # Totals are still available, under a name that says so.
    assert int(_metric(text, 'cybersec_alerts_total{severity="high"}')) >= 1

    # A dismissed alert is not open either (SEC-081: dismissing needs a reason).
    other = next(a for a in client.get("/api/soc/alerts").json()["items"] if a["status"] != "closed")
    assert client.patch(f"/api/soc/alerts/{other['id']}",
                        json={"status": "dismissed", "notes": "probe: false positive"}).status_code == 200
    text2 = client.get("/metrics").text
    assert int(_metric(text2, "cybersec_alerts_open")) == total - 2


def test_metrics_sessions_active_excludes_expired(client, seeded, conn):
    """SEC-105: session rows are only deleted on logout, so `cybersec_sessions_active`
    grew forever. Live repro: with every session forced to `expires_at 2000-01-01`,
    the metric still reported 2."""
    assert int(_metric(client.get("/metrics").text, "cybersec_sessions_active")) >= 1

    conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00Z'")
    conn.commit()
    text = client.get("/metrics").text
    assert int(_metric(text, "cybersec_sessions_active")) == 0
    # ...and the stale rows are visible rather than hidden in `active`.
    assert int(_metric(text, "cybersec_sessions_expired")) >= 1
