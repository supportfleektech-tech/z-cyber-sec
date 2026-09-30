"""Authentication & session lifecycle (SEC-020, test layer 1/4)."""
from __future__ import annotations


def test_login_ok_and_me(client, seeded):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["username"] == "admin"
    assert body["user"]["role"] == "admin"
    assert "admin.users" in body["user"]["permissions"]
    # cookie is set, httpOnly
    cookie = r.cookies.get("cybersec_token")
    assert cookie
    r2 = client.get("/api/auth/me")
    assert r2.status_code == 200
    assert r2.json()["username"] == "admin"


def test_login_wrong_password_401_and_audited(client, seeded):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "invalid_credentials"
    from app import db
    row = db.one(db.connect(), "SELECT action FROM audit_events WHERE action='auth.failed'")
    assert row is not None


def test_login_unknown_user_same_401(client, seeded):
    r = client.post("/api/auth/login", json={"username": "ghost", "password": "whatever123"})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "invalid_credentials"  # no oracle


def test_requires_auth(client, seeded):
    client.post("/api/auth/logout")
    r = client.get("/api/soc/alerts")
    assert r.status_code == 401
    r = client.get("/api/auth/users")
    assert r.status_code == 401


def test_logout_revokes_session(client, seeded):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    r = client.post("/api/auth/logout")
    assert r.status_code == 200
    r2 = client.get("/api/auth/me")
    assert r2.status_code == 401


def test_expired_session_rejected(client, seeded, conn):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00Z'")
    conn.commit()
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_session_stores_hash_not_token(client, seeded, conn):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    token = r.cookies.get("cybersec_token")
    from app import db
    row = db.one(conn, "SELECT token_hash FROM sessions ORDER BY id DESC LIMIT 1")
    assert row["token_hash"] != token
    assert len(row["token_hash"]) == 64  # sha256 hex


def test_passwords_are_pbkdf2(client, seeded, conn):
    from app import db
    row = db.one(conn, "SELECT password_hash FROM users WHERE username='admin'")
    assert row["password_hash"].startswith("pbkdf2_sha256$390000$")


def test_user_management_admin_only(client, seeded):
    r = client.post("/api/auth/login", json={"username": "sasha", "password": "SashaSocPass1!"})
    assert r.status_code == 200
    r = client.post("/api/auth/users", json={
        "username": "eve", "password": "EvePass12345", "role": "viewer"})
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "forbidden"
    # RBAC denial is audited
    from app import db
    row = db.one(seeded, "SELECT action FROM audit_events WHERE action='rbac.denied'")
    assert row is not None


def test_admin_creates_and_patching_users(client, seeded):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    assert r.status_code == 200
    r = client.post("/api/auth/users", json={
        "username": "neo", "password": "NeoPass12345", "display_name": "Neo", "role": "viewer"})
    assert r.status_code == 201
    uid = r.json()["id"]
    r = client.patch(f"/api/auth/users/{uid}", json={"role": "soc_analyst"})
    assert r.status_code == 200
    assert r.json()["role"] == "soc_analyst"
    # duplicate rejected
    r = client.post("/api/auth/users", json={"username": "neo", "password": "NeoPass12345"})
    assert r.status_code == 409
    # bad role rejected
    r = client.post("/api/auth/users", json={"username": "morpheus", "password": "Pass123456", "role": "wizard"})
    assert r.status_code == 400


def test_last_admin_lockout_guard(client, seeded):
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    users = client.get("/api/auth/users").json()["items"]
    admin = next(u for u in users if u["role"] == "admin")
    r = client.patch(f"/api/auth/users/{admin['id']}", json={"role": "viewer"})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "last_admin"


def test_inactive_user_cannot_login(client, seeded):
    from app import db
    row = db.one(seeded, "SELECT id FROM users WHERE username='viewer'")
    seeded.execute("UPDATE users SET active = 0 WHERE id = ?", (row["id"],))
    seeded.commit()
    r = client.post("/api/auth/login", json={"username": "viewer", "password": "ViewerRead1!"})
    assert r.status_code == 401


# --------------------------------------------------- session transport (SEC-124)

def test_session_transport_policy_is_scoped_to_lab_environments():
    """SEC-124: a preview is a cross-site context, so `SameSite=Strict` cookies are
    dropped and third-party cookie blocking drops the rest. Lab-like environments
    therefore relax the cookie (SameSite=None; Secure over HTTPS) and also hand the
    token to the SPA, while STAGING/PROD keep httpOnly Strict cookies and nothing in
    the body."""
    from app.security import effective_scheme, session_cookie_policy

    for env in ("LOCAL", "LAB", "CI", "anything-else"):
        kwargs, expose = session_cookie_policy(env, https=True)
        assert kwargs["samesite"] == "none" and kwargs["secure"] is True
        assert expose is True
        # Over plain HTTP, SameSite=None would be rejected by every browser.
        kwargs, expose = session_cookie_policy(env, https=False)
        assert kwargs["samesite"] == "strict" and kwargs["secure"] is False
        assert expose is True

    for env in ("STAGING", "PROD"):
        kwargs, expose = session_cookie_policy(env, https=True)
        assert kwargs["samesite"] == "strict" and kwargs["secure"] is True
        assert kwargs["httponly"] is True
        assert expose is False, "production sessions must stay httpOnly-only"

    # The cookie must match the scheme the *browser* used, not the app's view: a proxy
    # terminates TLS, so the app sees http while the browser needs a Secure cookie.
    assert effective_scheme("http", "https") == "https"
    assert effective_scheme("http", "https, http") == "https"
    assert effective_scheme("https", None) == "https"
    assert effective_scheme("http", "banana") == "http"


def test_login_cookie_attributes_follow_the_transport(client):
    """The cookie must match how the *browser* reaches the app, and the app has three
    signals for that: `X-Forwarded-Proto`, whether the seen Host is loopback, and the
    COOKIE_SECURE override (SEC-124c)."""
    from app.config import settings

    client.post("/api/auth/logout")
    proxied = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"},
                          headers={"x-forwarded-proto": "https"}).headers["set-cookie"]
    assert "SameSite=none" in proxied and "Secure" in proxied and "HttpOnly" in proxied

    local = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"},
                        headers={"host": "127.0.0.1:8080"}).headers["set-cookie"]
    assert "SameSite=strict" in local and "Secure" not in local

    # A proxy that strips X-Forwarded-Proto: the operator says "TLS is in front".
    settings.cookie_secure = "always"
    try:
        forced = client.post("/api/auth/login",
                             json={"username": "admin", "password": "CyberSecAdmin1!"},
                             headers={"host": "127.0.0.1:8080"}).headers["set-cookie"]
        assert "SameSite=none" in forced and "Secure" in forced
    finally:
        settings.cookie_secure = "auto"


def test_bearer_token_authenticates_the_same_session(client):
    """The SPA's preview transport: the token from the login body, sent as
    `Authorization: Bearer`, is the same server-side session — same user, same RBAC.

    The cookie jar is emptied first, so the header is the only thing that can
    authenticate: otherwise the test would pass on the cookie and prove nothing.
    """
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    token = r.json()["session_token"]
    client.cookies.clear()
    assert client.get("/api/auth/me").status_code == 401          # no cookie, no header

    r = client.get("/api/auth/me", headers={"authorization": f"Bearer {token}"})
    # `/me` returns the public user directly (not wrapped in `user`).
    assert r.status_code == 200 and r.json()["username"] == "admin"

    assert client.get("/api/auth/me",
                      headers={"authorization": "Bearer not-a-real-token"}).status_code == 401
    assert client.get("/api/auth/me",
                      headers={"authorization": "Basic abc"}).status_code == 401


def test_bearer_token_obeys_rbac_and_revocation(client):
    """A viewer's bearer token must be exactly as powerless as their cookie."""
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "viewer", "password": "ViewerRead1!"})
    token = r.json()["session_token"]
    client.cookies.clear()
    auth = {"authorization": f"Bearer {token}"}
    assert client.get("/api/soc/alerts", headers=auth).status_code == 200
    denied = client.post("/api/cases", headers=auth, json={"title": "bearer must not write"})
    assert denied.status_code == 403 and denied.json()["detail"]["code"] == "forbidden"

    client.post("/api/auth/logout", headers=auth)
    assert client.get("/api/auth/me", headers=auth).status_code == 401


def test_preview_host_gets_a_cross_site_cookie_even_without_forwarded_proto(client):
    """SEC-124c: the preview proxy may omit X-Forwarded-Proto. Deciding the cookie from
    the scheme alone then produced `SameSite=Strict` for a browser that is cross-site —
    a login that succeeds and a session the browser never sends. A non-loopback Host (or
    any forwarded header) must be enough to select the cross-site cookie."""
    from app.security import is_loopback_host, reached_through_a_proxy

    assert is_loopback_host("127.0.0.1:8080") and is_loopback_host("localhost:8080")
    assert is_loopback_host("[::1]:8080") and not is_loopback_host("8080-abc.e2b.app")

    class H(dict):
        pass

    assert not reached_through_a_proxy(H())
    assert reached_through_a_proxy(H({"x-forwarded-for": "10.0.0.9"}))
    assert reached_through_a_proxy(H({"x-real-ip": "10.0.0.9"}))

    client.post("/api/auth/logout")
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "CyberSecAdmin1!"},
                    headers={"host": "8080-abc.e2b.app"})          # no X-Forwarded-Proto
    assert r.status_code == 200
    assert "SameSite=none" in r.headers["set-cookie"] and "Secure" in r.headers["set-cookie"]
    # and the body still carries the bearer fallback for browsers that drop the cookie
    assert r.json()["session_token"]


def test_local_loopback_login_keeps_a_same_site_cookie(client):
    """The local lab (plain http on loopback) must keep working: `SameSite=None` without
    `Secure` is rejected by browsers, and a loopback caller is same-site anyway."""
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"},
                    headers={"host": "127.0.0.1:8080"})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"]
    assert "SameSite=strict" in cookie and "Secure" not in cookie


def test_lab_login_exposes_the_token_in_a_header_too(client):
    """SEC-124d: the body and the header are independent carriers. A proxy that rewrites
    the body must not cost the session — the SPA reads the header as a fallback."""
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"},
                    headers={"host": "8080-abc.e2b.app"})
    assert r.status_code == 200
    header_token = r.headers.get("X-Session-Token")
    assert header_token and header_token == r.json()["session_token"]
    assert r.headers["Access-Control-Expose-Headers"] == "X-Session-Token"
    # It authenticates on its own, without the cookie.
    client.cookies.clear()
    me = client.get("/api/auth/me", headers={"authorization": f"Bearer {header_token}"})
    assert me.status_code == 200 and me.json()["username"] == "admin"


def test_client_report_is_a_lab_only_diagnostic(client, caplog):
    """The only machine that can explain a blocked session is the browser; it reports the
    *shape* of what it saw, and the report is not available in a hardened environment."""
    r = client.post("/api/auth/client-report",
                    json={"stage": "login-response-without-token",
                          "detail": {"keys": ["user"], "content_type": "text/plain"}})
    assert r.status_code == 202 and r.json()["received"] is True

    from app.config import settings
    original = settings.env_name
    settings.env_name = "PROD"
    try:
        assert client.post("/api/auth/client-report", json={"stage": "x"}).status_code == 404
    finally:
        settings.env_name = original


def test_production_never_exposes_a_token(client):
    """The relaxation is scoped: a hardened environment keeps httpOnly-only sessions."""
    from app.config import settings
    original = settings.env_name
    settings.env_name = "PROD"
    try:
        client.post("/api/auth/logout")
        r = client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
        assert r.status_code == 200
        assert "session_token" not in r.json()
        assert "X-Session-Token" not in r.headers
        assert "SameSite=strict" in r.headers["set-cookie"]
    finally:
        settings.env_name = original
