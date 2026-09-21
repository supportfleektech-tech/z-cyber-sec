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
