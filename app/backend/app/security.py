"""Authentication, sessions, and RBAC.

ADR-002: application-managed auth (local-first, no external IdP).
- PBKDF2-HMAC-SHA256, 390k iterations (OWASP 2023 minimum), 16-byte salt — stdlib only.
- Opaque bearer sessions; the DB stores only the token's hash.
- Transport (SEC-124): an httpOnly `SameSite=Strict` cookie by default, and the *same*
  opaque token may also travel as `Authorization: Bearer` — the SPA keeps it in
  sessionStorage. Two reasons this exists, both about where the app runs:
    * a preview/embedded context is cross-site, so a `Strict` cookie is simply not sent
      (login succeeds, every later call is 401);
    * browsers with third-party cookie blocking drop even `SameSite=None` cookies.
  A bearer token works under any cookie policy. The relaxation is scoped: outside
  STAGING/PROD the login body also returns the token, the cookie drops to
  `SameSite=None` when the request arrived over HTTPS, and the app may be framed.
  STAGING/PROD keep `SameSite=Strict`, no token in the body, and framing denied.
- RBAC is enforced server-side in deps.require(); the UI never grants access.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC

from . import db

PBKDF2_ITERATIONS = 390_000
COOKIE_NAME = "cybersec_token"
TOKEN_BYTES = 32

ROLES = {"admin", "ir_lead", "soc_analyst", "viewer", "agent_service"}


# ------------------------------------------------------------- session policy

LAB_LIKE_ENVS = ("LOCAL", "LAB")


def session_cookie_policy(env_name: str, https: bool,
                          secure_mode: str = "auto") -> tuple[dict, bool]:
    """Cookie attributes for this request, and whether the token may ride the login body.

    Returns `(set_cookie_kwargs, expose_token)`.

    * STAGING/PROD — `SameSite=Strict`, `Secure` over HTTPS, never exposed in the body.
      These deployments are top-level, never framed, and their sessions stay
      httpOnly-only.
    * LAB-like (LOCAL/LAB) for a non-local caller — `SameSite=None; Secure`, token also
      returned, so an embedded preview (cross-site) can hold a session at all. "Non-local"
      is decided by host/forwarded headers, not only by the scheme: a preview proxy that
      forgets `X-Forwarded-Proto` would otherwise produce a `Strict` cookie that a
      cross-site frame never sends — a login that succeeds and a session that does not.
    * LAB-like for a local caller on plain HTTP — `SameSite=Strict`; `None` without
      `Secure` is rejected by browsers, and a loopback caller is same-site anyway.
    """
    lab_like = env_name not in ("STAGING", "PROD")
    # COOKIE_SECURE lets an operator settle the one question the app cannot answer by
    # itself — whether the browser's connection is TLS: `always` for a proxy that strips
    # X-Forwarded-Proto, `never` for a plain-HTTP lab reached over the LAN (a Secure
    # cookie over plain http is dropped by the browser, which looks exactly like a
    # failed login). STAGING/PROD ignore the knob: they never relax.
    if lab_like:
        if secure_mode == "always":
            return ({"httponly": True, "samesite": "none", "secure": True, "path": "/"}, True)
        if secure_mode == "never":
            return ({"httponly": True, "samesite": "strict", "secure": False, "path": "/"}, True)
    if lab_like and https:
        return ({"httponly": True, "samesite": "none", "secure": True, "path": "/"}, True)
    return ({"httponly": True, "samesite": "strict", "secure": https, "path": "/"}, lab_like)


def is_loopback_host(host: str | None) -> bool:
    """True when the client reached this process directly on the machine's loopback.

    Handles `host:port`, bracketed IPv6 (`[::1]:8080`) and bare names.
    """
    name = (host or "").strip().lower()
    if name.startswith("["):                       # [::1]:8080 / [::1]
        name = name[1:].split("]", 1)[0]
    elif name.count(":") == 1:                     # 127.0.0.1:8080
        name = name.split(":", 1)[0]
    return name in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or name.startswith("127.")


def reached_through_a_proxy(headers) -> bool:
    """Any forwarded-for/real-ip hop means an external client is on the other end."""
    return bool(headers.get("x-forwarded-for") or headers.get("x-real-ip")
                or headers.get("x-forwarded-host"))


def effective_scheme(url_scheme: str, forwarded_proto: str | None) -> str:
    """The scheme *the browser* used, which is what cookie attributes must match.

    A reverse proxy terminates TLS, so the app sees `http` while the browser is on
    `https`; a `Secure` cookie is correct in that case. Without this, every preview
    deployment sets same-site, non-secure cookies and the session cannot survive.
    """
    if forwarded_proto:
        first = forwarded_proto.split(",")[0].strip().lower()
        if first in ("http", "https"):
            return first
    return url_scheme


# ---------------------------------------------------------------- passwords

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


# ----------------------------------------------------------------- sessions

def create_session(conn, user_id: int, ip: str | None, user_agent: str | None) -> tuple[int, str]:
    from datetime import datetime, timedelta

    from .config import settings

    token = secrets.token_urlsafe(TOKEN_BYTES)
    now = datetime.now(UTC)
    expires = now + timedelta(hours=settings.token_ttl_hours)
    now_s = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    # SEC-105 follow-on: an expired session was only removed when its token was
    # presented again, so the table grew without bound and `cybersec_sessions_active`
    # (before the fix) counted the stale rows as live. Logging in is a moment an
    # operator does not notice, and it is the right time to drop this user's dead rows.
    conn.execute("DELETE FROM sessions WHERE user_id = ? AND expires_at <= ?", (user_id, now_s))
    cur = conn.execute(
        "INSERT INTO sessions (user_id, token_hash, ip, user_agent, created_at, expires_at, last_seen_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, sha256_hex(token), ip, user_agent, now_s,
         expires.strftime("%Y-%m-%dT%H:%M:%SZ"), now_s),
    )
    conn.commit()
    return int(cur.lastrowid), token


def get_session(conn, token: str | None) -> dict | None:
    if not token:
        return None
    row = db.one(
        conn,
        "SELECT s.*, u.username, u.display_name, u.role, u.active FROM sessions s "
        "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (sha256_hex(token),),
    )
    if not row or not row["active"]:
        return None
    if row["expires_at"] < db.utcnow():
        conn.execute("DELETE FROM sessions WHERE id = ?", (row["id"],))
        conn.commit()
        return None
    return row


def revoke_session(conn, session_id: int) -> None:
    conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
    conn.commit()


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def token_ttl_seconds() -> int:
    from .config import settings
    return settings.token_ttl_hours * 3600


# ----------------------------------------------------------------------- RBAC

# Permission registry. Roles are sets of permissions; every check is
# server-side (acceptance criteria: RBAC enforced server-side and tested).
ALL_READ = {
    "overview.read", "soc.read", "cases.read", "intel.read", "vulns.read",
    "appsec.read", "cloud.read", "grc.read", "exercises.read", "reports.read",
    "assets.read", "agents.read", "automation.read", "release.read",
    "tradecraft.read",
    # SEC-115: the range registry is posture data every role may read (which
    # targets exist, which are up, which are authorized); registering/modifying
    # them is an infrastructure act, so it sits with the other write grants.
    "lab.read",
}

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "viewer": set(ALL_READ),
    "soc_analyst": set(ALL_READ) | {
        "soc.write", "cases.write", "evidence.upload", "intel.write",
        "vulns.write", "appsec.write", "reports.generate", "agents.task",
        # SEC-075: recording exploitability reviews is analysis work (the same
        # tier as vulns.write). What keeps it safe is not role scarcity but the
        # scope guard: targets must belong to an authorized engagement, and
        # both the work and every refusal are audited.
        "tradecraft.write",
    },
    "ir_lead": set(ALL_READ) | {
        "soc.write", "cases.write", "evidence.upload", "evidence.download",
        "intel.write", "vulns.write", "appsec.write", "reports.generate",
        "exercises.write", "automation.write", "automation.run",
        "agents.approve", "agents.task", "tradecraft.write", "lab.write",
    },
    "admin": set(ALL_READ) | {
        "soc.write", "cases.write", "evidence.upload", "evidence.download",
        "intel.write", "vulns.write", "appsec.write", "cloud.write",
        "grc.write", "exercises.write", "reports.generate", "assets.write",
        "automation.write", "automation.run", "agents.manage", "agents.approve",
        "agents.task", "rules.write", "admin.users", "admin.integrations", "lab.write",
        "admin.flags", "admin.backup", "audit.read", "release.write",
        "tradecraft.write",
    },
    # Machine identity used by the agent gateway. Minimal, audited scope.
    "agent_service": {"agents.read", "agents.task"},
}


def has_permission(role: str, perm: str) -> bool:
    return perm in ROLE_PERMISSIONS.get(role, set())


def permissions_for(role: str) -> list[str]:
    return sorted(ROLE_PERMISSIONS.get(role, set()))


def user_public(user: dict) -> dict:
    """user is a session row joined with users: 'user_id' is the user, 'id' the session."""
    return {
        "id": user["user_id"],
        "username": user["username"],
        "display_name": user.get("display_name"),
        "role": user["role"],
        "active": bool(user.get("active", 1)),
        "permissions": permissions_for(user["role"]),
    }
