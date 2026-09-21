"""Authentication, sessions, and RBAC.

ADR-002: application-managed auth (local-first, no external IdP).
- PBKDF2-HMAC-SHA256, 390k iterations (OWASP 2023 minimum), 16-byte salt — stdlib only.
- Opaque bearer sessions in httpOnly SameSite=Strict cookies; DB stores token hash only.
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
    cur = conn.execute(
        "INSERT INTO sessions (user_id, token_hash, ip, user_agent, created_at, expires_at, last_seen_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, sha256_hex(token), ip, user_agent, now.strftime("%Y-%m-%dT%H:%M:%SZ"),
         expires.strftime("%Y-%m-%dT%H:%M:%SZ"), now.strftime("%Y-%m-%dT%H:%M:%SZ")),
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
    "assets.read", "agents.read", "automation.read",
}

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "viewer": set(ALL_READ),
    "soc_analyst": set(ALL_READ) | {
        "soc.write", "cases.write", "evidence.upload", "intel.write",
        "vulns.write", "appsec.write", "reports.generate", "agents.task",
    },
    "ir_lead": set(ALL_READ) | {
        "soc.write", "cases.write", "evidence.upload", "evidence.download",
        "intel.write", "vulns.write", "appsec.write", "reports.generate",
        "exercises.write", "automation.write", "automation.run",
        "agents.approve", "agents.task",
    },
    "admin": set(ALL_READ) | {
        "soc.write", "cases.write", "evidence.upload", "evidence.download",
        "intel.write", "vulns.write", "appsec.write", "cloud.write",
        "grc.write", "exercises.write", "reports.generate", "assets.write",
        "automation.write", "automation.run", "agents.manage", "agents.approve",
        "agents.task", "rules.write", "admin.users", "admin.integrations",
        "admin.flags", "admin.backup", "audit.read",
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
