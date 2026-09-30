"""FastAPI dependencies: DB connection, current user, server-side RBAC."""
from __future__ import annotations

import sqlite3

from fastapi import Depends, HTTPException, Request

from . import db, security
from .audit import record_audit


def _request_token(request: Request) -> str | None:
    """The session token, from the cookie or an `Authorization: Bearer` header (SEC-124).

    Both carry the same opaque token to the same server-side session row, so RBAC,
    expiry and revocation behave identically; only the transport differs. The header
    path exists because a cross-site/embedded context silently drops `SameSite=Strict`
    cookies, and third-party cookie blocking drops the rest — a bearer token survives
    both. See `security.session_cookie_policy` for where the relaxation is scoped.
    """
    token = request.cookies.get(security.COOKIE_NAME)
    if token:
        return token
    header = request.headers.get("authorization") or ""
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return None


def get_current_user(request: Request, conn: sqlite3.Connection = Depends(db.get_conn)) -> dict:
    token = _request_token(request)
    session = security.get_session(conn, token)
    if not session:
        raise HTTPException(status_code=401, detail={"code": "unauthenticated", "message": "Login required."})
    return session


def require(*perms: str):
    """Dependency factory enforcing a permission set server-side.

    Usage: user = Depends(require("cases.write"))
    Raises 403 with the missing permission (never discloses the full matrix).
    """
    def checker(user: dict = Depends(get_current_user),
                conn: sqlite3.Connection = Depends(db.get_conn)) -> dict:
        for p in perms:
            if not security.has_permission(user["role"], p):
                record_audit(
                    conn,
                    {"type": "user", "id": str(user["user_id"]), "name": user["username"]},
                    "rbac.denied", target_type="permission", target_id=p,
                    detail={"permission": p, "role": user["role"]},
                )
                raise HTTPException(
                    status_code=403,
                    detail={"code": "forbidden", "message": f"Missing permission: {p}"},
                )
        return user
    return checker
