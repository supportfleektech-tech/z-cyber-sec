"""FastAPI dependencies: DB connection, current user, server-side RBAC."""
from __future__ import annotations

import sqlite3

from fastapi import Depends, HTTPException, Request

from . import db, security
from .audit import record_audit


def get_current_user(request: Request, conn: sqlite3.Connection = Depends(db.get_conn)) -> dict:
    token = request.cookies.get(security.COOKIE_NAME)
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
