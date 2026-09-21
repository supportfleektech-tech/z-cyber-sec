"""Auth: login/logout/me + user administration (admin only)."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import db, security
from ..audit import record_audit
from ..deps import get_current_user, require

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response,
          conn: sqlite3.Connection = Depends(db.get_conn)):
    user = db.one(conn, "SELECT *, id AS user_id FROM users WHERE username = ?", (body.username,))
    if not user or not user["active"] or not security.verify_password(body.password, user["password_hash"]):
        record_audit(conn, {"type": "user", "id": None, "name": body.username},
                     "auth.failed", target_type="user", target_id=body.username)
        # Generic message: no user-existence oracle.
        raise HTTPException(status_code=401, detail={"code": "invalid_credentials"})
    session_id, token = security.create_session(
        conn, user["id"], request.client.host if request.client else None,
        request.headers.get("user-agent"))
    record_audit(conn, {"type": "user", "id": str(user["id"]), "name": user["username"]},
                 "auth.login", target_type="session", target_id=str(session_id))
    response.set_cookie(
        security.COOKIE_NAME, token, max_age=security.token_ttl_seconds(),
        httponly=True, samesite="strict", secure=request.url.scheme == "https",
    )
    return {"user": security.user_public(user)}


@router.post("/logout")
def logout(response: Response, user: dict = Depends(get_current_user),
           conn: sqlite3.Connection = Depends(db.get_conn)):
    security.revoke_session(conn, user["id"])  # session row id
    record_audit(conn, {"type": "user", "id": str(user["user_id"]), "name": user["username"]},
                 "auth.logout", target_type="session", target_id=str(user["id"]))
    response.delete_cookie(security.COOKIE_NAME)
    return {"ok": True}


@router.get("/me")
def me(user: dict = Depends(get_current_user)):
    return security.user_public(user)


# ------------------------------------------------------------ user management

class UserIn(BaseModel):
    username: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9._-]+$")
    password: str = Field(min_length=8, max_length=200)
    display_name: str | None = Field(default=None, max_length=100)
    role: str = "viewer"


class UserUpdate(BaseModel):
    display_name: str | None = None
    role: str | None = None
    active: bool | None = None


@router.post("/users", status_code=201)
def create_user(body: UserIn, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("admin.users"))):
    if body.role not in security.ROLES:
        raise HTTPException(400, {"code": "bad_role",
                                  "message": f"role must be one of {sorted(security.ROLES)}"})
    if db.one(conn, "SELECT id FROM users WHERE username = ?", (body.username,)):
        raise HTTPException(409, {"code": "exists"})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO users (username, display_name, password_hash, role, active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 1, ?, ?)",
        (body.username, body.display_name, security.hash_password(body.password), body.role, now, now),
    )
    conn.commit()
    record_audit(conn, {"type": "user", "id": str(user["user_id"]), "name": user["username"]},
                 "user.created", target_type="user", target_id=str(cur.lastrowid),
                 detail={"username": body.username, "role": body.role})
    return {"id": int(cur.lastrowid), "username": body.username, "role": body.role}


@router.get("/users")
def list_users(conn: sqlite3.Connection = Depends(db.get_conn),
               user: dict = Depends(require("admin.users"))):
    rows = db.q(conn, "SELECT id, username, display_name, role, active, created_at FROM users ORDER BY username")
    return {"items": rows, "total": len(rows)}


@router.patch("/users/{uid}")
def update_user(uid: int, body: UserUpdate, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("admin.users"))):
    target = db.one(conn, "SELECT * FROM users WHERE id = ?", (uid,))
    if not target:
        raise HTTPException(404, {"code": "not_found"})
    if body.role is not None and body.role not in security.ROLES:
        raise HTTPException(400, {"code": "bad_role"})
    # Self-lockout guard: cannot demote/deactivate the last active admin.
    if target["role"] == "admin" and (body.active is False or (body.role is not None and body.role != "admin")):
        others = db.one(conn, "SELECT COUNT(*) c FROM users WHERE role='admin' AND active=1 AND id != ?", (uid,))
        if int(others["c"]) == 0:
            raise HTTPException(400, {"code": "last_admin",
                                      "message": "Cannot remove the last active admin."})
    fields, params = [], []
    if body.display_name is not None:
        fields.append("display_name = ?")
        params.append(body.display_name)
    if body.role is not None:
        fields.append("role = ?")
        params.append(body.role)
    if body.active is not None:
        fields.append("active = ?")
        params.append(int(body.active))
    if not fields:
        raise HTTPException(400, {"code": "no_changes"})
    fields.append("updated_at = ?")
    params.append(db.utcnow())
    params.append(uid)
    conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()
    record_audit(conn, {"type": "user", "id": str(user["user_id"]), "name": user["username"]},
                 "user.updated", target_type="user", target_id=str(uid),
                 detail={k: v for k, v in body.model_dump().items() if v is not None})
    return db.one(conn, "SELECT id, username, display_name, role, active FROM users WHERE id = ?", (uid,))
