"""Admin: integrations, feature flags, settings, audit log, backups."""
from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit, verify_chain
from ..config import settings
from ..deps import require
from ..services.backup import create_backup, restore_from, verify_bundle

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


# ------------------------------------------------------------- integrations

class IntegrationIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: str = "manual"
    config: dict | None = Field(default=None, description="Must NOT contain secrets (secret scan in CI + review).")
    provenance: str | None = Field(default=None, max_length=500)


def _reject_secrets(obj, path="$") -> str | None:
    """Defensive: refuse integration configs that look like they carry secrets."""
    bad_keys = ("password", "secret", "token", "api_key", "apikey", "private_key")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if any(b in k.lower() for b in bad_keys):
                return f"{path}.{k}"
            r = _reject_secrets(v, f"{path}.{k}")
            if r:
                return r
    return None


@router.post("/integrations", status_code=201)
def create_integration(body: IntegrationIn, conn: sqlite3.Connection = Depends(db.get_conn),
                       user: dict = Depends(require("admin.integrations"))):
    leak = _reject_secrets(body.config or {})
    if leak:
        raise HTTPException(400, {"code": "secret_in_config", "message": f"field {leak} looks like a secret; "
                                                                          "secrets are not stored in the platform."})
    if db.one(conn, "SELECT id FROM integrations WHERE name = ?", (body.name,)):
        raise HTTPException(409, {"code": "exists"})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO integrations (name, kind, status, config, provenance, created_at, updated_at) "
        "VALUES (?, ?, 'unknown', ?, ?, ?, ?)",
        (body.name, body.kind, db.jdump(body.config), body.provenance, now, now))
    conn.commit()
    record_audit(conn, _actor(user), "integration.created", target_type="integration",
                 target_id=str(cur.lastrowid), detail={"name": body.name, "kind": body.kind})
    return db.one(conn, "SELECT * FROM integrations WHERE id = ?", (cur.lastrowid,))


@router.get("/integrations")
def list_integrations(conn: sqlite3.Connection = Depends(db.get_conn),
                      user: dict = Depends(require("admin.integrations"))):
    rows = db.q(conn, "SELECT * FROM integrations ORDER BY name")
    for r in rows:
        r["config"] = db.jload(r.get("config"), {})
    return {"items": rows, "total": len(rows)}


class IntegrationHealthIn(BaseModel):
    status: str  # ok | degraded | down | unknown
    last_status: str | None = Field(default=None, max_length=400)


@router.post("/integrations/{int_id}/health")
def integration_health(int_id: int, body: IntegrationHealthIn,
                       conn: sqlite3.Connection = Depends(db.get_conn),
                       user: dict = Depends(require("admin.integrations"))):
    i = db.one(conn, "SELECT * FROM integrations WHERE id = ?", (int_id,))
    if not i:
        raise HTTPException(404, {"code": "not_found"})
    if body.status not in {"ok", "degraded", "down", "unknown"}:
        raise HTTPException(400, {"code": "bad_status"})
    conn.execute("UPDATE integrations SET status = ?, last_run_at = ?, last_status = ?, updated_at = ? WHERE id = ?",
                 (body.status, db.utcnow(), body.last_status, db.utcnow(), int_id))
    conn.commit()
    record_audit(conn, _actor(user), "integration.health", target_type="integration", target_id=str(int_id),
                 detail={"status": body.status})
    return db.one(conn, "SELECT * FROM integrations WHERE id = ?", (int_id,))


# ------------------------------------------------------------ feature flags

class FlagIn(BaseModel):
    key: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9._-]+$")
    value: bool
    description: str | None = Field(default=None, max_length=300)


@router.post("/flags")
def set_flag(body: FlagIn, conn: sqlite3.Connection = Depends(db.get_conn),
             user: dict = Depends(require("admin.flags"))):
    conn.execute(
        "INSERT INTO feature_flags (key, value, description, updated_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, description = COALESCE(excluded.description, description), "
        "updated_at = excluded.updated_at",
        (body.key, int(body.value), body.description, db.utcnow()))
    conn.commit()
    record_audit(conn, _actor(user), "flag.set", target_type="feature_flag", target_id=body.key,
                 detail={"value": body.value})
    return {"key": body.key, "value": body.value}


@router.get("/flags")
def list_flags(conn: sqlite3.Connection = Depends(db.get_conn),
               user: dict = Depends(require("admin.flags"))):
    rows = db.q(conn, "SELECT * FROM feature_flags ORDER BY key")
    return {"items": rows, "total": len(rows)}


# ------------------------------------------------------------------ settings

class SettingIn(BaseModel):
    value: str = Field(max_length=2000)


@router.get("/settings")
def list_settings(conn: sqlite3.Connection = Depends(db.get_conn),
                  user: dict = Depends(require("admin.flags"))):
    rows = db.q(conn, "SELECT * FROM settings ORDER BY key")
    return {"items": rows, "total": len(rows)}


@router.put("/settings/{key}")
def put_setting(key: str, body: SettingIn, conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("admin.flags"))):
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, body.value, db.utcnow()))
    conn.commit()
    record_audit(conn, _actor(user), "setting.set", target_type="setting", target_id=key)
    return {"key": key, "value": body.value}


# ------------------------------------------------------------------ audit log

@router.get("/audit")
def list_audit(conn: sqlite3.Connection = Depends(db.get_conn),
               user: dict = Depends(require("audit.read")),
               action: str | None = None, actor: str | None = None,
               page: int = Query(1, ge=1), page_size: int = Query(100, ge=1, le=1000)):
    where, params = ["1=1"], []
    if action:
        where.append("action LIKE ?")
        params.append(f"{action}%")
    if actor:
        where.append("actor_name = ?")
        params.append(actor)
    sql = "SELECT * FROM audit_events WHERE " + " AND ".join(where)
    out = db.paged(conn, sql, tuple(params), "ORDER BY seq DESC", page, page_size)
    out["items"] = db.decode_rows(out["items"], "detail", default={})   # SEC-091
    return out


@router.get("/audit/verify")
def verify(conn: sqlite3.Connection = Depends(db.get_conn),
           user: dict = Depends(require("audit.read")),
           head_seq: int | None = None, head_hash: str | None = None,
           rows: int | None = None):
    """Integrity check of the hash chain + anchor (tamper evidence, SEC-084).

    Pass the values from a previously exported anchor (`head_seq`, `head_hash`,
    optional `rows`) to check the log against that copy — the in-DB anchor moves
    forward with new events, so deleted history eventually becomes invisible to
    it, while an anchor kept elsewhere still claims the event that is gone.
    """
    against = None
    if head_seq is not None or head_hash is not None:
        against = {"head_seq": head_seq, "head_hash": head_hash, "rows": rows}
    return verify_chain(conn, against=against)


@router.get("/audit/anchor")
def get_anchor(conn: sqlite3.Connection = Depends(db.get_conn),
               user: dict = Depends(require("audit.read"))):
    """The recorded head of the audit log — export this off-platform (SEC-084).

    Comparing an exported anchor against `GET /audit/verify` is what makes the
    log tamper-evident against an attacker who can rewrite the whole database,
    including the anchor itself: the copy kept outside the platform is the one
    they cannot reach. See docs/10-operations-runbook.md (Weekly).
    """
    from ..audit import anchor as read_anchor
    return {"anchor": read_anchor(conn), "verify": verify_chain(conn)}


# -------------------------------------------------------------------- backup

@router.post("/backup")
def backup(conn: sqlite3.Connection = Depends(db.get_conn),
           user: dict = Depends(require("admin.backup"))):
    return create_backup(conn, _actor(user))


class RestoreIn(BaseModel):
    path: str
    confirm: str = Field(default="", description="Must be the literal 'RESTORE' to proceed.")


@router.post("/backup/restore")
def restore(body: RestoreIn, conn: sqlite3.Connection = Depends(db.get_conn),
            user: dict = Depends(require("admin.backup"))):
    if body.confirm != "RESTORE":
        raise HTTPException(400, {"code": "confirm_required",
                                  "message": "Set confirm='RESTORE' — this replaces live data."})
    # SEC-085: this used to be `"backups" not in str(path)` — a substring test,
    # so any path that merely *mentions* backups (e.g. /tmp/evil-backups/x or
    # /backups/../../elsewhere/y) passed while the message claimed containment.
    # Resolve and require real containment in the backups directory.
    path = Path(body.path)
    backups_dir = settings.backups_dir.resolve()
    resolved = path.resolve() if path.exists() else None
    if resolved is None or not resolved.is_file() or \
            (resolved != backups_dir and backups_dir not in resolved.parents):
        raise HTTPException(400, {
            "code": "bad_path",
            "message": f"path must be an existing file inside the backups directory ({backups_dir})"})
    v = verify_bundle(None, path)
    if not v["ok"]:
        # SEC-086: `message` used to be `str(v.get("bad"))`, which renders as
        # "None" for bundles rejected with an `error` (unreadable, no manifest) —
        # the caller saw a 409 that explained nothing.
        raise HTTPException(409, {
            "code": "verify_failed",
            "message": v.get("error") or f"bundle contents failed verification: {v.get('bad')}"})
    # Quiesce: close all per-request connections for this process, then restore.
    import app.db as dbmod
    try:
        with dbmod._lock:
            result = restore_from(path, _actor(user))
    except RuntimeError as e:      # SEC-086: defence-in-depth refusals are 409, not 500
        raise HTTPException(409, {"code": "restore_refused",
                                  "message": str(e)[:300]}) from e
    return result


# ------------------------------------------------------------------ retention
# SEC-072: retention REPORT only — ADR-005: deletion is a human, audited
# operation; this surfaces what is due, pinned, or case-dependent.

_UNIT_DAYS = {"d": 1, "w": 7, "m": 30, "y": 365}


def _retention_due(retention: str | None, created_at: str, now: str) -> str | None:
    """Return 'due' if the label's window has elapsed; None otherwise.
    legal-hold / retain-case-close are never auto-due."""
    if not retention:
        return None
    label = retention.strip().lower()
    if label in ("legal-hold", "legal_hold", "retain-case-close", "indefinite"):
        return None
    m = re.fullmatch(r"(\d+)\s*([dwmy])", label)
    if not m:
        return None
    from datetime import timedelta
    days = int(m.group(1)) * _UNIT_DAYS[m.group(2)]
    created = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    current = datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return "due" if (current - created) > timedelta(days=days) else None


@router.get("/retention/report")
def retention_report(conn: sqlite3.Connection = Depends(db.get_conn),
                     user: dict = Depends(require("audit.read"))):
    now = db.utcnow()
    ev = db.q(conn, "SELECT id, name, sha256, size, classification, retention, created_at, case_id FROM evidence")
    due, pinned, case_bound, ok = [], 0, 0, 0
    for e in ev:
        label = (e["retention"] or "").strip().lower()
        if label in ("legal-hold", "legal_hold"):
            pinned += 1
            continue
        if label == "retain-case-close":
            case_bound += 1
            continue
        if _retention_due(e["retention"], e["created_at"], now) == "due":
            due.append({"id": e["id"], "name": e["name"], "retention": e["retention"],
                        "created_at": e["created_at"], "sha256": e["sha256"][:16]})
        else:
            ok += 1
    backups_dir = settings.backups_dir
    backups = []
    if backups_dir.exists():
        for f in sorted(backups_dir.glob("*.db")):
            age_days = (datetime.now(UTC).timestamp() - f.stat().st_mtime) / 86400
            backups.append({"name": f.name, "size_bytes": f.stat().st_size,
                            "age_days": round(age_days, 1)})
    return {
        "generated_at": now,
        "evidence": {
            "total": len(ev), "due_for_review": due, "due_count": len(due),
            "legal_hold": pinned, "case_bound": case_bound, "within_retention": ok,
            "note": "Report only (ADR-005). Deletion is a human, audited operation.",
        },
        "backups": {"total": len(backups), "items": backups},
    }


# ------------------------------------------------------------------ releases
# SEC-064: human release approval gate. A production/staging rollout requires
# a recorded HUMAN decision (release.write = admin) referencing the checklist
# artifact's sha256 (docs/14). Append-only; audit-logged; reject is allowed
# (records a decision not to release).

class ReleaseIn(BaseModel):
    version: str = Field(min_length=1, max_length=64)
    commit_sha: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-f]{7,64}$",
                            description="Git commit of the released artifact.")
    checklist_sha256: str = Field(pattern=r"^[0-9a-f]{64}$",
                                  description="sha256 of the signed release checklist artifact (docs/14).")
    decision: str = Field(pattern=r"^(approved|rejected)$")
    comment: str | None = Field(default=None, max_length=500)


@router.post("/releases", status_code=201)
def record_release(body: ReleaseIn, conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("release.write"))):
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO releases (version, commit_sha, checklist_sha256, decision, decided_by, comment, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (body.version, body.commit_sha, body.checklist_sha256, body.decision,
         user["username"], body.comment, now))
    conn.commit()
    record_audit(conn, _actor(user), "release." + ("approved" if body.decision == "approved" else "rejected"),
                 target_type="release", target_id=str(cur.lastrowid),
                 detail={"version": body.version, "commit_sha": body.commit_sha,
                         "checklist_sha256": body.checklist_sha256})
    return db.one(conn, "SELECT * FROM releases WHERE id = ?", (cur.lastrowid,))


@router.get("/releases")
def list_releases(conn: sqlite3.Connection = Depends(db.get_conn),
                  user: dict = Depends(require("release.read")),
                  page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    return db.paged(conn, "SELECT * FROM releases", (), "ORDER BY created_at DESC, id DESC", page, page_size)


@router.get("/releases/latest")
def latest_release(conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("release.read"))):
    """The gate view: the most recent decision. Rollout tooling/ops MUST see
    decision=approved for the target version+commit before promoting."""
    row = db.one(conn, "SELECT * FROM releases ORDER BY created_at DESC, id DESC LIMIT 1")
    if not row:
        return {"latest": None, "gate": "no_decision",
                "note": "No release decision recorded. Production rollout is blocked until an admin approves (docs/14)."}
    return {"latest": row, "gate": "approved" if row["decision"] == "approved" else "blocked",
            "note": None if row["decision"] == "approved" else "Latest decision is not an approval — rollout blocked."}
