"""Admin: integrations, feature flags, settings, audit log, backups."""
from __future__ import annotations

import os
import re
import sqlite3
import time
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


# --------------------------------------------------------------------- doctor

@router.get("/doctor")
def doctor(conn: sqlite3.Connection = Depends(db.get_conn),
           user: dict = Depends(require("audit.read"))):
    """One-shot self-diagnosis for an operator (SEC-116).

    Every check below existed separately — migrations, the audit chain, the
    scheduler, backups, the range, the environment — and each had to be reached
    through a different page or endpoint, so "is this install healthy?" was
    answerable only by someone who already knew where to look. This aggregates
    them into one verdict with per-check status, the values behind it and the
    command to run when something is wrong.

    Read-only by construction: nothing here writes, retries or repairs. Every
    finding names a `fix_hint`.
    """
    from ..audit import anchor as read_anchor
    from ..audit import verify_chain

    checks: list[dict] = []

    def check(name: str, status: str, detail, fix_hint: str | None = None) -> None:
        checks.append({"check": name, "status": status, "detail": detail, "fix_hint": fix_hint})

    # --- database + migrations
    try:
        applied = db.q(conn, "SELECT name, applied_at FROM schema_migrations ORDER BY name")
    except Exception as exc:
        applied = []
        check("database.migrations", "fail", {"error": str(exc)},
              "the database is unreadable — restore from the last verified backup (docs/10)")
    if applied:
        migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
        on_disk = sorted(f.name for f in migrations_dir.glob("*.sql"))
        missing = [m for m in on_disk if m not in {r["name"] for r in applied}]
        check("database.migrations", "fail" if missing else "ok",
              {"applied": len(applied), "latest": applied[-1]["name"], "pending": missing},
              "restart the app to apply pending migrations" if missing else None)

    # --- audit chain + anchor
    verdict = verify_chain(conn)
    head = read_anchor(conn)
    check("audit.chain", "ok" if verdict.get("ok") else "fail",
          {"ok": verdict.get("ok"), "rows": verdict.get("rows"),
           "head_seq": head.get("seq"), "reason": verdict.get("reason")},
          "do NOT delete audit rows; compare against the last exported anchor and escalate (docs/10)")

    # --- counters the operator would otherwise eyeball one page at a time
    open_alerts = db.one(conn, "SELECT COUNT(*) c FROM alerts WHERE status NOT IN ('closed','dismissed')")["c"]
    stale = db.one(conn, "SELECT COUNT(*) c FROM report_schedules WHERE status='active' AND "
                         "failures > 0")["c"]
    check("reports.schedules", "warn" if stale else "ok",
          {"active_with_failures": stale,
           "next_due": (db.one(conn, "SELECT MIN(next_run_at) m FROM report_schedules WHERE status='active'")
                        or {}).get("m")},
          "inspect /api/reports/schedules for last_error, then fix the template or filters")

    # --- sessions (SEC-105 semantics: expired rows are not active)
    sessions = db.one(conn, "SELECT COUNT(*) c FROM sessions WHERE expires_at > ?", (db.utcnow(),))["c"]
    expired = db.one(conn, "SELECT COUNT(*) c FROM sessions WHERE expires_at <= ?", (db.utcnow(),))["c"]
    check("sessions", "ok", {"active": sessions, "expired_rows": expired, "open_alerts": open_alerts})

    # --- backups: present, recent, verifiable
    backups = sorted(settings.backups_dir.glob("*.tar.gz"), key=lambda f: f.stat().st_mtime, reverse=True)
    newest = backups[0] if backups else None
    if not backup_recent(newest):
        check("backup.freshness", "fail",
              {"backups": len(backups), "newest": newest.name if newest else None},
              "create one: POST /api/admin/backup, then verify it (docs/10 Weekly drill)")
    else:
        check("backup.freshness", "ok",
              {"backups": len(backups), "newest": newest.name,
               "age_hours": round((time.time() - newest.stat().st_mtime) / 3600, 1)})

    # --- data directories writable (evidence upload, reports, backups)
    for label, path in (("data.evidence_dir", settings.evidence_dir),
                        ("data.reports_dir", settings.reports_dir),
                        ("data.backups_dir", settings.backups_dir)):
        writable = os.access(path, os.W_OK) if path.exists() else False
        check(label, "ok" if writable else "fail", {"path": str(path), "exists": path.exists()},
              f"create it and grant the service account write access: mkdir -p {path}")

    # --- environment + the guards that depend on it
    check("env.guards", "ok" if settings.env_name in ("STAGING", "PROD") or settings.secret_key
          else "warn",
          {"env": settings.env_name, "secret_key_is_default": settings.secret_key == "dev-only-change-me-in-staging",
           "login_rate_limit": settings.login_rate_limit_enabled,
           "metrics_token_set": bool(settings.metrics_token)},
          "STAGING/PROD refuse to boot with a weak SECRET_KEY (ADR-006); set METRICS_TOKEN and "
          "LOGIN_RATE_LIMIT_ENABLED=1 before exposing the app")

    # --- lab range cross-check (SEC-115)
    try:
        from .lab import _looks_like_lab_target
        targets = {r["name"]: r["status"] for r in db.q(conn, "SELECT name, status FROM lab_targets")}
        if targets:
            drift, dangling = [], []
            for ex in db.q(conn, "SELECT name, status, targets FROM exercises "
                                 "WHERE status IN ('authorized', 'running')"):
                for name in db.jload(ex["targets"], []) or []:
                    if name not in targets and _looks_like_lab_target(name):
                        dangling.append(name)
            for name, status in targets.items():
                if status == "running" and not db.one(
                        conn, "SELECT id FROM exercises WHERE status IN ('authorized','running') "
                              "AND targets LIKE ?", (f'%"{name}"%',)):
                    drift.append(name)
            check("lab.range", "fail" if (drift or dangling) else "ok",
                  {"registered": len(targets), "running_but_not_authorized": drift,
                   "authorized_but_not_registered": dangling},
                  "GET /api/lab/coverage explains both; register the target or authorize it")
        else:
            check("lab.range", "warn", {"registered": 0},
                  "no range targets registered — see docs/17 and infra/lab/docker-compose.yml")
    except Exception as exc:  # a diagnostic must never be the thing that breaks
        check("lab.range", "warn", {"error": str(exc)})

    # --- agent governance: are the eval results in place?
    agents = db.one(conn, "SELECT COUNT(*) c FROM agents")["c"]
    check("agents", "ok" if agents else "warn", {"agents": agents},
          "register an agent and run the governance evals: POST /api/agents/evals/run")

    failed = [c for c in checks if c["status"] == "fail"]
    warned = [c for c in checks if c["status"] == "warn"]
    return {
        "env": settings.env_name,
        "version": (db.one(conn, "SELECT value FROM settings WHERE key = 'platform_version'") or {})
                   .get("value"),
        "generated_at": db.utcnow(),
        "verdict": "fail" if failed else ("warn" if warned else "ok"),
        "summary": {"checks": len(checks), "ok": len(checks) - len(failed) - len(warned),
                    "warn": len(warned), "fail": len(failed)},
        "checks": checks,
        "note": ("Read-only diagnosis: nothing here writes, retries or repairs. Each failing "
                 "check's `fix_hint` is the action; `docs/10-operations-runbook.md` is the "
                 "procedure it belongs to."),
    }


def backup_recent(newest, max_age_hours: float = 48.0) -> bool:
    """A backup older than two days does not satisfy the restore drill cadence."""
    if newest is None:
        return False
    return (time.time() - newest.stat().st_mtime) <= max_age_hours * 3600


# -------------------------------------------------------------------- backup

@router.post("/backup")
def backup(conn: sqlite3.Connection = Depends(db.get_conn),
           user: dict = Depends(require("admin.backup"))):
    return create_backup(conn, _actor(user))


def _checked_backup_path(raw: str) -> Path:
    """Resolve a caller-supplied bundle path, requiring it to be inside backups.

    SEC-085: this used to be `"backups" not in str(path)` — a substring test, so
    any path that merely *mentions* backups (e.g. /tmp/evil-backups/x or
    /backups/../../elsewhere/y) passed while the message claimed containment.
    """
    path = Path(raw)
    backups_dir = settings.backups_dir.resolve()
    resolved = path.resolve() if path.exists() else None
    if resolved is None or not resolved.is_file() or \
            (resolved != backups_dir and backups_dir not in resolved.parents):
        raise HTTPException(400, {
            "code": "bad_path",
            "message": f"path must be an existing file inside the backups directory ({backups_dir})"})
    return path


@router.post("/backup/verify")
def verify_backup(body: RestoreIn, conn: sqlite3.Connection = Depends(db.get_conn),
                  user: dict = Depends(require("admin.backup"))):
    """Check a bundle without restoring it (SEC-100).

    Compares the archive against the sha256 the hash-chained audit log recorded
    when it was created, so a bundle edited after creation (its manifest can be
    edited with it) is refused here and by the restore gate.
    """
    path = _checked_backup_path(body.path)
    out = verify_bundle(conn, path)
    out["path"] = str(path)
    return out


class RestoreIn(BaseModel):
    path: str
    confirm: str = Field(default="", description="Must be the literal 'RESTORE' to proceed.")
    # SEC-100: a bundle this log has no creation record for cannot be checked against
    # the hash the platform recorded. Restoring one is a deliberate act (disaster
    # recovery from a bundle built elsewhere), so it needs an explicit flag.
    allow_unrecorded: bool = Field(default=False,
                                   description="Restore a bundle with no recorded creation hash.")


@router.post("/backup/restore")
def restore(body: RestoreIn, conn: sqlite3.Connection = Depends(db.get_conn),
            user: dict = Depends(require("admin.backup"))):
    if body.confirm != "RESTORE":
        raise HTTPException(400, {"code": "confirm_required",
                                  "message": "Set confirm='RESTORE' — this replaces live data."})
    path = _checked_backup_path(body.path)
    v = verify_bundle(conn, path)
    if not v["ok"]:
        # SEC-086: `message` used to be `str(v.get("bad"))`, which renders as
        # "None" for bundles rejected with an `error` (unreadable, no manifest) —
        # the caller saw a 409 that explained nothing.
        raise HTTPException(409, {
            "code": "verify_failed",
            "message": v.get("error") or f"bundle contents failed verification: {v.get('bad')}"})
    if not (v.get("recorded") or {}).get("found") and not body.allow_unrecorded:
        raise HTTPException(409, {
            "code": "unrecorded_bundle",
            "message": ((v.get("recorded") or {}).get("note") or "no recorded creation hash") +
                       " — pass allow_unrecorded=true only if you verified the bundle elsewhere"})
    # Quiesce: close all per-request connections for this process, then restore.
    import app.db as dbmod
    try:
        with dbmod._lock:
            result = restore_from(path, _actor(user), conn)
    except RuntimeError as e:      # SEC-086: defence-in-depth refusals are 409, not 500
        raise HTTPException(409, {"code": "restore_refused",
                                  "message": str(e)[:300]}) from e
    return result


# ------------------------------------------------------------------ retention
# SEC-072: retention REPORT only — ADR-005: deletion is a human, audited
# operation; this surfaces what is due, pinned, or case-dependent.

_UNIT_DAYS = {"d": 1, "w": 7, "m": 30, "y": 365}


def _retention_understood(retention: str | None) -> bool:
    """True when the label is one the report can act on (SEC-112)."""
    label = (retention or "").strip().lower()
    return label in ("legal-hold", "legal_hold", "retain-case-close", "indefinite") or \
        bool(re.fullmatch(r"\d+\s*[dwmy]", label))


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
    due, unrecognised, pinned, case_bound, ok = [], [], 0, 0, 0
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
        elif label and not _retention_understood(e["retention"]):
            # SEC-112: a label the report cannot parse is *not* evidence of being
            # within retention — it used to be counted as `within_retention`, so a
            # typo made an artefact never come due while the report blessed it.
            # Writes are validated now (cases.py); this surfaces rows already stored.
            unrecognised.append({"id": e["id"], "name": e["name"], "retention": e["retention"],
                                 "created_at": e["created_at"]})
        else:
            ok += 1
    backups_dir = settings.backups_dir
    backups = []
    if backups_dir.exists():
        # SEC-101: `create_backup` packs everything into `<name>.tar.gz` and removes
        # the intermediate `.db`, so globbing `*.db` reported `total: 0` while
        # backups existed — the one report an operator checks claimed there were no
        # backups at all.
        for f in sorted(list(backups_dir.glob("*.tar.gz")) + list(backups_dir.glob("*.db"))):
            age_days = (datetime.now(UTC).timestamp() - f.stat().st_mtime) / 86400
            entry = {"name": f.name, "size_bytes": f.stat().st_size,
                     "age_days": round(age_days, 1),
                     "kind": "bundle" if f.name.endswith(".tar.gz") else "db"}
            if entry["kind"] == "bundle":
                # Cross-check against the hash recorded at creation (SEC-100), so a
                # backup that was edited afterwards is visible here too.
                v = verify_bundle(conn, f)
                entry["sha256"] = (v.get("recorded") or {}).get("actual") or ""
                entry["matches_recorded"] = (v.get("recorded") or {}).get("matches")
                entry["verifies"] = bool(v.get("ok"))
            backups.append(entry)
    return {
        "generated_at": now,
        "evidence": {
            "total": len(ev), "due_for_review": due, "due_count": len(due),
            "legal_hold": pinned, "case_bound": case_bound, "within_retention": ok,
            "unrecognised_retention": unrecognised, "unrecognised_count": len(unrecognised),
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
