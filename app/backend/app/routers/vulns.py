"""Vulnerability Management (SEC-035): findings, triage, remediation, exceptions.

Imports: CSV (asset,cve,title,cvss,severity,status) and JSON list — a
zero-cost replacement for a paid vuln DB; CVSS v3.1 base scores are accepted
as numbers (severity auto-derived when absent).
"""
from __future__ import annotations

import csv
import io
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require

router = APIRouter(prefix="/api/vulns", tags=["vulns"])

STATUSES = {"new", "triaged", "in_progress", "fixed", "accepted_risk"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
# `accepted_risk` is a risk acceptance, so it is not settable through the
# generic status PATCH (SEC-082): it must go through the exception record,
# which captures the rationale, the approver and an expiry.
PATCHABLE_STATUSES = STATUSES - {"accepted_risk"}


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


def severity_from_cvss(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


class FindingIn(BaseModel):
    asset_id: int | None = None
    cve_id: str | None = Field(default=None, max_length=30, pattern=r"^(CVE-\d{4}-\d{4,7}|[A-Z0-9-]+)$")
    title: str = Field(min_length=3, max_length=300)
    cvss: float | None = Field(default=None, ge=0, le=10)
    severity: str | None = None
    status: str = "new"
    exploitability: str | None = None
    description: str | None = Field(default=None, max_length=4000)
    source: str | None = None
    due_date: str | None = Field(default=None, max_length=40)


def _insert_finding(conn, f: dict) -> tuple[int, bool]:
    asset = f.get("asset_id")
    # SEC-109: `if asset and …` treated a falsy id (0) as "no asset", skipped the
    # existence check and let 0 through to the INSERT, where the foreign key failed as
    # an opaque 500. Only *absent* means "no asset".
    if asset is not None and not db.one(conn, "SELECT id FROM assets WHERE id = ?", (asset,)):
        raise HTTPException(400, {"code": "bad_asset"})
    sev = f.get("severity") or severity_from_cvss(f.get("cvss"))
    # SEC-082: severity is a finding's triage input, not free text — an imported
    # `severity: "banana"` used to be stored and then counted nowhere.
    if sev is not None and sev not in SEVERITIES:
        raise HTTPException(400, {"code": "bad_severity", "allowed": sorted(SEVERITIES)})
    existing = db.one(conn, "SELECT id FROM vuln_findings WHERE asset_id IS ? AND cve_id IS ? AND title = ?",
                      (asset, f.get("cve_id"), f["title"]))
    if existing:
        return existing["id"], False
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO vuln_findings (asset_id, cve_id, title, cvss, severity, status, exploitability, "
        "description, source, discovered_at, due_date, meta) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (asset, f.get("cve_id"), f["title"], f.get("cvss"), sev,
         f.get("status") or "new", f.get("exploitability"), f.get("description"), f.get("source"),
         now, f.get("due_date"), None))
    return int(cur.lastrowid), True


@router.post("", status_code=201)
def create_finding(body: FindingIn, conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("vulns.write"))):
    if body.status not in STATUSES:
        raise HTTPException(400, {"code": "bad_status"})
    fid, created = _insert_finding(conn, body.model_dump())
    conn.commit()
    if created:
        record_audit(conn, _actor(user), "vuln.created", target_type="vuln_finding", target_id=str(fid),
                     detail={"cve_id": body.cve_id, "severity": body.severity})
    return {"id": fid, "created": created}


@router.post("/import/csv", status_code=201)
def import_csv(file: UploadFile, conn: sqlite3.Connection = Depends(db.get_conn),
               user: dict = Depends(require("vulns.write"))):
    content = file.file.read().decode("utf-8-sig", errors="replace")
    rows = list(csv.DictReader(io.StringIO(content)))
    if not rows:
        raise HTTPException(400, {"code": "empty"})
    asset_names = {a["name"]: a["id"] for a in db.q(conn, "SELECT id, name FROM assets")}
    created = updated = errors = 0
    err_msgs = []
    for i, row in enumerate(rows[:2000]):
        try:
            asset = asset_names.get((row.get("asset") or "").strip())
            cvss = float(row["cvss"]) if (row.get("cvss") or "").strip() else None
            f = {"asset_id": asset, "cve_id": (row.get("cve") or "").strip() or None,
                 "title": (row.get("title") or "").strip() or f"finding-{i}",
                 "cvss": cvss, "severity": (row.get("severity") or "").strip() or None,
                 "status": (row.get("status") or "new").strip(), "source": "csv-import"}
            fid, created_now = _insert_finding(conn, f)
            if created_now:
                created += 1
            else:
                updated += 1
        except HTTPException as e:
            errors += 1
            err_msgs.append(f"row {i}: {e.detail}")
    conn.commit()
    record_audit(conn, _actor(user), "vuln.csv_imported", target_type="vulns",
                 detail={"created": created, "updated": updated, "errors": errors})
    return {"created": created, "updated": updated, "errors": errors, "error_sample": err_msgs[:5]}


@router.post("/import/json", status_code=201)
def import_json(body: list[FindingIn], conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("vulns.write"))):
    created = updated = 0
    for f in body[:2000]:
        fid, created_now = _insert_finding(conn, f.model_dump())
        created += created_now
        updated += (not created_now)
    conn.commit()
    record_audit(conn, _actor(user), "vuln.json_imported", target_type="vulns",
                 detail={"created": created, "updated": updated})
    return {"created": created, "updated": updated}


@router.get("")
def list_findings(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("vulns.read")),
                  status: str | None = None, severity: str | None = None,
                  asset_id: int | None = None, q: str | None = None,
                  page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    where, params = ["1=1"], []
    if status:
        where.append("v.status = ?")
        params.append(status)
    if severity:
        where.append("v.severity = ?")
        params.append(severity)
    if asset_id is not None:
        where.append("v.asset_id = ?")
        params.append(asset_id)
    if q:
        where.append("(v.title LIKE ? OR v.cve_id LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    sql = ("SELECT v.*, a.name AS asset_name FROM vuln_findings v "
           "LEFT JOIN assets a ON a.id = v.asset_id WHERE " + " AND ".join(where))
    return db.paged(conn, sql, tuple(params), "ORDER BY v.cvss DESC, v.id DESC", page, page_size)


class FindingUpdate(BaseModel):
    status: str | None = None
    exploitability: str | None = None
    due_date: str | None = Field(default=None, max_length=40)
    assigned_to: str | None = Field(default=None, max_length=100)
    note: str | None = Field(default=None, max_length=1000)


@router.patch("/{fid}")
def update_finding(fid: int, body: FindingUpdate, conn: sqlite3.Connection = Depends(db.get_conn),
                   user: dict = Depends(require("vulns.write"))):
    f = db.one(conn, "SELECT * FROM vuln_findings WHERE id = ?", (fid,))
    if not f:
        raise HTTPException(404, {"code": "not_found"})
    if body.status and body.status not in STATUSES:
        raise HTTPException(400, {"code": "bad_status"})
    # SEC-082: accepting a finding's risk is a documented decision with an
    # approver, a rationale and an expiry (POST /{fid}/exceptions). Setting the
    # status directly recorded none of them, so the same decision had two
    # representations, one of them without a reason or an end date.
    if body.status == "accepted_risk":
        raise HTTPException(400, {"code": "use_exception_endpoint",
                                  "message": ("risk acceptance is recorded as an exception — "
                                              "POST /api/vulns/{id}/exceptions with a reason "
                                              "(and an expiry where possible)")})
    fields, params = [], []
    for k in ("status", "exploitability", "due_date"):
        if getattr(body, k) is not None:
            fields.append(f"{k} = ?")
            params.append(getattr(body, k))
    # SEC-092: same defect as `cases.closed_at` — `fixed_at` was stamped when a
    # finding became `fixed` and left set when it was reopened (and rewritten by
    # a repeat `fixed`), so "when was this fixed?" had no reliable answer.
    if body.status == "fixed" and (f["status"] != "fixed" or not f["fixed_at"]):
        fields.append("fixed_at = ?")
        params.append(db.utcnow())
    elif body.status is not None and body.status != "fixed" and f["status"] == "fixed":
        fields.append("fixed_at = NULL")
    if not fields:
        raise HTTPException(400, {"code": "no_changes"})
    params.append(fid)
    conn.execute(f"UPDATE vuln_findings SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()
    detail = {k: v for k, v in body.model_dump().items() if v is not None}
    if body.status is not None and body.status != f["status"]:
        detail["from_status"], detail["to_status"] = f["status"], body.status
    record_audit(conn, _actor(user), "vuln.updated", target_type="vuln_finding", target_id=str(fid),
                 detail=detail)
    return db.one(conn, "SELECT * FROM vuln_findings WHERE id = ?", (fid,))


class ExceptionIn(BaseModel):
    reason: str = Field(min_length=10, max_length=1000)
    expires_at: str | None = Field(default=None, max_length=40)


@router.post("/{fid}/exceptions", status_code=201)
def add_exception(fid: int, body: ExceptionIn, conn: sqlite3.Connection = Depends(db.get_conn),
                  user: dict = Depends(require("vulns.write"))):
    f = db.one(conn, "SELECT * FROM vuln_findings WHERE id = ?", (fid,))
    if not f:
        raise HTTPException(404, {"code": "not_found"})
    cur = conn.execute(
        "INSERT INTO finding_exceptions (vuln_id, reason, approved_by, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (fid, body.reason, user["username"], body.expires_at, db.utcnow()))
    conn.execute("UPDATE vuln_findings SET status = 'accepted_risk' WHERE id = ?", (fid,))
    conn.commit()
    record_audit(conn, _actor(user), "vuln.exception_added", target_type="vuln_finding", target_id=str(fid),
                 detail={"expires_at": body.expires_at, "approved_by": user["username"]})
    return db.one(conn, "SELECT * FROM finding_exceptions WHERE id = ?", (cur.lastrowid,))


@router.get("/{fid}/exceptions")
def list_exceptions(fid: int, conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("vulns.read"))):
    rows = db.q(conn, "SELECT * FROM finding_exceptions WHERE vuln_id = ? ORDER BY id", (fid,))
    return {"items": rows, "total": len(rows)}


class RemediationIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    owner: str | None = Field(default=None, max_length=100)
    due: str | None = Field(default=None, max_length=40)


@router.post("/{fid}/remediation", status_code=201)
def add_remediation(fid: int, body: RemediationIn, conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("vulns.write"))):
    if not db.one(conn, "SELECT id FROM vuln_findings WHERE id = ?", (fid,)):
        raise HTTPException(404, {"code": "not_found"})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO remediation_tasks (vuln_id, title, status, owner, due, created_at, updated_at) "
        "VALUES (?, ?, 'open', ?, ?, ?, ?)",
        (fid, body.title, body.owner, body.due, now, now))
    conn.execute("UPDATE vuln_findings SET status = 'in_progress' WHERE id = ?", (fid,))
    conn.commit()
    record_audit(conn, _actor(user), "vuln.remediation_added", target_type="vuln_finding", target_id=str(fid))
    return db.one(conn, "SELECT * FROM remediation_tasks WHERE id = ?", (cur.lastrowid,))


@router.get("/{fid}/remediation")
def list_remediation(fid: int, conn: sqlite3.Connection = Depends(db.get_conn),
                     user: dict = Depends(require("vulns.read"))):
    rows = db.q(conn, "SELECT * FROM remediation_tasks WHERE vuln_id = ? ORDER BY id", (fid,))
    return {"items": rows, "total": len(rows)}
