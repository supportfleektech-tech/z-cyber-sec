"""Application Security (SEC-036): scan runs, SARIF import, findings, suppressions.

SARIF 2.1.0 subset import — free interop with free SAST tools (Semgrep,
CodeQL OSS, ESLint --format json converted). CI status flows in as scan runs.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require

router = APIRouter(prefix="/api/appsec", tags=["appsec"])


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


class ScanRunIn(BaseModel):
    repo: str = Field(min_length=1, max_length=300)
    kind: str = "sast"
    status: str = "completed"
    started_at: str | None = None
    finished_at: str | None = None
    ci_url: str | None = Field(default=None, max_length=500)
    meta: dict[str, Any] | None = None


@router.post("/scan-runs", status_code=201)
def create_scan_run(body: ScanRunIn, conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("appsec.write"))):
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO scan_runs (repo, kind, status, started_at, finished_at, findings_total, findings_new, "
        "ci_url, meta) VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?)",
        (body.repo, body.kind, body.status, body.started_at or now,
         body.finished_at or now, body.ci_url, db.jdump(body.meta)))
    conn.commit()
    record_audit(conn, _actor(user), "appsec.scan_run.created", target_type="scan_run",
                 target_id=str(cur.lastrowid), detail={"repo": body.repo, "kind": body.kind})
    return db.one(conn, "SELECT * FROM scan_runs WHERE id = ?", (cur.lastrowid,))


@router.get("/scan-runs")
def list_scan_runs(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("appsec.read")),
                   repo: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    sql, params = "SELECT * FROM scan_runs", ()
    if repo:
        sql += " WHERE repo = ?"
        params = (repo,)
    return db.paged(conn, sql, params, "ORDER BY COALESCE(finished_at, started_at) DESC, id DESC",
                    page, page_size)


class SarifImportIn(BaseModel):
    scan_run_id: int
    sarif: dict[str, Any]


@router.post("/sarif", status_code=201)
def import_sarif(body: SarifImportIn, conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("appsec.write"))):
    run = db.one(conn, "SELECT * FROM scan_runs WHERE id = ?", (body.scan_run_id,))
    if not run:
        raise HTTPException(404, {"code": "scan_run_not_found"})
    sarif = body.sarif
    if str(sarif.get("version", "")).split(".")[0] not in {"2", "3"} or not isinstance(sarif.get("runs"), list):
        raise HTTPException(400, {"code": "bad_sarif", "message": "Expected SARIF 2.x with runs[]"})
    created = 0
    rule_meta = {}
    for run_obj in sarif["runs"]:
        driver = (run_obj.get("tool") or {}).get("driver") or {}
        for r in driver.get("rules") or []:
            rule_meta[r.get("id")] = r
        for result in run_obj.get("results") or []:
            rule_id = str(result.get("ruleId") or "unknown")
            level = str(result.get("level") or "note").lower()
            severity = {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "low")
            message = (result.get("message") or {}).get("text", "")
            loc = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            file_path = ((loc.get("artifactLocation") or {}).get("uri") or "").replace("\\", "/")
            line = int((loc.get("region") or {}).get("startLine") or 0)
            existing = db.one(conn,
                              "SELECT id FROM appsec_findings WHERE scan_run_id = ? AND rule_id = ? "
                              "AND file = ? AND line = ?", (run["id"], rule_id, file_path, line))
            if existing:
                continue
            conn.execute(
                "INSERT INTO appsec_findings (scan_run_id, rule_id, severity, file, line, message, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'open', ?)",
                (run["id"], rule_id, severity, file_path, line, message[:2000], db.utcnow()))
            created += 1
    conn.execute("UPDATE scan_runs SET findings_total = ?, status = 'completed' WHERE id = ?",
                 (created, run["id"]))
    conn.commit()
    record_audit(conn, _actor(user), "appsec.sarif.imported", target_type="scan_run",
                 target_id=str(run["id"]), detail={"findings": created})
    return {"imported": created, "scan_run_id": run["id"]}


@router.get("/findings")
def list_findings(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("appsec.read")),
                  scan_run_id: int | None = None, severity: str | None = None,
                  status: str | None = None,
                  page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    where, params = ["1=1"], []
    if scan_run_id is not None:
        where.append("f.scan_run_id = ?")
        params.append(scan_run_id)
    if severity:
        where.append("f.severity = ?")
        params.append(severity)
    if status:
        where.append("f.status = ?")
        params.append(status)
    sql = ("SELECT f.*, s.repo FROM appsec_findings f JOIN scan_runs s ON s.id = f.scan_run_id "
           "WHERE " + " AND ".join(where))
    return db.paged(conn, sql, tuple(params), "ORDER BY f.id DESC", page, page_size)


class SuppressIn(BaseModel):
    reason: str = Field(min_length=10, max_length=500)


@router.post("/findings/{finding_id}/suppress", status_code=200)
def suppress_finding(finding_id: int, body: SuppressIn, conn: sqlite3.Connection = Depends(db.get_conn),
                     user: dict = Depends(require("appsec.write"))):
    f = db.one(conn, "SELECT * FROM appsec_findings WHERE id = ?", (finding_id,))
    if not f:
        raise HTTPException(404, {"code": "not_found"})
    conn.execute("UPDATE appsec_findings SET status = 'suppressed', suppression_reason = ? WHERE id = ?",
                 (body.reason, finding_id))
    conn.commit()
    record_audit(conn, _actor(user), "appsec.finding.suppressed", target_type="appsec_finding",
                 target_id=str(finding_id), detail={"reason": body.reason, "by": user["username"]})
    return {"id": finding_id, "status": "suppressed"}
