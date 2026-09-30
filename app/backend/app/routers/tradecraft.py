"""Tradecraft API (SEC-075) — The-Xploiter persona, scope guard, validation,
attack chains and triage-ready reporting.

Every write here is authorization-bound: a target must belong to an exercise in
status `authorized`/`running`. A refusal is not just a 409 — it is audited
(`tradecraft.out_of_scope`) so that attempts against un-authorized targets are
visible in the same tamper-evident log as everything else.
"""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import db
from ..audit import record_audit
from ..deps import require
from ..services import tradecraft

router = APIRouter(prefix="/api/tradecraft", tags=["tradecraft"])


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["user_id"]), "name": user["username"]}


# ------------------------------------------------------------------- persona

@router.get("/persona")
def get_persona(user: dict = Depends(require("tradecraft.read"))):
    """The-Xploiter: focus areas, principles, use cases — and its guardrails."""
    return tradecraft.PERSONA


@router.get("/rubric")
def get_rubric(user: dict = Depends(require("tradecraft.read"))):
    """Verdict vocabulary + the questions a review must answer."""
    return {
        "verdicts": tradecraft.VERDICTS,
        "reportable": tradecraft.REPORTABLE,
        "impacts": tradecraft.IMPACTS,
        "trust_boundaries": tradecraft.TRUST_BOUNDARIES,
        "questions": tradecraft.REVIEW_QUESTIONS,
        "evidence_policy": {
            "exploitable": "requires evidence + reproduction + impact (hostile-triager standard)",
            "not_exploitable": "requires the disproof evidence (recorded so it is not re-tested)",
            "needs_evidence": "unproven lead — never reportable",
            "theoretical": "rejected by policy — never reportable, never chainable",
        },
    }


# --------------------------------------------------------------- scope guard

@router.get("/scope")
def get_scope(conn: sqlite3.Connection = Depends(db.get_conn),
              user: dict = Depends(require("tradecraft.read"))):
    """Currently authorizing targets, flattened from authorized engagements."""
    return tradecraft.scope_summary(conn)


@router.get("/scope/check")
def check_scope(target: str = Query(min_length=1, max_length=300),
                conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("tradecraft.read"))):
    """Ask before acting: is this target inside an authorized engagement?"""
    return {"target": target, **tradecraft.check_target(conn, target)}


# ------------------------------------------------------- exploitability reviews

class ReviewIn(BaseModel):
    vuln_id: int | None = None
    target: str | None = Field(default=None, max_length=300)
    verdict: str
    trust_boundary: str | None = Field(default=None, max_length=60)
    impact_before: str | None = Field(default=None, max_length=40)
    impact_after: str | None = Field(default=None, max_length=40)
    preconditions: list[str] | None = None
    evidence: list[str] | dict | None = None
    reproduction: str | None = Field(default=None, max_length=8000)
    rationale: str = Field(min_length=1, max_length=8000)


@router.post("/reviews", status_code=201)
def create_review(body: ReviewIn, conn: sqlite3.Connection = Depends(db.get_conn),
                  user: dict = Depends(require("tradecraft.write"))):
    payload = body.model_dump()
    if body.vuln_id is not None and not db.one(conn, "SELECT id FROM vuln_findings WHERE id = ?",
                                               (body.vuln_id,)):
        raise HTTPException(404, {"code": "not_found", "message": "finding not found"})

    decision = tradecraft.validate_review(conn, payload)
    if not decision["ok"]:
        out_of_scope = any(e.startswith("out of scope") for e in decision["errors"])
        if out_of_scope:
            # Un-authorized targeting is a governance event, not just a 400.
            record_audit(conn, _actor(user), "tradecraft.out_of_scope",
                         target_type="target", target_id=body.target or "(none)",
                         detail={"verdict": body.verdict, "reason": decision["scope"]})
        raise HTTPException(400, {"code": "bad_review", "errors": decision["errors"]})

    finding = db.one(conn, "SELECT * FROM vuln_findings WHERE id = ?", (body.vuln_id,)) if body.vuln_id else None
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO exploitability_reviews (vuln_id, exercise_id, target, verdict, trust_boundary, "
        "impact_before, impact_after, preconditions, evidence, reproduction, rationale, triage_ready, "
        "policy_note, dedupe_key, reviewed_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (body.vuln_id, (decision["scope"] or {}).get("exercise_id"), body.target, body.verdict,
         body.trust_boundary, body.impact_before, body.impact_after,
         db.jdump(body.preconditions or []), db.jdump(body.evidence or []), body.reproduction,
         body.rationale, 1 if decision["triage_ready"] else 0, decision["policy_note"],
         tradecraft._fingerprint(body.target, finding, None), user["username"], now))
    conn.commit()
    record_audit(conn, _actor(user), "tradecraft.review_recorded",
                 target_type="exploitability_review", target_id=str(cur.lastrowid),
                 detail={"vuln_id": body.vuln_id, "target": body.target, "verdict": body.verdict,
                         "triage_ready": decision["triage_ready"],
                         "scope": (decision["scope"] or {}).get("reason")})
    row = db.one(conn, "SELECT * FROM exploitability_reviews WHERE id = ?", (cur.lastrowid,))
    return {"review": row, "triage_ready": decision["triage_ready"],
            "policy_note": decision["policy_note"], "scope": decision["scope"]}


@router.get("/reviews")
def list_reviews(conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("tradecraft.read")),
                 verdict: str | None = None, triage_ready: bool | None = None,
                 limit: int = Query(default=100, ge=1, le=500)):
    sql, params = "SELECT * FROM exploitability_reviews", []
    where = []
    if verdict:
        if verdict not in tradecraft.VERDICTS:
            raise HTTPException(400, {"code": "bad_verdict", "verdicts": list(tradecraft.VERDICTS)})
        where.append("verdict = ?")
        params.append(verdict)
    if triage_ready is not None:
        where.append("triage_ready = ?")
        params.append(1 if triage_ready else 0)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(limit)
    items = db.q(conn, sql, tuple(params))
    for r in items:
        r["preconditions"] = db.jload(r.get("preconditions"), [])
        r["evidence"] = db.jload(r.get("evidence"), [])
    return {"items": items, "total": len(items), "stats": tradecraft.stats(conn)}


@router.get("/duplicates")
def list_duplicates(conn: sqlite3.Connection = Depends(db.get_conn),
                    user: dict = Depends(require("tradecraft.read"))):
    """Clustered reviews by fingerprint — bug bounty signal-to-noise view."""
    return {"clusters": tradecraft.duplicates(conn)}


# ---------------------------------------------------------------- attack chains

class ChainIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    entry_point: str = Field(min_length=1, max_length=200)
    trust_boundary: str | None = Field(default=None, max_length=60)
    steps: list[dict]
    combined_impact: str
    escalation_note: str | None = Field(default=None, max_length=2000)
    rationale: str = Field(min_length=1, max_length=8000)
    exercise_id: int | None = None
    targets: list[str] | None = None


@router.post("/chains", status_code=201)
def create_chain(body: ChainIn, conn: sqlite3.Connection = Depends(db.get_conn),
                 user: dict = Depends(require("tradecraft.write"))):
    decision = tradecraft.validate_chain(conn, body.model_dump())
    if not decision["ok"]:
        if decision["out_of_scope"]:
            record_audit(conn, _actor(user), "tradecraft.out_of_scope",
                         target_type="chain", target_id=body.title,
                         detail={"targets": decision["out_of_scope"], "reason": "chain targets"})
        raise HTTPException(400, {"code": "bad_chain", "errors": decision["errors"]})

    steps = []
    for i, s in enumerate(body.steps, start=1):
        steps.append({**s, "order": s.get("order") or i})
    now = db.utcnow()
    cur = conn.execute(
        "INSERT INTO attack_chains (exercise_id, title, entry_point, trust_boundary, steps, "
        "combined_impact, status, escalation_note, rationale, meta, created_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?)",
        (body.exercise_id, body.title, body.entry_point, body.trust_boundary, db.jdump(steps),
         body.combined_impact, body.escalation_note, body.rationale,
         db.jdump({"targets": body.targets or []}), user["username"], now, now))
    conn.commit()
    record_audit(conn, _actor(user), "tradecraft.chain_recorded",
                 target_type="attack_chain", target_id=str(cur.lastrowid),
                 detail={"title": body.title, "steps": len(steps),
                         "combined_impact": body.combined_impact})
    return db.one(conn, "SELECT * FROM attack_chains WHERE id = ?", (cur.lastrowid,))


@router.get("/chains")
def list_chains(conn: sqlite3.Connection = Depends(db.get_conn),
                user: dict = Depends(require("tradecraft.read")),
                status: str | None = None):
    sql, params = "SELECT * FROM attack_chains", ()
    if status:
        sql += " WHERE status = ?"
        params = (status,)
    rows = db.q(conn, f"{sql} ORDER BY updated_at DESC, id DESC", params)
    for r in rows:
        r["steps"] = db.jload(r.get("steps"), [])
        r["meta"] = db.jload(r.get("meta"), {})
    return {"items": rows, "total": len(rows)}


class ChainStatusIn(BaseModel):
    status: str                       # validated | rejected | draft
    rationale: str = Field(min_length=1, max_length=4000)


@router.post("/chains/{chain_id}/status")
def set_chain_status(chain_id: int, body: ChainStatusIn,
                     conn: sqlite3.Connection = Depends(db.get_conn),
                     user: dict = Depends(require("tradecraft.write"))):
    """Promote or reject a chain — a human judgement, always with a reason."""
    if body.status not in ("draft", "validated", "rejected"):
        raise HTTPException(400, {"code": "bad_status", "allowed": ["draft", "validated", "rejected"]})
    c = db.one(conn, "SELECT * FROM attack_chains WHERE id = ?", (chain_id,))
    if not c:
        raise HTTPException(404, {"code": "not_found"})
    conn.execute("UPDATE attack_chains SET status = ?, rationale = ?, updated_at = ? WHERE id = ?",
                 (body.status, body.rationale, db.utcnow(), chain_id))
    conn.commit()
    record_audit(conn, _actor(user), "tradecraft.chain_status",
                 target_type="attack_chain", target_id=str(chain_id),
                 detail={"from": c["status"], "to": body.status, "rationale": body.rationale})
    return db.one(conn, "SELECT * FROM attack_chains WHERE id = ?", (chain_id,))


# ------------------------------------------------------------ triage reporting

@router.get("/findings/{vuln_id}/triage-report")
def triage_report(vuln_id: int, conn: sqlite3.Connection = Depends(db.get_conn),
                  user: dict = Depends(require("tradecraft.read"))):
    """Triage-ready markdown draft (plain text body, hostile-triager shape)."""
    ctx = tradecraft.vuln_context(conn, vuln_id)
    if not ctx:
        raise HTTPException(404, {"code": "not_found"})
    body = tradecraft.triage_report(ctx["finding"], ctx["reviews"], ctx["chains"])
    return {"vuln_id": vuln_id,
            "reportable": bool(ctx["reviews"] and ctx["reviews"][0]["triage_ready"]),
            "verdict": ctx["reviews"][0]["verdict"] if ctx["reviews"] else "unreviewed",
            "reviews": len(ctx["reviews"]), "chains": len(ctx["chains"]),
            "markdown": body}


@router.get("/stats")
def get_stats(conn: sqlite3.Connection = Depends(db.get_conn),
              user: dict = Depends(require("tradecraft.read"))):
    return tradecraft.stats(conn)
