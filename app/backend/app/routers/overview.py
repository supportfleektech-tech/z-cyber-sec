"""Overview: platform health, dashboard stats, Prometheus-format metrics."""
from __future__ import annotations

import platform
import secrets
import sqlite3
import time
from datetime import UTC

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response

from .. import db
from ..config import settings
from ..deps import require

router = APIRouter(tags=["overview"])

_started = time.time()

# Alert statuses that mean "still needs attention" (SEC-105). Kept next to the
# metrics so the total and the per-severity series cannot drift apart.
_OPEN_ALERT_STATUSES = ("new", "triaging", "confirmed")
_OPEN_ALERT_SQL = "(" + ", ".join(f"'{s}'" for s in _OPEN_ALERT_STATUSES) + ")"


@router.get("/api/healthz")
def healthz(conn: sqlite3.Connection = Depends(db.get_conn)):
    ok = conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    return {"ok": ok, "env": settings.env_name, "version": "1.0.0"}


@router.get("/api/overview/stats")
def stats(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("overview.read"))):
    def c(sql, params=()):
        r = db.one(conn, sql, params)
        return int(r["c"]) if r else 0

    by_sev = {row["severity"]: row["c"] for row in db.q(conn, "SELECT severity, COUNT(*) c FROM alerts GROUP BY severity")}
    cases_by_status = {row["status"]: row["c"] for row in db.q(conn, "SELECT status, COUNT(*) c FROM cases GROUP BY status")}
    vulns_open = c("SELECT COUNT(*) c FROM vuln_findings WHERE status IN ('new','triaged','in_progress')")
    events_last_24h = c("SELECT COUNT(*) c FROM events WHERE ts >= ?", (_hours_ago(conn, 24),))
    return {
        "env": settings.env_name,
        "uptime_seconds": int(time.time() - _started),
        "events_total": c("SELECT COUNT(*) c FROM events"),
        "events_last_24h": events_last_24h,
        "alerts": {"total": c("SELECT COUNT(*) c FROM alerts"), **by_sev},
        "cases": {"total": c("SELECT COUNT(*) c FROM cases"), **cases_by_status},
        "vulns": {"total": c("SELECT COUNT(*) c FROM vuln_findings"), "open": vulns_open},
        "indicators": c("SELECT COUNT(*) c FROM threat_indicators WHERE status='active'"),
        "posture_open": c("SELECT COUNT(*) c FROM posture_findings WHERE status='open'"),
        "controls": {row["status"]: row["c"] for row in db.q(conn, "SELECT status, COUNT(*) c FROM controls GROUP BY status")},
        "open_approvals": c("SELECT COUNT(*) c FROM approvals WHERE status='pending'"),
        "active_agents": c("SELECT COUNT(*) c FROM agents WHERE status='active'"),
        "playbooks": c("SELECT COUNT(*) c FROM playbooks WHERE status='active'"),
    }


def _hours_ago(conn, hours: int) -> str:
    from datetime import datetime, timedelta
    return (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


@router.get("/api/overview/alert-trend")
def alert_trend(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("overview.read")),
                days: int = 7):
    days = max(1, min(days, 30))
    since = _hours_ago(conn, days * 24)
    rows = db.q(conn,
                "SELECT substr(first_seen, 1, 10) AS day, severity, COUNT(*) c FROM alerts "
                "WHERE first_seen >= ? GROUP BY day, severity ORDER BY day", (since,))
    return {"days": days, "points": rows}


@router.get("/api/overview/integrations")
def integrations_public(conn: sqlite3.Connection = Depends(db.get_conn),
                        user: dict = Depends(require("overview.read"))):
    """Health panel data — public to any authenticated user (no secrets in config)."""
    rows = db.q(conn, "SELECT name, kind, status, last_run_at, last_status FROM integrations ORDER BY name")
    return {"items": rows, "total": len(rows)}


@router.get("/api/overview/services")
def services(conn: sqlite3.Connection = Depends(db.get_conn), user: dict = Depends(require("overview.read"))):
    """Service health for the overview page (all in-process; honest reporting)."""
    db_ok = conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    ev_dir = settings.evidence_dir
    return {
        "api": {"status": "ok", "python": platform.python_version()},
        "database": {"status": "ok" if db_ok else "error", "engine": "sqlite3",
                     "path_exists": settings.db_path.exists()},
        "detection_engine": {"status": "ok", "active_rules":
                             int(db.one(conn, "SELECT COUNT(*) c FROM detection_rules WHERE status='active'")["c"])},
        "evidence_store": {"status": "ok" if ev_dir.exists() else "missing", "path": str(ev_dir)},
        "agent_gateway": {"status": "ok"},
        "metrics": {"status": "ok", "endpoint": "/metrics"},
    }


@router.get("/metrics")
def metrics(request: Request, conn: sqlite3.Connection = Depends(db.get_conn)):
    """Prometheus text format (free standard). Read-only; counts only — no
    secrets, no user data, no event contents.

    Exposure (SEC-073): the app binds to an internal address and the prod
    edge denies ``/metrics`` publicly (``infra/prod/Caddyfile``), so the
    endpoint is reachable from the host / scrape network only. Set
    ``METRICS_TOKEN`` to additionally require ``Authorization: Bearer <token>``
    (mandatory if the port is ever published beyond the internal bind).
    """
    expected = settings.metrics_token
    if expected:
        supplied = request.headers.get("authorization", "")
        if not secrets.compare_digest(supplied, f"Bearer {expected}"):
            raise HTTPException(
                status_code=401,
                detail={"code": "unauthenticated", "message": "Metrics token required."},
                headers={"WWW-Authenticate": "Bearer"},
            )

    def c(sql, params=()):
        r = db.one(conn, sql, params)
        return int(r["c"]) if r else 0

    # SEC-105: one definition of "open", shared by the total and the per-severity
    # series. The labelled series used to count *every* alert of that severity, so
    # `cybersec_alerts_open{severity="critical"} > 0` never cleared when the alert was
    # closed — an alert that cannot resolve is worse than no alert.
    alerts_open = c(f"SELECT COUNT(*) c FROM alerts WHERE status IN {_OPEN_ALERT_SQL}")
    cases_open = c("SELECT COUNT(*) c FROM cases WHERE status != 'closed'")
    vulns_open = c("SELECT COUNT(*) c FROM vuln_findings WHERE status IN ('new','triaged','in_progress')")
    inds_active = c("SELECT COUNT(*) c FROM threat_indicators WHERE status='active'")
    appr_pending = c("SELECT COUNT(*) c FROM approvals WHERE status='pending'")
    # SEC-105: session rows are only deleted on logout, so counting rows reported
    # expired sessions as "active" forever. Count live sessions, and surface the
    # expired rows separately instead of hiding them in `active`.
    now = db.utcnow()
    sessions_active = c("SELECT COUNT(*) c FROM sessions WHERE expires_at > ?", (now,))
    sessions_expired = c("SELECT COUNT(*) c FROM sessions WHERE expires_at <= ?", (now,))
    db_size = settings.db_path.stat().st_size if settings.db_path.exists() else 0
    lines = [
        "# CYBER-SEC metrics (Prometheus text format v0.0.4)",
        f"cybersec_uptime_seconds {int(time.time() - _started)}",
        f"cybersec_events_total {c('SELECT COUNT(*) c FROM events')}",
        f"cybersec_alerts_total {c('SELECT COUNT(*) c FROM alerts')}",
        f"cybersec_alerts_open {alerts_open}",
        f"cybersec_cases_total {c('SELECT COUNT(*) c FROM cases')}",
        f"cybersec_cases_open {cases_open}",
        f"cybersec_vulns_open {vulns_open}",
        f"cybersec_indicators_active {inds_active}",
        f"cybersec_approvals_pending {appr_pending}",
        f"cybersec_sessions_active {sessions_active}",
        f"cybersec_sessions_expired {sessions_expired}",
        f"cybersec_db_size_bytes {db_size}",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        n = c(f"SELECT COUNT(*) c FROM alerts WHERE severity = ? AND status IN {_OPEN_ALERT_SQL}", (sev,))
        lines.append(f'cybersec_alerts_open{{severity="{sev}"}} {n}')
        total = c("SELECT COUNT(*) c FROM alerts WHERE severity = ?", (sev,))
        lines.append(f'cybersec_alerts_total{{severity="{sev}"}} {total}')
    return Response("\n".join(lines) + "\n", media_type="text/plain; charset=utf-8")
