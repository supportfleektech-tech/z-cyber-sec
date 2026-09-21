"""Report generation with full provenance (docs/04, acceptance criteria).

Every report embeds: generator, actor, timestamp, filters, input row counts,
sha256 of the input snapshot, and the environment/demo label. Reports are
written to data/reports (0600) and only served through the API with the
reports.download-equivalent permission (reports.read for admin/ir_lead via
their role; others 403).
"""
from __future__ import annotations

import hashlib
import json

from jinja2 import BaseLoader, Environment
from markupsafe import escape

from .. import db
from ..audit import record_audit
from ..config import settings

_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{{ title }} — CYBER-SEC ({{ env_name }})</title>
<style>
 body{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0b0f14;color:#d7e0ea;margin:0;padding:24px}
 h1{font-size:20px} h2{font-size:15px;margin-top:28px;border-bottom:1px solid #24344d;padding-bottom:4px}
 table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
 th,td{border:1px solid #24344d;padding:5px 8px;text-align:left}
 th{background:#111a26}
 .badge{display:inline-block;padding:1px 8px;border-radius:8px;font-size:11px;font-weight:600}
 .critical{background:#3b1120;color:#ff8fa3}.high{background:#3a1d12;color:#ffb27d}
 .medium{background:#3a3312;color:#ffe08a}.low{background:#12303a;color:#8fd3ff}
 .info{background:#1d2740;color:#a8c3ff}
 .prov{background:#111a26;border:1px solid #24344d;padding:10px;font-size:11px;margin-top:24px}
 .demo{background:#2a1a3a;color:#d9a8ff;padding:1px 8px;border-radius:8px;font-size:11px}
</style></head><body>
<h1>🛡 {{ title }} <span class="badge info">{{ env_name }}</span>{% if synthetic %} <span class="demo">SYNTHETIC DATA</span>{% endif %}</h1>
<p>Generated {{ generated_at }} by {{ generated_by }} — filters: <code>{{ filters }}</code></p>
{% block body %}{{ body_html | safe }}{% endblock %}
<div class="prov"><b>Provenance</b><br>
input_rows: {{ meta.input_rows }}<br>
input_sha256: <code>{{ meta.input_sha256 }}</code><br>
generator: {{ meta.generator }}<br>
environment: {{ env_name }} — local-first lab; no production data.<br>
All records carry data_class labeling; demo fixtures are synthetic.
</div></body></html>"""


class ReportBuilder:
    def __init__(self, conn):
        self.conn = conn

    def _snap(self, *queries: str) -> tuple[int, str]:
        h = hashlib.sha256()
        rows = 0
        for sql in queries:
            rs = db.q(self.conn, sql)
            rows += len(rs)
            h.update(json.dumps(rs, default=str, sort_keys=True).encode())
        return rows, h.hexdigest()

    def _write(self, kind: str, title: str, generated_by: str, filters: dict,
               body_html: str) -> dict:
        env = Environment(loader=BaseLoader(), autoescape=True)
        tpl = env.from_string(_TEMPLATE)
        rows, sha = self._snap(
            "SELECT id FROM alerts", "SELECT id FROM cases", "SELECT id FROM events"
        )
        report_id = _next_id(self.conn, "reports")
        path = settings.reports_dir / f"{kind}-{report_id}.html"
        html = tpl.render(
            title=title, env_name=settings.env_name, synthetic=settings.env_name != "PROD",
            generated_at=db.utcnow(), generated_by=generated_by,
            filters=json.dumps(filters, sort_keys=True),
            meta={"input_rows": rows, "input_sha256": sha, "generator": "cybersec/report.py@v1"},
            body_html=body_html,
        )
        path.write_text(html)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        self.conn.execute(
            "INSERT INTO reports (id, kind, title, filters, generated_by, created_at, path, meta) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (report_id, kind, title, db.jdump(filters), generated_by, db.utcnow(), str(path),
             db.jdump({"input_rows": rows, "input_sha256": sha})),
        )
        self.conn.commit()
        record_audit(self.conn, {"type": "user", "id": generated_by, "name": generated_by},
                     "report.generated", target_type="report", target_id=str(report_id),
                     detail={"kind": kind, "input_rows": rows})
        return {"id": report_id, "path": str(path), "input_rows": rows, "input_sha256": sha}

    # ------------------------------------------------------------ report kinds

    def build(self, kind: str, filters: dict, actor: str) -> dict:
        if kind == "overview":
            return self._overview(actor, filters)
        if kind == "soc":
            return self._soc(actor, filters)
        if kind == "cases":
            return self._cases(actor, filters)
        if kind == "intel":
            return self._intel(actor, filters)
        if kind == "vulns":
            return self._vulns(actor, filters)
        raise ValueError(f"unknown report kind: {kind}")

    def _overview(self, actor, filters):
        by_sev = db.q(self.conn, "SELECT severity, COUNT(*) c FROM alerts GROUP BY severity")
        by_status = db.q(self.conn, "SELECT status, COUNT(*) c FROM cases GROUP BY status")
        counts = {
            "events": _count(self.conn, "SELECT COUNT(*) c FROM events"),
            "alerts": _count(self.conn, "SELECT COUNT(*) c FROM alerts"),
            "cases": _count(self.conn, "SELECT COUNT(*) c FROM cases"),
            "indicators": _count(self.conn, "SELECT COUNT(*) c FROM threat_indicators"),
            "vulns": _count(self.conn, "SELECT COUNT(*) c FROM vuln_findings"),
            "open_vulns": _count(self.conn, "SELECT COUNT(*) c FROM vuln_findings WHERE status IN ('new','triaged','in_progress')"),
        }
        body = _kv_table("Counts", counts) + _sev_table("Alerts by severity", by_sev) \
            + _kv_table("Cases by status", {r["status"]: r["c"] for r in by_status})
        return self._write("overview", "CYBER-SEC Overview", actor, filters, body)

    def _soc(self, actor, filters):
        sev = filters.get("severity")
        rows = db.q(self.conn,
                    "SELECT a.title, r.name AS rule, a.severity, a.status, a.count, a.first_seen, a.assigned_to "
                    "FROM alerts a LEFT JOIN detection_rules r ON r.id = a.rule_id "
                    + ("WHERE a.severity = ?" if sev else "") + " ORDER BY a.first_seen DESC LIMIT 200",
                    (sev,) if sev else ())
        body = _alerts_table("Alerts", rows)
        return self._write("soc", f"SOC Alert Report{f' ({sev})' if sev else ''}", actor, filters, body)

    def _cases(self, actor, filters):
        st = filters.get("status")
        rows = db.q(self.conn,
                    "SELECT number, title, status, priority, severity, assigned_to, created_at, closed_at "
                    "FROM cases" + (" WHERE status = ?" if st else "") + " ORDER BY created_at DESC LIMIT 200",
                    (st,) if st else ())
        body = _cases_table("Cases", rows)
        return self._write("cases", f"Case Report{f' ({st})' if st else ''}", actor, filters, body)

    def _intel(self, actor, filters):
        rows = db.q(self.conn,
                    "SELECT i.type, i.value, i.confidence, s.name AS source, i.status, i.mitre_tactics "
                    "FROM threat_indicators i LEFT JOIN intel_sources s ON s.id = i.source_id "
                    "ORDER BY i.confidence DESC LIMIT 200")
        body = _intel_table("Indicators", rows)
        return self._write("intel", "Threat Intel Report", actor, filters, body)

    def _vulns(self, actor, filters):
        rows = db.q(self.conn,
                    "SELECT v.cve_id, v.title, v.severity, v.status, v.cvss, a.name AS asset, v.due_date "
                    "FROM vuln_findings v LEFT JOIN assets a ON a.id = v.asset_id "
                    "ORDER BY v.cvss DESC LIMIT 200")
        body = _vulns_table("Vulnerabilities", rows)
        return self._write("vulns", "Vulnerability Report", actor, filters, body)


def _next_id(conn, table: str) -> int:
    r = db.one(conn, f"SELECT COALESCE(MAX(id), 0) + 1 AS n FROM {table}")
    return int(r["n"])


def _count(conn, sql: str) -> int:
    r = db.one(conn, sql)
    return int(r["c"]) if r else 0


def _esc(v) -> str:
    """Escape DB values for safe HTML embedding (reports are static files)."""
    return str(escape(str(v))) if v is not None else "—"


def _badge(sev: str | None) -> str:
    s = (sev or "info").lower()
    return f'<span class="badge {escape(s)}">{escape(s)}</span>'


def _kv_table(title: str, kv: dict) -> str:
    rows = "".join(f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in kv.items())
    return f"<h2>{_esc(title)}</h2><table>{rows}</table>"


def _sev_table(title: str, rows: list) -> str:
    body = "".join(f"<tr><td>{_badge(r['severity'])}</td><td>{_esc(r['c'])}</td></tr>" for r in rows)
    return f"<h2>{_esc(title)}</h2><table><tr><th>Severity</th><th>Count</th></tr>{body}</table>"


def _alerts_table(title: str, rows: list) -> str:
    body = "".join(
        f"<tr><td>{_esc(r['title'])}</td><td>{_esc(r['rule'])}</td><td>{_badge(r['severity'])}</td>"
        f"<td>{_esc(r['status'])}</td><td>{_esc(r['count'])}</td><td>{_esc(r['first_seen'])}</td>"
        f"<td>{_esc(r['assigned_to'])}</td></tr>"
        for r in rows)
    return (f"<h2>{_esc(title)}</h2><table><tr><th>Alert</th><th>Rule</th><th>Severity</th><th>Status</th>"
            f"<th>Count</th><th>First seen</th><th>Assignee</th></tr>{body}</table>")


def _cases_table(title: str, rows: list) -> str:
    body = "".join(
        f"<tr><td>{_esc(r['number'])}</td><td>{_esc(r['title'])}</td><td>{_esc(r['status'])}</td>"
        f"<td>{_badge(r['priority'])}</td><td>{_badge(r['severity'])}</td><td>{_esc(r['assigned_to'])}</td>"
        f"<td>{_esc(r['created_at'])}</td><td>{_esc(r['closed_at'])}</td></tr>" for r in rows)
    return (f"<h2>{_esc(title)}</h2><table><tr><th>Case</th><th>Title</th><th>Status</th><th>Priority</th>"
            f"<th>Severity</th><th>Assignee</th><th>Created</th><th>Closed</th></tr>{body}</table>")


def _intel_table(title: str, rows: list) -> str:
    body = "".join(
        f"<tr><td>{_esc(r['type'])}</td><td><code>{_esc(r['value'])}</code></td><td>{_esc(r['confidence'])}</td>"
        f"<td>{_esc(r['source'])}</td><td>{_esc(r['status'])}</td><td>{_esc(r['mitre_tactics'])}</td></tr>" for r in rows)
    return (f"<h2>{_esc(title)}</h2><table><tr><th>Type</th><th>Value</th><th>Confidence</th>"
            f"<th>Source</th><th>Status</th><th>MITRE tactics</th></tr>{body}</table>")


def _vulns_table(title: str, rows: list) -> str:
    body = "".join(
        f"<tr><td>{_esc(r['cve_id'])}</td><td>{_esc(r['title'])}</td><td>{_badge(r['severity'])}</td>"
        f"<td>{_esc(r['status'])}</td><td>{_esc(r['cvss'])}</td><td>{_esc(r['asset'])}</td><td>{_esc(r['due_date'])}</td></tr>"
        for r in rows)
    return (f"<h2>{_esc(title)}</h2><table><tr><th>CVE</th><th>Title</th><th>Severity</th><th>Status</th>"
            f"<th>CVSS</th><th>Asset</th><th>Due</th></tr>{body}</table>")
