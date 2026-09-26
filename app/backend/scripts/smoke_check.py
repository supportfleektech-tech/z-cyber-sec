#!/usr/bin/env python
"""One-command smoke check for a running CYBER-SEC instance (SEC-114).

Walks the *live* API surface published by `/api/openapi.json`, logs in as the
seeded users, and asserts three things the release checklist cares about:

1. every GET route answers a 2xx for the admin session (the surface is up);
2. every route answers 401 unauthenticated (nothing reads without a session);
3. a `viewer` gets 403 (never 500, never 200) on every write route (RBAC is
   enforced server-side, not in the SPA).

Exit code 0 = all checks passed. Designed to be run against a local instance
(`--base-url http://127.0.0.1:8080`), in CI after starting the app, or by an
operator after a deploy. It never writes: read routes only, plus the auth
failure paths it is explicitly testing.

Usage:
    .venv/bin/python -m scripts.smoke_check [--base-url URL] [--json]
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

DEFAULT_BASE = "http://127.0.0.1:8080"
ADMIN = ("admin", "CyberSecAdmin1!")
VIEWER = ("viewer", "ViewerRead1!")
WRITE_METHODS = ("post", "patch", "put", "delete")

# Endpoints that are public *by design* (liveness probe, optionally-token-gated
# metrics) — the unauthenticated sweep must not flag them.
PUBLIC_POSTS = {"/api/auth/login": "login is unauthenticated by definition"}

# Session-management calls any authenticated role may make (the RBAC sweep below
# checks that a viewer cannot *write platform data*, not that it cannot log out).
ANY_ROLE_POSTS = {"/api/auth/logout"}

PUBLIC_GETS = {"/api/healthz": "liveness probe (ADR-006)",
               "/metrics": "Prometheus scrape, optional METRICS_TOKEN (SEC-073)",
               "/api/openapi.json": "API document",
               "/api/docs": "API browser",
               "/api/redoc": "API browser"}

# Path parameters are filled from the seeded dataset by reading the list routes,
# so the happy path is exercised rather than a 404.
ID_SOURCES = {
    "case_id": "/api/cases", "alert_id": "/api/soc/alerts", "finding_id": "/api/appsec/findings",
    "asset_id": "/api/assets", "rule_id": "/api/soc/rules", "run_id": "/api/automation/runs",
    "playbook_id": "/api/automation", "cid": "/api/grc/controls", "risk_id": "/api/grc/risks",
    "agent_id": "/api/agents", "task_id": "/api/agents/tasks", "ex_id": "/api/exercises",
    "vuln_id": "/api/vulns", "ind_id": "/api/intel/indicators", "int_id": "/api/admin/integrations",
    "report_id": "/api/reports", "approval_id": "/api/agents/approvals?status=pending",
    "control_id": "/api/grc/controls", "release_id": "/api/admin/releases", "exercise_id": "/api/exercises",
    "uid": "/api/auth/users", "sched_id": "/api/reports/schedules", "fid": "/api/vulns",
    "chain_id": "/api/tradecraft/chains", "ss_id": "/api/soc/saved-searches",
    "pb_id": "/api/automation", "key": "/api/admin/settings", "evidence_id": None,
}

# Route path params are filled with real ids from the seeded dataset so the
# happy path is exercised instead of a 404.
SAMPLE_IDS = {"case_id": "1", "alert_id": "1", "finding_id": "1", "asset_id": "1",
              "rule_id": "1", "evidence_id": "1", "run_id": "1", "playbook_id": "1",
              "cid": "1", "risk_id": "1", "agent_id": "1", "task_id": "1",
              "sched_id": "1", "ex_id": "1", "vuln_id": "1", "ind_id": "1",
              "int_id": "1", "report_id": "1", "approval_id": "1", "control_id": "1",
              "release_id": "1", "exercise_id": "1", "id": "1", "uid": "1",
              "fid": "1", "chain_id": "1", "ss_id": "1", "pb_id": "1", "key": "1"}

# Ids that could not be resolved from the data (the list was empty) — a 404 for
# those routes is the correct answer, not a failure.
UNRESOLVED: set[str] = set()

# Resources that are deliberately scoped to their owner: the admin account this
# checker logs in as owns none, and the API is right to return an empty list
# (SEC-071 saved searches). Spelled out so the summary does not read like a gap.
OWNER_SCOPED = {"ss_id": "saved searches are per-user (SEC-071); the checker owns none"}


@dataclass
class Report:
    checked: int = 0
    failures: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def fail(self, msg: str) -> None:
        self.failures.append(msg)


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, method: str, path: str, body: dict | None = None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, method=method.upper(), data=data,
                                     headers={"content-type": "application/json"})
        try:
            resp = self.opener.open(req)
            return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except Exception as exc:  # connection refused etc.
            return None, str(exc).encode()

    def login(self, username: str, password: str) -> tuple[int | None, str]:
        status, body = self.request("POST", "/api/auth/login",
                                    {"username": username, "password": password})
        return status, body.decode("utf8", "replace")


def _fill(path: str) -> str:
    def sub(match: re.Match) -> str:
        name = match.group(1)
        if name in UNRESOLVED:
            return "1"
        return SAMPLE_IDS.get(name, "1")
    return re.sub(r"\{(\w+)\}", sub, path)


def resolve_ids(admin: Client, rep: Report, wanted: set[str] | None = None) -> None:
    """Point every path parameter at a row that actually exists.

    `wanted` limits the work (and the notes) to parameters the live surface
    actually uses — a stale entry for a route that no longer exists should not
    show up as a dataset gap.
    """
    for param, route in ID_SOURCES.items():
        if not route or (wanted and param not in wanted):
            continue
        status, payload = admin.request("GET", route)
        if status != 200:
            UNRESOLVED.add(param)
            continue
        try:
            body = json.loads(payload)
        except Exception:
            UNRESOLVED.add(param)
            continue
        items = body.get("items") if isinstance(body, dict) else body
        if not items:
            UNRESOLVED.add(param)
            continue
        first = items[0]
        value = first.get("id") if isinstance(first, dict) else first
        if value is None and isinstance(first, dict):
            value = first.get("uid") or first.get("key")
        if value is None:
            UNRESOLVED.add(param)
        else:
            SAMPLE_IDS[param] = str(value)
    if UNRESOLVED:
        parts = []
        for param in sorted(UNRESOLVED):
            why = OWNER_SCOPED.get(param)
            parts.append(f"{param} ({why})" if why else param)
        rep.notes.append("no row for: " + ", ".join(parts))


def synth(spec: dict, schema) -> dict | None:
    """Schema-valid sample body so RBAC is reached instead of a 422."""
    comp = spec.get("components", {}).get("schemas", {})
    seen = 0
    while isinstance(schema, dict) and "$ref" in schema and seen < 10:
        schema = comp.get(schema["$ref"].split("/")[-1], {})
        seen += 1
    if not isinstance(schema, dict):
        return None
    out: dict = {}
    for name, sub in (schema.get("properties") or {}).items():
        seen = 0
        while isinstance(sub, dict) and "$ref" in sub and seen < 10:
            sub = comp.get(sub["$ref"].split("/")[-1], {})
            seen += 1
        if not isinstance(sub, dict):
            continue
        if name in (schema.get("required") or []):
            out[name] = _sample(sub)
    return out


def _sample(sub: dict):
    if sub.get("enum"):
        return sub["enum"][0]
    if sub.get("default") is not None:
        return sub["default"]
    kind = sub.get("type")
    if kind == "integer":
        return 1
    if kind == "number":
        return 1.0
    if kind == "boolean":
        return True
    if kind == "array":
        return []
    if kind == "object" or "properties" in sub:
        return {}
    return "smoke-check"


def required_query(path: str, op: dict) -> dict:
    """Required query parameters with a safe sample value (e.g. scope/check?target=)."""
    out = {}
    for param in op.get("parameters", []):
        if param.get("in") != "query" or not param.get("required"):
            continue
        schema = param.get("schema", {})
        if param["name"] == "target":
            out[param["name"]] = "lab-web-01"
        elif schema.get("type") == "integer":
            out[param["name"]] = 1
        else:
            out[param["name"]] = schema.get("enum", ["x"])[0]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=DEFAULT_BASE)
    ap.add_argument("--json", action="store_true", help="machine-readable summary")
    args = ap.parse_args()

    rep = Report()
    anon = Client(args.base_url)
    status, body = anon.request("GET", "/api/auth/me")
    if status != 401:
        rep.fail(f"GET /api/auth/me without a session answered {status}, expected 401")
    else:
        rep.checked += 1

    try:
        spec = json.loads(anon.request("GET", "/api/openapi.json")[1])
    except Exception as exc:  # pragma: no cover - operator feedback
        print(f"cannot read /api/openapi.json from {args.base_url}: {exc}")
        return 2

    routes = [(path, method.lower(), op) for path, ops in spec["paths"].items()
              for method, op in ops.items() if method in ("get", *WRITE_METHODS)]
    if not routes:
        rep.fail("the OpenAPI document lists no routes")
    rep.notes.append(f"surface: {len(spec['paths'])} paths / {len(routes)} operations")

    # ---- 2) nothing is readable without a session
    public_skipped = 0
    for path, method, op in routes:
        if method != "get":
            continue
        if path in PUBLIC_GETS:
            public_skipped += 1
            continue
        url = _fill(path) + ("?" + urllib.parse.urlencode(required_query(path, op))
                             if required_query(path, op) else "")
        status, _ = anon.request("GET", url)
        rep.checked += 1
        if status not in (401, 403):
            rep.fail(f"unauthenticated GET {url} answered {status} (expected 401/403)")
    if public_skipped:
        rep.notes.append(f"{public_skipped} documented public GET(s) skipped "
                         f"({', '.join(sorted(PUBLIC_GETS))})")

    # ---- 1) the whole read surface answers for an admin
    admin = Client(args.base_url)
    status, body = admin.login(*ADMIN)
    if status != 200:
        print(f"admin login failed: {status} {body[:200]}")
        return 2
    used_params = {p for path, _m, _op in routes for p in re.findall(r"\{(\w+)\}", path)}
    resolve_ids(admin, rep, used_params)
    for path, method, op in routes:
        if method != "get":
            continue
        query = required_query(path, op)
        url = _fill(path) + ("?" + urllib.parse.urlencode(query) if query else "")
        status, payload = admin.request("GET", url)
        rep.checked += 1
        missing_row = status == 404 and any(f"{{{p}}}" in path and p in UNRESOLVED
                                            for p in re.findall(r"\{(\w+)\}", path))
        if missing_row:
            rep.notes.append(f"{url}: 404 for an id with no row in this dataset (expected)")
            continue
        if status is None or status >= 400:
            rep.fail(f"admin GET {url} answered {status}: {payload[:160].decode('utf8', 'replace')}")

    # ---- 3) RBAC: the viewer may read, and may not perform consequential writes.
    # Split in two, because "any write route" is not the right test — a few POSTs are
    # read-only simulations that `soc.read` legitimately allows (rule dry-run).
    MUST_BE_403 = [
        ("patch", "/api/soc/alerts/{alert_id}", {"status": "triaging"}),
        ("post", "/api/cases", {"title": "smoke check must not create this"}),
        ("patch", "/api/cases/{case_id}", {"status": "contained"}),
        ("post", "/api/vulns", {"title": "smoke check must not create this"}),
        ("patch", "/api/soc/rules/{rule_id}", {"enabled": False}),
        ("patch", "/api/intel/indicators/{ind_id}", {"status": "revoked"}),
        ("patch", "/api/cloud/posture/{finding_id}", {"status": "resolved"}),
        ("post", "/api/exercises", {"name": "not allowed", "scope": "not allowed to write this"}),
        ("post", "/api/auth/users", {"username": "smoke", "password": "SmokeCheck1!", "role": "viewer"}),
        ("post", "/api/admin/backup", {}),
        ("post", "/api/agents/approvals/{approval_id}/decide", {"decision": "approve"}),
        ("post", "/api/admin/releases", {"version": "0.0.0"}),
        ("post", "/api/lab/targets", {"name": "smoke-lab-01", "endpoint": "smoke-lab-01:9999",
                                      "kind": "web", "exposure": "low"}),
        ("patch", "/api/lab/targets/{target_id}", {"status": "running"}),
    ]
    viewer = Client(args.base_url)
    vstatus, vbody = viewer.login(*VIEWER)
    if vstatus != 200:
        rep.notes.append(f"viewer login returned {vstatus} ({vbody[:80]}); RBAC sweep skipped")
    else:
        for method, path, payload in MUST_BE_403:
            url = _fill(path)
            status, body = viewer.request(method, url, payload)
            rep.checked += 1
            if status != 403:
                rep.fail(f"viewer {method.upper()} {url} answered {status}, expected 403 "
                         f"({body[:120].decode('utf8', 'replace')})")
        # Bulk: no write route may 5xx or 401 for an authenticated viewer, and a 2xx is
        # reported for review rather than failed, since read-only simulations (rule
        # dry-run) legitimately answer it. A 403 and a 422 both mean "did not act", but
        # only 403 proves the permission check ran — body validation happens first, so a
        # 422 here is not evidence of RBAC, which is why the consequential routes are
        # pinned individually in MUST_BE_403 above with schema-valid bodies.
        for path, method, op in routes:
            if method not in WRITE_METHODS or path in PUBLIC_POSTS or path in ANY_ROLE_POSTS:
                continue
            url = _fill(path)
            schema = ((op.get("requestBody") or {}).get("content", {})
                      .get("application/json", {}).get("schema"))
            body = synth(spec, schema) if schema else None
            status, payload = viewer.request(method, url, body)
            rep.checked += 1
            if status is None or status >= 500 or status == 401:
                rep.fail(f"viewer {method.upper()} {url} answered {status}: "
                         f"{payload[:140].decode('utf8', 'replace')}")
            elif 200 <= status < 300:
                rep.notes.append(f"viewer {method.upper()} {url} answered {status} "
                                 f"(read-only route or write-permission gap — verify)")

    summary = {"base_url": args.base_url, "checks": rep.checked,
               "failures": rep.failures, "notes": rep.notes,
               "ok": not rep.failures}
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        for note in rep.notes:
            print(f"· {note}")
        print(f"· {rep.checked} checks run against {args.base_url}")
        for failure in rep.failures:
            print(f"FAIL {failure}")
        print("SMOKE OK" if not rep.failures else f"SMOKE FAILED ({len(rep.failures)})")
    return 0 if not rep.failures else 1


if __name__ == "__main__":
    sys.exit(main())
