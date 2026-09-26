#!/usr/bin/env python3
"""Print the platform's own self-diagnosis (SEC-116) from a shell.

`GET /api/admin/doctor` aggregates eleven checks into one verdict; this is the
operator-facing reader for it, so `make doctor` does not mean "log in with curl and
pipe through jq".

Credentials come from CYBERSEC_USER / CYBERSEC_PASSWORD and default to the documented
synthetic lab account. Nothing is printed from the credential values.

    python -m scripts.doctor_report [--base-url http://127.0.0.1:8080] [--json]

Exit codes: 0 verdict ok · 1 verdict warn · 2 verdict fail or unreachable.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

MARK = {"ok": "  ok ", "warn": " WARN", "fail": " FAIL"}


def _request(base: str, method: str, path: str, body: dict | None = None,
             cookie: str | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data:
        req.add_header("content-type", "application/json")
    if cookie:
        req.add_header("cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            token = next((c.split(";", 1)[0] for c in (r.headers.get_all("set-cookie") or [])
                          if c.startswith("cybersec_token=")), None)
            return r.status, json.loads(r.read()), token
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read()), None
        except Exception:  # noqa: BLE001
            return e.code, None, None
    except Exception as e:  # noqa: BLE001
        return None, {"error": str(e)}, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=os.environ.get("CYBERSEC_URL", "http://127.0.0.1:8080"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    status, body, cookie = _request(base, "POST", "/api/auth/login", {
        "username": os.environ.get("CYBERSEC_USER", "admin"),
        "password": os.environ.get("CYBERSEC_PASSWORD", "CyberSecAdmin1!")})
    if status != 200 or not cookie:
        detail = (body or {}).get("detail") if isinstance(body, dict) else body
        print(f"login failed ({status}): {detail} — set CYBERSEC_USER/CYBERSEC_PASSWORD")
        return 2

    status, report, _ = _request(base, "GET", "/api/admin/doctor", cookie=cookie)
    if status != 200 or not isinstance(report, dict) or "verdict" not in report:
        print(f"doctor unreachable ({status}): {report}")
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"CYBER-SEC doctor @ {base} · env {report['env']} · "
              f"v{report.get('version') or '?'} · {report['generated_at']}")
        print(f"verdict: {report['verdict'].upper()}  "
              f"({report['summary']['ok']} ok, {report['summary']['warn']} warn, "
              f"{report['summary']['fail']} fail)\n")
        for check in report["checks"]:
            print(f"[{MARK.get(check['status'], check['status'])}] {check['check']}")
            print(f"        {json.dumps(check['detail'], default=str)}")
            if check["status"] != "ok" and check.get("fix_hint"):
                print(f"        -> {check['fix_hint']}")
        print(f"\n{report['note']}")
    return {"ok": 0, "warn": 1, "fail": 2}.get(report["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
