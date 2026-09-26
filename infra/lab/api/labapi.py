"""`lab-api-01` — the range's intentionally broken REST API (SEC-115).

Deliberately vulnerable, deliberately tiny, and deliberately obvious: three
classic mistakes that the platform's own tooling can then be exercised against
(IDOR, missing authorization on an admin route, and a debug endpoint that leaks
the signing key). It exists so an exercise has a target that is *ours* — no
third-party image, no network dependency beyond the base Python image.

**It is not a product.** It has no tests, no dependencies beyond the standard
library, and one purpose: to be wrong in a way a trainee can find and a
platform can record. Never expose it beyond the lab network
(`infra/lab/docker-compose.yml` publishes it to 127.0.0.1 only).

Endpoints:
    GET  /api/users/{id}          -- returns any user (no ownership check: IDOR)
    GET  /api/admin/config        -- admin configuration (no authorization check)
    GET  /api/debug               -- environment dump incl. a fake signing key
    POST /api/login               -- trivial token issuing
"""
from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

USERS = {
    1: {"id": 1, "username": "trainee", "role": "user", "email": "trainee@lab.test"},
    2: {"id": 2, "username": "manager", "role": "user", "email": "manager@lab.test"},
    3: {"id": 3, "username": "admin", "role": "admin", "email": "admin@lab.test"},
}
ADMIN_CONFIG = {
    "signing_key": "lab-only-signing-key-do-not-use",
    "templates_dir": "/srv/app/templates",
    "feature_flags": {"debug_uploads": True},
}


class Handler(BaseHTTPRequestHandler):
    server_version = "lab-api/0.1"

    def _json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        path = urlparse(self.path).path.rstrip("/")
        if path.startswith("/api/users/"):
            try:
                uid = int(path.rsplit("/", 1)[1])
            except ValueError:
                return self._json({"error": "bad id"}, 400)
            user = USERS.get(uid)
            # Vulnerability 1 (IDOR): any caller reads any user. There is no
            # token check *and* no ownership check — both are the point.
            if not user:
                return self._json({"error": "not found"}, 404)
            return self._json({"user": user, "authorization": "none required (lab)"})
        if path == "/api/admin/config":
            # Vulnerability 2: an "admin" route with no authorization at all.
            return self._json({"config": ADMIN_CONFIG, "authorization": "none required (lab)"})
        if path == "/api/debug":
            # Vulnerability 3: debug endpoint leaking the environment.
            return self._json({"env": dict(os.environ), "note": "lab debug endpoint"})
        if path == "/api/health":
            return self._json({"ok": True, "target": "lab-api-01"})
        return self._json({"error": "not found", "endpoints": [
            "/api/users/{id}", "/api/admin/config", "/api/debug", "/api/health"]}, 404)

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        path = urlparse(self.path).path.rstrip("/")
        if path == "/api/login":
            length = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return self._json({"error": "bad json"}, 400)
            # Vulnerability 0: any password works, and the token is a constant.
            return self._json({"token": "lab-token", "role": USERS[1]["role"],
                               "note": "any credentials are accepted (lab)"})
        return self._json({"error": "not found"}, 404)

    def log_message(self, fmt: str, *args) -> None:  # keep the container quiet
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description="intentionally vulnerable lab API target")
    ap.add_argument("--port", type=int, default=8001)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    print(f"lab-api-01 listening on {args.host}:{args.port} (intentionally vulnerable)")
    HTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
