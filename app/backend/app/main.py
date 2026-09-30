"""CYBER-SEC platform — modular monolith entrypoint (ADR-001).

Single process: FastAPI API + static frontend + embedded telemetry.
Run:  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from .config import settings
from .db import raw_connection
from .middleware import ForwardedHeadersMiddleware
from .routers import (
    admin,
    agents,
    appsec,
    assets,
    auth,
    automation,
    cases,
    cloud,
    exercises,
    grc,
    intel,
    lab,
    overview,
    reports,
    soc,
    tradecraft,
    vulns,
)
from .security import COOKIE_NAME

API_ROUTERS = [
    overview.router, auth.router, soc.router, cases.router, intel.router, vulns.router,
    appsec.router, cloud.router, grc.router, exercises.router, agents.router,
    automation.router, reports.router, admin.router, assets.router,
    tradecraft.router, lab.router,
]


# SEC-117: the SPA is a Vite build served by this process, so the policy can be
# tight — no inline scripts, no external origins, no framing. `style-src
# 'unsafe-inline'` is required by the bundled component styles (a nonce would mean
# rewriting the build); everything else is `'self'`.
_CSP_COMMON = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
               "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
               "object-src 'none'; base-uri 'self'; form-action 'self'")
# SEC-124: STAGING/PROD refuse framing outright. A lab-like environment must allow it:
# a hosted preview shows this app inside someone else's page, and `frame-ancestors 'none'`
# (or X-Frame-Options: DENY) blanks that preview — the app then "does not work" for the
# only person looking at it. The CSP for lab-like environments simply omits the directive.
# Lab-like: no frame-ancestors directive at all — the ancestor is the preview host, not
# this app, so any listed value ('self', a scheme) would still blank the preview.
# STAGING/PROD: refused outright.
_CSP_FRAMED = _CSP_COMMON
_CSP_NO_FRAMING = _CSP_COMMON + "; frame-ancestors 'none'"


def create_app() -> FastAPI:
    app = FastAPI(title="CYBER-SEC", version="1.0.0",
                  description="Local-first cybersecurity lab & operations platform. "
                              "Synthetic data by default; environment labeled.",
                  docs_url="/api/docs", openapi_url="/api/openapi.json")

    # One terminating proxy hop (Caddy, SEC-061): forwarded headers make the
    # scheme https (Secure session cookie) and the client IP real (login
    # attribution). Locally (no proxy) headers are absent → unchanged.
    app.add_middleware(ForwardedHeadersMiddleware)

    app.add_middleware(
        CORSMiddleware,
        # SEC-124c: an embedded preview may make the app cross-origin. STAGING/PROD allow
        # only the configured dev origin; lab-like environments reflect whatever origin
        # the preview uses (including `null` from a sandboxed frame), because the whole
        # point of a lab is that it can be looked at from somewhere else. Credentials are
        # on, so the session cookie travels and is accepted when the request is cross-site.
        allow_origins=[settings.dev_origin] if settings.dev_origin and
        settings.env_name in ("STAGING", "PROD") else [],
        allow_origin_regex=None if settings.env_name in ("STAGING", "PROD") else ".*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        # SEC-080: docs/12 promises every non-2xx body carries
        # `detail = {code, message}` with stable codes, and the SPA renders that
        # shape. FastAPI's default 422 body is a bare list, so a client written
        # against the documented contract read `detail.message` as undefined.
        # Keep 422 (the status is right) but wrap it: the field-level detail is
        # preserved under `errors`, and `message` is human-readable.
        items = []
        for e in exc.errors():
            loc = ".".join(str(x) for x in e.get("loc", ()) if x not in ("body", "query", "path"))
            items.append({"field": loc or "(body)", "msg": e.get("msg", "invalid"),
                          "type": e.get("type", "value_error")})
        summary = "; ".join(f"{i['field']}: {i['msg']}" for i in items[:3])
        if len(items) > 3:
            summary += f" (+{len(items) - 3} more)"
        return JSONResponse(status_code=422,
                            content={"detail": {"code": "invalid_request",
                                                "message": summary or "Invalid request.",
                                                "errors": items}})

    @app.exception_handler(sqlite3.IntegrityError)
    async def integrity_violation(request: Request, exc: sqlite3.IntegrityError):
        # SEC-109: three live writes (a null into a NOT NULL column on
        # intel/cloud-posture, an asset_id of 0 that skipped its existence check and
        # then failed the foreign key) answered an opaque 500 for what is a bad
        # request the API can describe. Translate the constraint into the documented
        # {code, message} envelope; never echo the SQL or the table name.
        raw = str(exc)
        detail = raw.split(":", 1)[1].strip() if ":" in raw else ""
        fields = [f.rsplit(".", 1)[-1].strip() for f in detail.split(",") if f.strip()]
        if raw.startswith("NOT NULL"):
            code, status, msg = "missing_field", 400, "This field must not be null."
        elif raw.startswith("FOREIGN KEY"):
            code, status, msg = "bad_reference", 400, "A referenced row does not exist."
        elif raw.startswith("UNIQUE"):
            code, status, msg = "duplicate", 409, "A row with this value already exists."
        elif raw.startswith("CHECK"):
            code, status, msg = "constraint_violation", 400, "The value fails a data constraint."
        else:
            code, status, msg = "constraint_violation", 400, "The request violates a data constraint."
        return JSONResponse(status_code=status,
                            content={"detail": {"code": code, "message": msg,
                                                "fields": fields}})

    @app.exception_handler(OverflowError)
    async def out_of_range(request: Request, exc: OverflowError):
        # SEC-108: a query parameter is validated as a Python int, but Python ints are
        # unbounded while SQLite's are 64-bit — `?agent_id=999…` reached the driver and
        # answered an opaque 500. It is a client error: state the bound.
        return JSONResponse(status_code=422,
                            content={"detail": {
                                "code": "value_out_of_range",
                                "message": (f"a numeric parameter exceeds the supported range "
                                            f"(|value| <= {2**63 - 1})"),
                                "errors": [{"field": "(query)", "msg": str(exc)[:200],
                                            "type": "value_out_of_range"}]}})

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        # Never leak stack traces or SQL into responses.
        return JSONResponse(status_code=500,
                            content={"detail": {"code": "internal_error",
                                                "message": "Unexpected server error (see server logs)."}})

    @app.middleware("http")
    async def env_banner(request: Request, call_next):
        response = await call_next(request)
        # Distinguish lab from production at the HTTP edge (risk R-09).
        if settings.env_name != "PROD":
            response.headers["X-Environment"] = settings.env_name
            response.headers["X-Data-Class"] = "synthetic-by-default"
        # SEC-117: the baseline hardening headers belong in the application, not
        # only in the Caddyfile. A deployment that skips the edge (an internal
        # operator host, a staging stack behind someone else's proxy, `uvicorn`
        # started by hand) otherwise serves the SPA with no framing, MIME-sniffing
        # or referrer policy at all. The edge may override these; it can no longer
        # be the only place they exist.
        lab_like = settings.env_name not in ("STAGING", "PROD")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        if not lab_like:
            response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy",
                                    _CSP_FRAMED if lab_like else _CSP_NO_FRAMING)
        response.headers.setdefault("Permissions-Policy",
                                    "geolocation=(), camera=(), microphone=(), payment=()")
        # HSTS is meaningful only over TLS: sending it from a plain-HTTP lab would
        # pin browsers to https for the loopback host and break the local preview.
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security",
                                        "max-age=31536000; includeSubDomains")
        return response

    @app.middleware("http")
    async def auth_transport_log(request: Request, call_next):
        """Log what the browser actually sent on the auth surface (SEC-124c).

        A session that dies between `POST /login` and `GET /me` is a browser-policy
        question — cookie storage, third-party blocking, `SameSite`, an embedded frame —
        and the access log alone cannot tell the difference between "the cookie was
        refused" and "the client never sent it". This prints the headers that decide it.
        Lab-like environments only.
        """
        response = await call_next(request)
        if settings.env_name in ("LOCAL", "LAB") and request.url.path.startswith("/api/auth/"):
            log = logging.getLogger("uvicorn.error")
            # Attributes only: the Set-Cookie value is the session token and is never logged.
            set_cookie = response.headers.get("set-cookie") or ""
            attrs = ";".join(part.strip() for part in set_cookie.split(";")[1:]) or "-"
            log.info(
                "auth-transport %s %s -> %s | host=%s xfp=%s xff=%s | fetch-site=%s mode=%s "
                "origin=%s | cookie=%s bearer=%s | set-cookie[%s]",
                request.method, request.url.path, response.status_code,
                request.headers.get("host", "-"),
                request.headers.get("x-forwarded-proto", "-"),
                request.headers.get("x-forwarded-for", "-"),
                request.headers.get("sec-fetch-site", "-"),
                request.headers.get("sec-fetch-mode", "-"),
                request.headers.get("origin", "-"),
                "yes" if request.cookies.get(COOKIE_NAME) else "no",
                "yes" if (request.headers.get("authorization") or "")[:7].lower() == "bearer " else "no",
                attrs,
            )
        return response

    for r in API_ROUTERS:
        app.include_router(r)

    # Unknown /api/* paths must fail loudly as JSON — docs/12 promises
    # `404 {detail:{code:"not_found"}}`, and without this the SPA shell
    # below would answer 200 text/html for a typo'd API path, so a client
    # would try to parse HTML as JSON instead of seeing a real 404.
    # Registered after the real routers, which therefore always win.
    _ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    def _api_not_found(rest: str = ""):
        path = f"/api/{rest}".rstrip("/") or "/api"
        return JSONResponse(
            status_code=404,
            content={"detail": {"code": "not_found", "message": f"No API route: {path}"}},
        )

    app.add_api_route("/api", _api_not_found, methods=_ALL_METHODS, include_in_schema=False)
    app.add_api_route("/api/{rest:path}", _api_not_found, methods=_ALL_METHODS,
                      include_in_schema=False)

    # Health (no auth — designed for local probes; see flow matrix).
    dist: Path | None = settings.frontend_dist
    if dist and dist.exists() and (dist / "index.html").exists():
        root = dist.resolve()

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            """Serve the built SPA, with the two caching rules that keep a preview honest.

            `index.html` must revalidate: it names the content-hashed bundle, so a cached
            copy keeps pointing at the previous build and the fix just deployed is the one
            the browser does not load. The hashed assets under `assets/` can then be
            cached hard — their names change with their contents.

            A *missing* asset is a stale reference, not a client route: answering with
            `index.html` (which the generic SPA fallback would do) hands the browser HTML
            where it expects JavaScript, and the console shows a syntax error instead of a
            clean 404. Only extension-less paths fall through to the shell.
            """
            candidate = (dist / full_path).resolve()
            inside = str(candidate).startswith(str(root))
            if full_path and inside and candidate.is_file():
                cache = ("public, max-age=31536000, immutable"
                         if full_path.startswith("assets/") else "no-cache")
                return FileResponse(candidate, headers={"Cache-Control": cache})
            if full_path.startswith("assets/") or "." in Path(full_path).name:
                return JSONResponse(status_code=404, content={"detail": {"code": "not_found"}})
            return FileResponse(dist / "index.html", headers={"Cache-Control": "no-cache"})
    else:
        @app.get("/", include_in_schema=False)
        def root():
            return {"name": "CYBER-SEC API", "status": "running",
                    "frontend": "not built — run `npm run build` in app/frontend",
                    "docs": "/api/docs", "health": "/api/healthz", "metrics": "/metrics"}

    @app.on_event("startup")
    def _startup():
        conn = raw_connection()
        conn.close()
        # SEC-071: in-process report scheduler (daemon thread, stdlib only).
        from .services import scheduler
        scheduler.start()

    @app.on_event("shutdown")
    def _shutdown():
        from .services import scheduler
        scheduler.stop()

    return app


app = create_app()
