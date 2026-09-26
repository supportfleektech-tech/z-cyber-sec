"""CYBER-SEC platform — modular monolith entrypoint (ADR-001).

Single process: FastAPI API + static frontend + embedded telemetry.
Run:  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

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
    overview,
    reports,
    soc,
    tradecraft,
    vulns,
)

API_ROUTERS = [
    overview.router, auth.router, soc.router, cases.router, intel.router, vulns.router,
    appsec.router, cloud.router, grc.router, exercises.router, agents.router,
    automation.router, reports.router, admin.router, assets.router,
    tradecraft.router,
]


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
        allow_origins=[settings.dev_origin] if settings.dev_origin else [],
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
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="static-assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            candidate = (dist / full_path).resolve()
            if full_path and candidate.is_file() and str(candidate).startswith(str(dist.resolve())):
                return FileResponse(candidate)
            return FileResponse(dist / "index.html")
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
