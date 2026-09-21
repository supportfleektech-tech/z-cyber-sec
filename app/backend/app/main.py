"""CYBER-SEC platform — modular monolith entrypoint (ADR-001).

Single process: FastAPI API + static frontend + embedded telemetry.
Run:  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
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
    vulns,
)

API_ROUTERS = [
    overview.router, auth.router, soc.router, cases.router, intel.router, vulns.router,
    appsec.router, cloud.router, grc.router, exercises.router, agents.router,
    automation.router, reports.router, admin.router, assets.router,
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
