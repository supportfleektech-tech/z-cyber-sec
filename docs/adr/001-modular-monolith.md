# ADR-001: Frontend/backend framework — FastAPI + React SPA, modular monolith

**Status:** Accepted
**Date:** 2026-09-21

## Context

The platform needs a small web API with tight auth/audit semantics, a
responsive operations dashboard, and a zero-budget constraint (free,
open-source tooling only; no paid SDKs or platforms).

Candidates considered:

- **Backend:** FastAPI (Python) vs. Express/Fastify (TypeScript) vs.
  Django REST.
- **Frontend:** React + Vite + TypeScript vs. plain server-rendered templates.
- **Shape:** modular monolith vs. microservices.

## Decision

- **Backend: Python 3.11 + FastAPI**, pinned dependencies
  (`app/backend/requirements.txt`), stdlib `sqlite3`/`hashlib`/`hmac` for
  data + crypto. Rationale: single language for API, detection engine, STIX
  parsing, and report rendering; Pydantic gives the API an explicit contract;
  TestClient keeps the whole E2E suite in-process.
- **Frontend: React 18 + TypeScript + Vite**, built to static assets
  (`app/frontend/dist/`) and served by the backend itself (single origin, no
  separate web server, no CORS). Hash routing so the SPA works from the
  catch-all with zero server route configuration.
- **Shape: modular monolith** — one process, one SQLite database; domains are
  isolated as routers/services with cross-domain access only via the shared
  core. A module can be extracted to a service later if the load test gate
  (SEC-043) justifies it.

## Consequences

- One process to run (`uvicorn app.main:app`), one origin for browser + API,
  one test suite covering all domains in CI.
- Single-developer/agent ergonomics: no build matrix per service, no local
  service mesh; CI runs lint + tests + static build.
- The Python process is the scaling limit (acceptable at synthetic lab
  volume); the DB file and in-process detection engine are the first things a
  production swap (ADR-007) must replace.
