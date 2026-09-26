"""Edge-aware request middleware (SEC-061).

The pinned starlette build ships no ProxyHeadersMiddleware, so the
one-terminating-proxy (Caddy) semantics are implemented here, dependency-free:

- ``X-Forwarded-Proto`` (set/overwritten by Caddy from the real scheme)
  → ``scope["scheme"]`` so ``request.url.scheme == "https"`` behind TLS
  termination. That is what makes the session cookie ``Secure=`` (auth.py).
- ``X-Forwarded-For`` (Caddy appends the direct client IP as the LAST entry)
  or ``X-Real-IP`` → ``scope["client"]`` so login attribution and per-IP
  session logging see the real client, not the Caddy container.

Trust model: exactly ONE terminating hop. Caddy overwrites
``X-Forwarded-Proto`` and appends (never prepends) to ``X-Forwarded-For``,
so taking the last entry yields the direct client. With no proxy in front
(local lab) the headers are absent and behavior is unchanged. The app is
never exposed directly (flow matrix, docs/03), so client-forged headers
without the edge have no meaningful effect locally.
"""
from __future__ import annotations

from starlette.datastructures import Headers


class ForwardedHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = Headers(scope=scope)
            proto = headers.get("x-forwarded-proto")
            if proto:
                scope["scheme"] = proto.split(",")[0].strip() or scope["scheme"]
            xff = headers.get("x-forwarded-for")
            client = scope.get("client")
            port = client[1] if client else 0
            if xff:
                real = [p.strip() for p in xff.split(",") if p.strip()]
                if real:
                    scope["client"] = (real[-1], port)
            else:
                xri = headers.get("x-real-ip")
                if xri:
                    scope["client"] = (xri.strip(), port)
        await self.app(scope, receive, send)
