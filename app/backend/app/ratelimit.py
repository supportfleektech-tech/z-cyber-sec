"""In-process login rate limiting (SEC-073).

Why here and not at the edge: Caddy's ``rate_limit`` directive is **not**
part of the standard Caddy build (it needs a custom ``xcaddy`` image), so a
Caddyfile that used it would be rejected by the pinned ``caddy:2`` image with
"unknown directive: rate_limit" — a config that cannot load protects nothing.
The control therefore lives in the app: dependency-free, verifiable by the
test suite, and identical in every deployment (local, staging, prod). An
optional second layer at the edge is documented in ``infra/README.md``.

Enabled by default in STAGING/PROD and off in LOCAL/LAB, so the local lab and
the test suite are unaffected (see ``config.load_settings``). Bounded memory:
the per-key map is pruned when it exceeds ``_MAX_KEYS`` so a spoofed-source
flood cannot grow it without limit.
"""
from __future__ import annotations

import threading
from collections import deque

_lock = threading.Lock()
_hits: dict[str, deque[float]] = {}
_logged: dict[str, float] = {}

_MAX_KEYS = 10_000


def check(key: str, *, limit: int, window_s: float, now: float) -> tuple[bool, float]:
    """Record one attempt for ``key``; return ``(allowed, retry_after_s)``.

    Sliding window: attempts older than ``window_s`` are dropped first, so a
    client that waits out the window is served again immediately.
    """
    with _lock:
        if len(_hits) > _MAX_KEYS:
            stale = [k for k, d in _hits.items() if not d or d[-1] <= now - window_s]
            for k in stale:
                _hits.pop(k, None)
                _logged.pop(k, None)
        q = _hits.setdefault(key, deque())
        cutoff = now - window_s
        while q and q[0] <= cutoff:
            q.popleft()
        if len(q) >= limit:
            return False, max(0.0, q[0] + window_s - now)
        q.append(now)
        return True, 0.0


def should_log(key: str, *, window_s: float, now: float) -> bool:
    """True at most once per ``window_s`` per key (no audit-log flooding)."""
    with _lock:
        last = _logged.get(key)
        if last is not None and now - last < window_s:
            return False
        _logged[key] = now
        return True


def reset() -> None:
    """Clear all counters (used by tests)."""
    with _lock:
        _hits.clear()
        _logged.clear()
