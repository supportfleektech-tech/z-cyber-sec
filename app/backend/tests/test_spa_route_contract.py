"""Every API path the SPA calls must exist (SEC-123).

The suites either side of this boundary are thorough and neither crosses it: the backend
tests call routes directly, and `test_enum_parity.py` compares *vocabularies* by reading
the SPA source. Nothing checked the thing that breaks first when a router is renamed or a
prefix changes — that the 100-odd URLs the UI actually builds still resolve. A stale path
is not an exception in Python; it is a 404 the user sees as "failed to load", and the
backend suite stays green.

This test reads every `api.get/post/patch/delete(...)` call in the SPA source, turns the
FastAPI route table into matchers, and asserts each call resolves to a registered route
with that method. Template literals (`/api/cases/${id}/tasks`) match on their fixed
segments. New page added, new endpoint, renamed router — this is the test that notices.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.main import app

SRC = Path(__file__).resolve().parents[3] / "app" / "frontend" / "src"

# `api.get<Foo>(`/api/x?...`)`, `api.patch(`/api/y/${id}`, …)`, `api.delete(...)`.
CALL_RE = re.compile(
    r"""api\.(get|post|patch|put|delete)\s*(?:<[^>]*>)?\s*\(\s*[`"']([^`"']+)[`"']""")
# `${...}` (and the odd `{id}`) become a wildcard segment.
INTERP_RE = re.compile(r"\$\{[^}]+\}|\{[^}]+\}")


def _calls() -> list[tuple[str, str, str]]:
    """(file, method, path-template) for every API call in the SPA."""
    out = []
    for path in sorted(SRC.rglob("*.ts*")):
        if "node_modules" in path.parts:
            continue
        text = path.read_text()
        for method, raw in CALL_RE.findall(text):
            url = raw.split("?")[0]
            if not url.startswith("/api"):
                continue
            out.append((path.name, method.upper(), url))
    return out


def _route_matchers() -> dict[str, list[re.Pattern]]:
    """method -> list of regexes matching the app's registered paths.

    Read from the generated OpenAPI document rather than `app.routes`: that is the same
    surface the SPA and the smoke check see, and it stays correct across FastAPI versions
    that wrap included routers instead of flattening them.
    """
    matchers: dict[str, list[re.Pattern]] = {}
    for path, operations in app.openapi()["paths"].items():
        regex = re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", path.rstrip("/")) + "/?$")
        for method in operations:
            matchers.setdefault(method.upper(), []).append(regex)
    return matchers


def _matches(method: str, url: str, matchers: dict[str, list[re.Pattern]]) -> bool:
    # A template literal's interpolated segment is one path segment in practice, but the
    # values are ids so allow anything that is not a slash.
    fixed = INTERP_RE.sub("x", url).rstrip("/")
    candidates = matchers.get(method, []) + matchers.get("GET", []) if method != "GET" else \
        matchers.get("GET", [])
    return any(m.match(fixed) for m in candidates)


def test_every_spa_api_call_resolves_to_a_route():
    calls = _calls()
    assert len(calls) > 50, f"only found {len(calls)} API calls — did the SPA source move?"  # noqa: PLR2004
    matchers = _route_matchers()
    assert matchers, "the app registered no routes"

    unresolved = []
    for filename, method, url in calls:
        if not _matches(method, url, matchers):
            unresolved.append(f"{filename}: api.{method.lower()}('{url}')")
    assert not unresolved, (
        "the SPA calls API paths this build does not serve (a renamed router, a changed "
        "prefix, or a typo — the user would see a 404):\n  " + "\n  ".join(sorted(set(unresolved))))


def test_spa_calls_only_the_methods_it_declares():
    """`api.get` on a POST-only route is the same 405 in the browser."""
    matchers = _route_matchers()
    wrong_method = []
    for filename, method, url in _calls():
        fixed = INTERP_RE.sub("x", url).rstrip("/")
        if any(m.match(fixed) for m in matchers.get(method, [])):
            continue
        if any(m.match(fixed) for methods in matchers.values() for m in methods):
            wrong_method.append(f"{filename}: {method} {url}")
    assert not wrong_method, (
        "these paths exist but not for the method the SPA uses:\n  "
        + "\n  ".join(sorted(set(wrong_method))))


@pytest.mark.parametrize("path", ["App.tsx", "pages/Lab.tsx", "pages/Admin.tsx"])
def test_spa_source_is_present(path: str):
    """Guard the guard: if the SPA moves, this suite must fail loudly, not skip."""
    assert (SRC / path).exists(), f"{path} not found under {SRC}"
