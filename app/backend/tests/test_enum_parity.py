"""Enum parity between the SPA's pickers and the API's accepted values (SEC-079).

The UI and the API each carried their own copy of the same vocabulary, and they
drifted: the alert triage dropdown offered `false_positive` (the API answers
`400 bad_status`) while omitting the real `dismissed`, so a false positive could
not be recorded from the UI at all; the case-status list offered
`containment`/`recovered` and hid `contained`/`mitigated`. The same class of bug
produced the missing `tradecraft` report kind (SEC-076).

Silent vocabulary drift is a UI defect that looks like a backend failure to the
person using it. These tests read the frontend source and compare every named
picker list with the set the API actually accepts, so drift fails in CI.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app import security
from app.routers import cases, cloud, grc, reports, soc, vulns

PAGES = Path(__file__).resolve().parents[3] / "app" / "frontend" / "src" / "pages"


def _page(name: str) -> str:
    path = PAGES / name
    if not path.exists():  # frontend absent (e.g. backend-only checkout)
        pytest.skip(f"{path} not present")
    return path.read_text()


def _const(source: str, name: str) -> set[str]:
    """Extract a `const NAME = ["a", "b"];` list."""
    m = re.search(rf"const {name}\s*=\s*\[(.*?)\]", source, re.S)
    assert m, f"{name} not found — was it renamed? update this test with it"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


@pytest.mark.parametrize("page,name,expected", [
    ("Soc.tsx", "TRIAGE_STATUSES", soc.ALERT_STATUSES),
    ("Incidents.tsx", "CASE_STATUSES", cases.CASE_STATUSES),
    ("Incidents.tsx", "TASK_STATUS_OPTIONS", cases.TASK_STATUSES),
    ("Grc.tsx", "CONTROL_STATUSES", grc.CONTROL_STATUSES),
    ("Grc.tsx", "RISK_STATUSES", grc.RISK_STATUSES),
    ("Cloud.tsx", "POSTURE_STATUSES", cloud.POSTURE_STATUSES),
    ("Vulns.tsx", "VULN_STATUSES", vulns.STATUSES),
    ("Reports.tsx", "KINDS", set(reports.KINDS)),
    ("Admin.tsx", "ROLES", security.ROLES),
    ("Vulns.tsx", "SETTABLE_STATUSES", vulns.PATCHABLE_STATUSES),
])
def test_frontend_picker_matches_api(page, name, expected):
    offered = _const(_page(page), name)
    assert offered == set(expected), (
        f"{page}:{name} and the API disagree.\n"
        f"  offered by the UI but rejected by the API: {sorted(offered - set(expected))}\n"
        f"  accepted by the API but unreachable in the UI: {sorted(set(expected) - offered)}")


def test_no_severity_drift():
    """Severity lists are inline in a few pickers; every value the API accepts
    must be offered, and no value it rejects may be."""
    expected = soc.SEVERITIES
    for page in ("Soc.tsx", "Cloud.tsx", "Vulns.tsx"):
        src = _page(page)
        for m in re.finditer(r'\[((?:\s*"(?:critical|high|medium|low|info|severe|minor)"\s*,?)+)\]', src):
            offered = set(re.findall(r'"([^"]+)"', m.group(1)))
            assert offered <= expected, f"{page} offers severities the API rejects: {sorted(offered - expected)}"
