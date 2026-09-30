"""The lab range's isolation rules, pinned (SEC-120).

`docs/17-lab-range.md` states four rules, and rule 2 is the one that turns a lab into an
incident: "changing a publish to 0.0.0.0 to test from another machine". Prose cannot fail
a build, so the rules are asserted here against the committed compose file — the same
file an operator runs — and against the registry contract the platform serves.

These checks are static on purpose: they must hold on a host with no Docker, in CI, and
before anything is started.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "infra" / "lab" / "docker-compose.yml"
LABAPI = ROOT / "infra" / "lab" / "api" / "labapi.py"


@pytest.fixture(scope="module")
def compose() -> dict:
    assert COMPOSE.exists(), "the lab range compose file is part of the deliverable"
    return yaml.safe_load(COMPOSE.read_text())


def test_range_network_is_internal(compose):
    """No route from the range to the platform network or the internet."""
    networks = compose.get("networks") or {}
    assert "lab_range" in networks
    assert networks["lab_range"].get("internal") is True
    for name, service in compose["services"].items():
        assert service.get("networks", ["lab_range"]) == ["lab_range"], \
            f"{name} must join only the isolated range network"


def test_every_publish_is_loopback_only(compose):
    """A publish without the 127.0.0.1 prefix exposes a vulnerable container everywhere."""
    publishes = [(name, port) for name, service in compose["services"].items()
                 for port in (service.get("ports") or [])]
    assert publishes, "the range must publish something or no operator can reach it"
    for name, port in publishes:
        assert str(port).startswith("127.0.0.1:"), \
            f"{name} publishes {port!r} — vulnerable targets are reachable from the loopback only"


def test_range_targets_are_hardened_and_profiled(compose):
    """Disposable targets: no privilege escalation, bounded memory, opt-in by profile."""
    for name, service in compose["services"].items():
        assert service.get("security_opt") == ["no-new-privileges:true"], \
            f"{name} must refuse privilege escalation"
        assert service.get("mem_limit"), f"{name} must declare a memory limit"
        assert service.get("profiles"), \
            f"{name} must sit behind a compose profile — `docker compose up` must not start a target"
        assert service.get("restart") in (None, "no"), \
            f"{name} must not restart itself; a target nobody asked for is scope drift"


def test_registered_targets_match_the_range(client, conn, compose):
    """The registry must describe the range that exists — names *and* reachable endpoint.

    `exercises.targets` names have to be the compose service names, and each endpoint's
    port has to be the loopback publish, or the registry tells an operator to look
    somewhere nothing is listening. This is not hypothetical: the seeded CTF target was
    registered on 8080 — the platform's own port — while the range publishes 8081, and
    only this comparison notices.
    """
    from app.seed.seed_demo import seed_lab_extras
    seed_lab_extras(conn)          # the registration ships with the demo dataset
    items = client.get("/api/lab/targets").json()["items"]
    assert {t["name"] for t in items} == set(compose["services"]), \
        "the seeded registry and the range's service names have drifted apart"

    published = {}
    for name, service in compose["services"].items():
        ports = service.get("ports") or []
        assert len(ports) == 1, f"{name} must publish exactly one reachable port"
        published[name] = str(ports[0]).split(":")[1]      # 127.0.0.1:<host>:<container>
    for target in items:
        host, _, port = target["endpoint"].partition(":")
        assert host == target["name"], f"{target['name']} endpoint names another host: {host}"
        assert port == published[target["name"]], (
            f"{target['name']} is registered on port {port} but the range publishes "
            f"{published[target['name']]}")


def test_lab_api_is_deliberately_vulnerable_and_clearly_labeled():
    """The one target we author is the one we must be able to audit: standard library only,
    and every planted weakness carries a marker, so nobody mistakes it for product code."""
    text = LABAPI.read_text()
    assert "http.server" in text and "import requests" not in text
    weaknesses = [line for line in text.splitlines() if "VULNERABLE" in line.upper()]
    assert len(weaknesses) >= 4, "each planted weakness must be marked as such"
    routes = ["/api/users/", "/api/admin/config", "/api/debug", "/api/login"]
    for route in routes:
        assert route in text, f"{route} is documented as a weakness but is not implemented"
    assert "lab" in text.lower() and "synthetic" in text.lower()
