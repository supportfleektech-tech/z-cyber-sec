"""Shared fixtures: isolated temp data dir, fresh DB per test, ASGI test client.

The config singleton is loaded once per process (DATA_DIR set here before
import), so all tests share one temp dir but get a fresh database file.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

TEST_DATA = Path(__file__).resolve().parent / ".testdata"


def _fresh_dirs() -> None:
    for sub in ("", "evidence", "reports", "backups"):
        d = TEST_DATA / sub
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        p = TEST_DATA / f"cybersec.db{suffix}"
        if p.exists():
            p.unlink()


# Configure BEFORE importing the app package (config is a process singleton).
os.environ.setdefault("ENV_NAME", "LOCAL")
os.environ["DATA_DIR"] = str(TEST_DATA)
os.environ.pop("SECRET_KEY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from starlette.testclient import TestClient  # noqa: E402

from app import db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def conn():
    """Fresh, migrated database."""
    _fresh_dirs()
    c = db.raw_connection()
    yield c
    c.close()


@pytest.fixture()
def client(conn):
    """Seeded DB + admin-logged-in test client.

    Tests needing other roles call client.post('/api/auth/logout') and log in
    again; unauthenticated tests log out first.
    """
    from app.seed.seed_demo import seed_all
    seed_all(conn)
    # Run detection over the seeded events so alerts exist (like production backfill),
    # then create the linked demo case (case id 1 + evidence id 1 exist for all tests).
    from app.routers.soc import _run_detections
    events = db.q(conn, "SELECT id, ts, host, user, action, outcome, severity, "
                        "source_name, source_type, data FROM events ORDER BY ts")
    if events:
        _run_detections(conn, events, threshold_context=events)
    from app.seed.seed_demo import demo_case_and_evidence
    demo_case_and_evidence(conn)
    c = TestClient(app)
    r = _login(c, "admin", "CyberSecAdmin1!")
    assert r.status_code == 200, r.text
    yield c
    c.close()


def _login(c: TestClient, username: str, password: str):
    return c.post("/api/auth/login", json={"username": username, "password": password})


@pytest.fixture()
def seeded(conn):
    """Ensure the synthetic dataset exists (seed is idempotent)."""
    from app.seed.seed_demo import seed_all
    seed_all(conn)
    return conn


@pytest.fixture()
def seeded_client(conn, client):
    """Seeded DB + logged-in admin client (cookies on `client`)."""
    from app.seed.seed_demo import seed_all
    seed_all(conn)
    r = _login(client, "admin", "CyberSecAdmin1!")
    assert r.status_code == 200, r.text
    return client


@pytest.fixture()
def analyst_client(conn, client):
    """soc_analyst login on a fresh seeded DB."""
    from app.seed.seed_demo import seed_all
    seed_all(conn)
    r = _login(client, "sasha", "SashaSocPass1!")
    assert r.status_code == 200, r.text
    return client


@pytest.fixture()
def viewer_client(conn, client):
    from app.seed.seed_demo import seed_all
    seed_all(conn)
    r = _login(client, "viewer", "ViewerRead1!")
    assert r.status_code == 200, r.text
    return client
