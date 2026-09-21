"""SEC-043 regression guard — bounded capacity check inside the fast suite.

Full-scale runs live in scripts/load_test.py (not part of pytest, too slow).
This test keeps a floor: 2,000 events (8 batches of 250) must ingest within a
generous wall budget on the CI runner, with detection still firing.
"""
from __future__ import annotations

import random
import time
from datetime import datetime, timedelta, timezone

HOSTS = ["lab-web-01", "lab-db-01", "lab-jump-01"]
BENIGN = ("file_read", "success", "info", "read /var/log/app.log")
ATTACK = ("ssh_failed_login", "failure", "medium", "ssh auth failure")


def _events(n: int, offset: int) -> list[dict]:
    rng = random.Random(offset)
    now = datetime.now(timezone.utc)
    out = []
    for k in range(n):
        attack = rng.random() < 0.2
        action, outcome, sev, msg = ATTACK if attack else BENIGN
        out.append({
            "idempotency_key": f"cap-{offset}-{k}",
            "ts": (now - timedelta(seconds=k % 600)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_type": "syslog",
            "source_name": "sshd" if attack else "audisp",
            "host": HOSTS[k % 2] if attack else HOSTS[rng.randrange(len(HOSTS))],
            "user": "svc-backup",
            "action": action,
            "outcome": outcome,
            "severity": sev,
            "msg": f"[synthetic-cap] {msg}",
        })
    return out


def test_capacity_floor_2k_events(client):
    before = client.get("/api/soc/events?page_size=1").json()["total"]
    t0 = time.monotonic()
    for b in range(8):
        r = client.post("/api/soc/events", json={"events": _events(250, b)})
        assert r.status_code == 201, r.text[:200]
    wall = time.monotonic() - t0
    assert wall < 20, f"ingest too slow for CI floor: {wall:.1f}s for 2000 events"

    after = client.get("/api/soc/events?page_size=1").json()["total"]
    assert after - before == 2000

    # Detection work is real: the concentrated ssh failures must raise an alert.
    alerts = client.get("/api/soc/alerts?page_size=100").json()
    titles = " ".join(a["title"] for a in alerts["items"])
    assert "SSH Brute Force" in titles
