"""SEC-043 — Capacity/load test with expected lab event volume.

Zero-budget, in-process by default: drives the real ASGI app (API + detection
engine + SQLite) with a burst of synthetic events, then a sustained stream.
Not part of the pytest suite (too slow); a bounded regression guard lives in
tests/test_capacity.py.

Usage:
  .venv/bin/python -m scripts.load_test                 # ASGI mode, 20k events
  .venv/bin/python -m scripts.load_test --events 50000 --batch 500
  .venv/bin/python -m scripts.load_test --http http://127.0.0.1:8080   # live server

The synthetic stream embeds a realistic mix: ~85% benign operations across
lab hosts plus attack patterns (SSH brute force, login storm) so detection
work is representative, not idle.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent  # app/backend

HOSTS = ["lab-web-01", "lab-web-02", "lab-db-01", "lab-jump-01", "ws-analyst-01", "ws-analyst-02"]
USERS = ["svc-backup", "j.doe", "a.smith", "svc-monitor", "ops"]
BENIGN = [
    ("file_read", "success", "info", "read /var/log/app.log"),
    ("http_request", "success", "info", "GET /healthz 200"),
    ("file_write", "success", "info", "rotate /var/log/app.log"),
    ("process_start", "success", "info", "start cron job"),
    ("login", "success", "info", "ssh login ok"),
    ("db_query", "success", "info", "SELECT count(*)"),
    ("backup_complete", "success", "info", "backup finished"),
]
# Attack patterns that fire the shipped rules (cs-0001 ssh brute, cs-0002 login storm):
ATTACKS = [
    ("ssh_failed_login", "failure", "medium", "ssh auth failure", "sshd"),
    ("login_failed", "failure", "medium", "web login failure", "httpd"),
]


def _gen_event(rng: random.Random, i: int, now: datetime) -> dict:
    attack = rng.random() < 0.15
    if attack:
        action, outcome, sev, msg, src = ATTACKS[rng.randrange(len(ATTACKS))]
        host = rng.choice(HOSTS[:3])  # concentrated, so thresholds trip
    else:
        action, outcome, sev, msg = BENIGN[rng.randrange(len(BENIGN))]
        host, src = rng.choice(HOSTS), rng.choice(["sshd", "httpd", "cron", "audisp"])
    ts = now - timedelta(seconds=(i % 3600) * 0.5)
    return {
        "idempotency_key": f"load-{i}",
        "ts": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_type": "syslog",
        "source_name": src,
        "host": host,
        "user": rng.choice(USERS),
        "action": action,
        "outcome": outcome,
        "severity": sev,
        "msg": f"[synthetic-load] {msg}",
        "data": {"load_batch": i // 1000},
    }


def run(mode: str, base_url: str, events_n: int, batch: int) -> dict:
    os.environ.setdefault("ENV_NAME", "LOCAL")
    rng = random.Random(42)
    now = datetime.now(UTC)

    if mode == "asgi":
        tmp = Path(tempfile.mkdtemp(prefix="cybersec-load-"))
        os.environ["DATA_DIR"] = str(tmp)
        os.environ.pop("SECRET_KEY", None)
        sys.path.insert(0, str(HERE))
        # Dedicated load-test user with a runtime-generated password (no
        # credential literals in source — ADR-006).
        import uuid

        from starlette.testclient import TestClient  # noqa: E402

        from app import (
            db,  # noqa: E402
            security,
        )
        from app.main import app  # noqa: E402
        from app.seed.seed_demo import seed_all  # noqa: E402

        load_pw = uuid.uuid4().hex
        c = db.raw_connection()
        seed_all(c)
        c.execute(
            "INSERT OR REPLACE INTO users (username, display_name, password_hash, role, active, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            ("loadtest", "Load Test", security.hash_password(load_pw), "admin",
             db.utcnow(), db.utcnow()),
        )
        c.commit()
        c.close()
        client = TestClient(app)
        with client:
            r = client.post("/api/auth/login", json={"username": "loadtest", "password": load_pw})
            assert r.status_code == 200, r.text
        base_dir = tmp
    else:
        import uuid

        import httpx

        user = os.environ.get("LOAD_TEST_USER", "admin")
        pw = os.environ.get("LOAD_TEST_PASSWORD")
        assert pw, "set LOAD_TEST_PASSWORD for --mode http (never store it in source)"
        client = httpx.Client(base_url=base_url, timeout=120, follow_redirects=True)
        r = client.post("/api/auth/login", json={"username": user, "password": pw})
        assert r.status_code == 200, r.text
        base_dir = None

    stats_before = client.get("/api/overview/stats").json()
    db_path = (base_dir / "cybersec.db") if base_dir else None
    size_before = db_path.stat().st_size if db_path else None

    latencies: list[float] = []
    detected_total = 0
    t0 = time.monotonic()
    sent = 0
    for b0 in range(0, events_n, batch):
        evs = [_gen_event(rng, b0 + k, now) for k in range(min(batch, events_n - b0))]
        tb = time.monotonic()
        r = client.post("/api/soc/events", json={"events": evs})
        dt = time.monotonic() - tb
        assert r.status_code in (200, 201), f"batch failed: {r.status_code} {r.text[:200]}"
        body = r.json()
        detected_total += len(body.get("alerts", []))
        latencies.append(dt)
        sent += len(evs)
    wall = time.monotonic() - t0

    stats_after = client.get("/api/overview/stats").json()
    size_after = db_path.stat().st_size if db_path else None
    p = lambda q: sorted(latencies)[min(len(latencies) - 1, int(q * len(latencies)))]  # noqa: E731

    report = {
        "mode": mode,
        "events": sent,
        "batch_size": batch,
        "wall_seconds": round(wall, 2),
        "events_per_second": round(sent / wall, 1),
        "batch_latency_seconds": {
            "p50": round(p(0.50), 3), "p95": round(p(0.95), 3), "p99": round(p(0.99), 3),
            "max": round(max(latencies), 3),
        },
        "detections_fired": detected_total,
        "alerts": {"before": stats_before["alerts"]["total"], "after": stats_after["alerts"]["total"]},
        "events_total_after": stats_after["events_total"],
        "db_size_bytes": {"before": size_before, "after": size_after},
        "synthetic": True,
    }
    if mode == "http":
        client.close()
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["asgi", "http"], default="asgi")
    ap.add_argument("--http", default="http://127.0.0.1:8080")
    ap.add_argument("--events", type=int, default=20_000)
    ap.add_argument("--batch", type=int, default=250)
    args = ap.parse_args()

    report = run(args.mode, args.http, args.events, args.batch)
    print(json.dumps(report, indent=2))
    # Sanity gates (lab expectation: in-process handles ≥20k events in <90s)
    ok = (
        report["events"] == args.events
        and report["events_per_second"] > 200
        and report["batch_latency_seconds"]["p95"] < 10
        and report["detections_fired"] > 0
        and report["alerts"]["after"] > report["alerts"]["before"]
    )
    print("GATE:", "PASS" if ok else "FAIL", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
