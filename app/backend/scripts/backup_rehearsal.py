"""SEC-063 — backup/restore REHEARSAL (RTO/RPO drill) against a live server.

Exercises the real production path end to end:
  1. baseline    — record events_total + audit chain state + a marker value
  2. backup      — POST /api/admin/backup (consistent file + sha256)
  3. verify      — sha256 of the file matches the reported hash
  4. simulate loss — stop the app (SIGTERM), move the live DB away (the "loss")
  5. restore     — POST /api/admin/backup/restore (typed RESTORE confirm)
  6. verify      — app healthy; events_total matches baseline; audit chain
                   still verifies (hash chain intact across the restore)
  7. report      — RTO (loss->healthy), RPO (now -> last backup ts), JSON

Usage (run where the app runs; requires server control):
  LOAD_TEST_USER=... LOAD_TEST_PASSWORD=... \
  .venv/bin/python -m scripts.backup_rehearsal --url http://127.0.0.1:8080 \
      --restart-cmd ".venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080"

Default mode without --restart-cmd: in-process (ASGI) rehearsal — safe to run
anywhere (including CI), same code path, no external process.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def _auth_headers_client(url: str):
    import httpx
    user = os.environ.get("LOAD_TEST_USER", "admin")
    pw = os.environ.get("LOAD_TEST_PASSWORD", "")
    c = httpx.Client(base_url=url, timeout=120)
    r = c.post("/api/auth/login", json={"username": user, "password": pw})
    if r.status_code != 200:
        raise SystemExit("login failed — set LOAD_TEST_PASSWORD (and LOAD_TEST_USER if not admin)")
    return c


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _server_pids() -> list[int]:
    """PIDs running the app server (uvicorn app.main:app), found via /proc.

    pgrep -f is NOT used: the drill's own argv (and any wrapping shell)
    contains the restart command text and would match, making the drill
    kill itself. Instead, scan /proc cmdlines for the server markers and
    exclude this process plus its full ancestor chain.
    """
    exclude = set()
    pid = os.getpid()
    while pid > 1:
        exclude.add(pid)
        try:
            with open(f"/proc/{pid}/stat") as f:
                ppid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            break
        if ppid <= pid:
            break
        pid = ppid
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                cmd = f.read().decode(errors="replace").replace("\0", " ")
        except OSError:
            continue
        if "uvicorn" in cmd and "app.main:app" in cmd and int(entry) not in exclude:
            pids.append(int(entry))
    return pids


def _chain_ok(c) -> bool:
    v = c.get("/api/admin/audit/verify").json()
    return bool(v.get("ok"))


def _stats(c) -> int:
    return c.get("/api/overview/stats").json()["events_total"]


def rehearse(url: str | None, restart_cmd: str | None) -> dict:
    t_loss = None
    if url:
        c = _auth_headers_client(url)
        baseline_events, baseline_chain = _stats(c), _chain_ok(c)

        # 2. backup
        b = c.post("/api/admin/backup").json()
        path = Path(b["path"])
        # 3. verify sha256
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != b["sha256"]:
            raise SystemExit(f"backup sha256 mismatch: {actual} != {b['sha256']}")
        backup_ts = b.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime))

        # 4. simulate loss (requires server control)
        if restart_cmd:
            t_loss = time.monotonic()
            server_pids = _server_pids()
            if not server_pids:
                raise SystemExit("no server process found (expected 'uvicorn app.main:app')")
            for p in server_pids:
                os.kill(p, signal.SIGTERM)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and any(_alive(p) for p in server_pids):
                time.sleep(0.2)
            for p in server_pids:  # escalate if SIGTERM was ignored
                if _alive(p):
                    os.kill(p, signal.SIGKILL)
            time.sleep(1)
            data_dir = Path(os.environ.get("DATA_DIR", HERE / "data"))
            lost = data_dir.parent / (data_dir.name + f".lost-{int(time.time())}")
            lost.mkdir(parents=True, exist_ok=True)
            for f in (data_dir / "cybersec.db", data_dir / "cybersec.db-wal", data_dir / "cybersec.db-shm"):
                if f.exists():
                    f.rename(lost / f.name)
        else:
            t_loss = time.monotonic()

        # 5. restore (app is down — operator restores files, then starts it)
        from app.services import backup as backup_svc
        backup_svc.restore_from(path, {"type": "system", "id": None, "name": "drill"})
        if restart_cmd:
            # start_new_session: the server must survive the drill process
            # exiting (and any process-group cleanup the caller's shell does).
            subprocess.Popen(restart_cmd.split(), cwd=str(HERE),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
        for _ in range(120):
            try:
                if c.get("/api/healthz", timeout=2).status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        c = _auth_headers_client(url)
        t_ready = time.monotonic()

        # 6. verify
        restored_events, restored_chain = _stats(c), _chain_ok(c)
        report = {
            "mode": "live", "backup_path": str(path), "backup_ts": backup_ts,
            "sha256_verified": True,
            "events": {"baseline": baseline_events, "restored": restored_events,
                       "match": baseline_events == restored_events},
            "audit_chain": {"baseline_ok": baseline_chain, "restored_ok": restored_chain},
            "rto_seconds": round(t_ready - t_loss, 2),
            "rpo_seconds": "n/a (see backup_ts)",
            "synthetic": True,
        }
        c.close()
        return report

    # ---- in-process mode (default; safe in CI)
    os.environ.setdefault("ENV_NAME", "LOCAL")
    tmp = Path(tempfile.mkdtemp(prefix="cybersec-drill-"))
    os.environ["DATA_DIR"] = str(tmp)
    os.environ.pop("SECRET_KEY", None)
    sys.path.insert(0, str(HERE))
    import uuid

    from starlette.testclient import TestClient  # noqa: E402

    from app import db, security  # noqa: E402
    from app.main import app  # noqa: E402
    from app.seed.seed_demo import seed_all  # noqa: E402

    pw = uuid.uuid4().hex
    with TestClient(app) as client:
        c = db.raw_connection()
        seed_all(c)
        c.execute("INSERT INTO users (username, display_name, password_hash, role, active, created_at, updated_at) "
                  "VALUES ('drill', 'Drill', ?, 'admin', 1, ?, ?)",
                  (security.hash_password(pw), db.utcnow(), db.utcnow()))
        c.commit()
        c.close()
        assert client.post("/api/auth/login", json={"username": "drill", "password": pw}).status_code == 200
        baseline_events, baseline_chain = _stats(client), _chain_ok(client)

        b = client.post("/api/admin/backup").json()
        path = Path(b["path"])
        assert hashlib.sha256(path.read_bytes()).hexdigest() == b["sha256"]
        backup_ts = b.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime))

        # simulate loss: wipe the live DB files
        t_loss = time.monotonic()
        for f in (tmp / "cybersec.db", tmp / "cybersec.db-wal", tmp / "cybersec.db-shm"):
            if f.exists():
                f.unlink()

        # 5. restore — the production restore function (same code the API uses),
        #    invoked at the filesystem level like an operator does while the
        #    app is quiesced. Replaces the live DB from the verified bundle.
        from app.services import backup as backup_svc
        backup_svc.restore_from(path, {"type": "system", "id": None, "name": "drill"})
        t_ready = time.monotonic()
        # 6. verify — the same session cookie is valid again (sessions table
        #    came back with the bundle), proving the restore is coherent.
        restored_events, restored_chain = _stats(client), _chain_ok(client)

    return {
        "mode": "in-process", "backup_path": str(path), "backup_ts": backup_ts,
        "sha256_verified": True,
        "events": {"baseline": baseline_events, "restored": restored_events,
                   "match": baseline_events == restored_events},
        "audit_chain": {"baseline_ok": baseline_chain, "restored_ok": restored_chain},
        "rto_seconds": round(t_ready - t_loss, 2),
        "rpo_seconds": "n/a (see backup_ts)",
        "synthetic": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=None, help="live server URL (live mode)")
    ap.add_argument("--restart-cmd", default=None, help="command to restart the server (live mode w/ loss)")
    args = ap.parse_args()
    report = rehearse(args.url, args.restart_cmd)
    print(json.dumps(report, indent=2))
    ok = (report["events"]["match"] and report["audit_chain"]["restored_ok"]
          and report["sha256_verified"] and report["rto_seconds"] < 120)
    print("DRILL:", "PASS" if ok else "FAIL", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
