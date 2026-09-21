"""Backup & restore (SEC-042). Zero-budget: SQLite online backup API + tar.

- backup(): hot snapshot of the DB (WAL-safe), copies evidence files, writes
  a manifest.json with sha256 checksums, packs everything to .tar.gz.
- restore(path): verifies manifest checksums, replaces the DB file, integrity-checks.
Restore requires the admin.backup permission and is audited; the platform must
be quiesced for it (callers close connections first).
"""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import sqlite3
import tarfile
from pathlib import Path

from .. import db
from ..audit import record_audit
from ..config import settings


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def create_backup(conn, actor: dict, dest_dir: Path | None = None) -> dict:
    dest = (dest_dir or settings.backups_dir)
    dest.mkdir(parents=True, exist_ok=True)
    stamp = db.utcnow().replace(":", "").replace("-", "")
    stamp = stamp[:14]
    tmp = dest / f"cybersec-{stamp}.db.tmp"
    src = sqlite3.connect(settings.db_path)
    dst = sqlite3.connect(tmp)
    with dst:
        src.backup(dst)
    src.close()
    dst.close()
    tmp.rename(tmp.with_suffix(".db"))

    bundle = dest / f"cybersec-{stamp}"
    if bundle.exists():
        shutil.rmtree(bundle)
    bundle.mkdir()
    shutil.move(str(tmp.with_suffix(".db")), str(bundle / "cybersec.db"))
    ev_src = settings.evidence_dir
    ev_dst = bundle / "evidence"
    if ev_src.exists() and any(ev_src.iterdir()):
        shutil.copytree(ev_src, ev_dst)
    manifest = {
        "created_at": db.utcnow(),
        "env_name": settings.env_name,
        "files": {},
        "db_size_bytes": (bundle / "cybersec.db").stat().st_size,
        "record_counts": {
            t: int(db.one(conn, f"SELECT COUNT(*) c FROM {t}")["c"])
            for t in ("users", "events", "alerts", "cases", "evidence",
                      "threat_indicators", "vuln_findings", "audit_events")
        },
    }
    for f in sorted(bundle.rglob("*")):
        if f.is_file():
            manifest["files"][str(f.relative_to(bundle))] = _sha256(f)
    (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2))

    tar_path = dest / f"cybersec-{stamp}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(bundle, arcname="")
    shutil.rmtree(bundle)

    record_audit(conn, actor, "backup.created", target_type="backup", target_id=tar_path.name,
                 detail={"sha256": _sha256(tar_path), "bytes": tar_path.stat().st_size})
    return {"path": str(tar_path), "sha256": _sha256(tar_path), "bytes": tar_path.stat().st_size,
            "records": manifest["record_counts"]}


def verify_bundle(conn, tar_path: Path) -> dict:
    """Extract in-memory check: manifest exists and checksums match."""
    with tarfile.open(tar_path, "r:gz") as tar:
        members = {m.name: m for m in tar.getmembers() if m.isfile()}
        if "manifest.json" not in members:
            return {"ok": False, "error": "missing manifest"}
        manifest = json.load(io.BytesIO(tar.extractfile("manifest.json").read()))
        bad = []
        for name, expected in manifest["files"].items():
            if name not in members:
                bad.append(f"missing:{name}")
                continue
            data = tar.extractfile(name).read()
            if hashlib.sha256(data).hexdigest() != expected:
                bad.append(f"checksum:{name}")
        return {"ok": not bad, "bad": bad, "files": len(manifest["files"])}


def restore_from(tar_path: Path, actor: dict) -> dict:
    """Replace the live DB with the backup's DB. Caller must close connections."""
    v = verify_bundle(None, tar_path)
    if not v["ok"]:
        raise RuntimeError(f"backup failed verification: {v.get('bad')}")
    with tarfile.open(tar_path, "r:gz") as tar:
        db_member = tar.extractfile("cybersec.db")
        if not db_member:
            raise RuntimeError("backup missing cybersec.db")
        settings.db_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = settings.db_path.with_suffix(".db.restore")
        with tmp.open("wb") as f:
            shutil.copyfileobj(db_member, f)
        ev_dir = settings.evidence_dir
        if ev_dir.exists():
            shutil.rmtree(ev_dir)
        ev_dir.mkdir(parents=True, exist_ok=True)
        for m in tar.getmembers():
            if m.isfile() and m.name.startswith("evidence/"):
                target = ev_dir / m.name.split("/", 1)[1]
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(m) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
    for suffix in ("-wal", "-shm"):
        p = settings.db_path.parent / (settings.db_path.name + suffix)
        if p.exists():
            p.unlink()
    tmp.replace(settings.db_path)
    check = sqlite3.connect(settings.db_path)
    ok = check.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    check.close()
    if not ok:
        raise RuntimeError("restored database failed integrity check")
    conn = db.connect()
    db.migrate(conn)
    record_audit(conn, actor, "backup.restored", target_type="backup", target_id=tar_path.name)
    conn.close()
    return {"ok": True, "restored_from": str(tar_path)}
