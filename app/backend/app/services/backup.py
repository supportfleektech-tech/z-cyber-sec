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


def safe_member_name(name: str) -> bool:
    """Is this tar member name safe to join onto a destination directory?

    SEC-085: the restore path joined `evidence/<member>` onto the evidence
    directory, so a member named `evidence/../../../../tmp/x` wrote outside the
    store. Absolute paths, drive letters and any `..` segment are rejected.
    """
    if not name or name.startswith(("/", "\\")) or ":" in name[:2]:
        return False
    return ".." not in name.replace("\\", "/").split("/")


def contained(base: Path, relative: str) -> Path | None:
    """Resolve ``base/relative`` and return it only if it stays inside base."""
    target = (base / relative).resolve()
    try:
        base_res = base.resolve()
    except OSError:  # pragma: no cover - unresolvable base
        return None
    return target if target == base_res or base_res in target.parents else None


def verify_bundle(conn, tar_path: Path) -> dict:
    """Extract in-memory check: manifest exists, checksums match, and nothing
    is smuggled in that the manifest does not account for.

    SEC-085: this used to iterate *only* over `manifest["files"]`, so a member
    the manifest never mentions (e.g. `evidence/../../etc/x`) passed verification
    and was then written outside the evidence store by `restore_from`.
    """
    # SEC-086: a corrupt or truncated bundle (interrupted copy, disk full, a
    # file that is simply not a tar.gz) raised straight out of here and became an
    # opaque `500 internal_error` — the caller had to read server logs to learn
    # that their backup file was unreadable. Malformed input is a normal
    # operational case, so it is reported as a failed verification.
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            result = _verify_open_bundle(tar)
    except (tarfile.TarError, OSError, json.JSONDecodeError, KeyError, EOFError) as e:
        return {"ok": False, "error": f"unreadable bundle: {type(e).__name__}: {e}"[:200]}
    if conn is not None:
        result = _check_recorded_hash(conn, tar_path, result)
    return result


def _check_recorded_hash(conn, tar_path: Path, result: dict) -> dict:
    """Compare the bundle with the hashes recorded when backups were created (SEC-100).

    The manifest travels *inside* the bundle, so it can be edited along with any file
    it describes: a bundle whose database was swapped for one holding an extra admin
    user verified clean, and restoring it installed that account. The hash-chained
    audit log recorded each bundle's sha256 at creation and cannot be rewritten
    without breaking the chain, so compare against it.

    Matching is content-first, because a file name is not evidence:
      - same name, different hash -> modified in place (fail)
      - different name, same hash -> this platform's bundle, renamed (ok)
      - neither name nor content matches a recorded bundle -> provenance unknown: not
        proof of tampering (it may have been built elsewhere, or the platform's
        database rebuilt), reported as such, and refused by the restore gate unless
        the operator explicitly overrides it.
    """
    rows = conn.execute("SELECT target_id, detail FROM audit_events "
                        "WHERE action = 'backup.created' ORDER BY seq DESC").fetchall()
    recorded: dict[str, str] = {}
    for r in rows:
        h = (db.jload(r["detail"], {}) or {}).get("sha256")
        if h and r["target_id"] and r["target_id"] not in recorded:
            recorded[r["target_id"]] = h
    actual = _sha256(tar_path)
    if not recorded:
        result["recorded"] = {
            "found": False, "actual": actual,
            "note": ("this log records no created backups, so the bundle's hash cannot be "
                     "compared with one the platform recorded")}
        return result
    expected = recorded.get(tar_path.name)
    if expected:
        result["recorded"] = {"found": True, "matched_by": "name", "expected": expected,
                              "actual": actual, "matches": actual == expected}
        if actual != expected:
            result["ok"] = False
            bad = list(result.get("bad") or [])
            bad.append("modified: sha256 differs from the hash recorded when this backup was created")
            result["bad"] = bad[:10]
            result["error"] = ("bundle was modified after it was created: it hashes to "
                               f"{actual[:16]}…, the audit log recorded {expected[:16]}…")
        return result
    if actual in set(recorded.values()):
        result["recorded"] = {"found": True, "matched_by": "content", "expected": actual,
                              "actual": actual, "matches": True,
                              "note": "renamed, but the content is a bundle this platform created"}
        return result
    result["recorded"] = {
        "found": False, "actual": actual, "known_bundles": len(recorded),
        "note": (f"neither the name nor the content matches any of the {len(recorded)} bundle(s) "
                 "this platform recorded — it was built elsewhere, or edited and renamed; restoring "
                 "it needs the explicit override")}
    return result


def _verify_open_bundle(tar) -> dict:
    """The checks that need the archive open (called under verify_bundle's guard)."""
    members = {m.name: m for m in tar.getmembers() if m.isfile()}
    if "manifest.json" not in members:
        return {"ok": False, "error": "missing manifest"}
    manifest = json.load(io.BytesIO(tar.extractfile("manifest.json").read()))
    if not isinstance(manifest.get("files"), dict):
        return {"ok": False, "error": "manifest has no files map"}
    listed = set(manifest["files"])
    bad: list[str] = []
    # (1) reject unsafe names and links outright. Directory entries are skipped:
    # `tar.add(bundle, arcname="")` writes the bundle root as a member with an
    # empty name, and directories are never extracted.
    for m in tar.getmembers():
        if m.issym() or m.islnk():
            bad.append(f"link:{m.name}")
            continue
        if m.isfile() and not safe_member_name(m.name):
            bad.append(f"unsafe:{m.name}")
    # (2) every file in the archive must be declared in the manifest
    for name in members:
        if name != "manifest.json" and name not in listed:
            bad.append(f"unlisted:{name}")
    # (3) declared files must be present with matching checksums
    for name, expected in manifest["files"].items():
        if name not in members:
            bad.append(f"missing:{name}")
            continue
        if hashlib.sha256(tar.extractfile(name).read()).hexdigest() != expected:
            bad.append(f"checksum:{name}")
    return {"ok": not bad, "bad": bad[:10], "files": len(manifest["files"])}


def restore_from(tar_path: Path, actor: dict, conn=None) -> dict:
    """Replace the live DB with the backup's DB. Caller must close connections.

    `conn` (SEC-100) lets the pre-restore check compare the bundle against the hash
    the audit log recorded for it.
    """
    v = verify_bundle(conn, tar_path)
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
        listed = set(json.loads(tar.extractfile("manifest.json").read()).get("files") or {})
        for m in tar.getmembers():
            # SEC-085: only manifest-declared evidence files, and only when the
            # resolved path stays inside the evidence directory. Verification
            # already rejects these, but restore must not depend on it.
            if not (m.isfile() and m.name.startswith("evidence/") and m.name in listed):
                continue
            target = contained(ev_dir, m.name.split("/", 1)[1])
            if target is None:
                raise RuntimeError(f"refusing unsafe bundle member: {m.name}")
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
