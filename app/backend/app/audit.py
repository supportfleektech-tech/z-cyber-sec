"""Immutable, hash-chained audit log (docs/04-data-model.md, governance doc 06).

Each row's hash covers seq, ts, actor, action, target, detail and the previous
row's hash, so any modification of history is detectable via verify_chain().
Rows are INSERT-only: no UPDATE/DELETE paths exist in the codebase.
"""
from __future__ import annotations

import hashlib
import json

from .db import utcnow

GENESIS = "0" * 64


def _canonical(seq: int, ts: str, actor_type: str, actor_id: str | None, actor_name: str | None,
               action: str, target_type: str | None, target_id: str | None,
               detail_str: str | None, prev_hash: str) -> str:
    return "|".join([
        str(seq), ts, actor_type, actor_id or "", actor_name or "", action,
        target_type or "", target_id or "", detail_str or "", prev_hash,
    ])


def compute_hash(seq: int, ts: str, actor_type: str, actor_id: str | None, actor_name: str | None,
                 action: str, target_type: str | None, target_id: str | None,
                 detail_str: str | None, prev_hash: str) -> str:
    return hashlib.sha256(_canonical(
        seq, ts, actor_type, actor_id, actor_name, action,
        target_type, target_id, detail_str, prev_hash,
    ).encode()).hexdigest()


def record_audit(conn, actor: dict, action: str, target_type: str | None = None,
                 target_id: str | None = None, detail: dict | None = None) -> int:
    """Append one audit row. actor = {type: user|system|agent, id, name}."""
    row = conn.execute("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
    seq = (row["seq"] + 1) if row else 1
    prev_hash = row["hash"] if row else GENESIS
    ts = utcnow()
    detail_str = None if detail is None else json.dumps(detail, sort_keys=True, separators=(",", ":"))
    h = compute_hash(seq, ts, actor.get("type", "system"), actor.get("id"), actor.get("name"),
                     action, target_type, target_id, detail_str, prev_hash)
    cur = conn.execute(
        "INSERT INTO audit_events (seq, ts, actor_type, actor_id, actor_name, action, "
        "target_type, target_id, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (seq, ts, actor.get("type", "system"), actor.get("id"), actor.get("name"), action,
         target_type, target_id, detail_str, prev_hash, h),
    )
    conn.commit()
    return int(cur.lastrowid)


def verify_chain(conn) -> dict:
    """Recompute every hash. Returns {ok, rows, first_bad_seq}."""
    rows = conn.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
    prev = GENESIS
    for r in rows:
        expected = compute_hash(
            r["seq"], r["ts"], r["actor_type"], r["actor_id"], r["actor_name"],
            r["action"], r["target_type"], r["target_id"], r["detail"], prev,
        )
        if expected != r["hash"] or (r["prev_hash"] or GENESIS) != prev:
            return {"ok": False, "rows": len(rows), "first_bad_seq": r["seq"]}
        prev = r["hash"]
    return {"ok": True, "rows": len(rows), "first_bad_seq": None}
