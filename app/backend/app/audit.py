"""Immutable, hash-chained audit log (docs/04-data-model.md, governance doc 06).
SEC-084: each append also updates an anchor (audit_anchor) recording how much
history existed, so *deletion* of the newest rows is detectable — a plain hash
chain cannot see its own tail. The anchor lives in its own table (not
`settings`, which has a generic admin write endpoint).

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
    # SEC-084: record how much history exists, in the same transaction. Without
    # this the chain verifies just as happily after the newest rows are deleted.
    # Count actual rows rather than assuming rows == seq: a log that already had
    # a gap before anchoring existed must not be reported as tampered afterwards.
    n_rows = conn.execute("SELECT COUNT(*) c FROM audit_events").fetchone()["c"]
    # The anchor is monotonic in both size and sequence: it remembers the
    # furthest point history ever reached, and never relaxes. Counting rows
    # alone is not enough — an attacker can delete rows and then replenish the
    # count with fresh activity; pinning the (seq, hash) of the furthest event
    # means the deleted history can never be quietly replaced, because sequence
    # numbers are reused after a deletion and the anchored row would then exist
    # with a different hash. (Both laundering paths were found by verifying the
    # first version of this fix.) The first write on a legacy DB uses the real
    # values and does not pretend to know more than it does.
    conn.execute(
        "INSERT INTO audit_anchor (id, rows, head_seq, head_hash, updated_at) VALUES (1, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "rows = MAX(audit_anchor.rows, excluded.rows), "
        # strictly greater: an append must never re-point the anchor at a
        # different event that happens to have reused the same seq number after
        # a deletion (that is the laundering path this closes)
        "head_hash = CASE WHEN excluded.head_seq > audit_anchor.head_seq "
        "                 THEN excluded.head_hash ELSE audit_anchor.head_hash END, "
        "head_seq = MAX(audit_anchor.head_seq, excluded.head_seq), "
        "updated_at = excluded.updated_at",
        (n_rows, seq, h, ts),
    )
    conn.commit()
    return int(cur.lastrowid)


def anchor(conn) -> dict | None:
    """The recorded head of the log (rows, seq, hash) — export this externally."""
    row = conn.execute("SELECT * FROM audit_anchor WHERE id = 1").fetchone()
    return dict(row) if row else None


def verify_against_anchor(rows, against: dict) -> dict:
    """Check the current log against an anchor recorded earlier (SEC-084).

    This is what makes an *exported* anchor useful. A single in-database anchor
    moves forward as new events are appended, so history deleted before that
    point becomes invisible to it; a copy recorded elsewhere (ticket, log
    shipper, signed commit — docs/10) still claims the event that is gone.
    """
    head_seq = int(against.get("head_seq") or 0)
    row = next((r for r in rows if r["seq"] == head_seq), None)
    if row is None:
        return {"ok": False, "reason": "missing",
                "detail": f"the anchored event at seq {head_seq} is not in the log"}
    if row["hash"] != against.get("head_hash"):
        return {"ok": False, "reason": "replaced",
                "detail": (f"seq {head_seq} exists but hashes to {row['hash'][:16]}…, not the "
                           f"anchored {str(against.get('head_hash'))[:16]}… (sequence numbers are "
                           "reused after a deletion)")}
    if against.get("rows") is not None and len(rows) < int(against["rows"]):
        return {"ok": False, "reason": "truncated",
                "detail": f"anchor recorded {against['rows']} events, the log has {len(rows)}"}
    return {"ok": True, "reason": None, "head_seq": head_seq}


def _anchoring_expected(conn) -> bool:
    """True if this database has the anchoring migration applied (SEC-099)."""
    try:
        return any(r["name"] == "0005_audit_anchor.sql"
                   for r in conn.execute("SELECT name FROM schema_migrations"))
    except Exception:  # very old/partial DB without the table: can't conclude
        return False


def verify_chain(conn, against: dict | None = None) -> dict:
    """Recompute every hash and compare against the anchor.

    Sets `reason` so the operator knows which question failed: `linkage`
    (a row was modified or removed mid-log), `gap` (seq numbers are not
    contiguous) or `truncated` (history that the anchor recorded is gone).
    """
    rows = conn.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()

    def _with_external(res: dict) -> dict:
        if against:
            res["external"] = verify_against_anchor(rows, against)
        return res

    prev = GENESIS
    expected_seq = 1
    for r in rows:
        expected = compute_hash(
            r["seq"], r["ts"], r["actor_type"], r["actor_id"], r["actor_name"],
            r["action"], r["target_type"], r["target_id"], r["detail"], prev,
        )
        if expected != r["hash"] or (r["prev_hash"] or GENESIS) != prev:
            return {"ok": False, "rows": len(rows), "first_bad_seq": r["seq"],
                    "reason": "linkage"}
        if r["seq"] != expected_seq:
            return {"ok": False, "rows": len(rows), "first_bad_seq": expected_seq,
                    "reason": "gap"}
        expected_seq += 1
        prev = r["hash"]

    a = anchor(conn)
    if a is None:
        if rows and _anchoring_expected(conn):
            # SEC-099: the anchoring migration is applied and the log is not empty,
            # so the anchor row existed and was deleted. Reporting this as an
            # intact-but-unanchored log let a single DELETE turn a detected
            # truncation into a passing check — the laundering path SEC-084 set out
            # to close. Deleting history *and* its anchor is still tampering.
            return _with_external({
                "ok": False, "rows": len(rows), "first_bad_seq": None,
                "reason": "anchor_missing", "anchor": None,
                "detail": ("the anchor row is gone although the anchoring migration is applied and "
                           "the log is not empty — the anchor is written with every append and is "
                           "removed by nothing else, so history has been tampered with "
                           "(compare against an anchor exported earlier to see what is missing)")})
        # A log written before the anchor existed (or a brand-new DB): the links
        # verify, but truncation cannot be ruled out for history that predates
        # anchoring. Say so instead of implying more confidence than we have.
        return _with_external({
            "ok": True, "rows": len(rows), "first_bad_seq": None,
            "reason": None if not rows else "unanchored", "anchor": None,
            "warning": None if not rows else
            ("no anchor recorded — an intact chain cannot rule out that history was "
             "truncated before anchoring began")})
    anch = {"rows": a["rows"], "head_seq": a["head_seq"], "head_hash": a["head_hash"]}
    if len(rows) < int(a["rows"]):
        return {"ok": False, "rows": len(rows), "first_bad_seq": len(rows) + 1,
                "reason": "truncated", "missing_rows": int(a["rows"]) - len(rows), "anchor": anch}
    # The furthest event history ever reached must still be there, unchanged.
    # Checking only the newest row (or the count) lets an attacker delete the
    # tail and replenish it with new activity.
    head_seq = int(a["head_seq"])
    head_row = next((r for r in rows if r["seq"] == head_seq), None)
    if head_row is None or head_row["hash"] != a["head_hash"]:
        return _with_external({"ok": False, "rows": len(rows), "first_bad_seq": head_seq,
                               "reason": "truncated", "anchor": anch,
                               "detail": (f"the event history recorded at seq {head_seq} is gone or "
                                          "has been replaced (sequence numbers are reused after a "
                                          "deletion)")})
    if rows and rows[-1]["seq"] != head_seq:
        # Rows beyond the anchored head: appended without being anchored, which
        # the append path never does.
        return {"ok": False, "rows": len(rows), "first_bad_seq": head_seq + 1,
                "reason": "unaccounted", "anchor": anch}
    result = {"ok": True, "rows": len(rows), "first_bad_seq": None, "reason": None,
              "anchor": {"rows": a["rows"], "head_seq": a["head_seq"],
                         "head_hash": a["head_hash"]}}
    if against:
        result["external"] = verify_against_anchor(rows, against)
    return result
