"""SQLite data access. Local-first: one file, WAL mode, migrations tracked.

Free / zero-budget storage (ADR-001). Swap boundary: all access goes through
this module so a PostgreSQL driver can replace it for production (ADR-007).
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from .config import settings

_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
_lock = threading.Lock()


def utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or settings.db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    # check_same_thread=False: FastAPI runs sync dependency setup/teardown in
    # anyio's LIFO worker pool, and the pool can hand a request's teardown to
    # a different worker than its setup (e.g. when a background scheduler tick
    # runs in between). The connection itself is only touched by one request's
    # sequential operations, so cross-thread close is safe; WAL + busy_timeout
    # serialize writers across connections.
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def migrate(conn: sqlite3.Connection) -> list[str]:
    """Apply pending .sql migrations in name order. Returns applied names."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT)"
    )
    done = {r["name"] for r in conn.execute("SELECT name FROM schema_migrations")}
    applied = []
    for f in sorted(_MIGRATIONS_DIR.glob("*.sql")):
        if f.name in done:
            continue
        conn.executescript(f.read_text())
        conn.execute(
            "INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)",
            (f.name, utcnow()),
        )
        applied.append(f.name)
    conn.commit()
    return applied


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    return [dict(r) for r in rows]


def q(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    return rows_to_dicts(conn.execute(sql, params).fetchall())


def one(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> dict | None:
    return row_to_dict(conn.execute(sql, params).fetchone())


def jdump(v) -> str | None:
    return None if v is None else json.dumps(v)


def decode_json(row: dict | None, *columns: str, default=None) -> dict | None:
    """Copy `row` with JSON-text columns decoded (SEC-091).

    JSON columns are stored as text, and routes decoded them inconsistently: the
    same field was an array in one response and JSON text in another. Clients
    (including this project's own SPA) read the array shape, so a route that
    forgot to decode handed them a string — `mitigations?.join("; ")` does not
    fail on the string, it throws.
    """
    if row is None:
        return None
    out = dict(row)
    for col in columns:
        if col in out:
            out[col] = jload(out.get(col), default)
    return out


def decode_rows(rows: list[dict], *columns: str, default=None) -> list[dict]:
    """Row-list form of `decode_json`."""
    return [decode_json(r, *columns, default=default) or {} for r in rows]


def jload(v: str | None, default=None):
    if v in (None, ""):
        return default
    try:
        return json.loads(v)
    except (ValueError, TypeError):
        return default


def paged(conn: sqlite3.Connection, base_sql: str, params: tuple, order: str,
          page_no: int, page_size: int) -> dict:
    """Standard list response: {items, total, page, page_size}.

    base_sql is a SELECT without ORDER BY/LIMIT (the count is derived from it).
    """
    total_row = one(conn, f"SELECT COUNT(*) AS c FROM ({base_sql})", params)
    total = int(total_row["c"]) if total_row else 0
    items = q(conn, f"{base_sql} {order} LIMIT ? OFFSET ?",
              params + (page_size, (page_no - 1) * page_size))
    return {"items": items, "total": total, "page": page_no, "page_size": page_size}


def get_conn():
    """Yield a per-request connection with the schema guaranteed."""
    with _lock:
        conn = connect()
        migrate(conn)
    try:
        yield conn
    finally:
        conn.close()


def raw_connection():
    """For scripts/tests: connect + migrate, caller closes."""
    conn = connect()
    migrate(conn)
    return conn
