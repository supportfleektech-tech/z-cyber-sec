-- 0005_audit_anchor.sql (SEC-084)
--
-- The audit log is hash-chained, which detects modification of a row but NOT
-- deletion of the tail: removing the newest rows leaves a chain whose every
-- remaining link still verifies, so verify_chain() returned ok for exactly the
-- tamper that erases the evidence of what someone just did.
--
-- The anchor records how much history existed. One row (id=1), updated in the
-- same transaction as every append. Deliberately NOT in `settings`: that table
-- has a generic write endpoint (/api/admin/settings/{key}), and an anchor an
-- admin can rewrite proves nothing.
--
-- What this does and does not prove is documented in docs/04-data-model.md:
-- an attacker who rewrites the whole database can rewrite the anchor too, so
-- the anchor is meant to be exported externally (GET /api/admin/audit/anchor,
-- runbook step) — that external copy is what closes the loop.

CREATE TABLE IF NOT EXISTS audit_anchor (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    rows        INTEGER NOT NULL,
    head_seq    INTEGER NOT NULL,
    head_hash   TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);
