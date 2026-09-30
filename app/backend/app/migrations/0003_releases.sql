-- 0003_releases.sql — release approval records (SEC-064).
--
-- Every production/staging release must record a HUMAN decision here before
-- rollout (docs/14). The decision is the gate; the app enforces that a
-- released build's approval row exists and is `approved` (see
-- GET /api/admin/releases/latest + the boot note). Approval is admin-only
-- (release.write) and audit-logged; the row is append-only.

CREATE TABLE IF NOT EXISTS releases (
    id                INTEGER PRIMARY KEY,
    version           TEXT NOT NULL,
    commit_sha        TEXT NOT NULL,
    checklist_sha256  TEXT NOT NULL,
    decision          TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    decided_by        TEXT NOT NULL,
    comment           TEXT,
    created_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_releases_created ON releases (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_releases_version ON releases (version);
