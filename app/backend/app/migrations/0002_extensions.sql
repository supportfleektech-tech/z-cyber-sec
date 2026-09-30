-- 0002 — platform extensions (SEC-050/056/071/072)
-- Additive only; runs once (schema_migrations tracking).

-- SEC-050: agent adapters. `builtin` = deterministic explicit tool/steps only.
-- `openai_compat` / `cli` = an external brain proposes tool calls; proposals
-- ALWAYS pass through policy.plan_task (allowlist + approval gates). The
-- adapter can never waive its own guardrails (docs/06).
ALTER TABLE agents ADD COLUMN adapter TEXT NOT NULL DEFAULT 'builtin';
ALTER TABLE agents ADD COLUMN adapter_config TEXT;   -- JSON, per-adapter

-- SEC-071: saved searches (user-scoped, named filter sets)
CREATE TABLE IF NOT EXISTS saved_searches (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    owner       TEXT NOT NULL,
    module      TEXT NOT NULL DEFAULT 'soc',   -- 'events' | 'alerts'
    params      TEXT NOT NULL,                 -- JSON query params
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_saved_searches_owner ON saved_searches(owner, module);

-- SEC-071: scheduled reports (in-process scheduler, stdlib only)
CREATE TABLE IF NOT EXISTS report_schedules (
    id                INTEGER PRIMARY KEY,
    kind              TEXT NOT NULL,           -- overview | soc | cases | intel | vulns
    title             TEXT NOT NULL,
    filters           TEXT,                    -- JSON
    interval_minutes  INTEGER NOT NULL DEFAULT 1440,
    last_run_at       TEXT,
    next_run_at       TEXT,
    status            TEXT NOT NULL DEFAULT 'active',  -- active | paused
    created_by        TEXT NOT NULL,
    created_at        TEXT NOT NULL
);
