-- CYBER-SEC initial schema (see docs/04-data-model.md)
-- All timestamps are ISO-8601 UTC strings. All security data carries
-- provenance + data_class (synthetic | verified) + classification.

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    display_name  TEXT,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL,
    ip           TEXT,
    user_agent   TEXT,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    last_seen_at TEXT
);

-- Immutable, hash-chained audit log. Rows are never updated or deleted.
CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY,
    seq         INTEGER NOT NULL UNIQUE,
    ts          TEXT NOT NULL,
    actor_type  TEXT NOT NULL,          -- user | system | agent
    actor_id    TEXT,
    actor_name  TEXT,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    detail      TEXT,                   -- JSON, redacted by callers
    prev_hash   TEXT,
    hash        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    type        TEXT NOT NULL,          -- server | workstation | container | cloud | network | application
    environment TEXT,
    owner       TEXT,
    group_name  TEXT,
    status      TEXT NOT NULL DEFAULT 'active',
    meta        TEXT,                   -- JSON
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integrations (
    id          INTEGER PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    kind        TEXT NOT NULL,          -- feed | exporter | ci | scanner | manual
    status      TEXT NOT NULL DEFAULT 'unknown',
    last_run_at TEXT,
    last_status TEXT,
    config      TEXT,                   -- JSON, secrets NOT allowed here
    provenance  TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    ts              TEXT NOT NULL,
    source_type     TEXT,
    source_name     TEXT,
    host            TEXT,
    user            TEXT,
    action          TEXT,
    outcome         TEXT,
    severity        TEXT,
    msg             TEXT,
    data            TEXT,               -- JSON payload
    data_class      TEXT NOT NULL DEFAULT 'synthetic',
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);

CREATE TABLE IF NOT EXISTS detection_rules (
    id          INTEGER PRIMARY KEY,
    uid         TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    severity    TEXT,
    status      TEXT NOT NULL DEFAULT 'active',
    spec        TEXT NOT NULL,          -- JSON (compiled Sigma-subset spec)
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    rule_id     INTEGER REFERENCES detection_rules(id),
    uid         TEXT,
    title       TEXT NOT NULL,
    severity    TEXT,
    status      TEXT NOT NULL DEFAULT 'new',   -- new | triaging | confirmed | dismissed | closed
    event_ids   TEXT,                   -- JSON array
    first_seen  TEXT,
    last_seen   TEXT,
    count       INTEGER NOT NULL DEFAULT 0,
    assigned_to TEXT,
    notes       TEXT,
    case_id     INTEGER REFERENCES cases(id),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY,
    number      TEXT UNIQUE NOT NULL,   -- e.g. CASE-2026-0001
    title       TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'open',   -- open | investigating | contained | mitigated | closed
    priority    TEXT,                    -- low | medium | high | critical
    severity    TEXT,
    assigned_to TEXT,
    source      TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    closed_at   TEXT
);

CREATE TABLE IF NOT EXISTS case_tasks (
    id          INTEGER PRIMARY KEY,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    assigned_to TEXT,
    due         TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_timeline (
    id         INTEGER PRIMARY KEY,
    case_id    INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    ts         TEXT NOT NULL,
    actor      TEXT,
    entry_type TEXT NOT NULL,           -- note | task | evidence | status | alert | approval
    message    TEXT,
    meta       TEXT                     -- JSON
);

-- Evidence files live on disk under data/evidence (0600); only metadata
-- lives here. Downloads require evidence.download permission and are audited.
CREATE TABLE IF NOT EXISTS evidence (
    id             INTEGER PRIMARY KEY,
    case_id        INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    path           TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    size           INTEGER,
    classification TEXT NOT NULL DEFAULT 'internal',
    retention      TEXT,
    uploaded_by    TEXT,
    created_at     TEXT NOT NULL,
    meta           TEXT
);

CREATE TABLE IF NOT EXISTS intel_sources (
    id          INTEGER PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    kind        TEXT,                   -- osint | commercial | internal | ioc_feed
    reliability TEXT,                   -- a..f (STIX-like)
    description TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_indicators (
    id                INTEGER PRIMARY KEY,
    type              TEXT NOT NULL,     -- ip | domain | url | sha256 | email
    value             TEXT NOT NULL,
    confidence        INTEGER,           -- 0..100
    source_id         INTEGER REFERENCES intel_sources(id),
    status            TEXT NOT NULL DEFAULT 'active',
    ttl_hours         INTEGER,
    first_seen        TEXT,
    last_seen         TEXT,
    mitre_tactics     TEXT,              -- JSON array
    mitre_techniques  TEXT,              -- JSON array
    notes             TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    UNIQUE(type, value)
);

CREATE TABLE IF NOT EXISTS vuln_findings (
    id             INTEGER PRIMARY KEY,
    asset_id       INTEGER REFERENCES assets(id),
    cve_id         TEXT,
    title          TEXT NOT NULL,
    cvss           REAL,
    severity       TEXT,
    status         TEXT NOT NULL DEFAULT 'new',  -- new | triaged | in_progress | fixed | accepted_risk
    exploitability TEXT,
    description    TEXT,
    source         TEXT,
    discovered_at  TEXT,
    due_date       TEXT,
    fixed_at       TEXT,
    meta           TEXT,
    UNIQUE(asset_id, cve_id, title)
);

CREATE TABLE IF NOT EXISTS finding_exceptions (
    id          INTEGER PRIMARY KEY,
    vuln_id     INTEGER NOT NULL REFERENCES vuln_findings(id) ON DELETE CASCADE,
    reason      TEXT NOT NULL,
    approved_by TEXT,
    expires_at  TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remediation_tasks (
    id          INTEGER PRIMARY KEY,
    vuln_id     INTEGER NOT NULL REFERENCES vuln_findings(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    owner       TEXT,
    due         TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id             INTEGER PRIMARY KEY,
    repo           TEXT NOT NULL,
    kind           TEXT,                -- sast | dependency | container | iaas
    status         TEXT NOT NULL DEFAULT 'running',
    started_at     TEXT,
    finished_at    TEXT,
    findings_total INTEGER DEFAULT 0,
    findings_new   INTEGER DEFAULT 0,
    ci_url         TEXT,
    meta           TEXT
);

CREATE TABLE IF NOT EXISTS appsec_findings (
    id                  INTEGER PRIMARY KEY,
    scan_run_id         INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    rule_id             TEXT,
    severity            TEXT,
    file                TEXT,
    line                INTEGER,
    message             TEXT,
    status              TEXT NOT NULL DEFAULT 'open',
    suppression_reason  TEXT,
    created_at          TEXT NOT NULL,
    UNIQUE(scan_run_id, rule_id, file, line)
);

CREATE TABLE IF NOT EXISTS cloud_assets (
    id          INTEGER PRIMARY KEY,
    provider    TEXT,
    account     TEXT,
    region      TEXT,
    type        TEXT NOT NULL,
    name        TEXT NOT NULL,
    status      TEXT DEFAULT 'active',
    meta        TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS posture_findings (
    id          INTEGER PRIMARY KEY,
    asset_id    INTEGER NOT NULL REFERENCES cloud_assets(id) ON DELETE CASCADE,
    rule_id     TEXT,
    title       TEXT NOT NULL,
    severity    TEXT,
    status      TEXT NOT NULL DEFAULT 'open',
    detail      TEXT,
    checked_at  TEXT,
    meta        TEXT
);

CREATE TABLE IF NOT EXISTS controls (
    id          INTEGER PRIMARY KEY,
    framework   TEXT NOT NULL,
    code        TEXT NOT NULL,
    title       TEXT NOT NULL,
    category    TEXT,
    owner       TEXT,
    status      TEXT NOT NULL DEFAULT 'not_started',  -- not_started | in_progress | met | gap
    next_review TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE(framework, code)
);

CREATE TABLE IF NOT EXISTS risks (
    id          INTEGER PRIMARY KEY,
    title       TEXT NOT NULL,
    description TEXT,
    likelihood  INTEGER,   -- 1..5
    impact      INTEGER,   -- 1..5
    score       INTEGER,
    status      TEXT NOT NULL DEFAULT 'open',  -- open | mitigating | accepted | closed
    owner       TEXT,
    mitigations TEXT,      -- JSON array
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_evidence (
    id          INTEGER PRIMARY KEY,
    control_id  INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    path        TEXT,
    sha256      TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exercises (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    scope       TEXT NOT NULL,          -- written, authorized scope
    status      TEXT NOT NULL DEFAULT 'planned',  -- planned | authorized | running | completed | aborted
    owner       TEXT,
    starts_at   TEXT,
    ends_at     TEXT,
    targets     TEXT,                   -- JSON array
    meta        TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exercise_runs (
    id           INTEGER PRIMARY KEY,
    exercise_id  INTEGER NOT NULL REFERENCES exercises(id) ON DELETE CASCADE,
    started_at   TEXT,
    finished_at  TEXT,
    result       TEXT,
    detail       TEXT                   -- JSON
);

CREATE TABLE IF NOT EXISTS agents (
    id          INTEGER PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    provider    TEXT,                   -- opencode | openclaw | hermes | internal
    role        TEXT,
    scope       TEXT,                   -- JSON: allowed scopes, e.g. {"modules": [...]}
    tools       TEXT NOT NULL,          -- JSON array: tool allowlist (governance doc 06)
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_tasks (
    id           INTEGER PRIMARY KEY,
    agent_id     INTEGER NOT NULL REFERENCES agents(id),
    title        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending | awaiting_approval | running | completed | failed | denied
    request      TEXT,               -- JSON
    result       TEXT,               -- JSON (truthful: null until finished)
    approval_id  INTEGER REFERENCES approvals(id),
    created_at   TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT
);

CREATE TABLE IF NOT EXISTS tool_calls (
    id       INTEGER PRIMARY KEY,
    -- logical reference (NULL before the task row exists; may reference a
    -- playbook run id when called from automation — no hard FK on purpose)
    task_id  INTEGER,
    tool     TEXT NOT NULL,
    args     TEXT,
    allowed  INTEGER NOT NULL,
    reason   TEXT,
    result   TEXT,   -- JSON
    ts       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    id           INTEGER PRIMARY KEY,
    -- logical reference: agent_tasks(id) for agent approvals, or 0 / a
    -- playbook_runs(id) for automation — no hard FK (multiple owners)
    task_id      INTEGER NOT NULL DEFAULT 0,
    action       TEXT NOT NULL,        -- the consequential action requiring a human
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
    requested_by TEXT,
    decided_by   TEXT,
    decision     TEXT,
    comment      TEXT,
    created_at   TEXT NOT NULL,
    decided_at   TEXT
);

CREATE TABLE IF NOT EXISTS playbooks (
    id          INTEGER PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    description TEXT,
    trigger     TEXT,                  -- manual | on_alert:<severity>
    steps       TEXT NOT NULL,         -- JSON array [{tool, args}]
    status      TEXT NOT NULL DEFAULT 'active',
    auto_run    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS playbook_runs (
    id           INTEGER PRIMARY KEY,
    playbook_id  INTEGER NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    trigger      TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending | running | completed | failed
    started_at   TEXT,
    finished_at  TEXT,
    result       TEXT                   -- JSON
);

CREATE TABLE IF NOT EXISTS reports (
    id           INTEGER PRIMARY KEY,
    kind         TEXT NOT NULL,         -- overview | soc | cases | intel | vulns
    title        TEXT NOT NULL,
    filters      TEXT,                  -- JSON
    generated_by TEXT,
    created_at   TEXT NOT NULL,
    path         TEXT NOT NULL,
    meta         TEXT                   -- JSON provenance
);

CREATE TABLE IF NOT EXISTS feature_flags (
    id          INTEGER PRIMARY KEY,
    key         TEXT UNIQUE NOT NULL,
    value       INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
