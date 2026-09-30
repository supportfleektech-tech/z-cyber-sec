-- 0004_tradecraft.sql — adversary tradecraft: exploitability reviews + attack
-- chains (SEC-075, "The-Xploiter" persona).
--
-- Why these tables exist: a finding list answers "what is probably wrong". It
-- does not answer the two questions that decide remediation order and bug
-- bounty payout:
--
--   1. Is this ACTUALLY exploitable, under which preconditions, and what
--      evidence proves it?  -> exploitability_reviews
--   2. Can several low-impact issues be chained into one high-impact path?
--      -> attack_chains
--
-- Both are bound to the platform's authorization model: any target named here
-- must appear in the `targets` of an exercise in status `authorized`/`running`
-- (enforced in app/services/tradecraft.py, deny-by-default, denials audited).
-- No table stores exploit payloads; these are reasoning and evidence records.

CREATE TABLE IF NOT EXISTS exploitability_reviews (
    id             INTEGER PRIMARY KEY,
    vuln_id        INTEGER REFERENCES vuln_findings(id) ON DELETE CASCADE,
    exercise_id    INTEGER REFERENCES exercises(id) ON DELETE SET NULL,
    target         TEXT,                -- in-scope target the finding was proven against
    verdict        TEXT NOT NULL CHECK (verdict IN
                     ('exploitable', 'needs_evidence', 'not_exploitable', 'theoretical')),
    trust_boundary TEXT,                -- which boundary is crossed (user->admin, tenant->tenant, edge->internal)
    impact_before  TEXT,                -- impact with preconditions unmet
    impact_after   TEXT,                -- impact once exploited
    preconditions  TEXT,                -- JSON array: what must be true to exploit
    evidence       TEXT,                -- JSON: observed artifacts (request/response, output, screenshot ref)
    reproduction   TEXT,                -- ordered steps, enough for another engineer to repeat
    rationale      TEXT NOT NULL,       -- WHY it works / why it does not (the part a scanner cannot write)
    triage_ready   INTEGER NOT NULL DEFAULT 0,  -- 1 = reportable as-is (policy-checked)
    policy_note    TEXT,                -- e.g. why a theoretical verdict is not reportable
    dedupe_key     TEXT,                -- fingerprint for duplicate clustering (signal-to-noise)
    reviewed_by    TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_expl_reviews_vuln ON exploitability_reviews (vuln_id);
CREATE INDEX IF NOT EXISTS idx_expl_reviews_dedupe ON exploitability_reviews (dedupe_key);
CREATE INDEX IF NOT EXISTS idx_expl_reviews_created ON exploitability_reviews (created_at DESC);

CREATE TABLE IF NOT EXISTS attack_chains (
    id              INTEGER PRIMARY KEY,
    exercise_id     INTEGER REFERENCES exercises(id) ON DELETE SET NULL,
    title           TEXT NOT NULL,
    entry_point     TEXT NOT NULL,      -- where the attacker starts (unauthenticated, low-priv user, ...)
    trust_boundary  TEXT,               -- the boundary the chain ultimately crosses
    steps           TEXT NOT NULL,      -- JSON array: [{order, action, vuln_id, impact, precondition, evidence}]
    combined_impact TEXT NOT NULL,      -- critical | high | medium | low
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'validated', 'rejected')),
    escalation_note TEXT,               -- WHY low impact becomes high (required when impacts do not escalate)
    rationale       TEXT,
    meta            TEXT,
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attack_chains_status ON attack_chains (status);
CREATE INDEX IF NOT EXISTS idx_attack_chains_created ON attack_chains (created_at DESC);
