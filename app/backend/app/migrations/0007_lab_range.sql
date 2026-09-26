-- 0007_lab_range.sql — the local training range registry (SEC-115).
--
-- The platform's exercises authorize *targets*, and the tradecraft scope guard
-- refuses work outside them — but nothing recorded which targets actually exist
-- in the lab, whether they are running, or which image each one is. So an
-- exercise could be (and was, in the demo seed) authorized against a hostname
-- that no container ever served: a written authorization pointing at nothing.
--
-- This registry is the source of truth for that half of the range:
--   * `name` is what an exercise lists in `targets`;
--   * `endpoint` is the real address inside the lab network (never a public one);
--   * `image`/`kind`/`exposure` say what it is and how dangerous it is;
--   * `status` tracks whether it is running, so the UI can tell "authorized but
--     not up" apart from "up and out of scope" — the two mistakes that make a
--     range session either pointless or unsafe.
--
-- Deliberately vulnerable images live ONLY on the isolated `lab_range` docker
-- network (infra/lab/docker-compose.yml), never on the platform network.

CREATE TABLE IF NOT EXISTS lab_targets (
    id          INTEGER PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,       -- what exercises.targets lists
    kind        TEXT NOT NULL,              -- web | api | network | host | cloud
    endpoint    TEXT NOT NULL,              -- host:port inside the lab network
    image       TEXT,                       -- container image / VM profile
    exposure    TEXT NOT NULL DEFAULT 'low',-- critical | high | medium | low (risk if reached from outside)
    status      TEXT NOT NULL DEFAULT 'registered',  -- registered | running | stopped | retired
    purpose     TEXT,                       -- which skill the target exercises
    notes       TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_lab_targets_status ON lab_targets (status);
