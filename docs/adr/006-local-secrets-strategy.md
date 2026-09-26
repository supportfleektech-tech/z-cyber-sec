# ADR-006: Local secrets strategy

**Status:** Accepted
**Date:** 2026-09-21

## Context

The platform needs a `SECRET_KEY` (session integrity, signing) and must
never put real credentials in the repo, logs, prompts, or artifacts. The
lab is single-operator and often offline, so an external secrets manager is
out; the strategy has to work with files on the host and the environment.

## Decision

- **Environment-driven config** (`app/config.py`): every secret comes from
  the environment or `.env`; **`.env` is gitignored**, and a committed
  `.env.example` documents the shape (values are placeholders).
- **Boot guard:** if `ENV_NAME` is `STAGING` or `PROD`, the process
  **refuses to start** unless `SECRET_KEY` is a strong unique value: the
  committed dev default, unedited template placeholders (`__SET__`,
  `changeme`, …), and anything shorter than 32 chars are all rejected.
  There is no "it works, remember to change it later" path. (Hardened
  2026-09-21: the original guard only caught the dev default; an operator
  who copied `.env.example` without editing would have booted on
  `__SET__`.)
- **Synthetic credentials by default:** the seed creates lab accounts
  (e.g. `admin / CyberSecAdmin1!`) that exist **only** in the local
  synthetic database; no real identity, API key, or token is ever written
  to the repo, docs, tests, or fixtures.
- **What is stored where:**
  - repo: nothing secret (only `.env.example`, placeholder values);
  - `.env` (host, gitignored): `SECRET_KEY`, optional overrides
    (`ENV_NAME`, `PORT`, `DATA_DIR`, `TOKEN_TTL_HOURS`, `DEV_ORIGIN`);
  - database: **password hashes only** (PBKDF2, ADR-002) — never
    plaintext; session rows store `SHA-256(token)`, never the token.
- **Agent rule:** secrets are never pasted into agent context, commit
  messages, or test output; CI adds a secret-scan step (gitleaks via free
  tooling) in the hardening phase (SEC-062).

## Consequences

- A fresh clone boots fully offline with zero secrets (dev defaults are
  safe *because* the environment is labeled `LOCAL` and network-bounded).
- The dev-default boot guard is the main tripwire against a secret leak:
  anyone who promotes the env label without a real key gets a loud
  startup failure instead of a silent weak key.
- `.env` rotation = edit one file + restart; the 12h session TTL
  (`TOKEN_TTL_HOURS`) bounds the blast radius of a copied cookie.
- Known limitation: `.env` is file-permission-protected, not
  hardware-backed; production (ADR-007) moves the source of `SECRET_KEY`
  to the host's secret store.
