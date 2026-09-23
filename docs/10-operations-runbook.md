# Operations Runbook

Cadence + concrete procedures. All commands assume the repo root as CWD
unless noted; `ADMIN` = an admin session (cookie or `curl -b` handle).

## Daily
- Health: `GET /api/healthz` (200) + `GET /metrics`; disk headroom on the
  data volume; alert pipeline (`/api/soc/alerts?status=new`). Dismissals carry a
  note by design (SEC-081) — when reviewing the queue, `notes` is where the
  false-positive reasoning lives, so a dismissal without one cannot happen.
  - Metrics are internal-only: scrape `http://127.0.0.1:8080/metrics` on the
    host (the public edge answers `403` by design). If `METRICS_TOKEN` is
    set, add `-H "Authorization: Bearer $METRICS_TOKEN"`.
  ```bash
  curl -s http://127.0.0.1:8080/metrics | grep -E "alerts_open|db_size_bytes"
  ```
- Audit: `GET /api/admin/audit` — scan for `auth.failed` bursts,
  `auth.rate_limited` (login brute-force), `agent_tool_denied`, `release.*`.
- Chain: `GET /api/admin/audit/verify` → `ok: true` (tamper evidence).
- Backup: confirm today's backup exists in `data/backups/` (or the backup
  job's output) and note its `sha256`.

## Weekly
- Access: `GET /api/auth/users` — role changes, stale accounts; agent
  allowlists (`GET /api/agents`).
- Supply chain: review CI runs — gitleaks findings, `pip-audit`/`npm audit`
  output, SBOM artifact diff.
- Audit anchor: `GET /api/admin/audit/verify` must be `ok: true` (a
  `truncated`/`linkage`/`gap` reason is an incident, not a warning), and record
  `GET /api/admin/audit/anchor` somewhere the platform does not control — a
  ticket, a log shipper, a signed commit, a dated paper log. That external copy
  is what makes the log tamper-evident against someone who can rewrite the
  database and recompute the chain (SEC-084); the in-DB anchor alone only
  catches tampering that does not bother to update it. To *use* an earlier
  export, check the log against it:
  ```bash
  curl -s -b cookies.txt "http://127.0.0.1:8080/api/admin/audit/verify\
  ?head_seq=<seq>&head_hash=<hash>&rows=<rows>" | jq .external
  ```
  `external.ok: false` means the log no longer contains the event that anchor
  recorded — treat it as tamper, not drift.
- Retention: `GET /api/admin/retention/report` — review `due_for_review`
  (report only; any deletion is a human, audited act, ADR-005).
- Coverage: `GET /api/soc/rules/coverage` — new `gaps` = active rules that
  never fired (tune rule or add scenario, docs/12).
- Engagements: `GET /api/tradecraft/scope` — `expired_engagements` must be
  empty. A lapsed window silently stops authorizing tradecraft work (its
  findings would then be refused), so renew it, or close the exercise out with
  a report, before it lapses. Rolling windows should be extended while work is
  still planned.
- Capacity: run the capacity gate (Monthly in small labs; Weekly if event
  volume is growing):
  ```bash
  cd app/backend && LOAD_TEST_USER=admin LOAD_TEST_PASSWORD=*** \
      .venv/bin/python -m scripts.load_test --http http://127.0.0.1:8080
  ```
  Expect `GATE: PASS` (≥200 ev/s, p95 <10s, detections firing).

## Monthly
- **Restore drill (the real one, not the unit test):**
  ```bash
  cd app/backend
  # in-process (CI-safe, always safe to run):
  .venv/bin/python -m scripts.backup_rehearsal
  # live (stop/restart the real server; authorized, disposable instance):
  LOAD_TEST_USER=admin LOAD_TEST_PASSWORD=*** \
      .venv/bin/python -m scripts.backup_rehearsal \
      --url http://127.0.0.1:8080 \
      --restart-cmd ".venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080"
  ```
  PASS = backup sha256 ok, events_total identical after restore, audit chain
  ok, RTO < 120s. Keep the `data.lost-*` dir the drill creates until the
  restore is verified, then remove it.
- Purple-team validation: run every scenario on staging, confirm each
  expected rule fires (`POST /api/soc/purple-team/run`; UI: /soc → Purple
  team). A failing scenario is a detection regression — fix before the next
  release.
- Review threat model (docs/05), risk register (`planning/risk-register.md`),
  RTO/RPO vs measured drill numbers.
- Patch through the release flow below (staged, reversible).

## Release flow (SEC-064 — the human gate is real)
1. Commit on a branch; push; wait for CI: **all four jobs green**
   (secrets, backend, frontend, supply-chain). Record run IDs.
2. Build the artifact image: `docker build -f app/backend/Dockerfile -t cybersec:<version> .`
3. Deploy to **staging** (infra/staging) — same image as production will run.
4. Run the checklist acceptance (staging): health, login, one detection,
   one report, one backup, restore drill, network matrix check.
5. Complete `docs/14-release-checklist.md` → `RELEASES/<version>-checklist.md`;
   compute `sha256sum`.
6. **Human approval:** an admin records the decision
   (`POST /api/admin/releases` with version, commit sha, checklist sha256,
   `decision: approved`). Confirm the gate:
   `GET /api/admin/releases/latest` → `gate: approved` for that version.
   Anything else (`blocked`, `no_decision`) = **stop**.
7. Promote to production (infra/prod, Caddy TLS). Verify health criteria:
   `/api/healthz`, `/api/overview/stats` sane, login works, audit chain ok,
   `X-Environment` header absent (PROD strips it), HSTS present at the edge.
8. Record the outcome (next release checklist "last release" note).
   On failed health: roll back — `docker compose down`, restore the
   pre-release backup (`POST /api/admin/backup/restore` with
   `confirm: "RESTORE"`), restart, re-verify.

## Incident
1. Preserve relevant logs and evidence (take a backup first:
   `POST /api/admin/backup` — it's hot/WAL-safe).
2. Isolate the affected lab segment (flow matrix zones, docs/03).
3. Revoke exposed credentials; rotate `SECRET_KEY` only with a data reset
   or session invalidation plan (sessions are keyed to it).
4. Identify blast radius and persistence (cases module: open a case, attach
   evidence with a retention label).
5. Recover from known-good state (restore drill procedure above).
6. Verify service + detection health (coverage endpoint: no new gaps).
7. Document timeline, root cause, corrective actions; add a scenario or
   rule if the detection was missed (purple-team scenario so the fix is
   regression-tested).

## Escalation & ownership
- Platform owner: the operator (single-operator lab by design).
- Release approver: must be an admin-role human who is NOT the author of
  the change under review (the gate records `decided_by` in the audit chain).

### Restore safety (SEC-085/086)

Restore only accepts a file that resolves **inside** `data/backups`
(`400 bad_path` otherwise — a path like `/tmp/evil-backups/x` no longer passes
just because it contains the word "backups"). The bundle is verified before
anything is replaced: unlisted members, links, `..`/absolute member names and
checksum mismatches are refused, and an unreadable archive returns
`409 verify_failed: unreadable bundle: ...` instead of a 500. A refusal is
always **before** any file is overwritten, so a bad bundle cannot damage the
live database. Keep `data/backups` writable only by the service account —
whoever can write a bundle can author its manifest.
