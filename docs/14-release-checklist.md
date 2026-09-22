# Release checklist & human approval gate (SEC-064)

Release flow (docs/09): **Commit → CI gates → reviewed artifact → staging →
acceptance → human approval → production rollout → health checks → release
record.** This page defines the two human-side artifacts: the checklist, and
the recorded approval.

## 1. The checklist artifact

A release is not approvable without a checklist file. Contents (copy into
`RELEASES/<version>-checklist.md` on the target host or in the release
ticket — never commit signed checklists to the repo):

```markdown
# CYBER-SEC release checklist — v<version> (<commit sha>)
Date (UTC): ____   Approver (human, name + role): ____

## Quality gates (all must be green)
- [ ] CI backend job: ruff clean + full pytest suite passed (run ID: ___)
- [ ] CI frontend job: tsc + vite build passed (run ID: ___)
- [ ] CI supply-chain job: SBOM generated, pip-audit + npm audit reviewed (findings: ___)
- [ ] CI gitleaks: no secret findings (run ID: ___)
- [ ] Capacity gate: tests/test_capacity.py passed (part of backend job)

## Safety gates (all must pass)
- [ ] Backup rehearsal drill PASS for this build: `python -m scripts.backup_rehearsal`
      (RTO < 120s, events match, audit chain intact) — report attached: ___
- [ ] Migration review: new .sql migrations are additive, tested, rollback-safe (list: ___)
- [ ] Data class confirmed synthetic for staging (ENV_NAME, X-Data-Class header)
- [ ] Secrets: STAGING/PROD SECRET_KEY generated fresh (openssl rand -hex 32),
      not the dev default, in env only (never in repo) — ADR-006
- [ ] Network: flow matrix applied on target host (infra/network/validate_flows.sh → PASS)
- [ ] TLS (prod): Caddy ACME certificate active for <domain>; HSTS header present
- [ ] Caddyfile loads on the stock image (SEC-073): the file must use stock directives
      only — `docker compose --profile prod run --rm caddy caddy validate
      --config /etc/caddy/Caddyfile`. (`rate_limit` is NOT a stock directive.)
- [ ] Login rate limiting verified IN-APP (SEC-073): 50 attempts / 10 s per IP by
      default in STAGING/PROD → the 51st returns `429` + `Retry-After`
      (it is not an edge control; do not look for it in the Caddyfile)
- [ ] `/metrics` not publicly reachable (SEC-073): `curl -s -o /dev/null -w '%{http_code}'
      https://<domain>/metrics` → `403`, while the internal bind serves it
      (`curl -s http://127.0.0.1:8080/metrics`, plus the bearer token if `METRICS_TOKEN` is set)
- [ ] Unknown API path returns JSON, not the SPA (SEC-073):
      `curl -s -o /dev/null -w '%{http_code}' https://<domain>/api/nope` → `404`
- [ ] Detection rules all compile (SEC-074): `python -m scripts.lint_rules` → exit 0
- [ ] Tradecraft guardrails intact (SEC-075/076/077): `GET /api/tradecraft/scope` lists
      only targets of authorized/running exercises **with an in-force authorization
      window** (`expired_engagements` empty); an out-of-scope review is refused with
      `400` AND appears as `tradecraft.out_of_scope` in the audit log

## Rollout plan
- [ ] Backup of current production data taken and verified (sha256 recorded)
- [ ] Rollback command documented: `docker compose ... down` + restore latest backup
      (see docs/10 runbook)
- [ ] Health criteria after rollout: /api/healthz 200, /api/overview/stats sane,
      login works, audit chain verifies
```

**Signing:** compute the sha256 of the completed checklist file:

```bash
sha256sum RELEASES/v<version>-checklist.md   # → 64-hex string
```

## 2. Recording the human decision (the gate)

Only an **admin** (`release.write`) records decisions. This is the
human-approval step of the release flow — the API refuses everything else
and audit-logs the decision with the acting user:

```bash
curl -b <admin-session> -X POST https://<domain>/api/admin/releases \
  -H 'Content-Type: application/json' \
  -d '{"version":"1.1.0","commit_sha":"<full sha>","checklist_sha256":"<64 hex>",
       "decision":"approved","comment":"All gates green, drill PASS, rollback ready"}'
```

- `decision` is `approved` **or** `rejected` (a recorded "no" is valid and
  blocks rollout).
- The gate view is `GET /api/admin/releases/latest` →
  `{"gate": "approved" | "blocked" | "no_decision"}`. **Rollout tooling and
  operators must see `approved` for the exact version + commit they intend to
  promote.** A `blocked`/`no_decision` gate means: stop.
- The UI surfaces the same gate on the Admin page (Release section).

## 3. What this gate does and does not do

- **Does:** enforce that a named human made a decision; bind the decision to
  an exact commit and a specific checklist artifact (sha256); keep an
  append-only, audit-chained record.
- **Does not:** replace the other gates. The checklist items must be true
  before the decision is recorded — the platform verifies the *record*, the
  approver vouches for the *facts*. CI verifies the quality gates
  independently of any human.
