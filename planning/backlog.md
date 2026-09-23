# Prioritized Implementation Backlog

Priority: P0 = prerequisite/blocker; P1 = core; P2 = expansion; P3 = later optimization.

Status as of 2026-09-23 (branch `arena/01a0c152-z-cyber-sec`): **54/54 closed** — see docs/13 for verification evidence.

## P0 — Discover and protect
- [x] SEC-001 Inventory host, OS, resources, storage, ports, Docker networks/volumes. (docs/01)
- [x] SEC-002 Inventory existing repo and reconcile uploaded source. (docs/00)
- [x] SEC-003 Map current services and identify port/volume conflicts. (docs/01; platform isolated to :8080)
- [x] SEC-004 Establish backup and rollback before changes. (no existing host services touched; platform backup/restore implemented + tested)
- [x] SEC-005 Threat model and define authorized test scope. (docs/05)
- [x] SEC-006 Choose local resource profile and integration priorities. (planning/*)

## P0 — Engineering foundation
- [x] SEC-010 Create repo structure and contributor/agent rules. (README, docs/00, .gitignore)
- [x] SEC-011 Add CI formatting, lint, tests, secret scanning. (`.github/workflows/ci.yml`: gitleaks full-history scan (config `gitleaks.toml`, synthetic-data allowlist) + ruff + pytest + tsc build)
- [x] SEC-012 Create ADRs for framework, auth, SIEM, data, secrets. (docs/adr/001–007)
- [x] SEC-013 Define API conventions, schemas, error model, audit format. (docs/12, ADR-004)

## P1 — Core application
- [x] SEC-020 Implement auth/session lifecycle and RBAC. (ADR-002; tests/test_auth.py, test_rbac.py)
- [x] SEC-021 Implement server-side object authorization tests. (tests/test_rbac.py, test_security.py)
- [x] SEC-022 Implement audit event pipeline. (hash-chained, verify endpoint; tests)
- [x] SEC-023 Build responsive dashboard shell and environment labels. (React SPA, env badge, 13 pages)
- [x] SEC-024 Implement asset/integration inventory. (`/api/assets`, `/api/admin/integrations` + health)
- [x] SEC-025 Implement synthetic demo data with explicit labeling. (`data_class='synthetic'`, seed module)

## P1 — Defensive workflows
- [x] SEC-030 Select and deploy one telemetry/SIEM profile. (ADR-003: in-process Sigma-subset engine)
- [x] SEC-031 Ingest benign synthetic events and validate detections. (tests/test_detection.py; seed events)
- [x] SEC-032 Alert triage and case lifecycle. (SOC + cases modules)
- [x] SEC-033 Evidence metadata, access control, provenance, export. (ADR-005; permission split upload/download)
- [x] SEC-034 Threat indicator ingestion with source/confidence. (STIX subset import, lifecycle, correlation)
- [x] SEC-035 Vulnerability finding import, triage, remediation tracking. (CSV/JSON import, exceptions, remediation)
- [x] SEC-036 AppSec pipeline and findings integration. (scan runs, findings, SARIF, suppression)
- [x] SEC-037 Reporting and audit export. (kinds, sha256 provenance, audit log + verify)

## P1 — Infrastructure and reliability
- [x] SEC-040 Isolated networks and flow matrix. (Design docs/03 + `infra/network/nftables.conf` + `validate_flows.sh` implement the matrix; host-side apply is a target-host task — unapplied in sandbox, treated as Proposed there)
- [x] SEC-041 Health checks, logs, metrics, resource limits. (`/api/healthz`, `/metrics`, uvicorn logs; limits = single-process, documented)
- [x] SEC-042 Backup automation and demonstrated restore. (API-triggered backup w/ sha256; restore with typed confirm; round-trip tested — scheduled cron left to ops, P3)
- [x] SEC-043 Capacity/load test with expected event volume. (`scripts/load_test.py`: in-process 3.9k ev/s @20k, 6.7k ev/s @50k; **live-uvicorn HTTP mode verified: 4,501 ev/s @20k (p95 90ms), GATE PASS**; `tests/test_capacity.py` fast-suite floor)
- [x] SEC-044 Local deployment/rollback runbook. (docs/08, docs/10)

## P2 — AI and advanced modules
- [x] SEC-050 Inventory actual OpenCode/OpenClaw/Hermes capabilities. (Capability contract wired: builtin + openai_compat (local LLM, key-by-env-name) + cli adapters in `services/agent_adapters.py`; prompt→plan through the gateway; allowlist/bypass tested in test_extensions.py. Live local-model E2E = Proposed)
- [x] SEC-051 Build scoped agent gateway and tool allowlist. (read-only auto-run, consequential = approval, out-of-allowlist denied)
- [x] SEC-052 Add approval queue and immutable audit events. (approvals endpoint + decide; hash-chained audit)
- [x] SEC-053 Agent evals: prompt injection, scope, timeout, truthful status. (`POST /api/agents/evals/run`; tests/test_agents.py)
- [x] SEC-054 Add cloud posture and GRC modules. (cloud + grc routers/pages)
- [x] SEC-055 Add isolated CTF/exercise orchestration. (authorized lifecycle, reason-on-complete, run log)
- [x] SEC-056 Add detection coverage and purple-team validation. (`GET /api/soc/rules/coverage` + `scenarios/pt-00{1,2,3}-*.yaml` replayed through live detection (`POST /api/soc/purple-team/run`); UI panel on /soc; rerun dedupe + audit verified)

## P2 — Production readiness
- [x] SEC-060 Provision separate staging. (`infra/staging/` compose + env: separate volume/network/secret, HTTP-only on staging LAN, same image as prod, synthetic-labeled; actual host provisioning = ops task)
- [x] SEC-061 Production secrets, TLS, ingress, access controls. (Boot guard; Caddy ACME TLS + security headers; `ForwardedHeadersMiddleware` → Secure cookie + real client IP behind the edge; env templates. Edge rate limiting was replaced by the in-app limiter in SEC-073 — the stock `caddy:2` image cannot load `rate_limit`, so it would have been a control that existed nowhere. Actual deployment = ops task on the target host)
- [x] SEC-062 SBOM, dependency/image scanning, release provenance. (CI `supply-chain` job: CycloneDX SBOM from pinned requirements + pip-audit + npm audit; gitleaks secret scan; image scan/signed releases = Proposed for the registry stage)
- [x] SEC-063 RTO/RPO, backup isolation, restore/rollback rehearsal. (`scripts/backup_rehearsal.py`: in-process drill PASS (342/342, RTO 0.01s) AND live drill PASS (real uvicorn stop/start: 423/423 events, chain intact, RTO 16.68s; lost files preserved in data.lost-*)
- [x] SEC-064 Production acceptance and human release approval. (Release gate built: `POST/GET /api/admin/releases` + `/latest` gate view (admin-only, audit-chained, append-only) + Admin UI + `docs/14` checklist. The human approval act itself is recorded at deploy time by an admin — the platform enforces the gate, it does not simulate the human)

## P3 — Optimization
- [x] SEC-070 Capacity-based service extraction if justified. (ADR-008 decision: do NOT extract — measured 3.9k/6.7k ev/s single-process vs. expected volume; quantified revisit triggers; extraction seams already in place (db.py, `_run_detections`, scheduler `tick()`, stateless report builder))
- [x] SEC-071 Advanced dashboards, saved searches, scheduled reports. (Coverage + purple-team + saved-search panels on /soc; report schedules CRUD + in-process scheduler daemon; retention report on /admin)
- [x] SEC-072 Cost/resource optimization and retention tuning. (Retention labels + `GET /api/admin/retention/report` report-only per ADR-005; resource limits in compose. Service-extraction cost model = SEC-070, Proposed)
- [x] SEC-074 Inert-rule blind spot: rule validation across the whole lifecycle. (Was: `except RuleError: continue` skipped a non-compiling rule silently while `/rules` showed it `active`; `rules/*.yaml` were seeded uncompiled. Now: `detection.rule_health`; loud throttled warning; `/rules` → `compiles`/`error` + `broken` summary; `/coverage` → `inert_rules`/`broken_rules` separate from gaps; seed refuses a broken shipped rule; `scripts/lint_rules.py` in CI with porting advice; SOC page `live`/`inert` markers + banner. docs/15 = subset + porting guide (grammar verified by probing). 16 new tests)
- [x] SEC-073 API surface hardening from a post-build audit. (4 findings fixed + tested: unknown `/api/*` → JSON 404 not SPA HTML; `/metrics` denied on the public edge + optional `METRICS_TOKEN`; login brute-force limiting moved into the app (`app/ratelimit.py`, 50/10s per IP, on in STAGING/PROD, audited) because the stock `caddy:2` image cannot load `rate_limit`; `infra/prod/.env.example.prod` added + `.gitignore` negation so env templates are committable. Route audit: 111 `/api` routes, 0 unauthenticated. Suite 115 → 129. See docs/13)
- [x] SEC-075 Adversary tradecraft — The-Xploiter persona (requested integration). (Persona served at `GET /api/tradecraft/persona` (8 focus areas, 5 principles, 6 use cases, guardrails); scope guard: targets must belong to an exercise in status authorized/running, deny-by-default, over-broad entries (0.0.0.0/0, *, any) authorize nothing, refusals audited as `tradecraft.out_of_scope`; exploitability reviews with evidence policy (exploitable needs target+evidence+repro+impact; theoretical recorded but never reportable/chainable; needs_evidence is a lead); attack chains with escalation requirement + human validate/reject; triage-ready markdown report (READY/NOT SUBMITTABLE); fingerprint duplicate clustering; agent tools list_scope_targets/get_finding (read-only) + record_exploitability_review/propose_attack_chain (approval-gated); persona selectable via adapter_config.persona, cannot widen permissions; no shell/scanning tool exists (asserted by test); /tradecraft UI page. docs/16 + 46 tests)
- [x] SEC-076 Tradecraft follow-ups from real use. (Fix: prose-aware argument validation — tools declare `text_fields` skipped by the injection heuristic and length-capped instead, per-tool scoped (verified: same args still refused for undeclared tools/fields); `kind=tradecraft` engagement report incl. rejected/disproven list + chains as paths; seed ships `the-xploiter` (persona + 4 tools); duplicates UI panel. Full agent path verified live: read-only auto-exec, consequential -> awaiting_approval -> approve -> executed, prose preserved. Also: fingerprint fix (dedupe key was not invariant under URL/port/severity noise, so re-submissions did not cluster); Reports UI kind list; docs/14 stale edge-rate-limit gate replaced with command-level in-app checks. 24 tests)
- [x] SEC-077 Tradecraft authorization windows are enforced, not decorative. (Found while verifying SEC-076: `10.42.0.10` was reported usable on 2026-09-22 from an engagement whose window ended 2026-09-13 — the scope guard checked status only, so an authorization silently outlived the permission it rests on, and the seed made it invisible by shipping an already-lapsed window. Fix: `_window_state` (expired/not_started/active/open; missing dates = open-ended and labelled so; last day inclusive) drives `authorized_targets` usability and a per-row `window_state`; `scope_summary.expired_engagements`; `/tradecraft` shows the window column + a lapsed-engagement warning; seed window extended past today (asserted by test). Refusals now name the real cause — a lapsed window says which engagement lapsed and when to renew instead of 'not listed in any exercise'; over-broad entry says so; the `exploitable` reproduction refusal states its 20-character minimum. 8 new tests)
- [x] SEC-078 Approval gate: single-decision by construction. (The handler read the approval, checked `status != 'pending'` in Python, then wrote an unguarded `UPDATE approvals SET status=... WHERE id=?`; two concurrent approves both pass the check, both execute the consequential tool and the last writer becomes the recorded approver — demonstrated deterministically with two connections. Fix: compare-and-set on the approval (`WHERE id=? AND status='pending'`, rowcount != 1 -> 409 already_decided) plus an atomic task claim (`WHERE id=? AND status='awaiting_approval'`) so the tool runs once, for one approver; a second approval on a claimed task is approved but audited executed:false. Live: 6 concurrent approves -> 1x200 + 5x409, one case created, one approval.executed row, task completed. 2 new tests)
- [x] SEC-079 SPA vocabulary parity (pick every picker against the API). (Sweep found three screens that offered values the API rejects and hid values it accepts: /soc triage offered `false_positive` (live 400 bad_status) and omitted the real `dismissed` — so a false positive could not be recorded from the UI at all; /incidents case status offered `containment`/`recovered` (both 400) and hid `contained`/`mitigated`; case-task picker hid `canceled`. Cloud posture had NO validation — the API stored any string and the existing test asserted a third vocabulary (`remediated`) that neither the UI (`resolved`) nor the seed (`open`) used. Fix: pickers carry the API's exact values; posture status/severity validated on create and update; new tests/test_enum_parity.py (10 tests) reads the SPA source and compares every named picker list with the API's allowed set — verified non-vacuous by reintroducing the drift. Suite 234 passed.)
- [x] SEC-080 Uniform error envelope (validation failures included). (docs/12 promises `detail = {code, message}` for every non-2xx, but FastAPI's request-validation failures returned a bare list — a client written against the documented contract read `detail.code` as undefined; the SPA already branched on the list, which hid the inconsistency. Fix: a RequestValidationError handler keeps status 422 and returns the documented envelope with `message` naming the offending fields and `errors[] = {field, msg, type}` preserving detail; docs/12 documents the shape + new codes. 1 new test.)
- [x] SEC-081 Alert dismissal requires a recorded reason. (Found while verifying SEC-080: a critical-severity alert could be moved to `dismissed` with `notes: null` — the highest-volume false-positive judgement in a SOC left no reason anywhere, while chain status changes, release decisions and verdicts all require one. Fix: `dismissed` without a non-blank note -> 400 note_required; the note is stored and carried in the alert.updated audit detail; the triage panel gained a Disposition note field. Other statuses unchanged. 1 new test.)
- [x] SEC-082 Risk acceptance requires the exception record. (The generic `PATCH /api/vulns/{fid}` accepted `status:"accepted_risk"` with no reason, no approver and no expiry, duplicating a decision that already has a purpose-built record and silently defeating the expiry reminder; the UI offered it in the status dropdown beside the exception form. Fix: PATCH refuses `accepted_risk` with 400 use_exception_endpoint; UI offers only settable statuses (accepted_risk stays filterable). Also: finding `severity` validated on create/import (an imported "banana" was stored and counted nowhere; CSV reports it per row) and the UI severity filter gained `info`. 3 new tests + parity coverage.)
