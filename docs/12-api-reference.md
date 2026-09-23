# 12 — API Reference

**Status:** v1.0, all endpoints served by the single FastAPI app. Interactive
docs at `/api/docs` (OpenAPI at `/api/openapi.json`). See docs/13 for
verification evidence.

## Conventions

- **Base path:** `/api/*`; static SPA at `/`; health at `/api/healthz`
  (the only non-auth API endpoint besides login); Prometheus-style
  `/metrics` (counts only; optionally bearer-gated with `METRICS_TOKEN`
  and never served on the public edge — SEC-073).
- **Unknown API paths:** `/api/*` that matches no route returns
  `404 {detail:{code:"not_found"}}` — a real JSON 404, never the SPA shell
  (SEC-073). Requests to non-API paths still return the SPA.
- **Auth:** cookie session (`HttpOnly`, `SameSite=Strict`; ADR-002).
  Every other endpoint requires a session plus a named permission
  (RBAC). Unauthenticated → `401 {detail:{code:"unauthenticated"}}`;
  missing permission → `403`.
- **Errors:** every non-2xx body carries `detail = {code, message}` with stable
  machine-readable codes (`bad_status`, `not_found`, `bad_kind`,
  `no_changes`, `missing`, ...). Clients key off `code`. Request-validation
  failures are `422 invalid_request` and additionally carry
  `detail.errors[] = {field, msg, type}` — the envelope is uniform, so a client
  never has to branch on the shape (SEC-080).
- **Time:** ISO-8601 UTC strings.
- **List endpoints:** most return `{items, total}` with `page` /
  `page_size` query params; a few domain lists return a flat `{items}`.

## Endpoint table

### Auth & users (`/api/auth`)
| Method & path | Purpose | Permission |
|---|---|---|
| `POST /login` | Login (generic 401 on failure, audited) | — |
| `POST /logout` | Revoke session, clear cookie | session |
| `GET /me` | Current user | session |
| `GET/POST /users` · `PATCH /users/{uid}` | User admin (role, active) | `users.manage` |

### Overview (`/api/overview`)
`GET /stats` · `GET /alert-trend` · `GET /services` · `GET /integrations` — dashboard KPIs.

### Tradecraft — The-Xploiter (`/api/tradecraft`)  ·  SEC-075
| Method & path | Purpose | Permission |
|---|---|---|
| `GET /persona` · `GET /rubric` | Persona spec; verdict/evidence policy | `tradecraft.read` |
| `GET /scope` · `GET /scope/check?target=` | Authorized targets; deny-by-default check | `tradecraft.read` |
| `GET/POST /reviews` | Exploitability verdicts with evidence (see docs/16) | read / `tradecraft.write` |
| `GET /duplicates` | Fingerprint clusters (bug bounty signal-to-noise) | `tradecraft.read` |
| `GET/POST /chains` · `POST /chains/{id}/status` | Attack chains; human validate/reject with rationale | read / `tradecraft.write` |
| `GET /findings/{id}/triage-report` | Triage-ready markdown draft (READY / NOT SUBMITTABLE) | `tradecraft.read` |
| `GET /stats` | Review/chain counters incl. rejected-as-theoretical | `tradecraft.read` |

Targeted writes are scope-checked against exercises in status
`authorized`/`running`; out-of-scope attempts return `400` **and** write
`tradecraft.out_of_scope` to the audit chain.

### SOC (`/api/soc`)
| Method & path | Purpose |
|---|---|
| `POST /events` | Batched idempotent ingest; runs active rules inline (ADR-003/004) |
| `GET /events` | Event search (field filters, paging) |
| `GET /rules` | Rules + **compile health**: each item carries `compiles` and `error`; the response carries `summary{ok, broken, broken_uids}`. `compiles:false` means the rule is stored but **inert** — detection never fires it (SEC-074; see docs/15) |
| `GET /rules/coverage` | Coverage over runnable rules; adds `inert_rules` + `broken_rules` (kept out of `gaps`, which lists only rules that *can* fire but have not) |
| `GET /alerts` · `GET /alerts/{id}` · `PATCH /alerts/{id}` | Alert triage & lifecycle |
| `GET/POST /rules` · `PATCH /rules/{id}` | Detection rule CRUD (Sigma-subset) |
| `POST /rules/dry-run` | Evaluate a rule draft against stored events |
| `POST /detections/backfill` | Re-evaluate stored events after rule changes |
| `GET /rules/coverage` | Coverage report (SEC-071): which active rules have fired + gaps `{coverage_pct, fired_rules, active_rules, gaps[], rules[]}` |
| `POST /saved-searches` | Save the current alert filter `{name, module:"alerts", params{status,severity,q}}` (owner-scoped) |
| `GET /saved-searches` · `DELETE /saved-searches/{id}` | List own saved searches; delete (403 cross-owner) |

### Purple team (`/api/soc/purple-team`) — SEC-072
| Method & path | Purpose |
|---|---|
| `GET /scenarios` | List replayable synthetic-attack scenarios `{uid, name, description, expected_rule, events}` |
| `POST /run` | `{scenario: uid}` — replay through the live detection path (synthetic `pt-*` hosts) → `{run_id, passed, alerts, gaps}` |

Scenarios are recorded YAML under `app/backend/scenarios/`; each maps to a
real detection rule. Runs are synthetic and labeled `SYNTHETIC-PURPLE-TEAM`;
they never touch real entities and dedupe against prior runs.

### Cases / IR (`/api/cases`)
`GET/POST /` · `GET/PATCH /{case_id}` (lifecycle + severity) ·
`POST /{case_id}/tasks` · `PATCH /tasks/{task_id}` ·
`GET/POST /{case_id}/evidence` · `GET /evidence/{evidence_id}/download`
(download requires `evidence.download`; all access audited — ADR-005).

### Threat intel (`/api/intel`)
`GET/POST /indicators` · `PATCH /indicators/{id}` (status lifecycle
`active|expired|revoked`) · `POST /indicators/stix` (STIX 2.1 bundle
subset) · `GET /indicators/correlate?window_hours=` (flat hit list) ·
`GET/POST /sources`.

### Vulnerabilities (`/api/vulns`)
`GET/POST /` · `PATCH /{fid}` · `GET/POST /{fid}/exceptions` ·
`GET/POST /{fid}/remediation` · `POST /import/csv` · `POST /import/json`.

### AppSec (`/api/appsec`)
`GET/POST /scan-runs` · `GET /findings` ·
`POST /findings/{id}/suppress` · `POST /sarif` (SARIF import).

### Cloud (`/api/cloud`)
`GET/POST /assets` · `GET/POST /posture` · `PATCH /posture/{finding_id}`
(full-body update of the posture finding).

### GRC (`/api/grc`)
`GET/POST /controls` · `PATCH /controls/{cid}` ·
`GET/POST /controls/{cid}/evidence` · `GET/POST /risks` ·
`PATCH /risks/{risk_id}` (status/owner/likelihood/impact/mitigations;
`score = likelihood × impact` recomputed server-side).

### Exercises (`/api/exercises`)
`GET/POST /` · `GET/PATCH /{ex_id}` — authorized exercise lifecycle
(planned→authorized→running→completed, reason required to complete;
never initiates network action — threat model).

### Agents (`/api/agents`)
| Method & path | Purpose |
|---|---|
| `GET /approvals?status=` | Approval queue (`{id, task_id, action, status, requested_by, task_title, agent_name}`) |
| `POST /approvals/{id}/decide` | `{decision: approve|reject, comment?}` — the human gate. Single-decision by construction (SEC-078): the status transition is a guarded UPDATE, so concurrent approvals yield exactly one `200` and the rest `409 already_decided`; a second approval for an already-claimed task is approved but recorded `executed:false` |
| `GET/POST /tasks` · `GET /tasks/{id}` | Task queue; detail includes `result`, original `request`, `tool_calls[]` (tool, allowed, reason, result), `approvals[]` |
| `GET /tools` | Tool registry: `{name: {description, read_only, requires_approval}}` |
| `GET/POST /` · `PATCH /{agent_id}` | Agent registry + per-agent tool allowlists. Create/patch accept `adapter` (`builtin`\|`openai_compat`\|`cli`) + `adapter_config` (SEC-050) |
| `POST /evals/run` | Run the eval harness (`{agent_id}` → `{agent, passed, total, results}`) |

Governance (ADR in docs/06): non-read-only tools require approval;
out-of-allowlist tools are denied; agents cannot waive their own gates.

Adapter brains (SEC-050): a task whose `request` is `{prompt}` (no explicit
`tool`) is handed to the agent's adapter, which returns a `steps` plan; the
gateway still policy-checks every step against the allowlist and gates
consequential tools. `openai_compat` calls a **local** OpenAI-compatible
endpoint (config carries `base_url` + `model`; key only via env var name —
never stored). `cli` shells out to an allowlisted command with a timeout.
Builtin (default) is deterministic and needs no brain.

### Automation (`/api/automation`)
`GET /` (playbooks, `{items,total}`) · `GET /runs` ·
`POST /{pb_id}/run` with `{dry_run: bool, note?}` — **dry run returns a
plan and executes nothing**; real runs execute allowlisted steps via the
agent gateway.

### Reports (`/api/reports`)
`POST /` — generate (`{kind: overview|soc|cases|intel|vulns|tradecraft, title?, filters?}`
→ report row with `input_rows` + `input_sha256` provenance) ·
`GET /` (kind filter) · `GET /{id}/download` (requires
`reports.generate`; audited).

Scheduled reports (SEC-072):
| Method & path | Purpose |
|---|---|
| `GET /schedules` | List report schedules `{id, kind, title, filters, interval_minutes, last_run_at, next_run_at, status, created_by}` |
| `POST /schedules` | `{kind, title?, filters?, interval_minutes: 60..43200}` — creates an `active` schedule |
| `PATCH /schedules/{id}` | `{status: active\|paused}` (only) |
| `DELETE /schedules/{id}` | Remove a schedule |
| `POST /schedules/run-due` | Execute schedules whose `next_run_at` is due (the in-process scheduler calls this each tick); returns `{built, report_ids}` |

The scheduler is an in-process stdlib daemon (no external broker) that wakes
every ~30s, marks due schedules, and builds their reports as
`scheduler:<created_by>`. It resumes from persisted `next_run_at`, so restarts
are safe; at-most-once-per-interval by design.

### Admin (`/api/admin`)
| Method & path | Purpose |
|---|---|
| `GET /audit?action=&actor=&page=&page_size=≤1000` | Hash-chained audit rows `{seq, ts, actor_name, action, target_type, target_id, detail}` |
| `GET /audit/verify` | Chain verification → `{ok, rows, first_bad_seq}` |
| `GET/POST /flags` | Feature flags (`{key, value: bool, description?}`) |
| `GET /settings` · `PUT /settings/{key}` | Runtime settings |
| `GET/POST /integrations` · `POST /integrations/{id}/health` | Integration inventory + health probe |
| `POST /backup` | Consistent backup → `{path, sha256, ...}` |
| `POST /backup/restore` | `{path, confirm:"RESTORE"}`; path must be under `data/backups` |
| `GET /retention/report` | Evidence retention **report only** (SEC-072, ADR-005): per-item `within_retention`/`due` + `legal_hold` (case-bound) flags; never deletes — deletion stays a human, audited act |
| `POST /releases` | Record a human release decision (SEC-064): `{version, commit_sha, checklist_sha256 (64-hex), decision: approved\|rejected, comment?}` — admin only (`release.write`), audit-logged |
| `GET /releases` | Decision history (paginated, newest first) |
| `GET /releases/latest` | The gate: `{latest, gate: approved\|blocked\|no_decision, note}` — rollout must see `approved` for the exact version+commit |

## Audit format

Append-only, hash-chained (each row hash covers `seq, ts, actor, action,
target, detail` + previous row's hash). No update/delete API. Actor is
typed (`user`, `agent`, `system`) with name; every state-changing call
records one. `GET /api/admin/audit/verify` re-walks the chain.

## Error code catalogue (common)

| code | where |
|---|---|
| `unauthenticated` / `forbidden` | auth/permission failures |
| `invalid_credentials` | login (deliberately generic) |
| `not_found` | id-based lookups |
| `bad_status` / `bad_kind` / `bad_role` | enum validation |
| `bad_severity` | severity values outside the standard five (SEC-079) |
| `invalid_request` | request validation (422), with `errors[]` |
| `no_changes` | PATCH with empty diff |
| `missing` | report file gone |
| `confirm_required` | restore without `confirm:"RESTORE"` |
