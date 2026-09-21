# 12 — API Reference

**Status:** v1.0, all endpoints served by the single FastAPI app. Interactive
docs at `/api/docs` (OpenAPI at `/api/openapi.json`). See docs/13 for
verification evidence.

## Conventions

- **Base path:** `/api/*`; static SPA at `/`; health at `/api/healthz`
  (the only non-auth API endpoint besides login); Prometheus-style
  `/metrics`.
- **Auth:** cookie session (`HttpOnly`, `SameSite=Strict`; ADR-002).
  Every other endpoint requires a session plus a named permission
  (RBAC). Unauthenticated → `401 {detail:{code:"unauthenticated"}}`;
  missing permission → `403`.
- **Errors:** non-2xx bodies carry `detail = {code, message}` with stable
  machine-readable codes (`bad_status`, `not_found`, `bad_kind`,
  `no_changes`, `missing`, ...). Clients key off `code`.
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

### SOC (`/api/soc`)
| Method & path | Purpose |
|---|---|
| `POST /events` | Batched idempotent ingest; runs active rules inline (ADR-003/004) |
| `GET /events` | Event search (field filters, paging) |
| `GET /alerts` · `GET /alerts/{id}` · `PATCH /alerts/{id}` | Alert triage & lifecycle |
| `GET/POST /rules` · `PATCH /rules/{id}` | Detection rule CRUD (Sigma-subset) |
| `POST /rules/dry-run` | Evaluate a rule draft against stored events |
| `POST /detections/backfill` | Re-evaluate stored events after rule changes |

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
| `POST /approvals/{id}/decide` | `{decision: approve|reject, comment?}` — the human gate |
| `GET/POST /tasks` · `GET /tasks/{id}` | Task queue; detail includes `result`, original `request`, `tool_calls[]` (tool, allowed, reason, result), `approvals[]` |
| `GET /tools` | Tool registry: `{name: {description, read_only, requires_approval}}` |
| `GET/POST /` · `PATCH /{agent_id}` | Agent registry + per-agent tool allowlists |
| `POST /evals/run` | Run the eval harness (`{agent_id}` → `{agent, passed, total, results}`) |

Governance (ADR in docs/06): non-read-only tools require approval;
out-of-allowlist tools are denied; agents cannot waive their own gates.

### Automation (`/api/automation`)
`GET /` (playbooks, `{items,total}`) · `GET /runs` ·
`POST /{pb_id}/run` with `{dry_run: bool, note?}` — **dry run returns a
plan and executes nothing**; real runs execute allowlisted steps via the
agent gateway.

### Reports (`/api/reports`)
`POST /` — generate (`{kind: overview|soc|cases|intel|vulns, title?, filters?}`
→ report row with `input_rows` + `input_sha256` provenance) ·
`GET /` (kind filter) · `GET /{id}/download` (requires
`reports.generate`; audited).

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
| `no_changes` | PATCH with empty diff |
| `missing` | report file gone |
| `confirm_required` | restore without `confirm:"RESTORE"` |
