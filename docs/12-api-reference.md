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
| `GET /alerts` · `GET /alerts/{id}` · `PATCH /alerts/{id}` | Alert triage & lifecycle. Moving an alert to `dismissed` **requires a note** — a false-positive call is a judgement and the reason is recorded with it (SEC-081; missing/blank → `400 note_required`) |
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

**Indicator lifecycle (SEC-087/088/089).** `ttl_hours` is enforced: an
`active` indicator whose TTL has elapsed becomes `expired` on the next read of
`/indicators`, `/indicators/correlate` or a re-sighting POST, recorded once as a
system-actor `intel.indicators.expired` audit event (`{count, ids, reason}`) —
lazy rather than a background job, so it cannot drift from the data. `expires_at`
is returned on every listed indicator (`null` = never expires).

- `POST /indicators` honours and validates `status`; a re-sighting (same
  `type`+`value`) refreshes `confidence`/`last_seen`, is audited
  (`intel.indicator.reseen`), and revives an `expired` indicator — but never
  undoes a human `revoked`, which is a retraction.
- `PATCH /indicators/{id}` is a **true partial update**: only the fields you send
  are written, so a status change no longer erases the source, TTL, MITRE
  mappings and notes. An empty body is `400 no_changes`; `type`/`value` are
  editable (validated against `IND_TYPES`, and refused with `409
  duplicate_indicator` if they would collide with an existing pair); an explicit
  `null` still clears a field.
- `mitre_tactics`/`mitre_techniques` are lists in and lists out (they used to be
  returned as raw JSON text).
- `POST /indicators/stix` maps STIX `valid_from`/`valid_until` onto
  `first_seen`/`ttl_hours`; a bundle whose `valid_until` has already passed is
  imported `expired` rather than `active`, and the count is returned as
  `expired_on_arrival`. Other STIX fields (`revoked`, granular markings) remain
  out of subset (ADR-004).

**Silently-ignored request fields (SEC-090).** Three routes accepted input they
never applied, now fixed: `POST /reports` honours `title` (the SPA offers a title
box; the value used to be dropped and a generated title stored instead);
`POST /automation/{id}/run` keeps `note` on the run result and in the audit entry
for every outcome (dry-run, denied, awaiting-approval, executed); and PATCH
handlers that took a create model — `PATCH /cloud/posture/{id}` — are now true
partial updates (only the fields sent are written, omitted `detail` is preserved,
`400 no_changes` on an empty body, `400 bad_asset` for an unknown asset).
`PATCH /agents/{id}` and `PATCH /assets/{id}` now apply a rename for real
(previously it returned 200 and kept the old name), with `409 exists` on a
collision and `renamed_from` in the audit detail; renaming the automation agent
is refused (`409 rename_not_supported`) because the runner resolves it by name.

### Vulnerabilities (`/api/vulns`)
`GET/POST /` · `PATCH /{fid}` · `GET/POST /{fid}/exceptions` ·
`GET/POST /{fid}/remediation` · `POST /import/csv` · `POST /import/json`.

`PATCH /{fid}` accepts `new|triaged|in_progress|fixed` — **`accepted_risk` is not
settable here** (SEC-082): accepting a risk is a decision with a rationale, an
approver and an expiry, so it is recorded through
`POST /{fid}/exceptions` (reason ≥10 chars). Sending `accepted_risk` to the
PATCH returns `400 use_exception_endpoint`. `severity` is validated against
`{critical, high, medium, low, info}` on create and import
(`400 bad_severity`; unknown values are reported per row in the import result).

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

### Exercises (`/api/exercises`) — the engagement lifecycle

`planned → authorized → running → completed`, with `aborted` as the early exit
available from `planned`, `authorized` or `running`. **The lifecycle is one-way
(SEC-083):** anything else is `409 illegal_transition` with `from`, `to` and the
`allowed` set. There is deliberately no "revert to planned" — that would withdraw
the authority the scope guard reads, and `aborted`/`completed` are terminal so a
closed engagement cannot be quietly reopened. A refused transition is written to
the audit log as `exercise.transition_denied`.

Closing an engagement (`completed` or `aborted`) requires a `reason` of at least
10 characters (`400 reason_required`) — it ends an authorization other people and
processes depend on, and the reason is recorded on the `exercise_runs` row as
well as in the audit trail. Re-sending the current status is a no-op (it does not
start a second run).

`GET/POST /` · `GET/PATCH /{ex_id}` — authorized exercise lifecycle. An exercise
never initiates network action (threat model).

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
| `POST /backup/restore` | `{path, confirm:"RESTORE"}`; the path is **resolved and must be a file inside `data/backups`** (SEC-085 — a path that merely mentions "backups" is refused: `400 bad_path`). The bundle must pass `verify_bundle`: manifest present, every archive member declared in it, no symlinks/hardlinks, no `..`/absolute member names, checksums equal. Unreadable or corrupt archives are a `409 verify_failed` naming the reason (SEC-086), never a 500 |
| `GET /retention/report` | Evidence retention **report only** (SEC-072, ADR-005): per-item `within_retention`/`due` + `legal_hold` (case-bound) flags; never deletes — deletion stays a human, audited act |
| `POST /releases` | Record a human release decision (SEC-064): `{version, commit_sha, checklist_sha256 (64-hex), decision: approved\|rejected, comment?}` — admin only (`release.write`), audit-logged |
| `GET /releases` | Decision history (paginated, newest first) |
| `GET /releases/latest` | The gate: `{latest, gate: approved\|blocked\|no_decision, note}` — rollout must see `approved` for the exact version+commit |

## Plan admissibility

A request (agent task or playbook run) is planned against the agent allowlist,
the tool registry and the arg validators. If **any** step is refused — unknown
tool, not in the allowlist, failing arg validation — the whole unit fails closed:
the run/task is `failed`/`denied` with `reasons`, audited (`playbook.failed` /
`agent.task.denied` with `partial: true`), and **no** step executes. The refused
steps are recorded against the row that asked for them, so the task's or run's
audited call list shows exactly what was blocked. Before SEC-097 refused steps were
dropped silently, the surviving steps ran, and the unit reported success.

## Playbook runs

Alerts with severity `>=` a playbook's `on_alert:<severity>` threshold create a
run (scheduled/manual runs come from their own paths). If the playbook has
`auto_run = 1` the run is planned and executed immediately — read-only plans run,
plans with consequential steps wait on approvals, denied plans fail with reasons —
and every trigger is audited as `playbook.triggered` with the alert id, severity,
`auto_run` and outcome. Otherwise the run is created `pending` as a **suggestion**
and `POST /runs/{id}/execute` starts it (`automation.run`). That endpoint
compare-and-set claims the run, returns `409 not_pending` once it has started, and
refuses a run that is waiting on human approvals (`409 awaiting_approval`). Before
SEC-096 triggered runs were created and then never planned, executed or
progressable by any endpoint.

## Scan runs and SARIF import

`POST /api/appsec/sarif` attaches findings to a scan run (deduplicated on run + rule +
file + line) and updates the run's counters: `findings_total` is the number of findings
attached to the run, and `findings_new` is what this import added; both are returned
with `scan_run_id`. A run reported as `failed`/`cancelled` keeps that status when
results arrive (the response says so in `note`); a `running` run advances to
`completed`. Before SEC-106 `findings_total` was overwritten with the count created by
the latest call — so a re-import zeroed it — and `findings_new` was never maintained.

## Metrics

`GET /metrics` (Prometheus text format; optional `METRICS_TOKEN` bearer) reports counts
only. `cybersec_alerts_open` and `cybersec_alerts_open{severity="…"}` share one
definition of "open" (`new`, `triaging`, `confirmed`) and sum to the same total;
per-severity *totals* are separate, as `cybersec_alerts_total{severity="…"}`.
`cybersec_sessions_active` counts sessions whose `expires_at` has not passed, and
`cybersec_sessions_expired` exposes rows left behind by logouts — a user's expired rows
are pruned when that user logs in again. Before SEC-105 the
labelled series counted every alert of a severity (so it never cleared when an alert
was closed) and every session row counted as active.

## STIX import

`POST /api/intel/indicators/stix` accepts a STIX 2.1 bundle (subset parser: ip,
domain, url, sha256, file name, email patterns). Values are validated before anything
is written and the offending object is named in `400 bad_stix`: `confidence` must be
an integer 0-100, and `valid_from`/`valid_until` must be RFC3339 (fractional seconds
and offsets are normalised to UTC whole seconds, which is what the store's columns and
TTL logic use). Since SEC-104 an out-of-range or text confidence is refused instead of
being stored (a text value sorted above every real score), and a millisecond-precision
`valid_until` produces a real TTL instead of "never expires". Objects whose pattern
this subset does not support are ignored.

## Detection rule health

`GET /api/soc/rules` reports per rule whether it compiles (SEC-074: a rule that
cannot compile is inert) and, since SEC-103, `unmatched_fields` — term fields that no
ingested event carries, e.g. a typo (`user_name` for `user`). `GET
/api/soc/rules/coverage` adds `misconfigured_rules`, `observed_event_fields` and
`watching_unknown_fields`; a misconfigured rule is reported there instead of in
`gaps`, because it needs a field fix, not more coverage. The field universe is
derived from the newest 2000 events (columns plus nested `data.*` paths), so a field
a source simply has not emitted yet is flagged too — the point is that the operator
can see the rule cannot have matched anything ingested so far.

## Compliance evidence

Control evidence (`POST /api/grc/controls/{id}/evidence`) is stored in the evidence
store (mode 0600) and its sha256 is recorded in the row and the audit log.
`GET /api/grc/evidence/{id}/download` (permission `evidence.download`) returns the
artifact, `410` if it is missing from the store or was attached before SEC-102 (no
artifact was stored then), and `500 integrity_mismatch` — audited as
`evidence.integrity_failure` — if the file no longer matches its recorded digest. The
listing reports `storage` (`stored`/`missing`/`not_stored`) and a `missing` count, so
a control cannot look evidenced by a phantom. Before SEC-102 the upload was hashed and
discarded.

## Backups

`POST /api/admin/backup` writes a `.tar.gz` bundle (snapshot + evidence + manifest of
sha256 checksums) and records the archive's sha256 in the audit log.
`POST /api/admin/backup/verify` checks a bundle inside the backups directory without
restoring it: in-bundle consistency (manifest, checksums, no unlisted or unsafe
members) **and** the recorded hash. `POST /api/admin/backup/restore`
(`confirm: "RESTORE"`) refuses an edited bundle (`409 verify_failed`) and, unless
`allow_unrecorded: true` is passed explicitly, a bundle with no recorded creation
hash (`409 unrecorded_bundle`) — that case covers importing a bundle built elsewhere,
which is not evidence of tampering but is not verifiable either. The retention report
(`GET /api/admin/retention/report`) lists bundles with `sha256`, `matches_recorded`
and `verifies`. Before SEC-100 the recorded hash was consulted by nothing, so a
bundle whose manifest was rewritten verified clean and could be restored.

## Audit integrity

`GET /api/admin/audit/verify` recomputes the whole hash chain and compares it with
the anchor. Failure reasons: `linkage` (a row was modified or removed mid-log), `gap`
(non-contiguous sequence numbers), `truncated` (anchored history is gone or replaced),
`unaccounted` (rows beyond the anchored head) and — since SEC-099 — `anchor_missing`
(the anchoring migration is applied and the log is not empty, yet the anchor row
itself is gone, which only deletion can do). Pass `head_seq`, `head_hash` and
optionally `rows` from an anchor you exported earlier (`GET /api/admin/audit/anchor`)
to also detect a rewrite that rebuilt the chain *and* the in-database anchor.

## Scheduled reports

A schedule stores `kind`, optional `filters` and an interval. `filters` are
validated when the schedule is created (and when a report is generated ad hoc):
unsupported keys, empty/non-string values, unknown severities and unknown verdicts
are `400 bad_filters`. Every scheduler pass answers
`{"built": n, "failed": [{id, kind, error}]}` — a failing schedule records the reason
on its row (`last_error`, consecutive `failures`) plus an audit event
`report.scheduled_failed`, and only retries at its next slot rather than on every
tick; a successful run clears both fields. Before SEC-098 failures were invisible
(no audit, no row error, `last_run_at` untouched) and retried every tick forever.

## Approvals

`GET /api/agents/approvals?status=pending` returns every pending approval with
`kind` (`agent_task` | `playbook`), `task_title`, `agent_name` and — for playbook
approvals — `playbook_name` and `run_status`. `POST /{id}/decide`
(`{decision: approve|reject, comment?}`) is a compare-and-set: the second decision
gets `409 already_decided`.

- **Agent-task approval**: approving executes the tool through the policy engine
  once all approvals for the task are decided (SEC-078).
- **Playbook approval**: `task_id` is the `playbook_runs` row (SEC-094).
  Approving the last pending approval for a run claims it (`pending → running`) and
  executes the run's validated plan with the automation agent; rejecting fails the
  run with the reason. `409 missing_run` / `409 missing_task` if the owning row is
  gone (previously a 500 that left the run struck).

## Alert aggregation

`POST /api/soc/events` is idempotent per `idempotency_key` and returns
`{inserted, skipped, alerts}`. Alerts aggregate per (rule, entity) while open:
each batch's matching events are merged into the alert's `event_ids`
(de-duplicated, capped at 500) and `count` is the size of that merged set — so
`count == len(event_ids)` after every batch (SEC-093; it used to be this batch's
size, so a long-running alert under-reported how often it had fired).

## State timestamps

A timestamp that records *when* a state was entered is cleared when the state is
left, and is not rewritten by a repeat of the same transition (SEC-092):

- `cases.closed_at` — set on `status: closed`, cleared when the case is reopened
  (`PATCH` returns `closed_at: null`), and kept if `closed` is sent again. The
  reopen is recorded in `case_timeline` as
  `Status → investigating (reopened from closed)` and in the audit detail as
  `{from_status, to_status, reopened}`.
- `vuln_findings.fixed_at` — set on `status: fixed`, cleared when the finding is
  reopened, kept when `fixed` is repeated.

Before this, a reopened case still carried its closure time, so the case report
(an evidence artefact) and the case-detail header displayed an active case as
closed.

## JSON fields

JSON columns (lists, dicts) are stored as text in SQLite and **returned as JSON**:
a list field is a JSON array, a dict field a JSON object. They are not
double-encoded. This was not always true — routes decoded inconsistently, so the
same field was an array in one response and a JSON string in another, and the SPA
read the structured shape (`mitigations?.join("; ")` throws on a string, which
blanked the GRC and Exercises pages) — see SEC-091. `db.decode_json` /
`db.decode_rows` are the helpers, and
`tests/test_api_surface_hardening.py::test_no_get_route_returns_json_as_text`
walks every GET route in the schema and fails on the next route that forgets.

Fields that are deliberately opaque text (not JSON) are unaffected; the sweep
above currently reports zero leaked JSON strings across all GET routes.

## Backup bundles

A bundle is a `.tar.gz` produced by `POST /backup`: `cybersec.db`, an optional
`evidence/` tree, and `manifest.json` listing the sha256 of **every** file.
Restore trusts that manifest in two independent ways (SEC-085):

1. **`verify_bundle`** rejects any member the manifest does not declare, any
   symlink/hardlink, and any member name that is absolute or contains a `..`
   segment — so a valid-manifest bundle with an extra `evidence/../../tmp/x`
   member no longer passes.
2. **`restore_from`** does not rely on step 1: it copies only members that are
   both declared in the manifest *and* resolve inside the evidence directory,
   raising `restore_refused` otherwise.

Bundles are ordinary files, not authenticated: anyone who can write into
`data/backups` can craft one, so the directory's filesystem permissions are
part of the trust boundary (see docs/09).

## Audit format

Append-only, hash-chained (each row hash covers `seq, ts, actor, action,
target, detail` + previous row's hash). No update/delete API. Actor is
typed (`user`, `agent`, `system`) with name; every state-changing call
records one.

`GET /api/admin/audit/verify` re-walks the chain **and compares against the
anchor** (SEC-084), returning `{ok, rows, first_bad_seq, reason, anchor}` where
`reason` is `linkage` (a row was changed or removed mid-log), `gap` (sequence
numbers are not contiguous) or `truncated` (history the anchor recorded is gone,
with `missing_rows`). `GET /api/admin/audit/anchor` returns the recorded head
(`rows`, `head_seq`, `head_hash`) for off-platform export.

**What the chain proves, and what it does not.** It detects modification or
removal by anything that does not recompute the chain — a partial restore, an
ad-hoc `DELETE`, a bug — and the anchor makes *deletion* detectable (a plain
hash chain cannot see its own tail; before SEC-084 `DELETE FROM audit_events
WHERE seq > N` left every remaining link valid and verify said `ok`):

| Situation | Detected by |
|---|---|
| A row is modified mid-log | chain (`reason: linkage`) |
| Rows are removed mid-log | chain (`linkage`/`gap`) |
| The newest rows are deleted | anchor (`reason: truncated`, with `missing_rows`) |
| Deleted, then the attacker keeps working | **only an exported anchor** — the in-DB anchor advances with legitimate appends and eventually moves past the gap (`GET /verify?head_seq=&head_hash=&rows=` reports `external.reason` `missing`/`replaced`/`truncated`) |
| The database and the anchor are both rewritten | nothing local — the unkeyed hash can be recomputed |

That last row is why the weekly runbook step exports the anchor somewhere the
platform does not control: the copy is the control. A keyed HMAC chain (key held
outside the database) is the natural next hardening — **Proposed**, not
implemented.

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
| `bad_path` | restore path is not an existing file inside `data/backups` (SEC-085) |
| `verify_failed` | bundle failed verification — corrupt/unreadable, manifest missing/broken, unlisted, unsafe or link member, or checksum mismatch (SEC-085/086) |
| `restore_refused` | defence-in-depth refusal inside `restore_from` (SEC-085) |
| `bad_status` | indicator status outside `active|expired|revoked` |
| `duplicate_indicator` | indicator edit would duplicate an existing `type`+`value` |
| `no_changes` | PATCH with an empty body |
