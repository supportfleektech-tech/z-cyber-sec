# Core Data Model (Initial)

## Entities
- User, Role, Permission, Session
- Asset, AssetGroup, Environment
- Integration, IntegrationRun, IntegrationHealth
- Event, Alert, DetectionRule
- Case, CaseTask, EvidenceItem, TimelineEntry
- ThreatIndicator, IndicatorSource, IndicatorRelationship
- VulnerabilityFinding, FindingException, RemediationTask
- ScanRun, ScanTarget (authorized scope only)
- Control, Risk, AuditEvidence
- Exercise, ExerciseTarget, ExerciseRun
- Agent, AgentTask, AgentToolCall, Approval
- Report, ReportArtifact
- AuditEvent

## Required properties
- Stable IDs; created/updated timestamps; actor attribution
- Tenant/workspace boundary only if multi-user/multi-tenant is actually required
- Source/provenance and confidence for imported security data
- Classification and retention metadata for evidence
- Idempotency keys for ingest/job operations
- Soft-delete only where justified; define purge semantics

## Security
Enforce authorization server-side for every object and operation. Do not rely on frontend hiding. Store secrets outside ordinary records. Sanitize exports and prevent evidence URLs from being public by default.

## Migrations

Applied in order at startup (additive only; none rewrites or drops a table):

| Migration | Adds |
|---|---|
| `0001_init.sql` | the base schema: users, sessions, assets, events, detection rules, alerts, cases, tasks, evidence, intel, vulns, AppSec, cloud, GRC, exercises, agents, automation, reports, audit, settings |
| `0002_extensions.sql` | saved searches, tradecraft surface beginnings, integration/provenance columns |
| `0003_releases.sql` | release decision records (`domain:releases`) — version, commit, checklist hash, decision, decider, comment |
| `0004_tradecraft.sql` | exploitability reviews, attack chains, chain steps, duplicate fingerprints (adversary tradecraft, docs/16) |
| `0005_audit_anchor.sql` | `audit_anchor` — the exported-history anchor that makes a truncated audit log detectable (SEC-084) |
| `0006_report_schedule_errors.sql` | `report_schedules.last_error`/`failures` — a scheduler that cannot report its own failures is a scheduler nobody trusts (SEC-112) |
| `0007_lab_range.sql` | `lab_targets` — the range registry behind `/api/lab/*` (docs/17, SEC-115) |

The list is checked against the directory by `python -m scripts.lint_docs`, so a new
migration that is not documented here fails CI.
