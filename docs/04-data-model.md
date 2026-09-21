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
