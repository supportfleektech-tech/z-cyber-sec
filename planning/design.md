# UI/UX Design Specification

## Visual direction
Dark-first SOC/intelligence aesthetic, restrained high-contrast palette, clear severity semantics, accessible typography, responsive desktop/tablet layouts.

## Global shell
- Left navigation with collapsible modules
- Top bar: environment badge (LOCAL/LAB/STAGING/PROD), search, notifications, profile
- Main content with timestamp and data freshness
- Persistent distinction between live, simulated, stale, and unavailable data

## Pages
1. Overview: service health, alert trends, ingestion status, agent tasks, capacity.
2. SOC: alert queue, filters, source, severity, triage state, detection details.
3. Incidents: cases, timeline, tasks, evidence, approvals, closure report.
4. Threat Intel: indicators, source, confidence, relationships, expiry.
5. Vulnerabilities: asset, finding, severity, exploitability context, remediation, exceptions.
6. AppSec: repositories, scan runs, findings, CI status, suppressions with rationale.
7. Network/Cloud: assets, telemetry health, posture findings, policy boundaries.
8. GRC: controls, risks, evidence, owners, review dates.
9. Exercises: authorized scope, target inventory, schedule, reset, outcome.
10. Agent Center: provider/model, task queue, scoped tools, approvals, audit, evaluations.
11. Automation: playbooks, triggers, dry-run, execution history.
12. Reports: filters, provenance, export, generated timestamp.
13. Admin: users, roles, integrations, retention, feature flags, audit.

## UX rules
- No fake live data; demo fixtures carry a Demo label.
- Every metric drills into records.
- Destructive actions require confirmation and impact summary.
- No secrets rendered in UI.
- Keyboard accessibility, empty/loading/error states, pagination, and useful filters.
