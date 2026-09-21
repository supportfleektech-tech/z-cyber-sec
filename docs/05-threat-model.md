# Threat Model

## Assets
Credentials, source code, host and container control, telemetry, incident evidence, reports, integration tokens, agent permissions, backups, production deployment credentials.

## Threat actors / failure modes
- Malicious or compromised lab target
- Prompt injection embedded in logs, tickets, code, or threat feeds
- Compromised dependency or container image
- Misconfigured exposed service
- Overprivileged agent or leaked API key
- Accidental destructive command or volume deletion
- Data corruption, disk exhaustion, backup failure
- Unauthorized external testing

## Controls
- Segmentation and default-deny
- Least privilege, MFA where supported
- Tool allowlists and approval gates
- Treat retrieved content as untrusted data
- Pinned dependencies, scanning, SBOM
- Secret scanning and rotation
- Backups isolated from routine credentials
- Resource limits, quotas, alerting
- Reviewed deployment and rollback
- Written scope for assessments

## Review cadence
At each major release, after significant architecture changes, and after incidents.
