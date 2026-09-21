# CYBER-SEC — Cybersecurity Engineering & Intelligence Lab

**Package:** Implementation Blueprint v1.0  
**Date:** 2026-09-17  
**Deployment starting point:** Existing Pop!_OS host, local-first  
**Agent tools:** OpenCode, OpenClaw, Hermes

> This repository is a build blueprint and starter scaffold. It is not evidence that any services have been installed, tested, or deployed.

## Mission
Build a modular, secure, reproducible local cybersecurity lab and operations platform, with a path to a separately hardened production deployment.

## Capability scope
1. SOC & Blue Team
2. Incident Response & Forensics
3. Threat Intelligence
4. Application Security
5. Cloud Security
6. Network Security
7. Vulnerability Management
8. GRC & Compliance
9. Authorized Red Team / CTF
10. Security Engineering & Automation
11. Cybersecurity AI Agents

## Quick start
1. Read `docs/00-source-and-status.md`.
2. Read `docs/01-host-audit.md`.
3. Complete the audit before changing existing services.
4. Review `docs/02-architecture.md` and `docs/03-network-design.md`.
5. Work through `planning/roadmap.md` and `planning/backlog.md`.
6. Use `agents/MASTER_BUILD_PROMPT.md` with your coding agents.
7. Do not use `infra/compose/compose.yaml` until its placeholders, ports, storage, and security have been reviewed.

## Status vocabulary
- **Verified:** directly observed in the current environment during a recorded audit.
- **Previously reported:** supplied in earlier conversation; requires revalidation.
- **Proposed:** intended design, not deployed.
- **Unknown:** must be investigated.
- **Blocked:** requires access, approval, budget, or external dependency.

## Safety
Only assess systems you own or have explicit authorization to test. Keep vulnerable targets isolated. No public exposure of exercise targets. Require human approval for production changes, destructive operations, external testing, and consequential containment actions.
