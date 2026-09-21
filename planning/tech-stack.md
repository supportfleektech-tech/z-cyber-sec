# Technology Stack Decision Register

Initial candidates, not final selections:
- Linux + Docker Compose for local deployment
- TypeScript/React frontend
- TypeScript API or Python FastAPI (choose one via ADR)
- PostgreSQL
- Prometheus/Grafana as resource budget permits
- One SIEM/telemetry stack selected after capacity and integration review
- Ansible for host configuration; OpenTofu for later cloud provisioning
- GitHub Actions or restricted self-hosted CI
- SOPS/age or a secrets manager for shared environments

Choose based on compatibility, current maintenance, licensing, resource footprint, integration support, and operator familiarity. Pin versions and record decision rationale.
