# Network Design & Isolation

## Zones
- **Management:** trusted operator access; SSH and admin interfaces.
- **Platform:** frontend, API, database, workers, monitoring.
- **Blue-team telemetry:** collectors, SIEM, dashboards.
- **Exercise:** disposable targets and authorized simulations.
- **Lab range (`lab_range`, `internal: true`):** the containers that *are* the exercise
  targets — Juice Shop, the CTF target, `lab-api-01` (`infra/lab/docker-compose.yml`).
  Loopback-only publishes, no route to the platform network or the internet, registered
  in the platform as `lab_targets` and cross-checked by `GET /api/lab/coverage`
  (docs/17). These invariants are pinned by `tests/test_lab_range_infra.py`, not by
  prose.
- **External egress:** explicitly approved updates, feeds, and APIs.
- **Production:** separate environment; never bridged casually to exercises.

## Policy
Default deny between zones. Permit only documented flows. No direct inbound internet exposure to vulnerable targets. No unrestricted route from exercise targets to personal LAN, production, or secrets-bearing services.

## Required artifacts
- Network diagram with subnets/interfaces
- Flow matrix (source, destination, protocol, purpose, owner)
- Firewall configuration and rollback
- DNS and ingress plan
- Isolation test cases
- Emergency disconnect procedure

## Validation
Use benign connectivity checks between explicitly controlled test endpoints. Confirm prohibited paths fail. Record evidence and test date. Do not scan networks without authorization.
