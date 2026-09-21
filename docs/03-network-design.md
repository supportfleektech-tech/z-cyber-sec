# Network Design & Isolation

## Zones
- **Management:** trusted operator access; SSH and admin interfaces.
- **Platform:** frontend, API, database, workers, monitoring.
- **Blue-team telemetry:** collectors, SIEM, dashboards.
- **Exercise:** disposable targets and authorized simulations.
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
