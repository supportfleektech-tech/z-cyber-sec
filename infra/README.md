# Infrastructure

Zero-budget, local-first. Three layers, from least to most hardened:

| Layer | Path | What it does |
|---|---|---|
| Local dev | `infra/compose/compose.yaml` | Single container, host port 8080, named volume for `data/`. For day-to-day. |
| Target-host network | `infra/network/` | nftables flow matrix (mgmt/app/lab-targets zones) + validator. Applied **on the target host only**. |
| Staging/prod | `infra/prod/` | Docker image + Caddy TLS edge + hardened env. Built, not yet deployed (ADR-007). |

## 1. Local dev compose

```bash
docker compose -f infra/compose/compose.yaml up --build
# → http://localhost:8080
```

## 2. Target-host network isolation (SEC-040)

The platform is zone `app` (10.41.0.0/24). Operators come from `mgmt`
(10.40.0.0/24); exercise targets live in `lab-targets` (10.42.0.0/24).
Flow matrix (full table in `nftables.conf` header):

- mgmt → app :8080 **allow** (admin plane)
- mgmt → lab-targets :22 **allow** (operator exercise access)
- app → lab-targets :8080 **allow** (exercise orchestration hooks)
- lab-targets → app / mgmt **deny** (targets never call back)
- default: **deny** (except established/related, loopback, DNS)

Apply on the **target host** (requires root + nftables, and the zone
interfaces must be named `mgmt-if` / `app-if` / `lab-if`, or edit the file):

```bash
sudo nft -f infra/network/nftables.conf
sudo infra/network/validate_flows.sh     # PASS/FAIL table per matrix row
```

`validate_flows.sh` only does connectivity probes (no data written to the
platform). **Not applied in the CI sandbox** — no authorized target host.

## 3. Staging / production (ADR-007)

Build the multi-stage image from the repo root (it builds the SPA, then a
non-root python:3.11 runtime; pinned pip deps in the final stage):

```bash
docker build -f app/backend/Dockerfile -t cybersec:local .
```

Run the prod profile (needs a real domain for Caddy's ACME TLS):

```bash
cd infra/prod
cp .env.example.prod .env            # then set SECRET_KEY + PROD_DOMAIN (gitignored)
docker compose --profile prod up -d  # cybersec (internal :8080) + caddy (edge :443)
```

Production guarantees (enforced, not aspirational):

- App container is **non-root (uid/gid 10001)**, no public ports — only the
  internal network. TLS terminates at Caddy (ACME automatic).
- Login rate-limited at the edge (50 req / 10 s per IP, `Caddyfile`).
- Security headers: HSTS, `nosniff`, `no-referrer`.
- `SECRET_KEY` + `ENV_NAME=prod` come from `.env` (never committed); the
  backend **refuses to boot** in STAGING/PROD without a real secret (config guard).
- Resource caps (2 CPU / 2 GiB) and json-file log size caps in compose.

Secrets: copy `.env.example.prod`, generate `SECRET_KEY`
(`python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`), and fill
`PROD_DOMAIN`. The file is gitignored; never commit real values.

## 4. Backup & restore rehearsal (SEC-063)

Live drill (in-process, default): boots the app on a temp `DATA_DIR`,
seeds synthetic data, backs up, wipes the DB, runs the production restore,
and asserts events + audit chain match. Prints a JSON report and
`DRILL: PASS/FAIL`.

```bash
cd app/backend
.venv/bin/python -m scripts.backup_rehearsal            # in-process (CI-safe)
.venv/bin/python -m scripts.backup_rehearsal --url http://127.0.0.1:8080 \
    --restart-cmd "uvicorn app.main:app --port 8080"    # live mode (needs server control)
```

Live mode **stops the running server, moves its DB files aside, restores
from backup, and restarts** — run only against an authorized, disposable
instance, and keep the moved files (the script logs the `lost` dir) until the
restore is verified.

## 5. Supply chain (SEC-062)

CI (`.github/workflows/ci.yml`) generates a CycloneDX SBOM from the pinned
`requirements.txt`, runs `pip-audit` (backend) and `npm audit` (frontend),
and uploads the SBOM as an artifact. gitleaks scans for secrets on every
push/PR.
