# Infrastructure

Zero-budget, local-first. Three layers, from least to most hardened:

| Layer | Path | What it does |
|---|---|---|
| Local dev | `infra/compose/compose.yaml` | Single container, host port 8080, named volume for `data/`. For day-to-day. |
| Target-host network | `infra/network/` | nftables flow matrix (mgmt/app/lab-targets zones) + validator. Applied **on the target host only**. |
| Staging | `infra/staging/` | Separate stack (own volume + network), HTTP-only on the staging LAN, same image as prod. Acceptance environment (SEC-060). |
| Production | `infra/prod/` | Docker image + Caddy TLS edge + hardened env. Built, not yet deployed (ADR-007). |

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

## 3. Staging (SEC-060)

Staging is a **separate** environment — its own compose project, named
volume, network, and `SECRET_KEY` — running the **same image** as prod.
This is where the release checklist's acceptance section runs before human
approval (docs/14). It is HTTP-only on the staging LAN (no public DNS, no
TLS edge); production is the only environment with Caddy.

```bash
# same artifact as production
docker build -f app/backend/Dockerfile -t cybersec:local .

cd infra/staging
cp .env.example .env                  # set a SECRET_KEY DIFFERENT from prod's
docker compose up -d
# seed synthetic data (disposable; labeled synthetic via X-Data-Class)
docker compose exec cybersec python -m app.seed.seed_demo
```

Isolation guarantees: `cybersec-staging-data` volume + `cybersec-staging`
network are never shared with production; every response carries
`X-Environment: STAGING` + `X-Data-Class: synthetic-by-default`; the boot
guard refuses the dev `SECRET_KEY`.

## 4. Production (ADR-007)

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
- Login rate-limited **in the app** (50 req / 10 s per IP by default in
  STAGING/PROD, `app/ratelimit.py`, SEC-073), returning
  `429 {detail:{code:"rate_limited"}}` + `Retry-After`. This is deliberate:
  Caddy's `rate_limit` directive is *not* in the stock build, so a Caddyfile
  using it would be rejected by the pinned `caddy:2` image (a config that
  cannot load protects nothing). The app-side control is tested.
- `/metrics` is refused on the public edge (`Caddyfile` → `403`); scrape the
  internal bind address instead. Set `METRICS_TOKEN` to also require
  `Authorization: Bearer <token>`.
- Security headers: HSTS, `nosniff`, `no-referrer`.
- `SECRET_KEY` + `ENV_NAME=prod` come from `.env` (never committed); the
  backend **refuses to boot** in STAGING/PROD without a real secret (config guard).
- Resource caps (2 CPU / 2 GiB) and json-file log size caps in compose.

### Optional: edge-level rate limiting (custom image)

If you want a second, edge-level rate limit in addition to the app's, build
Caddy with the community plugin — the stock image has no such directive:

```dockerfile
FROM caddy:2-builder-alpine AS builder
RUN xcaddy build --with github.com/mholt/caddy-ratelimit
FROM caddy:2-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

Then add to `Caddyfile` (plugin syntax, **not** valid on stock `caddy:2`):

```text
@login path /api/auth/login
rate_limit @login {
	zone cybersec
	50r/10s
	by remote_ip
}
```

Secrets: copy `.env.example.prod`, generate `SECRET_KEY`
(`python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`), and fill
`PROD_DOMAIN`. The file is gitignored; never commit real values.

## 5. Backup & restore rehearsal (SEC-063)

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

## 6. Supply chain (SEC-062)

CI (`.github/workflows/ci.yml`) generates a CycloneDX SBOM from the pinned
`requirements.txt`, runs `pip-audit` (backend) and `npm audit` (frontend),
and uploads the SBOM as an artifact. gitleaks scans for secrets on every
push/PR.

## 7. Release gate (SEC-064)

The human-approval step of the release flow is recorded in the platform,
not just in a ticket: an admin posts the decision (version, commit sha,
signed-checklist sha256, `approved`/`rejected`) to
`POST /api/admin/releases`; the gate view is
`GET /api/admin/releases/latest` (`approved | blocked | no_decision`). The
Admin → Releases tab drives it. Full checklist + signing steps:
`docs/14-release-checklist.md`.
