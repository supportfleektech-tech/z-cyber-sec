# 11 — Frontend SPA (React + Vite + TypeScript)

**Status:** Built and served by the backend. See docs/13 for verification evidence.

## What it is

A single-page app in `app/frontend/` (React 18, TypeScript, Vite, no UI
framework dependencies — hand-rolled dark ops theme in `src/theme.css`).
It builds to static assets in `app/frontend/dist/`, which the backend
serves at `/` (with `/assets/*` and a SPA catch-all fallback). One origin,
no CORS, no separate web server.

## Build & serve

```bash
cd app/frontend
npm install        # or: npm ci (package-lock.json is committed)
npm run build      # tsc -b && vite build  → dist/
```

The backend serves `dist/` automatically when it exists
(`settings.frontend_dist`). Development: `npm run dev` (Vite on 5173 with
`/api` proxied to `:8080`).

## Page map (`src/pages/`)

| Page | Routes used (representative) | Notes |
|---|---|---|
| `Login` | `POST /api/auth/login` | Cookie session; failed logins get a generic 401 |
| `Overview` | `/api/overview/stats`, `/alert-trend`, `/services`, `/integrations` | KPI tiles, 30-day alert trend, service health |
| `Soc` | `/api/soc/events`, `/alerts`, `/rules` | Event search, alert triage (status/owner), rule CRUD + dry-run + backfill |
| `Incidents` | `/api/cases*` | Case lifecycle (new→investigating→contained→closed…), tasks, timeline, evidence upload (metadata-only list; download is permission-gated) |
| `Intel` | `/api/intel/indicators*`, `/sources`, `/stix`, `/correlate` | Indicator lifecycle (active/expired/revoked), STIX bundle import, correlation against stored events (flat hit list) |
| `Vulns` | `/api/vulns*`, `/import/csv`, `/import/json` | Finding triage, exceptions, remediation tracking |
| `Appsec` | `/api/appsec/scan-runs`, `/findings`, `/sarif` | Scan-run pipeline, finding review, suppression, SARIF import |
| `Cloud` | `/api/cloud/assets`, `/posture` | Cloud asset inventory, posture findings with full-body PATCH |
| `Grc` | `/api/grc/controls*`, `/risks*` | Control status + evidence, risk register with likelihood×impact score recomputation |
| `Exercises` | `/api/exercises*` | Authorized red-team/CTF flows: planned→authorized→running→completed (reason required on completion); detail modal with run log |
| `Agents` | `/api/agents*` | Pending approval queue with approve/reject + comment, task queue with tool-call trace, agent allowlists, tool registry, evals runner |
| `Automation` | `/api/automation*` | Playbook list with **dry run** (plan preview, nothing executes) and gated run, execution history |
| `Reports` | `/api/reports*` | Generated reports with input row count + `input_sha256` provenance; kind filter; download (requires `reports.generate`) |
| `Admin` | `/api/admin/*`, `/api/auth/users*` | Tabs: audit log (hash-chain verify banner, filters, pager) · users (roles, deactivation) · integrations + health · feature flags · backup/restore (typed `RESTORE` confirm) |

## Shell & safety conventions

- `src/main.tsx` uses **HashRouter** so the SPA works from the backend's
  catch-all with zero server configuration.
- `App.tsx` renders the environment badge (LOCAL/LAB/STAGING/PROD) and
  gates the shell on `GET /api/auth/me`.
- `src/api.ts` is the single fetch wrapper (cookie `credentials:
  "same-origin"`, error surfacing from `detail.code`).
- `src/components.tsx`: shared `useApi`, `LoadBlock`, `PageHead`,
  `SevBadge`, `StBadge`, `Stat`, `Pager`, `Modal`, `ConfirmButton`,
  `useFlash`.
- Destructive/gated actions use `ConfirmButton` with explicit confirm
  text (restore requires typing `RESTORE`).

## Testing

The frontend is typechecked + built in CI (`npm run build` runs
`tsc -b`). Behavioral coverage of the APIs it calls comes from the
backend suite (145 tests, `app/backend/tests/`); manual E2E flows are
recorded in docs/13.

Status badges reuse the `.st` classes in `theme.css`. SEC-074 added
`.st.inert` (red) for a detection rule that is stored as `active` but cannot
compile — it deliberately does not reuse the green `live` or amber `gap`
styling, because "will never fire" is a different state from "has not fired
yet".

## Vocabulary parity (SEC-079)

Every picker that sends a status, kind, severity or role value must offer exactly what the API accepts. `tests/test_enum_parity.py` reads the page sources and compares each named list with the API's allowed set, failing CI with a two-way diff — a UI that offers a value the API rejects (and hides one it accepts) is a defect that presents as a backend error to the person using it.
