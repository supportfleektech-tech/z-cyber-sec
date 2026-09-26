# Lab Range (training targets)

**Status:** implemented (SEC-115) · **Registry:** `/api/lab/*` · **UI:** *Lab range*
(Assurance group) · **Containers:** `infra/lab/docker-compose.yml`

## Why this exists

The platform has three halves of an authorized exercise:

| Half | Where it lives | What it answers |
|---|---|---|
| Written authorization | `exercises` (`scope`, `owner`, window, `targets`) | *Are we allowed to touch this?* |
| Scope enforcement | `/api/tradecraft/scope/check`, the review/chain guards | *Is this target inside that authorization?* |
| **The range** | **`lab_targets` + `infra/lab`** | ***Does the target actually exist and is it up?*** |

The third half was missing. The demo seed proved it: exercise 2 was authorized against
`lab-ctf-target-01`, a hostname no container ever served, and nothing in the platform
could say so. Worse, the inverse mistake was equally invisible: a container left running
that no exercise authorized is scope drift, and the platform's own `running` telemetry
never mentioned it.

`GET /api/lab/coverage` closes both:

```
authorized_but_not_running   -> the exercise is live, the target is down (session will fail)
running_but_not_authorized   -> scope drift; fix scope or stop the container
authorizations_with_no_target-> a range-shaped name in scope that is not registered
other_authorized_targets     -> legitimate non-container targets (mailboxes, vendor hosts)
ok                           -> false when running_but_not_authorized or
                                authorizations_with_no_target is non-empty
```

Only names that read like range targets (`lab-*`, `*.lab`, `host:port`) count as
dangling. A check that flags a phishing drill's mailbox addresses would be a check
someone turns off within a week — that judgement is recorded in the router and pinned by
a test.

## Using it

```bash
# 1. start the range (all ports publish to 127.0.0.1 only, on an internal network)
docker compose -f infra/lab/docker-compose.yml --profile juice --profile api up -d

# 2. register what you started (the name must match what exercises list)
curl -s -X POST http://127.0.0.1:8080/api/lab/targets -b cookie.txt \
  -H 'content-type: application/json' \
  -d '{"name":"lab-juice-01","kind":"web","endpoint":"lab-juice-01:3000","exposure":"high"}'

# 3. authorize it: create the exercise (starts `planned`), then PATCH status
#    -> `authorized` with a written scope and a window (SEC-107 validates the window)

# 4. check the cross-check
curl -s http://127.0.0.1:8080/api/lab/coverage -b cookie.txt | jq '.ok, .running_but_not_authorized'

# 5. tear down
docker compose -f infra/lab/docker-compose.yml down
```

The platform never starts, stops or touches a target: it records what exists. Actions
against a target are performed by the operator, inside the exercise's window, and every
step is audited on the platform side.

## Included targets

| Name | Image | Port (loopback) | Practises |
|---|---|---|---|
| `lab-juice-01` | `bkimminich/juice-shop` | 3000 | AppSec practice: the OWASP Top 10 in one SPA |
| `lab-ctf-target-01` | `vulnerables/web-dvwa` | 8081 | CTF-style web exploitation (default lab credentials) |
| `lab-api-01` | `python:3.11-alpine` + `infra/lab/api/labapi.py` | 8001 | API authorization: IDOR, unauthorised admin route, debug leak |

`lab-api-01` is ours on purpose — a few deliberately wrong endpoints in the standard
library only, so the range does not depend on a third-party image staying published:

```
GET  /api/users/{id}     -> any caller reads any user (no ownership check)
GET  /api/admin/config   -> an "admin" route with no authorization at all
GET  /api/debug          -> dumps the environment, including a fake signing key
POST /api/login          -> any password is accepted
```

## Isolation rules (do not edit casually)

1. Everything joins `lab_range`, declared `internal: true` — containers reach each other
   and nothing else. There is no route from the range to the platform network or the
   internet.
2. Every port publish is bound to `127.0.0.1`. Changing one to `0.0.0.0` "to test from
   another machine" is the single edit that turns a lab into an incident.
3. Vulnerable images never join the platform's network (`infra/compose/compose.yaml`),
   and the platform never joins `lab_range`.
4. The range carries synthetic data only. Nothing in it touches real records, evidence or
   credentials; `lab-api-01`'s "signing key" is a literal string in its source.

## What the registry is not

It is not container orchestration: the platform does not hold a Docker socket, cannot
start or stop a container, and `status` is operator-reported (or set by whoever ran
compose). Making the platform drive Docker would give an application-level compromise
host-level consequences — the isolation rules above are exactly what we would lose.

## Related

- `docs/16-adversary-tradecraft.md` — the review/chain workflow that consumes in-scope
  targets.
- `docs/03-network-design.md` — zone/flow matrix; the range is its own zone.
- `docs/12-api-reference.md#lab-range-apitlab` — endpoint reference.
- `infra/lab/docker-compose.yml`, `infra/lab/api/labapi.py` — the range itself.
