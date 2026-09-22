# 15 — Detection Rules: Subset, Validation, Porting

**Status:** v1.0. The engine is a deliberately small, auditable **Sigma
subset** (ADR-003), implemented natively so the lab runs with zero external
services. This doc is the authority on what the subset accepts, how a rule is
validated, and how to port a rule from a full Sigma pack (e.g. SigmaHQ)
without silently losing detection.

## The rule spec

```yaml
uid: cs-0001                 # REQUIRED, unique
name: SSH Brute Force        # shown in alerts
description: ...             # optional
severity: high               # critical|high|medium|low|info
status: active               # active rules are evaluated; anything else is stored only
detection:                   # REQUIRED — named terms
  fail:
    action: ssh_failed_login
    outcome: failure
  provider:
    source_name: sshd
condition: fail and provider # REQUIRED — grammar below
timeframe: 300               # seconds — only valid together with threshold
threshold: 5                 # minimum matches within timeframe
entity: host                 # field grouped for threshold counting (default host)
```

### Field values

| Form | Meaning |
|---|---|
| `field: value` | exact match (case-insensitive for strings) |
| `field: [a, b]` | **any** value matches |
| `field: {op: gt\|lt\|ge\|le, value: 10}` | numeric comparison |
| `field: {op: contains, value: x}` | substring / membership |

Backing store fields available to every rule: `ts`, `host`, `user`, `action`,
`outcome`, `severity`, `source_name`, `source_type`, plus anything inside the
free-form `data` object.

### Condition grammar (verified, not aspirational)

Supported — each of these compiles and evaluates:

| Condition | Meaning |
|---|---|
| `term` | that term matched |
| `a and b`, `a or b` | boolean combination |
| `not a` | negation |
| `(a or b) and c` | parenthesized grouping |
| `all` | **all** defined terms matched |
| `any` | **any** defined term matched |
| `2 of` | at least **2 of all defined terms** matched by one event |

**Not supported** (these are the constructs a full Sigma pack will contain):

| Sigma construct | Why it fails here |
|---|---|
| `1 of selection*` | no wildcard/glob term references — the tokenizer stops at `*` |
| `2 of (a, b)`, `all of (a, b)` | `of` takes no term list; `N of` counts over *all* terms |
| `field\|contains`, `field\|all`, `field\|re` | no field modifiers — use `{op: contains, value: …}` for a single field |
| `near` | proximity correlation is not implemented |
| `logsource`, `tags`, `falsepositives` | not part of the spec (matching is on event fields) |
| `title`, `id`, `level` | full-Sigma metadata names — use `name`, `uid`, `severity` |

Note the semantics of `N of`: it counts terms matched by **one event**. It is
not a cross-event correlation operator.

## Validation — three layers, so an inert rule cannot hide

A rule that does not compile is **inert**: detection skips it. Left
unchecked that is a silent blind spot — the rules list shows `active`,
coverage shows "not fired yet", and nothing tells the operator the truth.

| Layer | Behaviour |
|---|---|
| **Write** — `POST /api/soc/rules`, `PATCH /api/soc/rules/{id}` | rejected with `400 {code:"bad_rule"}` + reason; invalid rules cannot be created through the API |
| **Seed** — `python -m app.seed.seed_demo` | every shipped `rules/*.yaml` is compiled first; a failure raises immediately, naming the file (a broken shipped rule is a repository bug) |
| **Runtime** — detection, `GET /api/soc/rules`, `GET /api/soc/rules/coverage` | a non-compiling rule is logged as a warning (once per rule per process) and reported as `compiles:false` with the compiler's reason; coverage counts only runnable rules and lists inert ones separately |

Why all three: the API guards new rules, the seed guard catches shipped rules,
and the runtime + API reporting catches rules that **become** invalid — e.g. a
rule stored before the guard existed, restored from a backup, or invalidated by
a change to the grammar. That last case is invisible to any write-time check.

### Where to see rule health

```bash
# Rules with compile status + reason
curl -s -b cookies.txt http://127.0.0.1:8080/api/soc/rules | \
  python3 -m json.tool | head -30
# → summary: {"ok": 6, "broken": 0, "broken_uids": []}

# Coverage: inert rules are reported apart from coverage gaps
curl -s -b cookies.txt http://127.0.0.1:8080/api/soc/rules/coverage
# → "inert_rules": 0, "broken_rules": [], "gaps": []
```

The SOC page shows the same: a `live` / `inert` marker per rule, and a red
banner listing every inert rule with its compiler reason.

## Linting before you commit (or merge)

```bash
cd app/backend
.venv/bin/python -m scripts.lint_rules              # validate rules/*.yaml
.venv/bin/python -m scripts.lint_rules ported.yaml  # validate a ported file
```

Exit `0` = every rule can fire. Exit `1` = at least one rule would be INERT,
with the reason and porting advice on stderr. CI runs this on every push, so a
broken rule cannot merge.

## Porting a rule from a full Sigma pack

1. **Copy the logic, not the metadata.** Rename `title` → `name`, `id` →
   `uid`, `level` → `severity`. Drop `logsource`, `tags`, `falsepositives`.
2. **Flatten selections.** A Sigma rule with `selection_1`, `selection_2` and
   `condition: selection_1 and selection_2` maps directly to two terms
   `s1`/`s2` and `condition: s1 and s2`.
3. **Replace modifiers.** `field|contains: x` → `field: {op: contains, value: x}`.
   There is no `|all`; if you need "all of these substrings", add one term per
   substring and `and` them (or use `all`).
4. **Expand wildcards and `N of` lists.** `1 of selection*` must become an
   explicit `or` chain over named terms, or `any` when you mean every term.
5. **Dry-run before trusting it.**
   ```bash
   # compile check
   .venv/bin/python -m scripts.lint_rules my-rule.yaml
   # then, against real stored events (choose event ids from /api/soc/events)
   curl -s -b cookies.txt -X POST http://127.0.0.1:8080/api/soc/rules/dry-run \
     -H 'Content-Type: application/json' -d '{"rule_id": 7, "event_ids": [1,2,3]}'
   ```
6. **Watch coverage.** After a backfill, a new rule that stays `never_fired`
   is either no-traffic or still-not-matching — `GET /api/soc/rules/coverage`
   distinguishes that from `inert`.

Porting is deliberately a manual step: the subset is small enough to audit,
and a silently-wrong regex translation is worse than a rule you rewrote by
hand.

## Authoring a new rule

```bash
# 1. write the YAML in app/backend/rules/
# 2. validate it
.venv/bin/python -m scripts.lint_rules rules/cs-0007-my-rule.yaml
# 3. load it (fresh DB) or POST it to /api/soc/rules (rules.write)
# 4. re-run active rules over stored events to pick up history
curl -s -b cookies.txt -X POST http://127.0.0.1:8080/api/soc/detections/backfill
# 5. confirm it is live, not inert
curl -s -b cookies.txt http://127.0.0.1:8080/api/soc/rules | grep -o '"broken": [0-9]*'
```

Threshold rules need both `timeframe` and `threshold`; `threshold` without
`timeframe` is rejected (`threshold requires timeframe`).
