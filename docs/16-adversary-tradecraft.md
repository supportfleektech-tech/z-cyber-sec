# 16 — Adversary Tradecraft (The-Xploiter)

**Status:** v1.0 (SEC-075). The-Xploiter is the platform's offensive-reasoning
persona: exploitability validation, attack-chain modelling, and triage-ready
reporting — integrated into the existing agent governance (docs/06), not bolted
on beside it.

## What it is — and what it deliberately is not

**Is:** the reasoning, validation and reporting layer of an offensive
capability, bound to the platform's authorization model.

**Is not:** a weapon. No exploit payloads, no scanning engine, no network
action. The agent tool registry contains **no shell, execution, or scanning
tool at all** (docs/06; asserted by a test). The platform never initiates
network action against anything — exercises and tradecraft work are
*recorded*, and the tests that prove it are in `tests/test_tradecraft.py`.

This boundary is the point. A findings list tells you what a scanner *thinks*
is wrong. It cannot tell you whether an issue is reachable, what must be true
for it to matter, or whether several small issues add up to one serious one.
Those are human judgements — and this module exists to record and check them,
not to automate attack.

## The persona

| | |
|---|---|
| **Focus areas** | Ethical hacking/pentest workflows · bug bounty recon, validation, triage-ready reporting · red team tradecraft · web app security (OWASP Top 10 + logic flaws) · Active Directory attack paths · cloud/API/modern app security · tool-assisted + manual exploitation strategy · engineer-friendly remediation |
| **Design principles** | Attack surfaces and trust boundaries, not isolated bugs · pivoting and escalation (low → high) · explain **why**, not just how · reject theoretical/non-exploitable findings · assume hostile triage |
| **Use cases** | Validate real exploitability · turn low-severity into high-impact chains · think like the next attacker move · prepare for eJPT / OSCP / CRTO · improve bug bounty signal-to-noise · write stronger reports |

`GET /api/tradecraft/persona` serves this; `GET /api/tradecraft/rubric` serves
the verdict vocabulary and evidence policy.

### Persona ≠ permission

A persona changes the **system prompt** of an agent (`adapter_config.persona`),
never its authority. The tool allowlist, the approval gate and the scope guard
all sit *below* the adapter and cannot be reached through prompt text. Unknown
persona names are refused at creation (`400 bad_persona`) so a typo cannot
quietly leave an agent behaving differently from what an operator believes.

## The scope guard (the safety core)

Every target named in a review or a chain must appear in the `targets` of an
exercise whose status is `authorized` or `running`. Nothing else authorizes
work. Specifically:

- **Deny by default.** No engagement ⇒ no authorized targets ⇒ every targeted
  action is refused.
- **Authority cannot be withdrawn silently, nor restored silently.** The
  engagement lifecycle is one-way (SEC-083): `running → planned` is refused with
  `409 illegal_transition` (before the fix it was accepted, and an engagement's
  live authorization simply evaporated mid-flight — its targets stopped being
  authorized and in-flight tradecraft began failing as out-of-scope), and
  `aborted`/`completed` are terminal, so an explicitly stopped engagement cannot
  be reopened to `authorized` in one call. Closing requires a recorded reason.
  Attempts to make those moves are written to the audit log.
- **`planned` is not authorization.** An exercise that exists but has not been
  moved to `authorized` grants nothing (verified live: `lab-ctf-target-01`
  belongs to a *planned* CTF exercise and is correctly not in scope).
- **Over-broad entries authorize nothing.** `0.0.0.0/0`, `::/0`, `*`, `any`,
  `all` are listed in `GET /api/tradecraft/scope` under `ignored_entries` with
  a reason — they are visible, and inert.
- **Authorization is bounded in time.** An engagement carries
  `starts_at`/`ends_at`, and a window that has lapsed (or not yet begun)
  authorizes nothing — *an authorization that ended on the 13th does not
  authorize work on the 22nd*. The scope summary reports `window_state`
  (`active` / `expired` / `not_started` / `open`) per entry and lists lapsed
  engagements under `expired_engagements` with the renewal note, so the reason
  is visible in the UI rather than discovered as a mysterious refusal. A
  refusal caused by a lapsed window names the engagement and the date —
  "not listed in any exercise" would send an operator hunting for a missing
  entry when the fix is to renew the engagement. An engagement with no dates
  recorded is treated as `open` (open-ended), which is reported as such.
- **Refusals are governance events.** An out-of-scope attempt is not only a
  `400`: it writes `tradecraft.out_of_scope` to the hash-chained audit log with
  the target and the reason. Attempting to work outside scope is visible.
- **Scope wording is matched, not string-compared.** URLs, `host:port`, CIDR
  ranges and `*.wildcard` hosts all work — but normalisation is careful:
  userinfo is stripped only in URL form, so an account-style entry such as
  `test1@test.local` (a phish-simulation authorized account) authorizes that
  account and **not** the whole `test.local` domain.

```
GET /api/tradecraft/scope                      # what is authorized now
GET /api/tradecraft/scope/check?target=10.42.0.10   # ask before acting
```

## The four workflows

### 1. Validate whether a finding is actually exploitable

`POST /api/tradecraft/reviews` records a verdict **with its evidence**:

| Verdict | Required | Reportable |
|---|---|---|
| `exploitable` | in-scope target + evidence + reproduction + `impact_after` + rationale explaining the mechanism | **yes** |
| `not_exploitable` | the disproof evidence (so nobody re-tests it) | recorded as a rejection, not a deliverable |
| `needs_evidence` | rationale | no — it is a lead, not a finding |
| `theoretical` | rationale | **never** — rejected by persona policy, and barred from chains |

A rationale must explain *why* (≥20 chars) — "vulnerable" is refused, because
that is scanner output, not assessment.

### 2. Turn low-severity issues into high-impact chains

`POST /api/tradecraft/chains` models a path, not a list:

- **≥2 ordered steps**, each with an action and an impact.
- **Impact must escalate** above the entry point. A low→low "chain" is refused.
  If the compounding is real but not reflected in impact labels, document
  `escalation_note` and it is accepted — the point is that the reasoning is
  explicit, not that a number went up.
- Step targets are scope-checked individually, and an out-of-scope *step* is
  audited exactly like an out-of-scope top-level target.
- Chains start as `draft`; `POST /chains/{id}/status` records the human
  judgement (`validated` / `rejected`) with a mandatory rationale.

### 3. Understand the next attacker move

`GET /api/tradecraft/findings/{id}/triage-report` lists every chain the finding
participates in, with its steps and combined impact — the "what does this
unlock?" view. When a finding is in no chain, the report says so and prompts
the reviewer to look for one, because that is usually where the severity is.

### 4. Triage-ready reporting

`GET /api/tradecraft/findings/{id}/triage-report` returns markdown in the shape
a hostile triager expects: title, target, severity + justification, trust
boundary crossed, **status**, why it works, preconditions, reproduction,
evidence, impact, attack paths, remediation, and reviewer confidence.

The status line is the honesty mechanism: `READY FOR SUBMISSION` only for an
`exploitable` verdict that carried evidence, `NOT SUBMITTABLE` otherwise, with
the policy reason quoted (e.g. a `theoretical` verdict's rejection note).

**Duplicates:** every review carries a fingerprint (`target | CVE | normalised
title words`); `GET /api/tradecraft/duplicates` clusters them. Same target,
same weakness shape ⇒ one cluster, so triage does not re-review the same
submission twice. That is the signal-to-noise use case, implemented rather
than described.

## Agent access

The-Xploiter is usable through the governed agent gateway (docs/06):

| Tool | Type | Approval |
|---|---|---|
| `list_scope_targets` | read-only | auto |
| `get_finding` | read-only | auto |
| `record_exploitability_review` | consequential | **required** |
| `propose_attack_chain` | consequential | **required** |

An agent can read authorized scope and a finding's context freely, but cannot
write an assessment record without a human approving it. Both paths run the
same validators, so an agent cannot record a claim a human could not.

## Engagement deliverable

`POST /api/reports` with `{kind: "tradecraft"}` renders the engagement report
(schedulable like any other kind, e.g. a weekly digest):

- **Engagement summary** — reviews recorded, how many met the evidence
  standard, how many were rejected/disproven, chains (with how many are
  validated).
- **Findings ready for submission** — the triage-ready table, or an explicit
  "none has met the evidence standard".
- **Attack chains** — rendered as *paths* (entry point → steps → combined
  impact), because that is where the severity actually comes from.
- **Rejected & disproven** — included on purpose. A deliverable that lists only
  what was reported hides the discipline behind it; showing the theoretical and
  non-exploitable verdicts (with reasons) is what lets a client or triager
  trust the rest. It is also the answer to "did you test this?" — yes, and here
  is why it did not stand up.

Regenerate after each working session; the file is hashed and audited like
every other report.

## Agent arguments: prose vs. identifiers

Agent tool arguments pass through an injection heuristic
(`policy.validate_args`). Applied to *every* field it rejected ordinary
engagement prose — a reproduction step reading "run
``curl -s http://target/api``" is not an injection attempt, and a tool that
refuses to record it cannot do its job (SEC-076).

Tools therefore declare `text_fields`: free text that is **stored as data and
never interpreted** (reproduction, rationale, evidence, escalation notes, chain
steps). Those are length-capped (8000 chars/entry, 50 entries) instead of
pattern-blocked. Every other field keeps the strict check, and the declaration
is per-tool: the same arguments are still refused for a tool that did not
declare them.

Nothing here executes anything — the registry has no execution primitive at
all — so this is a scoping fix, not a relaxation of a safety boundary. The
approval gate for consequential tools is unaffected: a review recorded by an
agent still waits for a human.

## Certification use

The persona carries an explicit mapping (eJPT: methodology and exploit
validation; OSCP: manual exploitation, privesc, chained paths; CRTO: adversary
tradecraft and AD paths). Practising against an authorized exercise and
recording reviews/chains produces the artefact those exams actually test:
a defensible statement of *why* a path works and what it yields.

## Operating notes

- RBAC: `tradecraft.read` for every role; `tradecraft.write` for
  `soc_analyst`, `ir_lead`, `admin`. The guardrail is the scope check plus
  audit, not role scarcity — recording an assessment is analysis work, the
  same tier as `vulns.write`.
- Every write is audited (`tradecraft.review_recorded`,
  `tradecraft.chain_recorded`, `tradecraft.chain_status`) and the audit chain
  remains verifiable after the fact.
- The UI lives at `/tradecraft` (Assurance group): persona, authorized scope,
  reviews, chains, and the report viewer.
- Nothing here can send traffic. If you need active testing, that is an
  authorized exercise tool run by a human inside the documented scope — the
  platform records the outcome.
