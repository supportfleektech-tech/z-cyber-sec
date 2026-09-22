"""The-Xploiter — adversary tradecraft for authorized engagements (SEC-075).

What this module is: the *reasoning, validation and reporting* layer of an
offensive capability, integrated with the platform's existing governance
(docs/06) instead of bolted on beside it.

What this module deliberately is NOT: a weapon. No exploit payloads, no
scanners, no shell tool (the agent tool registry has none at all — policy.py).
It exists to answer the questions a findings list cannot:

  - Is this ACTUALLY exploitable, or is it a scanner's guess?
  - Under which preconditions, and what is the impact once those hold?
  - Can several low-impact issues be chained into one high-impact path?
  - What would an attacker do next from here?
  - What does a hostile triager need in order to accept this report?

Three design commitments, lifted from the persona but enforced in code:

1. **Authorization is structural, not a checkbox.** Every target named in a
   review or chain must appear in the `targets` of an exercise whose status is
   `authorized` or `running`. Unknown and out-of-scope targets are refused and
   the refusal is audited. Real-world scope wording ("*.example.com") is
   matched, but deliberately over-broad entries (0.0.0.0/0, ::/0, `*`) are
   treated as *not* authorizing anything.
2. **Non-exploitable findings are rejected, not reported.** `theoretical`
   verdicts are recorded (so nobody re-tests the same thing) but marked
   non-reportable and barred from chains — this is the "rejects theoretical or
   non-exploitable findings" principle made mechanical.
3. **Impact must escalate.** A chain that does not raise impact above its own
   entry point is not a chain, it is a list; it is refused unless the author
   documents why (``escalation_note``).
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import sqlite3
from datetime import UTC, datetime
from typing import Any

from .. import db

# ------------------------------------------------------------------- persona

PERSONA: dict[str, Any] = {
    "codename": "The-Xploiter",
    "role": "Offensive security reasoning, validation and reporting",
    "summary": (
        "A real-attacker and professional-consultant mindset: focus on attack "
        "surfaces and trust boundaries rather than isolated bugs, on pivoting "
        "and escalation rather than single findings, and on why an attack works "
        "rather than only how. Output is meant to be useful in real assessments."
    ),
    "focus_areas": [
        "Ethical hacking and penetration testing workflows",
        "Bug bounty reconnaissance, validation, and triage-ready reporting",
        "Red team tradecraft and adversary-style thinking",
        "Web application security (OWASP Top 10 + advanced logic flaws)",
        "Active Directory attack paths and misconfiguration analysis",
        "Cloud, API, and modern application security",
        "Tool-assisted and manual exploitation strategies",
        "Clear, engineer-friendly remediation guidance",
    ],
    "design_principles": [
        {
            "principle": "Surfaces and boundaries, not isolated bugs",
            "means": "A finding is described by the attack surface it sits in and "
                     "the trust boundary it crosses.",
        },
        {
            "principle": "Pivoting and escalation",
            "means": "Low impact becomes high impact only when a path is shown; "
                     "chains are modelled as ordered steps with impact deltas.",
        },
        {
            "principle": "Explain WHY, not just HOW",
            "means": "Every verdict carries a rationale: the mechanism that makes "
                     "the behaviour exploitable (or the mechanism that prevents it).",
        },
        {
            "principle": "Reject theoretical and non-exploitable findings",
            "means": "Unproven issues are recorded as non-reportable; they never "
                     "enter a deliverable or a chain.",
        },
        {
            "principle": "Assume hostile triage",
            "means": "Reportability requires evidence, reproduction and a named "
                     "in-scope target — the standard a bounty triager applies.",
        },
    ],
    "use_cases": [
        "Validating whether a finding is actually exploitable",
        "Turning low-severity issues into high-impact attack chains",
        "Understanding how an attacker would think next",
        "Preparing for certifications such as eJPT, OSCP, CRTO",
        "Improving bug bounty signal-to-noise ratio",
        "Writing clearer, stronger vulnerability reports",
    ],
    "guardrails": [
        "Targets must belong to an exercise in status authorized/running "
        "(deny-by-default; refusals are audited as tradecraft.out_of_scope).",
        "Over-broad scope entries (0.0.0.0/0, ::/0, *) authorize nothing.",
        "No exploit payloads and no scanning engine ship with the platform; the "
        "agent gateway's tool registry contains no shell tool at all.",
        "Agent-initiated reviews and chains are consequential tools and require "
        "a human approval before execution (docs/06).",
        "Theoretical/non-exploitable findings are recorded but never reportable.",
        "Every review, chain and refusal is written to the hash-chained audit log.",
    ],
    "certification_mapping": [
        {"cert": "eJPT", "focus": "methodology, host and web enumeration, exploit validation"},
        {"cert": "OSCP", "focus": "manual exploitation, privilege escalation, chained paths"},
        {"cert": "CRTO", "focus": "adversary tradecraft, AD attack paths, operational thinking"},
    ],
}

# ------------------------------------------------------------------ rubric

VERDICTS = ("exploitable", "needs_evidence", "not_exploitable", "theoretical")

IMPACTS = ("info", "low", "medium", "high", "critical")
_IMPACT_RANK = {name: i for i, name in enumerate(IMPACTS)}

# Verdicts that may appear in a deliverable at all.
REPORTABLE = ("exploitable", "not_exploitable")

TRUST_BOUNDARIES = (
    "unauthenticated->authenticated",
    "user->admin",
    "tenant->tenant",
    "edge->internal",
    "container->host",
    "workstation->domain",
    "cloud-identity->resource",
    "other",
)

REVIEW_QUESTIONS = [
    "What must be true for this to be exploitable? (preconditions)",
    "Which trust boundary is crossed?",
    "What is the impact before and after the preconditions hold?",
    "What evidence proves exploitation actually happened?",
    "Can another engineer repeat it from the reproduction steps?",
]


_SEVERITY_WORDS = {"critical", "high", "medium", "low", "info", "severe", "important", "minor",
                   "severity", "sev"}


def _fingerprint(target: str | None, vuln: dict | None, title: str | None) -> str:
    """Stable dedupe key: same target + same weakness class + same shape.

    Bug bounty triage dies on duplicates; identical submissions cluster instead
    of being re-reviewed. So the key must be invariant under presentation
    noise — otherwise the same finding submitted twice lands in two clusters
    and the feature silently does nothing:

    - the target is normalised the same way scope matching is (scheme, port,
      path and trailing dots dropped), so ``https://lab-web-01:8443/x`` and
      ``lab-web-01`` agree;
    - severity vocabulary is dropped from the title words, because
      "SQL Injection (critical)" and "sql injection" are one finding;
    - everything else about the title is sorted, so word order does not matter.
    """
    asset = _normalize_target(target or "") or str((vuln or {}).get("asset_id") or "")
    cve = ((vuln or {}).get("cve_id") or "").lower()
    raw = title or (vuln or {}).get("title") or ""
    words = re.sub(r"[^a-z0-9 ]", " ", raw.lower()).split()
    signature = " ".join(sorted(w for w in words if len(w) > 3 and w not in _SEVERITY_WORDS))
    return hashlib.sha256(f"{asset}|{cve}|{signature}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------- scope guard

_OVERBROAD = {"*", "0.0.0.0/0", "::/0", "0.0.0.0", "any", "all"}


def _normalize_target(raw: str) -> str:
    """Reduce a target to a comparable host/network token.

    Accepts URLs, host:port, CIDRs and bare hosts, because that is how scope
    documents are actually written.

    Careful: userinfo stripping applies to the URL form only. Scope entries are
    not always hostnames — an account identifier such as ``test1@test.local``
    (as in a phishing simulation's authorized account list) must survive
    normalization intact, or "test1@test.local" would collapse to "test.local"
    and silently authorize the whole domain.
    """
    t = (raw or "").strip().lower()
    scheme = re.match(r"^[a-z][a-z0-9+.-]*://", t)
    if scheme:
        t = t[scheme.end():]                         # strip scheme
        t = t.rsplit("@", 1)[-1]                     # strip userinfo (URL form only)
        t = t.split("/", 1)[0]                       # strip path
    elif not _looks_like_cidr(t):
        t = t.split("/", 1)[0]                       # tolerate "host/path"
    t = t.rstrip(".")
    if not _looks_like_cidr(t) and not _looks_like_wildcard(t):
        t = t.split(":", 1)[0]                       # strip port
    return t


def _looks_like_cidr(t: str) -> bool:
    return "/" in t and re.match(r"^[0-9a-f:.]+/\d{1,3}$", t) is not None


def _looks_like_wildcard(t: str) -> bool:
    return t.startswith("*.")


def _scope_entry_valid(entry: str) -> tuple[bool, str]:
    e = (entry or "").strip().lower()
    if not e:
        return False, "empty scope entry"
    if e in _OVERBROAD:
        return False, "over-broad scope entry authorizes nothing"
    if "/" in e and _looks_like_cidr(e):
        try:
            net = ipaddress.ip_network(e, strict=False)
        except ValueError:
            return False, "invalid CIDR"
        if net.prefixlen == 0:
            return False, "over-broad scope entry authorizes nothing"
    return True, ""


def _matches(entry: str, target: str) -> bool:
    e, t = _normalize_target(entry), _normalize_target(target)
    if not e or not t:
        return False
    if e == t:
        return True
    if _looks_like_wildcard(e):
        suffix = e[1:]  # ".example.com"
        return t.endswith(suffix) or t.split(":", 1)[0].endswith(suffix)
    if _looks_like_cidr(e):
        try:
            return ipaddress.ip_address(t) in ipaddress.ip_network(e, strict=False)
        except ValueError:
            return False
    return False


def _window_state(starts_at, ends_at, today: str) -> tuple[str, str | None]:
    """(state, note) for an engagement's authorization window.

    Authority is bounded in time: a written authorization that says "until
    Friday" stops authorizing on Saturday. Treating an expired engagement as
    live would mean the control quietly outlives the permission it rests on.
    Missing dates are treated as open-ended (state 'open') — explicit is
    better, but an engagement with no end date has not claimed one.
    """
    start = (str(starts_at)[:10] if starts_at else "") or ""
    end = (str(ends_at)[:10] if ends_at else "") or ""
    if end and end < today:
        return "expired", f"authorization window ended {end} — renew the engagement"
    if start and start > today:
        return "not_started", f"authorization window starts {start} — not in force yet"
    if not start and not end:
        return "open", "no window recorded — open-ended authorization"
    return "active", None


def authorized_targets(conn: sqlite3.Connection, today: str | None = None) -> list[dict]:
    """Every target currently authorizing tradecraft work (flattened, with owner).

    A target authorizes work only when its engagement is `authorized`/`running`
    **and** its window is in force. Over-broad entries and out-of-window
    engagements are still listed, but as unusable with the reason — visible,
    and inert.
    """
    today = today or datetime.now(UTC).strftime("%Y-%m-%d")
    rows = db.q(conn, "SELECT id, name, status, targets, owner, starts_at, ends_at "
                      "FROM exercises WHERE status IN ('authorized', 'running') ORDER BY id")
    out = []
    for r in rows:
        state, note = _window_state(r.get("starts_at"), r.get("ends_at"), today)
        for entry in (db.jload(r.get("targets"), []) or []):
            ok, why = _scope_entry_valid(str(entry))
            if ok and state in ("expired", "not_started"):
                ok, why = False, note
            out.append({
                "exercise_id": r["id"], "exercise": r["name"], "status": r["status"],
                "owner": r.get("owner"), "target": entry,
                "starts_at": r.get("starts_at"), "ends_at": r.get("ends_at"),
                "window_state": state,
                "usable": ok, "note": why or None,
            })
    return out


def check_target(conn: sqlite3.Connection, target: str) -> dict:
    """Is ``target`` inside a currently-authorized engagement? Deny by default."""
    if not (target or "").strip():
        return {"in_scope": False, "reason": "no target given",
                "exercise_id": None, "exercise": None}
    for row in authorized_targets(conn):
        if not row["usable"]:
            continue
        if _matches(str(row["target"]), target):
            return {"in_scope": True, "reason": f"authorized by exercise {row['exercise_id']}",
                    "exercise_id": row["exercise_id"], "exercise": row["exercise"],
                    "matched_entry": row["target"]}
    # The target may match an entry that exists but cannot authorize work
    # (lapsed window, over-broad entry). Answering "not listed in any exercise"
    # there sends the operator hunting for a missing entry when the real fix is
    # to renew the engagement — the refusal must name the actual cause.
    lapsed = [r for r in authorized_targets(conn)
              if not r["usable"] and _matches(str(r["target"]), target)]
    if lapsed:
        row = lapsed[0]
        return {
            "in_scope": False,
            "reason": (f"target matches exercise {row['exercise_id']} ({row['exercise']}), but "
                       f"that engagement does not authorize work right now: {row['note']}"),
            "exercise_id": None, "exercise": None,
        }
    return {
        "in_scope": False,
        "reason": ("target is not listed in any exercise in status authorized/running "
                   "— tradecraft work requires a written authorization first"),
        "exercise_id": None, "exercise": None,
    }


def scope_summary(conn: sqlite3.Connection) -> dict:
    rows = authorized_targets(conn)
    ignored = [r for r in rows if not r["usable"]]
    return {
        "authorized": [r for r in rows if r["usable"]],
        "ignored_entries": ignored,
        "expired_engagements": sorted({(r["exercise_id"], r["exercise"], r["note"])
                                       for r in ignored if r["window_state"] == "expired"}),
        "deny_by_default": True,
        "rule": ("Only targets of exercises in status authorized/running, with an "
                 "authorization window currently in force, authorize work; anything "
                 "else is refused and audited."),
    }


# ------------------------------------------------------------- review validation

def _has_content(v: Any) -> bool:
    if isinstance(v, str):
        return bool(v.strip())
    if isinstance(v, (list, dict)):
        return len(v) > 0
    return False


def validate_review(conn: sqlite3.Connection, payload: dict) -> dict:
    """Check a proposed exploitability review. Returns a decision dict.

    ``{"ok": bool, "errors": [...], "policy_note": str|None, "triage_ready": bool}``
    Never raises for user input: the router turns errors into a 400.
    """
    errors: list[str] = []
    verdict = (payload.get("verdict") or "").strip().lower()
    if verdict not in VERDICTS:
        errors.append(f"verdict must be one of {list(VERDICTS)}")

    target = (payload.get("target") or "").strip()
    scope = check_target(conn, target) if target else None
    if verdict == "exploitable" and not target:
        errors.append("an 'exploitable' verdict must name the in-scope target it was proven against")
    if target and scope and not scope["in_scope"]:
        errors.append(f"out of scope: {scope['reason']}")

    rationale = (payload.get("rationale") or "").strip()
    if len(rationale) < 20:
        errors.append("rationale must explain WHY (at least 20 characters) — "
                      "'what' alone is a scanner output, not an assessment")

    # Evidence requirements scale with the claim being made.
    if verdict == "exploitable":
        if not _has_content(payload.get("evidence")):
            errors.append("an 'exploitable' verdict requires evidence (observed output, "
                          "request/response, or artifact reference)")
        if len((payload.get("reproduction") or "").strip()) < 20:
            errors.append("an 'exploitable' verdict requires reproduction steps another "
                          "engineer can follow (at least 20 characters)")
        if not (payload.get("impact_after") or "").strip():
            errors.append("an 'exploitable' verdict requires an impact statement (impact_after)")
    if verdict == "not_exploitable" and not _has_content(payload.get("evidence")):
        errors.append("a 'not_exploitable' verdict requires the evidence that disproved it")

    policy_note = None
    triage_ready = False
    if verdict == "exploitable":
        triage_ready = not errors
    elif verdict == "not_exploitable":
        triage_ready = not errors
        policy_note = "recorded as a rejection with rationale — prevents re-testing, not a deliverable"
    elif verdict == "needs_evidence":
        policy_note = "lead, not a finding: unproven. Not reportable until upgraded to 'exploitable'."
    elif verdict == "theoretical":
        policy_note = ("rejected by persona policy: no demonstrated exploitation path. "
                       "Recorded so it is not re-tested; never reportable and never chainable.")

    return {"ok": not errors, "errors": errors, "policy_note": policy_note,
            "triage_ready": triage_ready, "scope": scope}


def validate_chain(conn: sqlite3.Connection, payload: dict) -> dict:
    """Check a proposed attack chain. Same contract as :func:`validate_review`."""
    errors: list[str] = []
    steps = payload.get("steps") or []
    if not isinstance(steps, list) or len(steps) < 2:
        errors.append("a chain needs at least 2 ordered steps — otherwise it is a finding, "
                      "not a chain")
    else:
        for i, s in enumerate(steps):
            if not isinstance(s, dict):
                errors.append(f"step {i + 1} must be an object")
                continue
            if not (s.get("action") or "").strip():
                errors.append(f"step {i + 1} needs an action")
            impact = (s.get("impact") or "").strip().lower()
            if impact not in IMPACTS:
                errors.append(f"step {i + 1} needs an impact from {list(IMPACTS)}")

        impacts = [(s.get("impact") or "").strip().lower() for s in steps if isinstance(s, dict)]
        impacts = [i for i in impacts if i in _IMPACT_RANK]
        if impacts:
            entry_rank = _IMPACT_RANK[impacts[0]]
            if all(_IMPACT_RANK[i] <= entry_rank for i in impacts[1:]) and not (
                    payload.get("escalation_note") or "").strip():
                errors.append(
                    "chain does not escalate: no step raises impact above the entry point. "
                    "Add a step that does, or document escalation_note explaining the "
                    "compounding effect.")

    combined = (payload.get("combined_impact") or "").strip().lower()
    if combined not in IMPACTS:
        errors.append(f"combined_impact must be one of {list(IMPACTS)}")
    if not (payload.get("entry_point") or "").strip():
        errors.append("entry_point is required (where the attacker starts)")

    targets = [t for t in (payload.get("targets") or []) if (t or "").strip()]
    out_of_scope = []
    for t in targets:
        scope = check_target(conn, t)
        if not scope["in_scope"]:
            out_of_scope.append({"target": t, "reason": scope["reason"]})
    if out_of_scope:
        errors.append("out of scope: " + "; ".join(f"{o['target']} — {o['reason']}"
                                                   for o in out_of_scope))

    for i, s in enumerate(steps if isinstance(steps, list) else []):
        if isinstance(s, dict) and (s.get("target") or "").strip():
            scope = check_target(conn, s["target"])
            if not scope["in_scope"]:
                errors.append(f"step {i + 1} target out of scope: {scope['reason']}")
                # Audited like the top-level case: a step pointing at an
                # un-authorized host is the same governance event.
                out_of_scope.append({"target": s["target"], "reason": scope["reason"],
                                     "step": i + 1})

    rationale = (payload.get("rationale") or "").strip()
    if len(rationale) < 20:
        errors.append("rationale must explain why the chain works end to end (at least 20 characters)")

    return {"ok": not errors, "errors": errors, "out_of_scope": out_of_scope}


# ------------------------------------------------------------ deliverable builder

def _bullets(items: Any) -> str:
    if not items:
        return "_(none recorded)_"
    if isinstance(items, dict):
        items = [f"{k}: {v}" for k, v in items.items()]
    return "\n".join(f"- {i}" for i in items)


def triage_report(finding: dict, reviews: list[dict], chains: list[dict]) -> str:
    """Build a hostile-triager-ready report from the recorded evidence.

    The shape is the one bounty triagers and clients ask for: what, where,
    why it works, proof, impact, remediation, and the honest confidence level.
    """
    latest = reviews[0] if reviews else None
    verdict = (latest or {}).get("verdict", "unreviewed")
    reportable = bool(latest and latest.get("triage_ready"))
    sev = finding.get("severity") or "unknown"

    review = latest or {}
    target_label = review.get("target") or f"asset {finding.get('asset_id') or 'unset'}"
    if finding.get("id"):
        target_label += f" · finding {finding['id']}"
    cvss_note = f" · CVSS {finding['cvss']}" if finding.get("cvss") else ""
    policy_note = f" · {review['policy_note']}" if review.get("policy_note") else ""
    impact_line = (f"- Impact before preconditions: {review.get('impact_before') or '—'}"
                   f" → after: {review.get('impact_after') or '—'}")
    impact_body = finding.get("description") or "_(finding description not recorded)_"
    if review.get("impact_after"):
        impact_body += f"\n\nObserved impact: {review['impact_after']}"

    lines = [
        "# Vulnerability Report — triage-ready draft",
        "",
        f"**Title:** {finding.get('title')}",
        f"**Target:** {target_label}",
        f"**Severity (reported):** {sev}{cvss_note}",
        f"**Weakness:** {finding.get('cve_id') or (finding.get('source') or 'unspecified')}",
        f"**Trust boundary crossed:** {review.get('trust_boundary') or 'not yet determined'}",
        "",
        "## Status: " + ("READY FOR SUBMISSION" if reportable else "NOT SUBMITTABLE"),
        "",
        f"- Verdict: `{verdict}`{policy_note}",
        impact_line,
        "- Include this report only if the verdict above is `exploitable`. Anything else "
        "is a lead or a rejection, and submitting it costs credibility (and bounty).",
        "",
        "## Why it works",
        review.get("rationale") or "_(no review recorded — this finding has not been validated)_",
        "",
        "## Preconditions",
        _bullets(review.get("preconditions")),
        "",
        "## Reproduction",
        review.get("reproduction") or "_(not recorded)_",
        "",
        "## Evidence",
        _bullets(review.get("evidence")),
        "",
        "## Impact",
        impact_body,
    ]

    if chains:
        lines += ["", "## Attack paths this finding participates in"]
        for c in chains:
            lines.append(f"- **{c['title']}** ({c['status']}, combined impact "
                         f"{c['combined_impact']}) — entry: {c['entry_point']}")
            for s in (c.get("steps") or []):
                lines.append(f"  {s.get('order', '?')}. {s.get('action')} "
                             f"[{s.get('impact')}]")
    else:
        lines += ["", "## Attack paths this finding participates in",
                  "_(none recorded — consider whether this issue enables or is enabled by "
                  "another finding: that is usually where severity comes from)_"]

    lines += [
        "",
        "## Remediation",
        finding.get("remediation") or "_(no remediation recorded — add engineer-friendly steps: "
                                      "what to change, where, and how to verify the fix)_",
        "",
        "## Reviewer confidence",
        f"- Recorded reviews: {len(reviews)}",
        f"- Triage-ready: {'yes' if reportable else 'no'}",
        "- Dedupe key: " + ", ".join(sorted({r.get('dedupe_key') or '—' for r in reviews})),
    ]
    return "\n".join(lines)


# ------------------------------------------------------------------ aggregation

def vuln_context(conn: sqlite3.Connection, vuln_id: int) -> dict:
    """Everything recorded about one finding: reviews + chains it appears in."""
    finding = db.one(conn, "SELECT * FROM vuln_findings WHERE id = ?", (vuln_id,))
    if not finding:
        return {}
    reviews = db.q(conn, "SELECT * FROM exploitability_reviews WHERE vuln_id = ? "
                         "ORDER BY created_at DESC, id DESC", (vuln_id,))
    for r in reviews:
        r["preconditions"] = db.jload(r.get("preconditions"), [])
        r["evidence"] = db.jload(r.get("evidence"), [])
    chains = []
    for c in db.q(conn, "SELECT * FROM attack_chains ORDER BY created_at DESC"):
        steps = db.jload(c.get("steps"), []) or []
        if any(str(s.get("vuln_id")) == str(vuln_id) for s in steps):
            c["steps"] = steps
            chains.append(c)
    finding["remediation"] = db.one(
        conn, "SELECT title FROM remediation_tasks WHERE vuln_id = ? "
              "ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, id DESC LIMIT 1", (vuln_id,),)
    finding["remediation"] = (finding.get("remediation") or {}).get("title")
    return {"finding": finding, "reviews": reviews, "chains": chains}


def stats(conn: sqlite3.Connection) -> dict:
    def c(sql, params=()):
        row = db.one(conn, sql, params)
        return int(row["c"]) if row else 0

    by_verdict = {v: c("SELECT COUNT(*) c FROM exploitability_reviews WHERE verdict = ?", (v,))
                  for v in VERDICTS}
    return {
        "reviews": c("SELECT COUNT(*) c FROM exploitability_reviews"),
        "reviews_triage_ready": c("SELECT COUNT(*) c FROM exploitability_reviews WHERE triage_ready = 1"),
        "by_verdict": by_verdict,
        "chains": c("SELECT COUNT(*) c FROM attack_chains"),
        "chains_validated": c("SELECT COUNT(*) c FROM attack_chains WHERE status = 'validated'"),
        "authorized_targets": len([t for t in authorized_targets(conn) if t["usable"]]),
        "rejected_as_theoretical": by_verdict.get("theoretical", 0),
    }


def duplicates(conn: sqlite3.Connection) -> list[dict]:
    """Cluster reviews by fingerprint — the signal-to-noise view for triage."""
    rows = db.q(conn, "SELECT dedupe_key, COUNT(*) AS n FROM exploitability_reviews "
                      "WHERE dedupe_key IS NOT NULL GROUP BY dedupe_key HAVING n > 1 "
                      "ORDER BY n DESC")
    out = []
    for r in rows:
        items = db.q(conn, "SELECT id, vuln_id, target, verdict, triage_ready, created_at "
                           "FROM exploitability_reviews WHERE dedupe_key = ? ORDER BY id", (r["dedupe_key"],))
        out.append({"dedupe_key": r["dedupe_key"], "count": r["n"], "reviews": items})
    return out
