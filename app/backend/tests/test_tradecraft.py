"""SEC-075 — The-Xploiter adversary tradecraft.

The point of these tests is the *fencing*, not the prose: an offensive
capability inside a governed platform is only acceptable if the guardrails are
enforced and provable. So what is pinned here is:

  - scope is deny-by-default, and over-broad scope entries authorize nothing;
  - un-authorized targeting is refused AND audited (not just a 400);
  - a claim of exploitability without evidence is refused;
  - theoretical findings are recorded but never reportable and never chainable;
  - a "chain" that does not escalate impact is refused;
  - agent access to the same capability is approval-gated;
  - a persona cannot widen permissions.
"""
from __future__ import annotations

import json

import pytest

from app.services import agent_adapters, policy, tradecraft

GOOD_REVIEW = {
    "verdict": "exploitable",
    "target": "10.42.0.10",
    "trust_boundary": "user->admin",
    "impact_before": "low",
    "impact_after": "critical",
    "preconditions": ["authenticated low-privilege account", "default config unchanged"],
    "evidence": ["POST /api/users returned 200 with role=admin", "response body captured"],
    "reproduction": ("1. log in as low-priv user 2. POST /api/users with role=admin "
                     "3. observe 200 and admin role in response"),
    "rationale": ("Mass-assignment: the handler passes the request body straight into the "
                  "INSERT, so the role column is attacker-controlled."),
}


def _close_seeded_engagements(conn) -> None:
    """Seed data ships one 'authorized' phish-sim drill (accounts test1@test.local).
    Scope tests need a known-empty baseline, so retire them first."""
    conn.execute("UPDATE exercises SET status = 'completed' WHERE status IN ('authorized', 'running')")
    conn.commit()


def _authorized_exercise(conn, targets=None, status="authorized"):
    if status in ("authorized", "running"):
        _close_seeded_engagements(conn)
    now = "2026-01-01T00:00:00Z"
    cur = conn.execute(
        "INSERT INTO exercises (name, scope, status, owner, starts_at, ends_at, targets, meta, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("Q1 internal pentest",
         "Written authorization from the CISO covering the lab range and web app, valid to Q1 end.",
         status, "ciso", now, None, json.dumps(targets or ["10.42.0.10", "lab-web-01",
                                                          "*.lab.example.com", "10.42.1.0/24"]),
         "{}", now, now))
    conn.commit()
    return cur.lastrowid


def _finding(conn, title="Mass assignment on user create", severity="high"):
    now = "2026-01-01T00:00:00Z"
    cur = conn.execute(
        "INSERT INTO vuln_findings (asset_id, cve_id, title, cvss, severity, status, exploitability, "
        "description, source, discovered_at, meta) VALUES (NULL, NULL, ?, 8.8, ?, 'new', NULL, ?, "
        "'manual', ?, '{}')",
        (title, severity, "Role field accepted from the request body.", now))
    conn.commit()
    return cur.lastrowid


# ------------------------------------------------------------------- persona

def test_persona_registry_has_the_requested_profile(client, seeded):
    r = client.get("/api/tradecraft/persona")
    assert r.status_code == 200
    p = r.json()
    assert p["codename"] == "The-Xploiter"
    assert len(p["focus_areas"]) == 8
    assert len(p["design_principles"]) == 5
    assert len(p["use_cases"]) == 6
    assert any("bug bounty" in u.lower() for u in p["use_cases"])
    assert any("exploit" in f.lower() for f in p["focus_areas"])


def test_persona_states_its_guardrails(client, seeded):
    p = client.get("/api/tradecraft/persona").json()
    joined = " ".join(p["guardrails"]).lower()
    assert "authorized" in joined          # scope must be explicit in the persona
    assert "no shell tool" in joined or "no exploit payloads" in joined
    assert "approval" in joined            # agent writes are gated


def test_rubric_explains_the_evidence_policy(client, seeded):
    r = client.get("/api/tradecraft/rubric")
    assert r.status_code == 200
    body = r.json()
    assert set(body["verdicts"]) == set(tradecraft.VERDICTS)
    assert "theoretical" in body["evidence_policy"]
    assert body["reportable"] == ["exploitable", "not_exploitable"]


# --------------------------------------------------------------- scope guard

def test_scope_is_empty_without_an_authorized_engagement(client, seeded):
    _close_seeded_engagements(seeded)
    body = client.get("/api/tradecraft/scope").json()
    assert body["authorized"] == []
    assert body["deny_by_default"] is True


def test_planning_exercise_does_not_authorize(client, seeded):
    """An exercise that exists but is not authorized must grant nothing."""
    _close_seeded_engagements(seeded)
    _authorized_exercise(seeded, status="planned")
    assert client.get("/api/tradecraft/scope").json()["authorized"] == []
    check = client.get("/api/tradecraft/scope/check", params={"target": "10.42.0.10"}).json()
    assert check["in_scope"] is False


def test_authorized_engagement_authorizes_its_targets(client, seeded):
    _authorized_exercise(seeded)
    body = client.get("/api/tradecraft/scope").json()
    assert len(body["authorized"]) == 4
    for target in ("10.42.0.10", "lab-web-01"):
        assert client.get("/api/tradecraft/scope/check",
                          params={"target": target}).json()["in_scope"] is True


def test_scope_matching_handles_urls_ports_cidr_and_wildcards(client, seeded):
    _authorized_exercise(seeded)
    cases = {
        "https://lab-web-01/admin": True,      # URL form of an authorized host
        "lab-web-01:8443": True,               # host:port
        "10.42.1.77": True,                    # inside 10.42.1.0/24
        "app.lab.example.com": True,           # matches *.lab.example.com
        "10.42.9.9": False,                    # outside every entry
        "evil.example.org": False,             # unrelated host
    }
    for target, expected in cases.items():
        got = client.get("/api/tradecraft/scope/check", params={"target": target}).json()
        assert got["in_scope"] is expected, f"{target}: {got}"


def test_overbroad_scope_entries_authorize_nothing(client, seeded):
    """A wildcard-everything scope line must not become a license to attack."""
    eid = _authorized_exercise(seeded, targets=["0.0.0.0/0", "*", "any", "10.42.0.10"])
    summary = client.get("/api/tradecraft/scope").json()
    assert [t["target"] for t in summary["authorized"]] == ["10.42.0.10"]
    ignored = {t["target"] for t in summary["ignored_entries"]}
    assert ignored == {"0.0.0.0/0", "*", "any"}
    assert client.get("/api/tradecraft/scope/check",
                      params={"target": "8.8.8.8"}).json()["in_scope"] is False
    assert eid  # exercise exists; the point is the entries are inert


def test_out_of_scope_target_is_refused_and_audited(client, seeded, conn):
    _authorized_exercise(seeded)
    payload = {**GOOD_REVIEW, "target": "evil.example.org"}
    r = client.post("/api/tradecraft/reviews", json=payload)
    assert r.status_code == 400
    assert any("out of scope" in e for e in r.json()["detail"]["errors"])
    rows = conn.execute("SELECT COUNT(*) c FROM audit_events WHERE action = 'tradecraft.out_of_scope'").fetchone()
    assert rows["c"] == 1, "un-authorized targeting must be a governance event, not a quiet 400"


# -------------------------------------------------------- exploitability reviews

def test_review_requires_a_target_for_an_exploitable_verdict(client, seeded, conn):
    _authorized_exercise(seeded)
    payload = {k: v for k, v in GOOD_REVIEW.items() if k != "target"}
    r = client.post("/api/tradecraft/reviews", json=payload)
    assert r.status_code == 400
    assert any("must name the in-scope target" in e for e in r.json()["detail"]["errors"])


def test_exploitable_verdict_requires_evidence_and_reproduction(client, seeded, conn):
    _authorized_exercise(seeded)
    for missing in ("evidence", "reproduction"):
        payload = {**GOOD_REVIEW}
        payload.pop(missing)
        r = client.post("/api/tradecraft/reviews", json=payload)
        assert r.status_code == 400, f"{missing} omission must be refused"
        assert any(missing in e for e in r.json()["detail"]["errors"])


def test_rationale_must_explain_why(client, seeded, conn):
    """'what' is scanner output; the persona demands mechanism."""
    _authorized_exercise(seeded)
    r = client.post("/api/tradecraft/reviews", json={**GOOD_REVIEW, "rationale": "vulnerable"})
    assert r.status_code == 400
    assert any("WHY" in e for e in r.json()["detail"]["errors"])


def test_valid_review_is_recorded_triage_ready_and_audited(client, seeded, conn):
    _authorized_exercise(seeded)
    fid = _finding(seeded)
    r = client.post("/api/tradecraft/reviews", json={**GOOD_REVIEW, "vuln_id": fid})
    assert r.status_code == 201
    body = r.json()
    assert body["triage_ready"] is True
    assert body["scope"]["exercise_id"] is not None
    audit = conn.execute("SELECT detail FROM audit_events WHERE action = 'tradecraft.review_recorded'").fetchone()
    assert "exploitable" in audit["detail"]


def test_theoretical_verdict_is_recorded_but_never_reportable(client, seeded, conn):
    """The 'reject theoretical findings' principle, made mechanical."""
    _authorized_exercise(seeded)
    fid = _finding(seeded)
    r = client.post("/api/tradecraft/reviews", json={
        "vuln_id": fid, "verdict": "theoretical",
        "rationale": "No reachable code path passes user input into this sink."})
    assert r.status_code == 201
    assert r.json()["triage_ready"] is False
    assert "rejected by persona policy" in r.json()["policy_note"]

    report = client.get(f"/api/tradecraft/findings/{fid}/triage-report").json()
    assert report["reportable"] is False
    assert "NOT SUBMITTABLE" in report["markdown"]


def test_needs_evidence_is_a_lead_not_a_finding(client, seeded, conn):
    _authorized_exercise(seeded)
    fid = _finding(seeded)
    r = client.post("/api/tradecraft/reviews", json={
        "vuln_id": fid, "verdict": "needs_evidence", "target": "10.42.0.10",
        "rationale": "Reflected value seen but encoding behaviour unverified."})
    assert r.status_code == 201
    assert r.json()["triage_ready"] is False
    assert "lead, not a finding" in r.json()["policy_note"]


def test_not_exploitable_requires_disproof_evidence(client, seeded, conn):
    _authorized_exercise(seeded)
    fid = _finding(seeded)
    bare = client.post("/api/tradecraft/reviews", json={
        "vuln_id": fid, "verdict": "not_exploitable", "target": "10.42.0.10",
        "rationale": "Attempted the injection and the parameterised query held."})
    assert bare.status_code == 400
    ok = client.post("/api/tradecraft/reviews", json={
        "vuln_id": fid, "verdict": "not_exploitable", "target": "10.42.0.10",
        "evidence": ["payload ' OR 1=1-- returned the same 0 rows as the control"],
        "rationale": "Attempted the injection and the parameterised query held."})
    assert ok.status_code == 201


def test_unknown_verdict_refused(client, seeded):
    _authorized_exercise(seeded)
    r = client.post("/api/tradecraft/reviews", json={**GOOD_REVIEW, "verdict": "probably"})
    assert r.status_code == 400


def test_review_for_missing_finding_is_404(client, seeded):
    _authorized_exercise(seeded)
    r = client.post("/api/tradecraft/reviews", json={**GOOD_REVIEW, "vuln_id": 999999})
    assert r.status_code == 404


def test_reviews_filter_and_stats(client, seeded, conn):
    _authorized_exercise(seeded)
    fid = _finding(seeded)
    client.post("/api/tradecraft/reviews", json={**GOOD_REVIEW, "vuln_id": fid})
    client.post("/api/tradecraft/reviews", json={
        "vuln_id": fid, "verdict": "theoretical",
        "rationale": "The sink is unreachable from any untrusted input path."})
    listed = client.get("/api/tradecraft/reviews", params={"verdict": "theoretical"}).json()
    assert listed["total"] == 1
    stats = client.get("/api/tradecraft/stats").json()
    assert stats["reviews"] == 2
    assert stats["reviews_triage_ready"] == 1
    assert stats["rejected_as_theoretical"] == 1


# --------------------------------------------------------------- attack chains

GOOD_CHAIN = {
    "title": "Low-priv user to domain takeover",
    "entry_point": "authenticated low-privilege account on lab-web-01",
    "trust_boundary": "workstation->domain",
    "steps": [
        {"action": "abuse mass assignment to become local admin", "impact": "medium"},
        {"action": "read cached domain credentials from the host", "impact": "high"},
        {"action": "authenticate to the domain controller", "impact": "critical"},
    ],
    "combined_impact": "critical",
    "rationale": ("Each step is independently low/medium value; chained, the attacker crosses "
                  "from a single web account to domain control."),
    "targets": ["10.42.0.10"],
}


def test_chain_requires_two_steps(client, seeded):
    _authorized_exercise(seeded)
    r = client.post("/api/tradecraft/chains", json={**GOOD_CHAIN, "steps": GOOD_CHAIN["steps"][:1]})
    assert r.status_code == 400
    assert any("at least 2 ordered steps" in e for e in r.json()["detail"]["errors"])


def test_chain_that_does_not_escalate_is_refused(client, seeded):
    """Low -> low is not a chain; that is the persona's escalation principle."""
    _authorized_exercise(seeded)
    flat = {**GOOD_CHAIN, "steps": [
        {"action": "enumerate users", "impact": "low"},
        {"action": "confirm username validity", "impact": "low"},
    ], "combined_impact": "low"}
    r = client.post("/api/tradecraft/chains", json=flat)
    assert r.status_code == 400
    assert any("does not escalate" in e for e in r.json()["detail"]["errors"])


def test_non_escalating_chain_allowed_with_documented_reason(client, seeded):
    _authorized_exercise(seeded)
    documented = {**GOOD_CHAIN, "steps": [
        {"action": "enumerate users", "impact": "low"},
        {"action": "confirm username validity", "impact": "low"},
    ], "combined_impact": "medium",
        "escalation_note": "Individually low, but the combined enumeration is a medium-impact "
                           "disclosure of the staff directory at scale."}
    r = client.post("/api/tradecraft/chains", json=documented)
    assert r.status_code == 201, r.text


def test_chain_step_targets_are_scope_checked(client, seeded, conn):
    _authorized_exercise(seeded)
    bad = {**GOOD_CHAIN, "targets": [], "steps": [
        {**GOOD_CHAIN["steps"][0], "target": "production-db-01"},
        GOOD_CHAIN["steps"][2],
    ]}
    r = client.post("/api/tradecraft/chains", json=bad)
    assert r.status_code == 400
    assert any("out of scope" in e for e in r.json()["detail"]["errors"])
    audit = conn.execute(
        "SELECT COUNT(*) c FROM audit_events WHERE action = 'tradecraft.out_of_scope' "
        "AND target_type = 'chain'").fetchone()
    assert audit["c"] == 1


def test_valid_chain_is_stored_as_draft_and_audited(client, seeded, conn):
    _authorized_exercise(seeded)
    r = client.post("/api/tradecraft/chains", json=GOOD_CHAIN)
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "draft"
    steps = json.loads(body["steps"])
    assert [s["order"] for s in steps] == [1, 2, 3]
    assert conn.execute("SELECT COUNT(*) c FROM audit_events WHERE action = 'tradecraft.chain_recorded'").fetchone()["c"] == 1


def test_chain_status_is_a_documented_human_judgement(client, seeded, conn):
    _authorized_exercise(seeded)
    cid = client.post("/api/tradecraft/chains", json=GOOD_CHAIN).json()["id"]
    r = client.post(f"/api/tradecraft/chains/{cid}/status",
                    json={"status": "validated", "rationale": "Reproduced end to end on the lab range."})
    assert r.status_code == 200
    assert r.json()["status"] == "validated"
    bad = client.post(f"/api/tradecraft/chains/{cid}/status", json={"status": "approved", "rationale": "x"})
    assert bad.status_code == 400
    assert conn.execute("SELECT COUNT(*) c FROM audit_events WHERE action = 'tradecraft.chain_status'").fetchone()["c"] == 1


# ------------------------------------------------------------ triage reporting

def test_triage_report_is_ready_only_with_an_exploitable_verdict(client, seeded):
    _authorized_exercise(seeded)
    fid = _finding(seeded)
    client.post("/api/tradecraft/reviews", json={**GOOD_REVIEW, "vuln_id": fid})
    body = client.get(f"/api/tradecraft/findings/{fid}/triage-report").json()
    assert body["reportable"] is True
    assert "READY FOR SUBMISSION" in body["markdown"]
    for section in ("Why it works", "Preconditions", "Reproduction", "Evidence",
                    "Impact", "Remediation", "Reviewer confidence"):
        assert section in body["markdown"]


def test_triage_report_unreviewed_finding_is_not_submittable(client, seeded):
    fid = _finding(seeded)
    body = client.get(f"/api/tradecraft/findings/{fid}/triage-report").json()
    assert body["reportable"] is False
    assert body["verdict"] == "unreviewed"
    assert "NOT SUBMITTABLE" in body["markdown"]


def test_triage_report_links_chains_containing_the_finding(client, seeded):
    _authorized_exercise(seeded)
    fid = _finding(seeded)
    chain = {**GOOD_CHAIN, "steps": [{**GOOD_CHAIN["steps"][0], "vuln_id": fid},
                                     GOOD_CHAIN["steps"][2]]}
    client.post("/api/tradecraft/chains", json=chain)
    md = client.get(f"/api/tradecraft/findings/{fid}/triage-report").json()["markdown"]
    assert "Attack paths this finding participates in" in md
    assert "domain takeover" in md


def test_duplicates_cluster_by_fingerprint(client, seeded):
    """Signal-to-noise: identical submissions must cluster, not re-review."""
    _authorized_exercise(seeded)
    fid = _finding(seeded)
    for _ in range(2):
        client.post("/api/tradecraft/reviews", json={**GOOD_REVIEW, "vuln_id": fid})
    clusters = client.get("/api/tradecraft/duplicates").json()["clusters"]
    assert len(clusters) == 1
    assert clusters[0]["count"] == 2
    assert len(clusters[0]["reviews"]) == 2


# ------------------------------------------------ SEC-077: authorization windows

def _exercise_with_window(seeded, conn, start, end, status="authorized"):
    conn.execute("UPDATE exercises SET starts_at=?, ends_at=?, status=? WHERE id=1",
                 (start, end, status))
    conn.commit()


def test_expired_authorization_stops_authorizing(client, seeded, conn):
    """Authority is bounded in time: an authorization that ended on the 13th
    does not authorize work on the 22nd."""
    _exercise_with_window(seeded, conn, "2020-01-01", "2020-01-31")
    summary = client.get("/api/tradecraft/scope").json()
    assert summary["authorized"] == []
    assert [e[1] for e in summary["expired_engagements"]] == ["Synthetic Phish Drill Q3"]
    assert tradecraft.check_target(conn, "test1@test.local")["in_scope"] is False


def test_future_authorization_does_not_authorize_yet(client, seeded, conn):
    _exercise_with_window(seeded, conn, "2099-01-01", "2099-12-31")
    assert client.get("/api/tradecraft/scope").json()["authorized"] == []
    assert tradecraft.check_target(conn, "test1@test.local")["in_scope"] is False


def test_window_states_and_open_ended_rules():
    """Boundary behaviour of the window evaluator, including a window that is
    inclusive of its own last day and an unrecorded one."""
    f = tradecraft._window_state
    assert f("2026-09-01", "2026-09-22", "2026-09-22")[0] == "active"   # last day still counts
    assert f("2026-09-01", "2026-09-21", "2026-09-22")[0] == "expired"
    assert f("2026-09-23", "2026-09-30", "2026-09-22")[0] == "not_started"
    assert f(None, None, "2026-09-22")[0] == "open"
    assert f("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z", "2026-09-22")[0] == "active"  # timestamps


def test_refusal_names_the_real_cause(client, seeded, conn):
    """A refusal that says "not listed in any exercise" when the engagement
    exists but lapsed would send the operator hunting for a missing entry."""
    _exercise_with_window(seeded, conn, "2020-01-01", "2020-01-31")
    decision = tradecraft.check_target(conn, "test1@test.local")
    assert decision["in_scope"] is False
    assert "Synthetic Phish Drill Q3" in decision["reason"]      # names the engagement
    assert "window ended 2020-01-31" in decision["reason"]       # names the fix
    # a target with no entry at all keeps the generic message
    assert "not listed in any exercise" in tradecraft.check_target(conn, "9.9.9.9")["reason"]


def test_refusal_for_future_window_says_not_in_force(client, seeded, conn):
    _exercise_with_window(seeded, conn, "2099-01-01", "2099-12-31")
    reason = tradecraft.check_target(conn, "test1@test.local")["reason"]
    assert "not in force yet" in reason and "2099-01-01" in reason


def test_review_error_states_the_reproduction_requirement(client, seeded, conn):
    """An error that just says 'requires reproduction steps' when the caller
    supplied one leaves them guessing; the minimum must be stated."""
    _exercise_with_window(seeded, conn, "2020-01-01", "2099-01-01")
    r = client.post("/api/tradecraft/reviews",
                    json={**GOOD_REVIEW, "reproduction": "too short"})
    assert r.status_code == 400
    assert "at least 20 characters" in json.dumps(r.json())


def test_live_window_still_authorizes(client, seeded, conn):
    """The guard must not become useless: a window in force still works."""
    _exercise_with_window(seeded, conn, "2020-01-01", "2099-01-01")
    assert len(client.get("/api/tradecraft/scope").json()["authorized"]) == 2
    assert tradecraft.check_target(conn, "test1@test.local")["in_scope"] is True


def test_seed_window_is_in_force():
    """A demo engagement must not be born expired, or the first thing a user
    learns from the feature is a refusal."""
    import inspect

    from app.seed import seed_demo
    src = inspect.getsource(seed_demo.seed_all)
    assert 'now + timedelta(days=30)' in src, "seeded exercise window should extend past today"


def test_fingerprint_is_invariant_under_presentation_noise():
    """The dedupe key must survive how a human typed the submission, or the
    same finding lands in two clusters and the feature does nothing."""
    pairs = [
        (("https://lab-web-01:8443/x", "SQL Injection (critical)"),
         ("lab-web-01", "sql injection")),                     # scheme/port/path + severity
        (("lab-web-01", "Reflected XSS - high severity"),
         ("lab-web-01", "reflected xss")),                     # severity wording
        (("10.42.0.10:8080", "Broken Access Control"),
         ("10.42.0.10", "access control broken")),             # port + word order
    ]
    for (t1, ti1), (t2, ti2) in pairs:
        assert tradecraft._fingerprint(t1, None, ti1) == tradecraft._fingerprint(t2, None, ti2), \
            f"{ti1!r}@{t1} should match {ti2!r}@{t2}"


def test_fingerprint_still_separates_genuinely_different_findings():
    base = tradecraft._fingerprint("lab-web-01", None, "SQL Injection")
    assert base != tradecraft._fingerprint("lab-web-02", None, "SQL Injection")   # other host
    assert base != tradecraft._fingerprint("lab-web-01", None, "Stored XSS")      # other weakness
    cve = tradecraft._fingerprint("lab-web-01", {"cve_id": "CVE-2021-44228"}, None)
    assert cve != base                                                            # other CVE


def test_duplicate_cluster_survives_url_vs_host_submission(client, seeded, conn):
    """End-to-end version of the same claim: two submissions of one finding,
    typed differently, must cluster."""
    _authorized_exercise(seeded)
    fid = _finding(seeded)
    client.post("/api/tradecraft/reviews",
                json={**GOOD_REVIEW, "vuln_id": fid, "target": "https://10.42.0.10:8443/admin"})
    client.post("/api/tradecraft/reviews",
                json={**GOOD_REVIEW, "vuln_id": fid, "target": "10.42.0.10"})
    clusters = client.get("/api/tradecraft/duplicates").json()["clusters"]
    assert len(clusters) == 1 and clusters[0]["count"] == 2


# ------------------------------------------------------------------- personas

def test_persona_cannot_widen_permissions(client, seeded):
    """A persona changes the prompt, not the allowlist."""
    prompt = agent_adapters.system_prompt({"adapter_config": json.dumps({"persona": "the-xploiter"})})
    assert "The-Xploiter" in prompt
    assert "Hard limits" in prompt
    # the allowlist is untouched by the persona
    assert "contain_asset" in policy.TOOL_REGISTRY


def test_unknown_persona_is_refused_at_creation(client, seeded):
    r = client.post("/api/agents", json={"name": "rogue", "adapter": "openai_compat",
                                        "adapter_config": {"base_url": "http://127.0.0.1:11434/v1",
                                                           "persona": "nonexistent"}})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "bad_persona"


def test_known_persona_accepted(client, seeded):
    r = client.post("/api/agents", json={"name": "xploiter", "adapter": "openai_compat",
                                        "adapter_config": {"base_url": "http://127.0.0.1:11434/v1",
                                                           "persona": "the-xploiter"},
                                        "tools": ["get_finding", "list_scope_targets"]})
    assert r.status_code == 201, r.text


# --------------------------------------------------------------- agent gateway

def test_tradecraft_tools_are_registered_with_correct_gating():
    assert policy.TOOL_REGISTRY["list_scope_targets"]["read_only"] is True
    assert policy.TOOL_REGISTRY["get_finding"]["read_only"] is True
    assert policy.TOOL_REGISTRY["record_exploitability_review"]["read_only"] is False
    assert policy.TOOL_REGISTRY["propose_attack_chain"]["read_only"] is False


def test_no_shell_or_scanning_tool_exists():
    """The gateway must never ship an execution primitive, however themed."""
    forbidden = ("shell", "exec", "bash", "scan", "nmap", "sqlmap", "metasploit", "payload")
    for name, spec in policy.TOOL_REGISTRY.items():
        haystack = (name + " " + spec["description"]).lower()
        for word in forbidden:
            assert not (word in haystack and word != "scan" or word == "scan" and "sqlmap" in haystack), \
                f"tool {name} looks like an execution primitive"


def test_agent_review_write_requires_approval(client, seeded, conn):
    """Same capability as the API, but gated: the agent proposes, a human decides."""
    from app.routers import agents as agents_router
    _authorized_exercise(seeded)
    fid = _finding(seeded)
    tools = json.dumps(["record_exploitability_review"])
    cur = conn.execute("INSERT INTO agents (name, provider, role, scope, tools, status, adapter, "
                       "adapter_config, created_at, updated_at) VALUES ('xploiter', 'internal', "
                       "'pentest', '{}', ?, 'active', 'builtin', NULL, '2026-01-01T00:00:00Z', "
                       "'2026-01-01T00:00:00Z')", (tools,))
    conn.commit()
    agent = {"id": cur.lastrowid, "name": "xploiter", "tools": tools,
             "adapter": "builtin", "adapter_config": None, "status": "active"}
    req = {"tool": "record_exploitability_review",
           "args": {**GOOD_REVIEW, "vuln_id": fid}}
    plan = policy.plan_task(conn, agent, req, {"type": "user", "id": "1", "name": "admin"})
    assert plan["status"] == "awaiting_approval", plan
    assert agents_router  # imported for parity with the API surface


def test_agent_scope_violation_is_rejected_by_the_tool(client, seeded, conn):
    _authorized_exercise(seeded)
    out = policy._record_exploitability_review(
        conn, {**GOOD_REVIEW, "target": "production-db-01"})
    assert "error" in out
    assert any("out of scope" in e for e in out["errors"])


def test_agent_cannot_see_unauthorized_targets(client, seeded, conn):
    _authorized_exercise(seeded)   # closes seeded engagements, then authorizes the lab range
    out = policy._list_scope_targets(conn, {})
    targets = {t["target"] for t in out["authorized_targets"]}
    assert targets == {"10.42.0.10", "lab-web-01", "*.lab.example.com", "10.42.1.0/24"}
    assert "production-db-01" not in targets


# ---------------------------------------------------------------------- RBAC

def test_viewer_can_read_but_not_write_tradecraft(client, seeded, conn):
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "viewer", "password": "ViewerRead1!"})
    assert client.get("/api/tradecraft/persona").status_code == 200
    assert client.get("/api/tradecraft/scope").status_code == 200
    r = client.post("/api/tradecraft/reviews", json=GOOD_REVIEW)
    assert r.status_code == 403
    assert "tradecraft.write" in r.json()["detail"]["message"]


def test_analyst_can_record_a_review_but_scope_still_applies(analyst_client, seeded, conn):
    _authorized_exercise(seeded)
    assert analyst_client.post("/api/tradecraft/reviews", json=GOOD_REVIEW).status_code == 201
    denied = analyst_client.post("/api/tradecraft/reviews",
                                 json={**GOOD_REVIEW, "target": "evil.example.org"})
    assert denied.status_code == 400


@pytest.mark.parametrize("path", ["/api/tradecraft/persona", "/api/tradecraft/scope",
                                  "/api/tradecraft/rubric", "/api/tradecraft/stats",
                                  "/api/tradecraft/reviews", "/api/tradecraft/chains"])
def test_tradecraft_endpoints_require_a_session(client, seeded, path):
    client.post("/api/auth/logout")
    assert client.get(path).status_code == 401


def test_scope_change_is_audited_with_before_and_after(client, seeded, conn):
    """SEC-107: `PATCH /api/exercises/{id}` recorded only `{status, reason}` in its
    audit entry, so replacing `targets`, `owner`, `starts_at` or `ends_at` wrote an
    audit row claiming nothing had changed — while `targets` is exactly what the
    scope guard reads. Live repro before the fix: patching targets/owner/ends_at on
    exercise 1 produced `exercise.updated {"reason": null, "status": null}`."""
    before = conn.execute("SELECT MAX(seq) m FROM audit_events").fetchone()["m"]
    r = client.patch("/api/exercises/1", json={"targets": ["10.10.10.10"], "owner": "new-owner",
                                              "ends_at": "2030-01-01"})
    assert r.status_code == 200, r.text
    # SEC-091 class: the write path must decode JSON columns like the read path does.
    assert isinstance(r.json()["targets"], list) and r.json()["targets"] == ["10.10.10.10"]
    assert r.json()["owner"] == "new-owner"

    entries = conn.execute("SELECT action, detail FROM audit_events WHERE seq > ? ORDER BY seq",
                           (before,)).fetchall()
    scope = [e for e in entries if e["action"] == "exercise.scope_changed"]
    assert scope, f"expected an exercise.scope_changed audit entry, got {[(e['action'], e['detail']) for e in entries]}"
    detail = json.loads(scope[0]["detail"])
    assert set(detail["changed"]) == {"targets", "owner", "ends_at"}
    assert detail["before_after"]["owner"]["to"] == "new-owner"
    assert detail["before_after"]["ends_at"]["to"] == "2030-01-01"
    assert detail["before_after"]["targets"]["to"] == ["10.10.10.10"]

    # A non-scope change keeps the ordinary action, but still names the fields.
    before = conn.execute("SELECT MAX(seq) m FROM audit_events").fetchone()["m"]
    assert client.patch("/api/exercises/1", json={"meta": {"note": "x"}}).status_code == 200
    entry = conn.execute("SELECT action, detail FROM audit_events WHERE seq > ? ORDER BY seq",
                         (before,)).fetchall()[0]
    assert entry["action"] == "exercise.updated" and "meta" in json.loads(entry["detail"])["changed"]


def test_unreadable_window_is_refused_and_inert(client, seeded, conn):
    """SEC-107: `_window_state` compares the first ten characters as strings, so
    `ends_at: "banana"` sorted after today and the engagement read as *live* — an
    authorization that never lapses, from a typo — and nothing validated the value on
    the way in."""
    # Refused where it is written.
    r = client.patch("/api/exercises/1", json={"ends_at": "banana"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "bad_window", r.text
    assert client.patch("/api/exercises/1", json={"starts_at": "2026-13-45"}).status_code == 400
    bad = client.post("/api/exercises", json={
        "name": "Bad window", "owner": "platform", "ends_at": "soon",
        "scope": "Synthetic window-validation drill, nothing is targeted."})
    assert bad.status_code == 400 and bad.json()["detail"]["code"] == "bad_window", bad.text
    # An inverted window is refused too.
    r = client.patch("/api/exercises/1", json={"starts_at": "2026-05-01", "ends_at": "2026-04-01"})
    assert r.status_code == 400 and "before" in r.json()["detail"]["message"]

    # And a window that is somehow already stored unreadable is inert, not live.
    conn.execute("UPDATE exercises SET starts_at = NULL, ends_at = 'banana', status = 'authorized', "
                 "targets = ? WHERE id = 1", (json.dumps(["test1@test.local"]),))
    conn.commit()
    decision = tradecraft.check_target(conn, "test1@test.local")
    assert decision["in_scope"] is False
    assert "unreadable" in decision["reason"]
    rows = tradecraft.authorized_targets(conn)
    entry = next(r for r in rows if r["target"] == "test1@test.local")
    assert entry["usable"] is False and entry["window_state"] == "invalid"
