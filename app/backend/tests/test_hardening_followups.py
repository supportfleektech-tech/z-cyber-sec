"""SEC-076 — prose-aware argument validation, engagement reporting, discovery.

Three follow-ups from using the SEC-075 capability rather than just shipping it:

1. **The injection heuristic broke the product's own workflow.** It was applied
   to every argument field, so a reproduction step reading "run
   ``curl -s http://target/api``" — ordinary pentest prose — was rejected as
   "possible injection". Tools can now declare ``text_fields``: free text that
   is stored as data and never interpreted. It is length-capped instead, and
   every other field keeps the strict check.
2. **Tradecraft output was unreachable from the reporting system**, so an
   engagement had no deliverable. `kind=tradecraft` now renders findings ready
   for submission, chains as paths, and — deliberately — the rejected and
   disproven verdicts.
3. **The-Xploiter was not discoverable** on a fresh install; the seed now
   creates it with its persona.

The tests below pin the *scoping* of the relaxation (it must apply to the
declared tool only, never globally) as much as the behaviour.
"""
from __future__ import annotations

import json

from app.services import policy
from app.services.report import ReportBuilder

# --- prose that a security engineer legitimately writes ----------------------

BACKTICK_PROSE = {
    "verdict": "exploitable",
    "rationale": "The handler passes the body into the INSERT, so role is attacker-controlled.",
    "reproduction": "1. authenticate 2. run `curl -s http://target/api/users -d @admin.json` 3. observe",
    "evidence": ["response: 200 with role=admin"],
}
PIPE_PROSE = {"reproduction": "the attacker runs: curl http://target/x | sh to drop the implant"}


# ------------------------------------------------- 1. prose-aware validation

def test_tradecraft_prose_with_backticks_is_allowed():
    assert policy.validate_args(BACKTICK_PROSE, "record_exploitability_review") is None


def test_tradecraft_prose_with_shell_operators_is_allowed():
    """Describing an attacker's command line is the job, not an attack."""
    assert policy.validate_args(PIPE_PROSE, "record_exploitability_review") is None


def test_relaxation_is_scoped_to_the_declaring_tool():
    """The same args must still be refused for a tool that did not declare them —
    this is a per-tool contract, not a global loosening."""
    assert policy.validate_args(BACKTICK_PROSE, "propose_attack_chain") is not None
    assert policy.validate_args(BACKTICK_PROSE, "create_case") is not None
    assert policy.validate_args(BACKTICK_PROSE, None) is not None


def test_identifier_fields_stay_strict_even_for_tradecraft_tools():
    for args in ({"target": "$(rm -rf /)"}, {"title": "`whoami`"}):
        assert policy.validate_args(args, "record_exploitability_review") is not None


def test_prose_fields_are_length_capped():
    """Skipping the heuristic must not skip bounding."""
    huge = {"rationale": "x" * (policy._TEXT_FIELD_LIMITS["max_chars"] + 1)}
    reason = policy.validate_args(huge, "record_exploitability_review")
    assert reason and "exceeds" in reason


def test_prose_list_items_are_capped():
    many = {"evidence": ["x"] * (policy._TEXT_FIELD_LIMITS["max_items"] + 1)}
    reason = policy.validate_args(many, "record_exploitability_review")
    assert reason and "too many entries" in reason


def test_prose_entries_must_be_strings():
    reason = policy.validate_args({"evidence": [{"cmd": "x"}]}, "record_exploitability_review")
    assert reason and "must be strings" in reason


def test_declared_text_fields_are_the_expected_ones():
    assert set(policy.TOOL_REGISTRY["record_exploitability_review"]["text_fields"]) >= {
        "rationale", "reproduction", "evidence"}
    assert set(policy.TOOL_REGISTRY["propose_attack_chain"]["text_fields"]) >= {
        "rationale", "escalation_note", "steps"}
    # tools that did not declare prose keep the original behaviour
    assert "text_fields" not in policy.TOOL_REGISTRY["create_case"]


def test_strict_behaviour_unchanged_for_undeclared_fields():
    assert policy.validate_args({"note": "hi; rm -rf /"}) is not None
    assert policy.validate_args({"note": "plain text"}) is None


# ------------------------------------------------- 2. engagement deliverable

def _authorize(conn, targets=("10.42.0.10",), status="authorized"):
    now = "2026-01-01T00:00:00Z"
    cur = conn.execute(
        "INSERT INTO exercises (name, scope, status, owner, starts_at, ends_at, targets, meta, "
        "created_at, updated_at) VALUES (?, ?, ?, 'ciso', ?, NULL, ?, '{}', ?, ?)",
        ("Tradecraft deliverables", "Written authorization covering the lab range for this test.",
         status, now, json.dumps(list(targets)), now, now))
    conn.commit()
    return cur.lastrowid


def _review(conn, verdict, vuln_id=None, **kw):
    now = "2026-01-01T00:00:00Z"
    conn.execute(
        "INSERT INTO exploitability_reviews (vuln_id, target, verdict, rationale, triage_ready, "
        "policy_note, dedupe_key, reviewed_by, created_at) VALUES (?,?,?,?,?,?,?, 'tester', ?)",
        (vuln_id, kw.get("target", "10.42.0.10"), verdict, kw.get("rationale", "Because of the mechanism."),
         1 if kw.get("triage_ready") else 0, kw.get("policy_note"), kw.get("dedupe_key"), now))
    conn.commit()


def test_tradecraft_report_kind_is_available(conn, seeded):
    assert "tradecraft" in __import__("app.routers.reports", fromlist=["KINDS"]).KINDS


def test_tradecraft_report_renders_submittable_findings(conn, seeded):
    _authorize(conn)
    _review(conn, "exploitable", vuln_id=1, triage_ready=True)
    res = ReportBuilder(conn).build("tradecraft", {}, "tester")
    html = open(res["path"], encoding="utf-8").read()
    assert "Findings ready for submission" in html
    assert "Engagement summary" in html


def test_tradecraft_report_includes_rejections(conn, seeded):
    """A deliverable that hides its rejections hides its discipline."""
    _authorize(conn)
    _review(conn, "exploitable", vuln_id=1, triage_ready=True)
    _review(conn, "theoretical", rationale="The sink is unreachable from untrusted input.")
    res = ReportBuilder(conn).build("tradecraft", {}, "tester")
    html = open(res["path"], encoding="utf-8").read()
    assert "Rejected" in html and "disproven" in html
    assert "unreachable" in html


def test_tradecraft_report_renders_chains_as_paths(conn, seeded):
    _authorize(conn)
    now = "2026-01-01T00:00:00Z"
    conn.execute(
        "INSERT INTO attack_chains (title, entry_point, trust_boundary, steps, combined_impact, "
        "status, escalation_note, rationale, meta, created_by, created_at, updated_at) "
        "VALUES ('Low to domain', 'low-priv web account', 'workstation->domain', ?, 'critical', "
        "'validated', 'steps compound', 'because', '{}', 'tester', ?, ?)",
        (json.dumps([{"order": 1, "action": "become local admin", "impact": "medium"},
                     {"order": 2, "action": "read cached creds", "impact": "high"}]), now, now))
    conn.commit()
    html = open(ReportBuilder(conn).build("tradecraft", {}, "tester")["path"], encoding="utf-8").read()
    assert "Attack chains" in html
    assert "become local admin" in html and "read cached creds" in html
    assert "Why it compounds" in html


def test_tradecraft_report_says_so_when_nothing_is_submittable(conn, seeded):
    _authorize(conn)
    _review(conn, "needs_evidence", rationale="Unverified lead only.")
    html = open(ReportBuilder(conn).build("tradecraft", {}, "tester")["path"], encoding="utf-8").read()
    assert "None — no review has met the evidence standard" in html


def test_tradecraft_report_is_audited_and_hashed(conn, seeded):
    res = ReportBuilder(conn).build("tradecraft", {}, "tester")
    assert res["input_sha256"] and res["input_rows"] >= 0
    row = conn.execute("SELECT COUNT(*) c FROM audit_events WHERE action='report.generated' "
                       "AND detail LIKE '%tradecraft%'").fetchone()
    assert row["c"] == 1


def test_tradecraft_report_endpoint_accepts_the_kind(client, seeded):
    _authorize(seeded)
    r = client.post("/api/reports", json={"kind": "tradecraft", "filters": {}})
    assert r.status_code == 201, r.text
    assert r.json()["id"]


def test_tradecraft_report_is_schedulable(client, seeded):
    r = client.post("/api/reports/schedules", json={"kind": "tradecraft", "title": "Weekly engagement digest",
                                                    "interval_minutes": 10080})
    assert r.status_code == 201, r.text


def test_html_escaping_applies_to_tradecraft_content(conn, seeded):
    """Report bodies embed operator/agent-supplied prose — it must be escaped."""
    _authorize(conn)
    _review(conn, "theoretical", rationale="<script>alert(1)</script> in the rationale")
    html = open(ReportBuilder(conn).build("tradecraft", {}, "tester")["path"], encoding="utf-8").read()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ------------------------------------------------------------ 3. discovery

def test_seed_ships_the_xploiter_with_its_persona(client, seeded, conn):
    row = conn.execute("SELECT * FROM agents WHERE name = 'the-xploiter'").fetchone()
    assert row, "a fresh install must expose the persona"
    cfg = json.loads(row["adapter_config"] or "{}")
    assert cfg["persona"] == "the-xploiter"
    assert row["adapter"] == "openai_compat"
    tools = json.loads(row["tools"])
    assert set(tools) == {"list_scope_targets", "get_finding",
                          "record_exploitability_review", "propose_attack_chain"}


def test_seeded_persona_agent_has_no_execution_tool(client, seeded, conn):
    """The shipped example must not demonstrate a capability the platform refuses."""
    row = conn.execute("SELECT tools FROM agents WHERE name = 'the-xploiter'").fetchone()
    for tool in json.loads(row["tools"]):
        assert tool in policy.TOOL_REGISTRY
        assert "shell" not in tool and "exec" not in tool and "scan" not in tool


def test_persona_agent_tools_are_gated_as_documented(client, seeded, conn):
    row = conn.execute("SELECT tools FROM agents WHERE name = 'the-xploiter'").fetchone()
    for tool in json.loads(row["tools"]):
        spec = policy.TOOL_REGISTRY[tool]
        if not spec["read_only"]:
            assert spec.get("text_fields"), f"{tool} is consequential and should declare prose fields"
