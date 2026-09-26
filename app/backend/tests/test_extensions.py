"""SEC-050/056/071/072 — adapters, purple team, coverage, schedules, retention."""
from __future__ import annotations

import json
import sys
import textwrap

from test_rbac import PASSWORDS

from app.services import agent_adapters

# ------------------------------------------------------------- purple team

def test_purple_team_all_scenarios_pass(client, conn):
    out = client.get("/api/soc/purple-team/scenarios").json()
    uids = [s["uid"] for s in out["scenarios"]]
    assert {"pt-001", "pt-002", "pt-003"} <= set(uids)

    for uid in uids:
        r = client.post("/api/soc/purple-team/run", json={"scenario": uid})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["passed"] is True, body
        assert body["events_injected"] > 0
        assert body["matched_alert"]["status"] in ("created", "updated")

    # Unknown scenario -> 404
    r = client.post("/api/soc/purple-team/run", json={"scenario": "pt-999"})
    assert r.status_code == 404

    # Runs are audited
    rows = conn.execute("SELECT detail FROM audit_events WHERE action = 'purple_team.run'").fetchall()
    assert len(rows) >= len(uids)


def test_purple_team_rerun_does_not_spam_alerts(client, conn):
    before = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    r1 = client.post("/api/soc/purple-team/run", json={"scenario": "pt-001"}).json()
    r2 = client.post("/api/soc/purple-team/run", json={"scenario": "pt-001"}).json()
    after = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    # First run creates the alert; second run updates it (dedupe per rule+entity).
    assert r1["matched_alert"]["status"] == "created"
    assert r2["matched_alert"]["status"] == "updated"
    assert after - before <= 1


def test_detection_coverage_reflects_purple_runs(client):
    client.post("/api/soc/purple-team/run", json={"scenario": "pt-001"})
    cov = client.get("/api/soc/rules/coverage").json()
    assert cov["total_rules"] >= 6
    by_uid = {p["uid"]: p for p in cov["rules"]}
    assert by_uid["cs-0001"]["never_fired"] is False
    assert by_uid["cs-0001"]["alerts_total"] >= 1
    assert 0 <= cov["coverage_pct"] <= 100
    # gaps = active rules that have never fired
    assert all(g["uid"] in by_uid and by_uid[g["uid"]]["never_fired"] for g in cov["gaps"])


# ----------------------------------------------------------- saved searches

def test_saved_searches_owner_scoped(client, conn):
    r = client.post("/api/soc/saved-searches",
                    json={"name": "ssh failures", "module": "events",
                          "params": {"action": "ssh_failed_login"}})
    assert r.status_code == 201, r.text
    ss_id = r.json()["id"]

    items = client.get("/api/soc/saved-searches?module=events").json()["items"]
    assert any(i["id"] == ss_id and i["params"]["action"] == "ssh_failed_login" for i in items)

    # Owner-scoped: another user cannot see or delete it
    client.post("/api/auth/logout")
    r2 = client.post("/api/auth/login", json={"username": "sasha", "password": PASSWORDS["sasha"]})
    assert r2.status_code == 200
    ids = [i["id"] for i in client.get("/api/soc/saved-searches").json()["items"]]
    assert ss_id not in ids
    assert client.delete(f"/api/soc/saved-searches/{ss_id}").status_code == 403

    # Bad module rejected
    assert client.post("/api/soc/saved-searches",
                       json={"name": "xx", "module": "bogus"}).status_code == 400

    # Owner can delete
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "admin", "password": PASSWORDS["admin"]})
    assert client.delete(f"/api/soc/saved-searches/{ss_id}").json() == {"ok": True}


# ----------------------------------------------------------- report schedules

def test_report_schedules_lifecycle(client, conn):
    r = client.post("/api/reports/schedules",
                    json={"kind": "overview", "title": "Nightly overview", "interval_minutes": 60})
    assert r.status_code == 201, r.text
    sched_id = r.json()["id"]

    items = client.get("/api/reports/schedules").json()["items"]
    assert any(i["id"] == sched_id and i["status"] == "active" for i in items)

    # Not due yet (next_run_at in the future) -> nothing built
    assert client.post("/api/reports/schedules/run-due").json()["built"] == 0

    # Force-due, then run
    from app import db
    conn.execute("UPDATE report_schedules SET next_run_at = ? WHERE id = ?", (db.utcnow(), sched_id))
    conn.commit()
    reports_before = client.get("/api/reports?page_size=1").json()["total"]
    built = client.post("/api/reports/schedules/run-due").json()["built"]
    assert built == 1
    reports_after = client.get("/api/reports?page_size=1").json()["total"]
    assert reports_after == reports_before + 1

    s = conn.execute("SELECT * FROM report_schedules WHERE id = ?", (sched_id,)).fetchone()
    assert s["last_run_at"] is not None
    assert s["next_run_at"] > s["last_run_at"]  # advanced forward

    # Pause + delete
    assert client.patch(f"/api/reports/schedules/{sched_id}",
                        json={"status": "paused"}).json()["status"] == "paused"
    assert client.patch(f"/api/reports/schedules/{sched_id}",
                        json={"status": "bogus"}).status_code == 400
    assert client.delete(f"/api/reports/schedules/{sched_id}").json() == {"ok": True}


# ------------------------------------------------------------- retention report

def test_retention_report_flags_due_items(client, conn):
    old = "2000-01-02T03:04:05Z"
    conn.execute(
        "INSERT INTO evidence (case_id, name, path, sha256, size, classification, retention, uploaded_by, created_at) "
        "VALUES (1, 'old- pcap.syn', 'syn/old.pcap', 'a' * 64, 10, 'synthetic', '1d', 'admin', ?)", (old,))
    conn.execute(
        "INSERT INTO evidence (case_id, name, path, sha256, size, classification, retention, uploaded_by, created_at) "
        "VALUES (1, 'held-evidence.syn', 'syn/held.bin', 'b' * 64, 10, 'synthetic', 'legal-hold', 'admin', ?)", (old,))
    conn.commit()

    rep = client.get("/api/admin/retention/report").json()
    assert rep["evidence"]["due_count"] >= 1
    assert any(e["name"] == "old- pcap.syn" for e in rep["evidence"]["due_for_review"])
    assert rep["evidence"]["legal_hold"] >= 1
    assert "Report only" in rep["evidence"]["note"]
    assert isinstance(rep["backups"]["total"], int)


def test_unreadable_retention_is_refused_and_never_blessed(client, seeded, conn):
    """SEC-112: retention is a control, not a note, and only the report's grammar has
    meaning. Live pre-fix: `retention: "banana"` (or "90 days") was accepted on upload
    and `_retention_due` returned None for it, which the report counted as
    `within_retention` — evidence that never comes due while the report says it is
    fine."""
    import io

    def upload(retention):
        return client.post("/api/cases/1/evidence",
                           files={"file": ("note.txt", io.BytesIO(b"synthetic"), "text/plain")},
                           data={"classification": "internal", "retention": retention})

    for bad in ("banana", "90 days", "ninety", "d90", "999999d"):
        r = upload(bad)
        assert r.status_code == 400, f"{bad}: {r.status_code} {r.text}"
        assert r.json()["detail"]["code"] == "bad_retention"
        assert r.json()["detail"]["allowed"]

    # Accepted forms are normalised, and "no label" is null rather than "".
    assert upload("6M").json()["retention"] == "6m"
    assert upload("legal_hold").json()["retention"] == "legal_hold"
    assert upload("1d").json()["retention"] == "1d"
    assert upload("  ").json()["retention"] is None

    # A row already stored with a label the report cannot parse is surfaced, not
    # blessed: it must not land in `within_retention`.
    conn.execute(
        "INSERT INTO evidence (case_id, name, path, sha256, size, classification, retention, uploaded_by, created_at) "
        "VALUES (1, 'legacy-typo.syn', 'syn/legacy.bin', 'c' * 64, 10, 'internal', 'banana', 'admin', ?)",
        ("2000-01-02T03:04:05Z",))
    conn.commit()
    ev = client.get("/api/admin/retention/report").json()["evidence"]
    assert ev["unrecognised_count"] >= 1
    assert any(e["name"] == "legacy-typo.syn" for e in ev["unrecognised_retention"])
    assert not any(e["name"] == "legacy-typo.syn" for e in ev["due_for_review"])


# ------------------------------------------------------------- agent adapters

def _make_agent(client, tools, adapter, config=None, name="adapt-test"):
    return client.post("/api/agents", json={
        "name": name, "provider": "internal", "tools": tools,
        "adapter": adapter, "adapter_config": config,
    })


def test_builtin_adapter_rejects_prompt(client):
    r = _make_agent(client, ["summarize_alerts"], "builtin", name="bt-1")
    agent_id = r.json()["id"]
    t = client.post("/api/agents/tasks",
                    json={"agent_id": agent_id, "title": "prompt task", "request": {"prompt": "summarize"}})
    assert t.status_code == 400
    assert "no brain" in t.json()["detail"]["message"]


def test_bad_adapter_rejected(client):
    assert _make_agent(client, ["get_alerts"], "gpt-9", name="bt-bad").status_code == 400


def test_openai_compat_adapter_executes_allowlisted_tool(client, monkeypatch):
    class FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"tool_calls": [{
                "function": {"name": "summarize_alerts", "arguments": "{}"}}]}}]}

    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["body"] = json
        return FakeResp()

    monkeypatch.setattr(agent_adapters.httpx, "post", fake_post)

    r = _make_agent(client, ["summarize_alerts"], "openai_compat",
                    {"base_url": "http://llm.local/v1", "model": "m"}, name="oa-1")
    agent_id = r.json()["id"]
    t = client.post("/api/agents/tasks",
                    json={"agent_id": agent_id, "title": "llm task",
                          "request": {"prompt": "summarize the latest alerts"}})
    assert t.status_code == 201, t.text
    task = t.json()
    assert task["status"] == "completed", task
    assert captured["url"] == "http://llm.local/v1/chat/completions"
    tool_names = [tf["function"]["name"] for tf in captured["body"]["tools"]]
    assert tool_names == ["summarize_alerts"]  # only allowlisted tools exposed to the model
    detail = client.get(f"/api/agents/tasks/{task['id']}").json()
    res = detail["result"]
    assert res["truthful"] is True and not res["errors"]
    assert any(r["tool"] == "summarize_alerts" for r in res["results"])


def test_adapter_cannot_bypass_allowlist(client, monkeypatch):
    class FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"tool_calls": [{
                "function": {"name": "create_case", "arguments": "{}"}}]}}]}

    monkeypatch.setattr(agent_adapters.httpx, "post", lambda *a, **k: FakeResp())
    r = _make_agent(client, ["summarize_alerts"], "openai_compat",
                    {"base_url": "http://llm.local/v1", "model": "m"}, name="oa-2")
    agent_id = r.json()["id"]
    t = client.post("/api/agents/tasks",
                    json={"agent_id": agent_id, "title": "sneaky task",
                          "request": {"prompt": "open a case please"}})
    assert t.status_code == 201
    task = t.json()
    assert task["status"] == "denied"  # gateway enforced, not the model
    res = json.loads(task["result"]) if isinstance(task["result"], str) else (task["result"] or {})
    assert any("allowlist" in rsn for rsn in res.get("reasons", []))


def test_cli_adapter_roundtrip(client, tmp_path):
    script = tmp_path / "adapter.py"
    script.write_text(textwrap.dedent("""
        import json, sys
        req = json.loads(sys.stdin.read())
        assert req["prompt"]
        print(json.dumps({"tool": "get_alerts", "args": {"status": "new"}}))
    """))
    r = _make_agent(client, ["get_alerts"], "cli",
                    {"command": f"{sys.executable} {script}"}, name="cli-1")
    agent_id = r.json()["id"]
    t = client.post("/api/agents/tasks",
                    json={"agent_id": agent_id, "title": "cli task",
                          "request": {"prompt": "list new alerts"}})
    assert t.status_code == 201, t.text
    task = t.json()
    assert task["status"] == "completed", task
    detail = client.get(f"/api/agents/tasks/{task['id']}").json()
    calls = detail["tool_calls"]
    assert any(c["tool"] == "get_alerts" and c["allowed"] for c in calls)
    res = detail["result"]
    assert res["truthful"] is True and any(r["tool"] == "get_alerts" for r in res["results"])


def test_cli_adapter_malformed_output_denied(client, tmp_path):
    script = tmp_path / "bad.py"
    script.write_text("print('not json')")
    r = _make_agent(client, ["get_alerts"], "cli",
                    {"command": f"{sys.executable} {script}"}, name="cli-2")
    agent_id = r.json()["id"]
    t = client.post("/api/agents/tasks",
                    json={"agent_id": agent_id, "title": "bad cli", "request": {"prompt": "x"}})
    assert t.status_code == 400
    assert "JSON" in t.json()["detail"]["message"]


def test_agents_list_decodes_adapter_fields(client):
    _make_agent(client, ["get_alerts"], "openai_compat",
                {"base_url": "http://x/v1"}, name="dec-1")
    items = client.get("/api/agents").json()["items"]
    row = next(i for i in items if i["name"] == "dec-1")
    assert row["adapter"] == "openai_compat"
    assert row["adapter_config"]["base_url"] == "http://x/v1"

# ----------------------------------------------------------------- release gate
# SEC-064: human release approval — admin-only, bound to commit + checklist
# sha256, append-only, audited; gate view drives rollout decisions.

_FAKE_SHA = "a" * 64
_FAKE_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _as(client, username):
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": username, "password": PASSWORDS[username]})
    assert r.status_code == 200


def test_release_gate_requires_admin(client, conn):
    _as(client, "sasha")  # soc_analyst: no release.write
    r = client.post("/api/admin/releases",
                    json={"version": "1.1.0", "commit_sha": _FAKE_COMMIT,
                          "checklist_sha256": _FAKE_SHA, "decision": "approved"})
    assert r.status_code == 403

    # gate is readable (release.read is a read perm)
    r = client.get("/api/admin/releases/latest")
    assert r.status_code == 200
    assert r.json()["gate"] == "no_decision"


def test_release_decision_recorded_and_gates_rollout(client, conn):
    # A rejection first: gate must read blocked, and the decision is audited.
    r = client.post("/api/admin/releases",
                    json={"version": "1.1.0-rc1", "commit_sha": _FAKE_COMMIT,
                          "checklist_sha256": _FAKE_SHA, "decision": "rejected",
                          "comment": "drill failed"})
    assert r.status_code == 201, r.text
    gate = client.get("/api/admin/releases/latest").json()
    assert gate["gate"] == "blocked"
    assert gate["latest"]["decision"] == "rejected"

    rows = conn.execute("SELECT * FROM audit_events WHERE action = 'release.rejected'").fetchall()
    assert len(rows) == 1

    # Then approval for the final build: gate flips to approved.
    r = client.post("/api/admin/releases",
                    json={"version": "1.1.0", "commit_sha": _FAKE_COMMIT,
                          "checklist_sha256": _FAKE_SHA, "decision": "approved",
                          "comment": "all gates green"})
    assert r.status_code == 201, r.text
    gate = client.get("/api/admin/releases/latest").json()
    assert gate["gate"] == "approved"
    assert gate["latest"]["version"] == "1.1.0"
    assert gate["latest"]["decided_by"] == "admin"

    # History lists both, newest first
    items = client.get("/api/admin/releases").json()["items"]
    assert [i["decision"] for i in items] == ["approved", "rejected"]

    # Validation: bad commit sha / short sha / bad decision rejected
    assert client.post("/api/admin/releases",
                       json={"version": "1.2.0", "commit_sha": "XYZ",
                             "checklist_sha256": _FAKE_SHA, "decision": "approved"}).status_code == 422
    assert client.post("/api/admin/releases",
                       json={"version": "1.2.0", "commit_sha": _FAKE_COMMIT,
                             "checklist_sha256": "abc", "decision": "approved"}).status_code == 422
    assert client.post("/api/admin/releases",
                       json={"version": "1.2.0", "commit_sha": _FAKE_COMMIT,
                             "checklist_sha256": _FAKE_SHA, "decision": "maybe"}).status_code == 422


def test_failing_schedule_is_recorded_and_retried_on_cadence(client, conn):
    """SEC-098: a schedule whose build raises used to be retried on every scheduler
    tick forever and recorded nowhere. Live repro before the fix: a `cases` schedule
    with `filters={"status": {"a": 1}}` (bound straight into SQL by the builder)
    answered `{"built": 0}` for every pass, left `last_run_at` NULL, kept its overdue
    `next_run_at` (so the 30s daemon retried it forever), wrote no audit event, and
    the row carried no error at all."""
    from app import db

    r = client.post("/api/reports/schedules",
                    json={"kind": "cases", "filters": {"status": {"a": 1}}, "interval_minutes": 5})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "bad_filters", r.text

    # Unsupported keys are refused too — the builder would silently ignore them,
    # so the report would not mean what the schedule says.
    r = client.post("/api/reports/schedules", json={"kind": "overview", "filters": {"severity": "high"}})
    assert r.status_code == 400 and "not used by a overview report" in r.json()["detail"]["message"]
    # A supported key with a bad value is refused as well.
    assert client.post("/api/reports/schedules",
                       json={"kind": "soc", "filters": {"severity": "urgent"}}).status_code == 400

    # A schedule that is valid but whose build fails at runtime must still report
    # itself: force a failure by deleting the reports table row the builder reads.
    ok = client.post("/api/reports/schedules",
                     json={"kind": "overview", "interval_minutes": 5}).json()
    conn.execute("ALTER TABLE alerts RENAME TO alerts_moved")
    conn.commit()
    conn.execute("UPDATE report_schedules SET next_run_at = ? WHERE id = ?", ("2000-01-01T00:00:00Z", ok["id"]))
    conn.commit()

    out = client.post("/api/reports/schedules/run-due").json()
    assert out["built"] == 0
    assert [f["id"] for f in out["failed"]] == [ok["id"]] and "alerts" in out["failed"][0]["error"]

    row = conn.execute("SELECT * FROM report_schedules WHERE id = ?", (ok["id"],)).fetchone()
    assert row["failures"] == 1 and row["last_error"]
    assert row["last_run_at"] is not None
    # Retried on its own cadence (5 min in the future), not on every tick.
    assert row["next_run_at"] > db.utcnow()
    failed_audit = conn.execute("SELECT target_id, detail FROM audit_events "
                                "WHERE action = 'report.scheduled_failed' ORDER BY seq DESC LIMIT 1").fetchone()
    assert failed_audit and failed_audit["target_id"] == str(ok["id"])
    assert "no such table: alerts" in failed_audit["detail"]

    # A second pass has nothing due — and now says so truthfully.
    out2 = client.post("/api/reports/schedules/run-due").json()
    assert out2 == {"built": 0, "failed": []}

    # Repair the database: the schedule heals itself and clears its error state.
    conn.execute("ALTER TABLE alerts_moved RENAME TO alerts")
    conn.commit()
    conn.execute("UPDATE report_schedules SET next_run_at = ? WHERE id = ?", ("2000-01-01T00:00:00Z", ok["id"]))
    conn.commit()
    out3 = client.post("/api/reports/schedules/run-due").json()
    assert out3["built"] == 1 and out3["failed"] == []
    row = conn.execute("SELECT * FROM report_schedules WHERE id = ?", (ok["id"],)).fetchone()
    assert row["failures"] == 0 and row["last_error"] is None
    assert row["next_run_at"] > db.utcnow()
