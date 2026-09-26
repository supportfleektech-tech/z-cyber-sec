"""Engagement lifecycle is one-way, and closing it records why (SEC-083).

Found by auditing the state machine rather than the happy path: `running ->
planned` was accepted silently, which de-authorized an engagement mid-flight
(2 authorized targets became 0, and in-flight tradecraft started failing as
out-of-scope), and `aborted -> authorized` restored the authority of an
engagement that had been explicitly stopped. Aborting recorded no reason.
"""
from __future__ import annotations

from app.services import tradecraft

SCOPE = "Authorized synthetic exercise limited to lab-ctf-target-01 only."


def _exercise(client, targets=("lab-ctf-target-01",)):
    r = client.post("/api/exercises", json={"name": "Lifecycle test exercise",
                                            "scope": SCOPE, "targets": list(targets)})
    assert r.status_code == 201
    return r.json()["id"]


def _advance(client, ex_id, status, reason=None):
    body = {"status": status}
    if reason is not None:
        body["reason"] = reason
    return client.patch(f"/api/exercises/{ex_id}", json=body)


def _state(conn, ex_id):
    return conn.execute("SELECT status FROM exercises WHERE id=?", (ex_id,)).fetchone()["status"]


def test_running_engagement_cannot_be_quietly_de_authorized(client, seeded, conn):
    """The core hole: running -> planned silently withdrew authorization."""
    ex_id = _exercise(client)
    assert _advance(client, ex_id, "authorized").status_code == 200
    assert _advance(client, ex_id, "running").status_code == 200
    before = len(tradecraft.authorized_targets(conn))
    assert before >= 1                                   # the engagement is authorizing work

    r = _advance(client, ex_id, "planned")
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "illegal_transition"
    assert r.json()["detail"]["from"] == "running"
    assert _state(conn, ex_id) == "running"               # nothing changed
    assert len(tradecraft.authorized_targets(conn)) == before


def test_denied_transitions_are_audited(client, seeded, conn):
    """A request to withdraw an engagement's authority is a governance signal,
    like an out-of-scope targeting attempt — not just a 409."""
    ex_id = _exercise(client)
    _advance(client, ex_id, "authorized")
    _advance(client, ex_id, "running")
    assert _advance(client, ex_id, "planned").status_code == 409
    ev = conn.execute("SELECT action, detail FROM audit_events WHERE action='exercise.transition_denied'"
                      " ORDER BY id DESC LIMIT 1").fetchone()
    assert ev is not None
    assert '"from":"running"' in ev["detail"] and '"to":"planned"' in ev["detail"]


def test_terminal_engagements_cannot_be_reopened(client, seeded, conn):
    """`aborted -> authorized` re-authorized an engagement that was stopped."""
    ex_id = _exercise(client)
    _advance(client, ex_id, "authorized")
    _advance(client, ex_id, "running")
    assert _advance(client, ex_id, "aborted",
                    reason="authorization withdrawn by the customer").status_code == 200
    assert _state(conn, ex_id) == "aborted"
    # this engagement authorizes nothing now (other seeded exercises are untouched)
    assert all(r["exercise_id"] != ex_id for r in tradecraft.authorized_targets(conn))

    r = _advance(client, ex_id, "authorized")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "illegal_transition"
    assert _state(conn, ex_id) == "aborted"

    done = _exercise(client)
    _advance(client, done, "authorized")
    _advance(client, done, "running")
    _advance(client, done, "completed", reason="range cleaned up; report filed")
    assert _advance(client, done, "authorized").status_code == 409
    assert _advance(client, done, "running").status_code == 409
    assert _state(conn, done) == "completed"


def test_closing_an_engagement_requires_a_reason(client, seeded, conn):
    ex_id = _exercise(client)
    _advance(client, ex_id, "authorized")
    _advance(client, ex_id, "running")

    r = _advance(client, ex_id, "aborted")
    assert r.status_code == 400 and r.json()["detail"]["code"] == "reason_required"
    assert _state(conn, ex_id) == "running"               # still live, as intended

    r = _advance(client, ex_id, "aborted", reason="   ")
    assert r.status_code == 400                           # whitespace is not a reason

    r = _advance(client, ex_id, "aborted", reason="authorization withdrawn by the customer")
    assert r.status_code == 200
    run = conn.execute("SELECT result, detail FROM exercise_runs WHERE exercise_id=? "
                       "ORDER BY id DESC LIMIT 1", (ex_id,)).fetchone()
    assert run["result"] == "aborted"
    assert "withdrawn" in run["detail"]                    # the reason is on the run record too


def test_planned_engagement_can_be_cancelled_with_a_record(client, seeded, conn):
    """Cancelling before start is a real case (authorization never signed)."""
    ex_id = _exercise(client)
    r = _advance(client, ex_id, "aborted", reason="authorization never signed by the customer")
    assert r.status_code == 200 and _state(conn, ex_id) == "aborted"


def test_planned_engagement_still_cannot_run_or_complete(client, seeded):
    ex_id = _exercise(client)
    r = _advance(client, ex_id, "running")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "not_authorized"
    r = _advance(client, ex_id, "completed", reason="synthetic exercise closed cleanly")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "not_authorized"


def test_repatching_the_same_status_does_not_start_a_second_run(client, seeded, conn):
    """A run row is the record of one execution; setting `running` twice made two."""
    ex_id = _exercise(client)
    _advance(client, ex_id, "authorized")
    assert _advance(client, ex_id, "running").status_code == 200
    assert _advance(client, ex_id, "running").status_code == 200
    runs = conn.execute("SELECT COUNT(*) c FROM exercise_runs WHERE exercise_id=?", (ex_id,)).fetchone()["c"]
    assert runs == 1


def test_transition_table_is_forward_only_and_terminal_states_are_sinks():
    from app.routers.exercises import ALLOWED_TRANSITIONS, ORDER, STATUSES

    for frm, allowed in ALLOWED_TRANSITIONS.items():
        for to in allowed:
            assert to in STATUSES, f"{frm} -> {to}: unknown status"
            assert to != frm, f"{frm} -> {to}: self-transition belongs in ALLOWED, not the table"
            if to not in ("aborted",):                     # aborted is the one early exit
                assert ORDER[to] > ORDER[frm], f"backwards transition allowed: {frm} -> {to}"
    assert ALLOWED_TRANSITIONS["completed"] == set()
    assert ALLOWED_TRANSITIONS["aborted"] == set()
