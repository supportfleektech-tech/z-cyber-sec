"""SEC-074 — an inert rule must never be invisible.

A rule that cannot compile is skipped by detection. Before this change the skip
was `except RuleError: continue`: no log, no audit, no counter — and
`GET /rules` still listed the rule as `active`. An operator porting a rule from
a full Sigma pack (unsupported condition syntax, or full-Sigma metadata keys)
would therefore believe they had coverage that could never fire.

These tests pin the whole path: the engine's health helper, the loud skip, the
`/rules` and `/rules/coverage` views, seed-time refusal, and the CLI linter.
"""
from __future__ import annotations

import json

from app.routers import soc
from app.services.detection import compile_rule, rule_health

# A rule ported from SigmaHQ with constructs outside the engine subset.
UNSUPPORTED = {
    "uid": "test-unsupported",
    "name": "Ported rule with unsupported constructs",
    "severity": "high",
    "status": "active",
    "detection": {"selection": {"action|contains|all": ["powershell", "download"]}},
    "condition": "1 of selection*",
}

GOOD = {
    "uid": "test-good",
    "name": "Compiles fine",
    "severity": "medium",
    "status": "active",
    "detection": {"fail": {"action": "ssh_failed_login", "outcome": "failure"}},
    "condition": "fail",
}


def _insert_rule(conn, spec: dict) -> int:
    cur = conn.execute(
        "INSERT INTO detection_rules (uid, name, description, severity, status, spec, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (spec["uid"], spec["name"], None, spec["severity"], spec["status"],
         json.dumps(spec), "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    return cur.lastrowid


# ------------------------------------------------------------- engine helper

def test_rule_health_reports_ok_for_valid_rule():
    h = rule_health(GOOD)
    assert h["compiles"] is True
    assert h["error"] is None
    assert h["rule"].uid == "test-good"


def test_rule_health_reports_reason_instead_of_raising():
    h = rule_health(UNSUPPORTED)
    assert h["compiles"] is False
    assert h["error"], "the compiler's reason must be surfaced, not swallowed"


def test_rule_health_survives_malformed_spec():
    """A spec that is not even a dict must not crash the rules list."""
    for bad in ({}, {"uid": "x"}, {"uid": "x", "detection": []}, {"detection": {}}):
        h = rule_health(bad)
        assert h["compiles"] is False
        assert isinstance(h["error"], str)


def test_compile_rule_still_raises_directly():
    """The strict API is unchanged for callers that want exceptions."""
    import pytest

    from app.services.detection import RuleError
    with pytest.raises(RuleError):
        compile_rule(UNSUPPORTED)


# ------------------------------------------------------------ visible in API

def test_rules_list_flags_inert_rule(client, seeded):
    _insert_rule(seeded, UNSUPPORTED)
    r = client.get("/api/soc/rules")
    assert r.status_code == 200
    body = r.json()
    by_uid = {i["uid"]: i for i in body["items"]}
    assert by_uid["test-unsupported"]["compiles"] is False
    assert by_uid["test-unsupported"]["error"]
    assert by_uid["test-unsupported"]["status"] == "active"  # stored, but inert
    assert body["summary"]["broken"] >= 1
    assert "test-unsupported" in body["summary"]["broken_uids"]


def test_rules_list_does_not_leak_spec(client, seeded):
    _insert_rule(seeded, UNSUPPORTED)
    r = client.get("/api/soc/rules")
    assert all("spec" not in i for i in r.json()["items"])


def test_shipped_rules_all_compile(client, seeded):
    r = client.get("/api/soc/rules")
    assert r.status_code == 200
    assert r.json()["summary"]["broken"] == 0


def test_coverage_counts_only_runnable_rules(client, seeded):
    _insert_rule(seeded, UNSUPPORTED)
    r = client.get("/api/soc/rules/coverage")
    assert r.status_code == 200
    body = r.json()
    broken_uids = {b["uid"] for b in body["broken_rules"]}
    gap_uids = {g["uid"] for g in body["gaps"]}
    assert "test-unsupported" in broken_uids
    # A config fault is not a coverage gap — keeping it out of `gaps` keeps
    # that list actionable.
    assert "test-unsupported" not in gap_uids
    assert body["inert_rules"] >= 1


# ------------------------------------------------------- detection behaviour

def test_inert_rule_is_logged_not_silent(client, seeded, caplog):
    import logging
    soc._reported_broken.clear()
    _insert_rule(seeded, UNSUPPORTED)
    events = [{"id": 1, "ts": "2026-01-01T00:00:00Z", "host": "h1", "user": "u",
               "action": "ssh_failed_login", "outcome": "failure", "severity": "high",
               "source_name": "sshd", "source_type": "host", "data": {}}]
    with caplog.at_level(logging.WARNING, logger="cybersec.detection"):
        soc._run_detections(seeded, events, threshold_context=events)
    assert "cannot compile and is INERT" in caplog.text
    assert "test-unsupported" in caplog.text
    assert "test-unsupported" in soc._reported_broken


def test_broken_rule_does_not_disable_working_rules(client, seeded):
    """One bad rule must not take the rest of detection down with it."""
    soc._reported_broken.clear()
    _insert_rule(seeded, UNSUPPORTED)
    events = [{"id": 2, "ts": "2026-01-01T00:00:00Z", "host": "h9", "user": "u",
               "action": "ssh_failed_login", "outcome": "failure", "severity": "high",
               "source_name": "sshd", "source_type": "host", "data": {}} for _ in range(6)]
    for i, e in enumerate(events):
        e["id"] = 100 + i
    raised = soc._run_detections(seeded, events, threshold_context=events)
    assert raised, "shipped rules must still fire while a broken rule is present"


# ------------------------------------------------------------- seed refusal

def test_seed_refuses_a_shipped_rule_that_cannot_compile(conn, tmp_path, monkeypatch):
    """A bad shipped rule is a repository bug: fail loudly at seed time rather
    than stocking an inert rule."""
    import pytest

    from app.config import settings
    from app.seed import seed_demo
    bad = tmp_path / "cs-9999-broken.yaml"
    good = tmp_path / "cs-0001-good.yaml"
    bad.write_text("uid: cs-9999\nname: broken\nstatus: active\n"
                   "detection:\n  sel:\n    action|contains|all: [a, b]\n"
                   "condition: 1 of sel*\n")
    good.write_text("uid: cs-0001\nname: good\nstatus: active\n"
                    "detection:\n  sel:\n    action: x\ncondition: sel\n")
    monkeypatch.setattr(settings, "rules_dir", tmp_path)
    with pytest.raises(RuntimeError, match="cs-9999-broken.yaml"):
        seed_demo._seed_rules(conn)


def test_seed_accepts_valid_rules(conn, tmp_path, monkeypatch):
    from app.config import settings
    from app.seed import seed_demo
    (tmp_path / "cs-0001-good.yaml").write_text(
        "uid: cs-0001\nname: good\nstatus: active\n"
        "detection:\n  sel:\n    action: x\ncondition: sel\n")
    monkeypatch.setattr(settings, "rules_dir", tmp_path)
    assert seed_demo._seed_rules(conn) == 1


# -------------------------------------------------------------- CLI linter

def test_linter_passes_on_shipped_rules():
    from scripts.lint_rules import main
    assert main([]) == 0


def test_linter_fails_and_explains_for_unsupported_rule(tmp_path, capsys):
    from scripts.lint_rules import main
    f = tmp_path / "ported.yaml"
    f.write_text("uid: ported\nname: ported\nstatus: active\n"
                 "detection:\n  sel:\n    action|contains|all: [a, b]\n"
                 "condition: 1 of sel*\n")
    assert main([str(f)]) == 1
    assert "INERT" in capsys.readouterr().err


def test_linter_maps_full_sigma_metadata_names(tmp_path, capsys):
    """A verbatim SigmaHQ rule fails on `title`/`id`/`level`; the linter must
    say so instead of just 'Rule must have a uid'."""
    from scripts.lint_rules import main
    f = tmp_path / "sigmahq.yaml"
    f.write_text("title: Some SigmaHQ rule\nid: 1234\nlevel: high\n"
                 "detection:\n  sel:\n    action: x\ncondition: sel\n")
    assert main([str(f)]) == 1
    err = capsys.readouterr().err
    assert "`title`" in err and "`level`" in err


def test_linter_reports_invalid_yaml(tmp_path, capsys):
    from scripts.lint_rules import main
    f = tmp_path / "broken.yaml"
    f.write_text("uid: [unclosed\n")
    assert main([str(f)]) == 1
    assert "invalid YAML" in capsys.readouterr().err
