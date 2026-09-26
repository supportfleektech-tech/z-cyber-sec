"""Detection engine unit tests: Sigma-subset grammar, matching, thresholds."""
from __future__ import annotations

from app.services.detection import RuleError, compile_rule, evaluate_batch, parse_condition, rule_matches


def _rule(**over):
    base = {
        "uid": "t-001", "name": "Test", "severity": "high", "status": "active",
        "detection": {"sel": {"action": "bad_thing"}},
        "condition": "sel",
    }
    base.update(over)
    return compile_rule(base)


# ------------------------------------------------------------- condition grammar

def test_condition_grammar():
    c = parse_condition("a and b")
    assert c.kind == "and"
    c = parse_condition("a or not b")
    assert c.kind == "or"
    c = parse_condition("(a or b) and c")
    assert c.kind == "and"
    assert c.children[0].kind == "or"
    c = parse_condition("2 of")
    assert c.kind == "of_n" and c.n == 2
    c = parse_condition("all")
    assert c.kind == "all"


def test_condition_syntax_errors():
    for bad in ("a and", "and b", "(a", "a ))", "a or b c"):
        try:
            parse_condition(bad)
            raise AssertionError(f"should have failed: {bad}")
        except RuleError:
            pass


# ------------------------------------------------------------------ rule matching

def test_simple_match_and_nonmatch():
    rule = _rule()
    assert rule_matches(rule, {"action": "bad_thing"}) is True
    assert rule_matches(rule, {"action": "good_thing"}) is False


def test_list_values():
    rule = _rule(detection={"sel": {"action": ["a", "b"], "host": ["h1"]}}, condition="sel")
    assert rule_matches(rule, {"action": "B", "host": "h1"}) is True  # case-insensitive
    assert rule_matches(rule, {"action": "c", "host": "h1"}) is False


def test_numeric_ops():
    rule = _rule(detection={"sel": {"data.bytes": {"op": "gt", "value": 100}}}, condition="sel")
    assert rule_matches(rule, {"data": {"bytes": 150}}) is True
    assert rule_matches(rule, {"data": {"bytes": 90}}) is False
    rule = _rule(detection={"sel": {"data.bytes": {"op": "le", "value": 100}}}, condition="sel")
    assert rule_matches(rule, {"data": {"bytes": 100}}) is True


def test_contains_op():
    rule = _rule(detection={"sel": {"msg": {"op": "contains", "value": "pwn"}}}, condition="sel")
    assert rule_matches(rule, {"msg": "host pwned"}) is True
    assert rule_matches(rule, {"msg": "hello"}) is False
    # list membership form
    rule = _rule(detection={"sel": {"data.flags": ["-enc"]}}, condition="sel")
    assert rule_matches(rule, {"data": {"flags": ["-enc", "-x"]}}) is True
    assert rule_matches(rule, {"data": {"flags": ["-x"]}}) is False


def test_nested_data_fields_and_json_strings():
    rule = _rule(detection={"sel": {"data.nested.deep": "x"}}, condition="sel")
    assert rule_matches(rule, {"data": {"nested": {"deep": "x"}}}) is True
    assert rule_matches(rule, {"data": '{"nested": {"deep": "x"}}'}) is True  # DB rows are JSON strings


def test_all_any_of_n():
    rule = _rule(detection={"a": {"data.x": "1"}, "b": {"data.y": "2"}, "c": {"data.z": "3"}},
                 condition="2 of")
    assert rule_matches(rule, {"data": {"x": "1", "y": "2"}}) is True
    assert rule_matches(rule, {"data": {"x": "1"}}) is False
    rule = _rule(detection={"a": {"data.x": "1"}, "b": {"data.y": "2"}}, condition="all")
    assert rule_matches(rule, {"data": {"x": "1", "y": "2"}}) is True
    assert rule_matches(rule, {"data": {"x": "1"}}) is False
    rule = _rule(detection={"a": {"data.x": "1"}, "b": {"data.y": "2"}}, condition="any")
    assert rule_matches(rule, {"data": {"x": "1"}}) is True
    assert rule_matches(rule, {"data": {"w": "9"}}) is False


def test_rule_requires_uid_and_detection():
    for bad in ({}, {"uid": "x"}, {"uid": "x", "detection": {}}):
        try:
            compile_rule(bad)
            raise AssertionError("should fail")
        except RuleError:
            pass


def test_threshold_requires_timeframe():
    try:
        _rule(threshold=5)
        raise AssertionError("should fail")
    except RuleError:
        pass


# ------------------------------------------------------------------- evaluation

def _ev(i, ts, action="bad_thing", host="h1"):
    return {"id": i, "ts": ts, "action": action, "host": host, "data": {}}


def test_non_threshold_burst_grouping():
    rule = _rule()
    events = [_ev(1, "2026-09-21T00:00:00Z"), _ev(2, "2026-09-21T00:01:00Z"),
              _ev(3, "2026-09-21T02:00:00Z")]  # gap > 900s -> second burst
    groups = evaluate_batch(rule, events)
    assert len(groups) == 2
    assert groups[0]["count"] == 2
    assert groups[1]["count"] == 1


def test_threshold_fires_within_window():
    rule = _rule(threshold=3, timeframe=300, entity="host")
    events = [_ev(i, f"2026-09-21T00:00:{i:02d}Z") for i in range(3)]
    groups = evaluate_batch(rule, events)
    assert len(groups) == 1
    assert groups[0]["count"] == 3


def test_threshold_does_not_fire_outside_window():
    rule = _rule(threshold=3, timeframe=60, entity="host")
    events = [_ev(i, f"2026-09-21T00:0{i}:00Z") for i in range(3)]  # 60s+ apart
    groups = evaluate_batch(rule, events)
    assert groups == []


def test_stale_burst_not_realerted_on_fresh_event_elsewhere():
    rule = _rule(threshold=3, timeframe=300, entity="host")
    old = [_ev(i, f"2026-09-18T00:00:{i:02d}Z", host="h1") for i in range(5)]
    fresh_other = [_ev(100, "2026-09-21T00:00:00Z", action="other")]
    groups = evaluate_batch(rule, old + fresh_other, new_ids={100})
    assert groups == []  # h1 burst is stale; fresh event is not a match


def test_fresh_event_triggers_entity_with_stale_plus_new():
    rule = _rule(threshold=3, timeframe=300, entity="host")
    old = [_ev(i, f"2026-09-21T00:00:{i:02d}Z", host="h1") for i in range(2)]
    fresh = [_ev(50, "2026-09-21T00:01:00Z", host="h1")]
    groups = evaluate_batch(rule, old + fresh, new_ids={50})
    assert len(groups) == 1
    assert groups[0]["count"] == 3
    assert groups[0]["entity"] == "h1"
