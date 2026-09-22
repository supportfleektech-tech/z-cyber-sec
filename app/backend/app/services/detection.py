"""Detection engine — a deliberately small, auditable Sigma-subset.

Design borrowed from free/open projects (Sigma rule model, Wazuh alerting,
elastic-detection) and implemented natively so the local lab runs with zero
external services (ADR-003).

Rule spec (YAML, also accepted as JSON):
  uid, name, description, severity, status
  detection:  {term_name: {field: value | [values] | {op: gt|lt|contains, value: x}}}
  condition:  grammar over term names, 'all', 'any', 'not', 'and', 'or', 'N of'
  timeframe:  seconds (only with threshold)
  threshold:  minimum matches within timeframe
  entity:     field to group threshold counts by (default: host)

Values:
  scalar         -> exact match (case-insensitive for str)
  list           -> any exact match
  {op: gt|lt|ge|le, value} -> numeric comparison
  {op: contains, value}    -> substring / membership
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import UTC

OPS = {"gt", "lt", "ge", "le", "contains"}


class RuleError(ValueError):
    pass


def rule_health(spec: dict) -> dict:
    """Compile ``spec`` and report the outcome instead of raising.

    A rule that cannot compile is *silently* inert at detection time, so every
    surface that lists rules (``GET /rules``, ``/rules/coverage``) must be able
    to say "this rule can never fire" and why. Returning a status dict keeps
    that check in one place (SEC-074).
    """
    try:
        rule = compile_rule(spec)
    except RuleError as e:
        return {"compiles": False, "error": str(e)}
    except Exception as e:  # defensive: malformed spec that isn't a RuleError
        return {"compiles": False, "error": f"{type(e).__name__}: {e}"}
    return {"compiles": True, "error": None, "rule": rule}


# --------------------------------------------------------------- condition parser

_TOKEN_RE = re.compile(r"\s*(\d+|[A-Za-z_][A-Za-z0-9_]*|of|all|any|not|and|or|\(|\))")


def tokenize_condition(text: str) -> list[str]:
    tokens, pos = [], 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise RuleError(f"Cannot parse condition at: {text[pos:pos+20]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


@dataclass
class Condition:
    # node kinds: "and" | "or" | "not" | "ref" | "all" | "any" | "of_n"
    kind: str
    children: list = dc_field(default_factory=list)
    name: str | None = None
    n: int = 0


def parse_condition(text: str) -> Condition:
    tokens = tokenize_condition(text)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise RuleError(f"Unexpected end of condition: {text!r}")
        t = tokens[pos]
        pos += 1
        return t

    def parse_or() -> Condition:
        left = parse_and()
        if peek() == "or":
            take()
            children = [left, parse_or()]
            return Condition("or", children)
        return left

    def parse_and() -> Condition:
        left = parse_not()
        if peek() == "and":
            take()
            children = [left, parse_and()]
            return Condition("and", children)
        return left

    def parse_not() -> Condition:
        if peek() == "not":
            take()
            return Condition("not", [parse_not()])
        return parse_atom()

    def parse_atom() -> Condition:
        t = take()
        if t == "(":
            inner = parse_or()
            if take() != ")":
                raise RuleError("Expected ')' in condition")
            return inner
        if t == "all":
            return Condition("all")
        if t == "any":
            return Condition("any")
        if re.fullmatch(r"\d+", t):
            if take() != "of":
                raise RuleError("Expected 'of' after number in condition")
            return Condition("of_n", n=int(t))
        return Condition("ref", name=t)

    result = parse_or()
    if pos != len(tokens):
        raise RuleError(f"Trailing tokens in condition: {tokens[pos:]}")
    return result


def eval_condition(cond: Condition, matched: set[str], all_terms: set[str]) -> bool:
    if cond.kind == "ref":
        return cond.name in matched
    if cond.kind == "all":
        return all_terms <= matched
    if cond.kind == "any":
        return bool(matched & all_terms)
    if cond.kind == "of_n":
        return len(matched & all_terms) >= cond.n
    if cond.kind == "not":
        return not eval_condition(cond.children[0], matched, all_terms)
    if cond.kind == "and":
        return all(eval_condition(c, matched, all_terms) for c in cond.children)
    if cond.kind == "or":
        return any(eval_condition(c, matched, all_terms) for c in cond.children)
    raise RuleError(f"Unknown condition kind {cond.kind}")


# ------------------------------------------------------------------ value matching

def _get_field(event: dict, field_name: str):
    """Top-level event fields, or nested paths inside the JSON `data` payload.

    'action' -> event['action']; 'data.bytes_out' / 'bytes_out' -> data['bytes_out'].
    """
    if field_name in event:
        return event[field_name]
    if "." in field_name or field_name not in ("action", "host", "user", "outcome", "severity"):
        path = field_name
        if path.startswith("data."):
            path = path[len("data."):]
        cur = event.get("data")
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except (ValueError, TypeError):
                cur = {}
        cur = cur or {}
        for k in path.split("."):
            if not isinstance(cur, dict) or k not in cur:
                return None
            cur = cur[k]
        return cur
    return None


def _match_value(actual, expected) -> bool:
    if actual is None:
        return False
    if isinstance(expected, dict):
        op = expected.get("op")
        if op not in OPS:
            raise RuleError(f"Unknown op {op}")
        if op == "contains":
            if isinstance(actual, (list, tuple, set)):
                return expected["value"] in actual
            return str(expected["value"]).lower() in str(actual).lower()
        try:
            a, v = float(actual), float(expected["value"])
        except (TypeError, ValueError):
            return False
        return {"gt": a > v, "lt": a < v, "ge": a >= v, "le": a <= v}[op]
    if isinstance(expected, list):
        if isinstance(actual, (list, tuple, set)):
            return any(_eq(a, e) for a in actual for e in expected)
        return any(_eq(actual, e) for e in expected)
    if isinstance(actual, (list, tuple, set)):
        return any(_eq(a, expected) for a in actual)
    return _eq(actual, expected)


def _eq(a, b) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b or a == b
    return a == b


# ------------------------------------------------------------------- rule loading

@dataclass
class DetectionRule:
    uid: str
    name: str
    description: str
    severity: str
    status: str
    terms: dict            # term_name -> {field: expected}
    condition: Condition
    all_terms: set
    timeframe: int | None
    threshold: int | None
    entity: str

    @property
    def requires_threshold(self) -> bool:
        return self.threshold is not None


def compile_rule(spec: dict) -> DetectionRule:
    uid = spec.get("uid")
    if not uid:
        raise RuleError("Rule must have a uid")
    detection = spec.get("detection") or {}
    if not detection:
        raise RuleError("Rule must define detection terms")
    terms = {}
    for name, fields in detection.items():
        if not isinstance(fields, dict):
            raise RuleError(f"Detection term {name} must be a field map")
        for field_name, expected in fields.items():
            if isinstance(expected, dict):
                op = expected.get("op")
                if op not in OPS or "value" not in expected:
                    raise RuleError(f"term {name}: field {field_name} has an invalid value spec")
        terms[name] = fields
    cond = parse_condition(spec.get("condition") or "all")
    threshold = spec.get("threshold")
    if threshold is not None and not spec.get("timeframe"):
        raise RuleError("threshold requires timeframe")
    return DetectionRule(
        uid=str(uid), name=spec.get("name", str(uid)), description=spec.get("description", ""),
        severity=str(spec.get("severity", "medium")).lower(),
        status=str(spec.get("status", "active")).lower(),
        terms=terms, condition=cond, all_terms=set(terms.keys()),
        timeframe=spec.get("timeframe"), threshold=threshold,
        entity=spec.get("entity") or "host",
    )


def _term_matches(fields: dict, event: dict) -> bool:
    for field_name, expected in fields.items():
        if not _match_value(_get_field(event, field_name), expected):
            return False
    return True


def term_matched(rule: DetectionRule, event: dict) -> set[str]:
    return {name for name, fields in rule.terms.items() if _term_matches(fields, event)}


def rule_matches(rule: DetectionRule, event: dict) -> bool:
    matched = term_matched(rule, event)
    return eval_condition(rule.condition, matched, rule.all_terms)


# ---------------------------------------------------------------- evaluation

def _parse_ts(ts: str | None):
    if not ts:
        return None
    try:
        from datetime import datetime
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def evaluate_batch(rule: DetectionRule, context: list[dict], new_ids: set | None = None) -> list[dict]:
    """Return alert groups: [{event_ids, first_seen, last_seen, count, entity}].

    `context` is the pool of candidate events; `new_ids` marks which are fresh
    (for ingest) — all ids for backfill/dry-run.

    Non-threshold: burst grouping (gap > 900s starts a new group) over fresh events.
    Threshold: anchored window — only entities with at least one fresh event are
    evaluated, counting matches within [newest_fresh - timeframe, newest_fresh].
    This prevents stale bursts from re-alerting on every ingest.
    """
    if new_ids is None:
        new_ids = {e["id"] for e in context}
    fresh = [e for e in context if e["id"] in new_ids]
    if not fresh:
        return []

    if not rule.requires_threshold:
        hits = sorted((e for e in fresh if rule_matches(rule, e)), key=lambda e: e["ts"] or "")
        groups, cur = [], None
        prev_ts = None
        for e in hits:
            t = _parse_ts(e["ts"])
            if cur is None or (t is not None and prev_ts is not None and (t - prev_ts) > 900):
                cur = {"event_ids": [], "first_seen": e["ts"], "last_seen": e["ts"],
                       "count": 0, "entity": e.get(rule.entity)}
                groups.append(cur)
            cur["event_ids"].append(e["id"])
            cur["last_seen"] = e["ts"]
            cur["count"] += 1
            prev_ts = t if t is not None else prev_ts
        return groups

    # threshold mode — per-entity window anchored at the newest FRESH event
    hits = [e for e in context if rule_matches(rule, e)]
    buckets: dict[str, list] = {}
    for e in hits:
        key = str(e.get(rule.entity) or "unknown")
        buckets.setdefault(key, []).append(e)
    groups = []
    for entity, evs in buckets.items():
        fresh_evs = [e for e in evs if e["id"] in new_ids]
        if not fresh_evs:
            continue  # nothing new for this entity — never re-alert stale bursts
        anchor = max((t for t in (_parse_ts(e["ts"]) for e in fresh_evs) if t is not None), default=None)
        window = []
        for e in evs:
            t = _parse_ts(e["ts"])
            if anchor is not None and rule.timeframe and t is not None:
                if not (anchor - rule.timeframe <= t <= anchor):
                    continue
            window.append(e)
        if len(window) < rule.threshold:
            continue
        window.sort(key=lambda e: e["ts"] or "")
        groups.append({
            "event_ids": [e["id"] for e in window],
            "first_seen": window[0]["ts"], "last_seen": window[-1]["ts"],
            "count": len(window), "entity": entity,
        })
    return groups
