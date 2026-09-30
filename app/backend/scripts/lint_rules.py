"""Validate every shipped detection rule against the engine's Sigma subset.

Closes the gap recorded in docs/13 ("the engine is a documented subset; no
linter for out-of-subset rules yet"): a rule that does not compile is *inert* —
detection silently never fires it — so porting a rule from a full Sigma pack
(e.g. SigmaHQ) without checking is how an operator ends up believing they have
coverage they do not have. Run this before trusting a new or ported rule, and
in CI so a broken rule cannot merge.

    .venv/bin/python -m scripts.lint_rules              # validate rules/
    .venv/bin/python -m scripts.lint_rules path/to.yaml # validate a ported file

Exit code 0 = every rule compiles; 1 = at least one rule is inert (details on
stderr, one block per failure, naming the construct that is unsupported).
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from app.config import settings
from app.services.detection import rule_health

OK = "\033[32mOK\033[0m" if sys.stderr.isatty() else "OK"
BAD = "\033[31mINERT\033[0m" if sys.stderr.isatty() else "INERT"

# Full Sigma (SigmaHQ) spells the metadata differently. A verbatim port fails on
# the very first field, so the linter maps the keys instead of just saying
# "Rule must have a uid".
SIGMA_FIELD_MAP = {
    "id": "uid",
    "title": "name (and `uid`)",
    "level": "severity",
    "logsource": "(not part of the spec — this engine matches on event fields)",
    "tags": "(not part of the spec)",
    "falsepositives": "(not part of the spec)",
}

# Condition / value constructs outside the documented subset.
PORTING_HINTS = (
    ("*", "wildcard in a condition (e.g. `1 of selection*`) — name each term instead"),
    ("|all", "`|all` requires every value to match; use one field per value in the term"),
    ("|contains", "field modifier — use `{op: contains, value: x}` for a single field"),
    ("|re", "regex matching is not supported; use `{op: contains, value: x}`"),
    ("near", "`near` (proximity correlation) is not supported"),
    ("timeframe", "`timeframe` is supported, but only together with `threshold`"),
)


def _spec_hints(spec: dict) -> list[str]:
    """Porting advice for a spec that failed to compile."""
    hints = []
    if isinstance(spec, dict):
        for key, advice in SIGMA_FIELD_MAP.items():
            if key in spec:
                hints.append(f"`{key}` is full-Sigma naming — use `{advice}` here")
        condition = str(spec.get("condition") or "")
        for token, advice in PORTING_HINTS:
            if token in condition and "wildcard" in advice:
                hints.append(advice)
        for term in (spec.get("detection") or {}).values():
            if isinstance(term, dict):
                for field_name in term:
                    for token, advice in PORTING_HINTS:
                        if token in field_name:
                            hints.append(f"field `{field_name}`: {advice}")
    return list(dict.fromkeys(hints))


def _hint(error: str, spec: dict) -> list[str]:
    hints = _spec_hints(spec)
    for token, advice in PORTING_HINTS:
        if token in error and token not in ("timeframe",):
            if token == "timeframe" and "threshold" in error:
                continue
            hints.append(advice)
    return list(dict.fromkeys(hints))


def main(argv: list[str]) -> int:
    targets: list[Path] = []
    for arg in argv:
        p = Path(arg)
        if p.is_file():
            targets.append(p)
        elif p.is_dir():
            targets.extend(sorted(p.glob("*.yaml")))
        else:
            print(f"lint_rules: not found: {arg}", file=sys.stderr)
            return 2
    if not targets:
        targets = sorted(settings.rules_dir.glob("*.yaml"))
    if not targets:
        print("lint_rules: no rules found", file=sys.stderr)
        return 2

    failures = 0
    print(f"lint_rules: validating {len(targets)} rule file(s) "
          f"against the engine subset\n")
    for f in targets:
        try:
            spec = yaml.safe_load(f.read_text())
        except yaml.YAMLError as e:
            failures += 1
            print(f"  {BAD}  {f.name}: invalid YAML: {e}", file=sys.stderr)
            continue
        health = rule_health(spec or {})
        if health["compiles"]:
            print(f"  {OK}    {f.name}")
        else:
            failures += 1
            print(f"  {BAD} {f.name}", file=sys.stderr)
            print(f"        reason: {health['error']}", file=sys.stderr)
            for hint in _hint(health["error"], spec or {}):
                print(f"        porting: {hint}", file=sys.stderr)
            print("        effect: stored as 'active' but INERT — detection would "
                  "never fire it and /rules would report compiles=false.",
                  file=sys.stderr)

    if failures:
        print(f"\nlint_rules: {failures} rule(s) would be INERT — fix before "
              f"shipping (see docs/15-detection-rules.md).", file=sys.stderr)
        return 1
    print(f"\nlint_rules: all {len(targets)} rule(s) compile — every shipped "
          f"rule can fire.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
