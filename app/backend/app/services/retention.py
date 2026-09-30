"""Evidence retention labels: one grammar, shared by the writer and the report (SEC-122).

Retention is a *control*, not a note (SEC-112). It was being parsed twice — once in
`routers/cases.py` when an artefact is uploaded, once in `routers/admin.py` when the
retention report decides what is due for review — and the two grammars had drifted:

* the writer accepted `\\d{1,5}<d|w|m|y>`, the report accepted `\\d+<d|w|m|y>`, so a
  legacy row with a six-digit window was "understood" (and counted `within_retention`)
  while the same label was refused on write;
* neither rejected **zero** (`0d`, `0y`, `00w`), so a typo produced evidence that landed
  in `due_for_review` — the queue a human works through to *destroy* artefacts —
  immediately after upload (SEC-122, found by uploading one).

This module is now the single source of truth. `parse()` never raises; callers decide
what to refuse. Kinds:

| kind | meaning | examples |
|---|---|---|
| `empty` | no label at all | ``None``, `""`, `"  "` |
| `sentinel` | never auto-due | `legal-hold`, `legal_hold`, `retain-case-close`, `indefinite` |
| `window` | keep for `days`, then due for review | `90d`, `6M`, `12y`, `00w` (see below) |
| `unrecognised` | not this grammar; must not be blessed as "within retention" | `banana`, `90 days`, `999999d` |

A window of zero days is grammatically a window but semantically a demand to destroy
evidence the moment it is uploaded; writes refuse it and the report surfaces it rather
than acting on it.

Units are calendar-approximate on purpose (`m` = 30 days, `y` = 365), because the label
declares an intention a human reviews — `docs/10-operations-runbook.md` and
`docs/12-api-reference.md` both say so.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

#: Labels that mean "never comes due for review by itself".
SENTINELS = frozenset({"legal-hold", "legal_hold", "retain-case-close", "indefinite"})

#: Sentinels the report counts separately rather than in `within_retention`.
PINNED = frozenset({"legal-hold", "legal_hold"})
CASE_BOUND = "retain-case-close"

#: `<1-5 digits><d|w|m|y>`, optional internal space, case-insensitive. Five digits is
#: ~273 years in days: beyond that the label is a mistyped number, not a policy.
WINDOW_RE = re.compile(r"^(\d{1,5})\s*([dwmy])$")

UNIT_DAYS = {"d": 1, "w": 7, "m": 30, "y": 365}

ALLOWED = sorted(SENTINELS) + ["<n>d", "<n>w", "<n>m", "<n>y"]


@dataclass(frozen=True)
class Label:
    kind: str                     # empty | sentinel | window | unrecognised
    canonical: str | None         # normalised label, or None for empty
    days: int | None              # windows only

    @property
    def is_zero_window(self) -> bool:
        return self.kind == "window" and self.days == 0


def parse(label: str | None) -> Label:
    """Classify a retention label. Never raises: the caller decides what is refusable."""
    text = (label or "").strip().lower()
    if not text:
        return Label("empty", None, None)
    if text in SENTINELS:
        return Label("sentinel", text, None)
    match = WINDOW_RE.match(text)
    if not match:
        return Label("unrecognised", text, None)
    amount, unit = int(match.group(1)), match.group(2)
    return Label("window", f"{amount}{unit}", amount * UNIT_DAYS[unit])


def due(label: str | None, elapsed_days: float) -> bool:
    """True when a *valid, non-zero* window has elapsed. Everything else is not due."""
    parsed = parse(label)
    if parsed.kind != "window" or parsed.days == 0:
        return False
    return elapsed_days > parsed.days
