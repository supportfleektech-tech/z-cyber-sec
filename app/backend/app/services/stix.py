"""STIX 2.1 bundle import (subset) — free interop format for threat intel.

Supports the common pattern shapes produced by OpenCTI/MISP/elastic export:
  [ipv4-addr:value = '1.2.3.4']
  [domain-name:value = 'evil.example']
  [url:value = 'http://evil.example/x']
  [file:hashes.'SHA-256' = 'abc...']
  [file:name = 'payload.exe']
  [email-addr:value = 'a@b.c']
Indicators are deduplicated on (type, value); confidence, source, `valid_from`
and `valid_until` are kept (the latter becomes the indicator's TTL).

SEC-104: values from the bundle are checked and normalised here rather than written
straight into the store. A bundle carrying `confidence: 999` or `"high"` used to be
imported as-is — the same field the manual endpoint bounds (0-100) — and a text
confidence sorted above every real one in `ORDER BY confidence DESC`. STIX timestamps
with milliseconds (spec-valid) were stored verbatim, which the store's parsers cannot
read, so `valid_until` silently became "never expires".
"""
from __future__ import annotations

import re
from datetime import UTC, datetime

_PATTERNS = [
    ("ip", re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'")),
    ("ip", re.compile(r'\[ipv4-addr:value\s*=\s*"([^"]+)"')),
    ("domain", re.compile(r"\[domain-name:value\s*=\s*'([^']+)'")),
    ("domain", re.compile(r"\[domain-name:value\s*=\s*\"([^\"]+)\"")),
    ("url", re.compile(r"\[url:value\s*=\s*'([^']+)'")),
    ("url", re.compile(r'\[url:value\s*=\s*"([^"]+)"')),
    ("sha256", re.compile(r"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'", re.IGNORECASE)),
    ("sha256", re.compile(r'\[file:hashes\."SHA-256"\s*=\s*"([^"]+)"', re.IGNORECASE)),
    ("file", re.compile(r"\[file:name\s*=\s*'([^']+)'")),
    ("file", re.compile(r'\[file:name\s*=\s*"([^"]+)"')),
    ("email", re.compile(r"\[email-addr:value\s*=\s*'([^']+)'")),
]


def extract_indicators(pattern: str) -> list[dict]:
    out = []
    for typ, rx in _PATTERNS:
        for m in rx.finditer(pattern or ""):
            value = m.group(1).strip()
            if value:
                out.append({"type": typ, "value": value})
    return out


def normalize_ts(value, where: str) -> str:
    """A STIX timestamp as the store's `%Y-%m-%dT%H:%M:%SZ`, or ValueError (SEC-104).

    STIX 2.1 timestamps are RFC3339 with optional fractional seconds; the store's
    columns and parsers use whole seconds, so a value like
    `2027-09-01T00:00:00.000Z` must be normalised rather than stored verbatim (it
    parsed as "no expiry at all").
    """
    if not isinstance(value, str):
        raise ValueError(f"{where}: timestamp must be a string, got {value!r}")
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(f"{where}: not an RFC3339 timestamp: {value!r}") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_confidence(value, where: str):
    """A STIX `confidence` as an int 0-100, or ValueError (SEC-104).

    The manual indicator endpoint bounds this field (`ge=0, le=100`); a bundle is
    the other way into the same column.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise ValueError(f"{where}: confidence must be an integer 0-100, got {value!r}")
    return value


def parse_bundle(bundle: dict) -> list[dict]:
    """Parse a STIX 2.1 bundle dict into [{type, value, confidence, name}].

    Raises ValueError for a bundle that is not an objects list, or for an indicator
    whose `confidence`, `valid_from` or `valid_until` cannot be represented in the
    store — naming the object, so the operator can fix the export instead of
    discovering later that an IOC never expires.
    """
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        raise ValueError("Expected a STIX bundle with an 'objects' list")
    out: list[dict] = []
    for idx, obj in enumerate(objects):
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        extracted = extract_indicators(obj.get("pattern") or "")
        if not extracted:
            continue  # an object we cannot read contributes nothing, valid or not
        confidence = validate_confidence(obj.get("confidence"), f"indicator {idx}")
        valid_from = (normalize_ts(obj["valid_from"], f"indicator {idx} valid_from")
                      if obj.get("valid_from") is not None else None)
        # SEC-087: STIX's own expiry field. Dropping it meant an imported IOC with a
        # `valid_until` in the past was stored `active` and matched by correlation
        # forever.
        valid_until = (normalize_ts(obj["valid_until"], f"indicator {idx} valid_until")
                       if obj.get("valid_until") is not None else None)
        for ind in extracted:
            ind["confidence"] = confidence
            ind["name"] = obj.get("name", "")
            ind["valid_from"] = valid_from
            ind["valid_until"] = valid_until
            out.append(ind)
    return out
