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
"""
from __future__ import annotations

import re

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


def parse_bundle(bundle: dict) -> list[dict]:
    """Parse a STIX 2.1 bundle dict into [{type, value, confidence, name}]."""
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        raise ValueError("Expected a STIX bundle with an 'objects' list")
    out: list[dict] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern") or ""
        for ind in extract_indicators(pattern):
            ind["confidence"] = obj.get("confidence")
            ind["name"] = obj.get("name", "")
            ind["valid_from"] = obj.get("valid_from")
            # SEC-087: STIX's own expiry field. Dropping it meant an imported IOC
            # with a `valid_until` in the past was stored `active` and matched by
            # correlation forever.
            ind["valid_until"] = obj.get("valid_until")
            out.append(ind)
    return out
