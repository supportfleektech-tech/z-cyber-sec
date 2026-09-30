"""Agent adapters (SEC-050/051) — pluggable "brains" behind the gateway.

The gateway (policy.plan_task / execute_task) is the ONLY path to tools.
An adapter translates a free-form `{"prompt": ...}` request into explicit
tool steps; those steps then go through the standard allowlist + injection
+ approval gates exactly like user-submitted requests. An adapter can never
waive its own guardrails (docs/06):

- builtin:        deterministic; requires explicit tool/steps (no brain).
- openai_compat:  any OpenAI-compatible /chat/completions endpoint (free
                  local servers such as Ollama work with api_key omitted).
- cli:            a local command receives {prompt, tools} on stdin and
                  must answer {"tool":..., "args":...} or {"steps":[...]}
                  on stdout (sandboxed: fixed env, timeout, no network
                  assumptions).

Zero-budget: no paid SDKs; httpx (already a dependency) for HTTP.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess

import httpx

from .. import db
from . import policy

ADAPTERS = ("builtin", "openai_compat", "cli")

# SEC-075: selectable personas (adapter_config.persona). A persona shapes the
# system prompt only — authority stays with the tool allowlist, the approval
# gate and the scope guard, none of which the adapter can bypass.
PERSONAS = ("the-xploiter",)
HTTP_TIMEOUT = 30.0
CLI_TIMEOUT = 60.0


class AdapterError(ValueError):
    pass


def system_prompt(agent: dict, config: dict | None = None) -> str:
    """Base system prompt, extended by a persona when the agent declares one.

    Personas (SEC-075) shape *how* an agent reasons — they never widen what it
    may do. Tool allowlist, approval gating and scope checks are enforced below
    the adapter, so a persona cannot grant a capability.
    """
    base = ("You are a scoped cybersecurity assistant. Choose ONE tool "
            "call from the allowed tools to make progress on the request. "
            "If no allowed tool applies, answer with a final message.")
    cfg = config if config is not None else (db.jload(agent.get("adapter_config"), {}) or {})
    persona = (cfg.get("persona") or "").strip().lower()
    if not persona:
        return base
    from . import tradecraft as tc
    if persona != tc.PERSONA["codename"].lower():
        return base
    principles = "; ".join(p["principle"] for p in tc.PERSONA["design_principles"])
    guardrails = " ".join(tc.PERSONA["guardrails"])
    return (
        f"{base}\n\nAdopt the '{tc.PERSONA['codename']}' persona: {tc.PERSONA['summary']} "
        f"Operating principles: {principles}. "
        "Report only what your tools actually returned; never invent evidence, "
        "targets or exploit results. Ask 'is this actually exploitable, under "
        "which preconditions, and what would an attacker do next' before "
        "answering. Prefer explaining WHY a behaviour is exploitable over "
        "restating WHAT was found. "
        f"Hard limits: {guardrails}"
    )


def _tool_schemas(agent: dict) -> list[dict]:
    tools = db.jload(agent.get("tools"), [])
    out = []
    for name in tools:
        spec = policy.TOOL_REGISTRY.get(name)
        if spec:
            out.append({"name": name, "description": spec["description"],
                        "read_only": spec["read_only"]})
    return out


def resolve_steps(agent: dict, request: dict) -> dict:
    """Turn an incoming request into an explicit step-based request.

    Explicit {tool}/{steps} requests pass through unchanged (deterministic
    path — no adapter involved). Only {"prompt": ...} uses the brain.
    """
    if "tool" in request or "steps" in request:
        return request
    prompt = (request.get("prompt") or "").strip()
    if not prompt:
        raise AdapterError("request must include 'tool', 'steps', or 'prompt'")

    adapter = (agent.get("adapter") or "builtin").strip()
    config = db.jload(agent.get("adapter_config"), {}) or {}

    if adapter == "builtin":
        raise AdapterError(
            "builtin adapter has no brain — send an explicit 'tool' or 'steps' request")
    if adapter == "openai_compat":
        steps = _openai_compat(prompt, config, _tool_schemas(agent), agent)
    elif adapter == "cli":
        steps = _cli(prompt, config, _tool_schemas(agent))
    else:
        raise AdapterError(f"unknown adapter: {adapter}")
    return {"steps": steps, "adapter": adapter}


# ---------------------------------------------------------------- backends

def _openai_compat(prompt: str, config: dict, tools: list[dict], agent: dict) -> list[dict]:
    base_url = (config.get("base_url") or "").rstrip("/")
    model = config.get("model") or "local-model"
    if not base_url:
        raise AdapterError("openai_compat adapter requires adapter_config.base_url")
    headers = {"Content-Type": "application/json"}
    api_key = config.get("api_key") or os.environ.get(config.get("api_key_env") or "", "")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt(agent, config)},
            {"role": "user", "content": prompt},
        ],
        "tools": [{"type": "function", "function": {
            "name": t["name"], "description": t["description"],
            "parameters": {"type": "object", "properties": {}, "additionalProperties": True}}}
            for t in tools],
    }
    try:
        resp = httpx.post(f"{base_url}/chat/completions", json=body, headers=headers,
                          timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        raise AdapterError(f"adapter request failed: {e}") from e
    msg = (data.get("choices") or [{}])[0].get("message") or {}
    calls = msg.get("tool_calls") or []
    if not calls:
        raise AdapterError("model returned no tool call; no allowed tool fits the prompt")
    fn = calls[0].get("function") or {}
    args_raw = fn.get("arguments") or "{}"
    try:
        args = json.loads(args_raw) if isinstance(args_raw, str) else dict(args_raw)
    except ValueError as e:
        raise AdapterError(f"model returned invalid tool arguments: {e}") from e
    return [{"tool": fn.get("name"), "args": args if isinstance(args, dict) else {}}]


def _cli(prompt: str, config: dict, tools: list[dict]) -> list[dict]:
    command = config.get("command")
    if not command:
        raise AdapterError("cli adapter requires adapter_config.command")
    payload = json.dumps({"prompt": prompt, "tools": tools})
    try:
        proc = subprocess.run(
            shlex.split(command), input=payload.encode(), capture_output=True,
            timeout=config.get("timeout", CLI_TIMEOUT),
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},  # minimal fixed env
        )
    except (subprocess.SubprocessError, OSError) as e:
        raise AdapterError(f"cli adapter failed: {e}") from e
    if proc.returncode != 0:
        raise AdapterError(f"cli adapter exited {proc.returncode}: "
                           f"{proc.stderr.decode(errors='replace')[:200]}")
    try:
        out = json.loads(proc.stdout.decode() or "{}")
    except ValueError as e:
        raise AdapterError("cli adapter did not return JSON: "
                           f"{proc.stdout.decode(errors='replace')[:200]}") from e
    if "steps" in out:
        steps = out["steps"]
        if not isinstance(steps, list) or not steps:
            raise AdapterError("cli adapter 'steps' must be a non-empty list")
        return steps
    if out.get("tool"):
        return [{"tool": out["tool"], "args": out.get("args") or {}}]
    raise AdapterError("cli adapter returned neither 'tool' nor 'steps'")
