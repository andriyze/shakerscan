"""Keyless AI-directed connected-device investigation contracts.

The coding-agent session is the planner; ShakerScan executes a small bounded
tool set.  The planner never receives arbitrary shell, network destinations,
credentials, or a way to raise the session safety profile.  Deterministic
device scans remain the source of findings and evidence.
"""

from __future__ import annotations

import json
from typing import Any

try:
    import agent_text_toolcalls
except ModuleNotFoundError:  # pragma: no cover - package import in host tests
    from api import agent_text_toolcalls


CALLABLE_TOOL_NAMES = {
    "inspect_device",
    "queue_device_scan",
    "inspect_device_scan",
    "query_device_evidence",
    "note",
}
MAX_TOOL_CALLS_PER_TURN = 6
MAX_ACTIONS_PER_SESSION = 36
MAX_SCANS_PER_SESSION = 3


def tool_schemas() -> list[dict[str, Any]]:
    return [
        {
            "name": "inspect_device",
            "description": "Read the selected device identity, current services, policy, recent scans, and findings summary.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "queue_device_scan",
            "description": (
                "Queue one deterministic device scan on the already-selected device. "
                "The server fixes the safety profile and rejects concurrent or over-budget scans."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "coverage_profile": {"type": "string", "enum": ["inventory", "posture", "thorough"]},
                    "include_web_dast": {"type": "boolean"},
                    "web_scan_type": {"type": "string", "enum": ["quick", "standard", "deep"]},
                    "reason": {"type": "string", "maxLength": 500},
                },
                "required": ["coverage_profile", "reason"],
                "additionalProperties": False,
            },
        },
        {
            "name": "inspect_device_scan",
            "description": "Read status and bounded result/evidence summaries for a scan that belongs to this device.",
            "parameters": {
                "type": "object",
                "properties": {"scan_id": {"type": "string"}},
                "required": ["scan_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "query_device_evidence",
            "description": "Query normalized nodes, edges, or observations from a completed scan on this device.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "collection": {"type": "string", "enum": ["nodes", "edges", "observations"]},
                    "kind": {"type": "string", "maxLength": 100},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                },
                "required": ["scan_id", "collection"],
                "additionalProperties": False,
            },
        },
        {
            "name": "note",
            "description": "Record a bounded hypothesis, observation, or next step. Notes are not findings or proof.",
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": ["hypothesis", "observation", "todo"]},
                    "content": {"type": "string", "maxLength": 1000},
                },
                "required": ["kind", "content"],
                "additionalProperties": False,
            },
        },
    ]


def render_contract() -> str:
    tools = tool_schemas()
    lines = [
        "## CONNECTED-DEVICE AGENT TOOL CONTRACT",
        "You are directing an authorized investigation of exactly one registered connected device.",
        "ShakerScan fixes the device locator and safety profile. Never invent another target or request arbitrary shell/network access.",
        "Start from existing evidence, choose the smallest useful scan, inspect its result, and stop when the objective is answered.",
        "A queued scan is asynchronous: use inspect_device_scan on a later turn; do not repeatedly queue equivalent scans.",
        "Only deterministic scanner findings are findings. Your final leads are hypotheses and must cite real devref_N evidence references.",
        "",
        "Available tools:",
    ]
    for tool in tools:
        params = (tool.get("parameters") or {}).get("properties") or {}
        required = set((tool.get("parameters") or {}).get("required") or [])
        signature = ", ".join(f"{name}{'*' if name in required else ''}" for name in params)
        lines.append(f"- {tool['name']}({signature}): {tool['description']}")
    lines.extend([
        "",
        "To execute tools, reply with only:",
        "```json",
        '{"tool_calls":[{"name":"inspect_device","arguments":{}}]}',
        "```",
        "When done, reply with only:",
        "```json",
        '{"done":true,"summary":"...","leads":[{"title":"...","rationale":"...","evidence_refs":["devref_1"]}],"next_actions":["..."]}',
        "```",
        "Do not call a lead verified. A lead without a valid evidence reference is discarded.",
    ])
    return "\n".join(lines)


def validate_tool_call(call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    name = str(call.get("name") or "").strip()
    if name not in CALLABLE_TOOL_NAMES:
        raise ValueError(f"unknown connected-device agent tool: {name or 'empty'}")
    args = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
    allowed_fields = {
        "inspect_device": set(),
        "queue_device_scan": {"coverage_profile", "include_web_dast", "web_scan_type", "reason"},
        "inspect_device_scan": {"scan_id"},
        "query_device_evidence": {"scan_id", "collection", "kind", "limit"},
        "note": {"kind", "content"},
    }[name]
    if set(args) - allowed_fields:
        raise ValueError(f"{name} contains unsupported arguments")
    if name == "queue_device_scan":
        coverage = str(args.get("coverage_profile") or "").lower()
        if coverage not in {"inventory", "posture", "thorough"}:
            raise ValueError("queue_device_scan coverage_profile is invalid")
        web_type = str(args.get("web_scan_type") or "standard").lower()
        if web_type not in {"quick", "standard", "deep"}:
            raise ValueError("queue_device_scan web_scan_type is invalid")
        reason = str(args.get("reason") or "").strip()
        if not reason:
            raise ValueError("queue_device_scan reason is required")
        args = {
            "coverage_profile": coverage,
            "include_web_dast": bool(args.get("include_web_dast", True)),
            "web_scan_type": web_type,
            "reason": reason[:500],
        }
    elif name in {"inspect_device_scan", "query_device_evidence"}:
        scan_id = str(args.get("scan_id") or "").strip()
        if not scan_id or len(scan_id) > 80:
            raise ValueError(f"{name} scan_id is required")
        args = dict(args)
        args["scan_id"] = scan_id
        if name == "query_device_evidence":
            collection = str(args.get("collection") or "").lower()
            if collection not in {"nodes", "edges", "observations"}:
                raise ValueError("query_device_evidence collection is invalid")
            args["collection"] = collection
            args["kind"] = str(args.get("kind") or "").strip()[:100] or None
            args["limit"] = max(1, min(int(args.get("limit") or 25), 50))
    elif name == "note":
        kind = str(args.get("kind") or "").lower()
        content = str(args.get("content") or "").strip()
        if kind not in {"hypothesis", "observation", "todo"} or not content:
            raise ValueError("note requires kind and content")
        args = {"kind": kind, "content": content[:1000]}
    else:
        args = {}
    return name, args


def _done_payload(reply: str) -> dict[str, Any] | None:
    for candidate in agent_text_toolcalls.balanced_object_spans(reply[:200_000]):
        try:
            parsed = json.loads(candidate)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(parsed, dict) and parsed.get("done") is True:
            return parsed
    return None


def interpret_reply(reply: str) -> dict[str, Any]:
    calls = agent_text_toolcalls.parse_text_tool_calls(reply)
    if calls:
        return {"kind": "tool_calls", "calls": calls[:MAX_TOOL_CALLS_PER_TURN]}
    done = _done_payload(reply)
    if not done:
        raise ValueError("reply must contain tool_calls or a done debrief")
    leads: list[dict[str, Any]] = []
    for raw in list(done.get("leads") or [])[:25]:
        if not isinstance(raw, dict):
            continue
        refs = [str(ref) for ref in list(raw.get("evidence_refs") or [])[:10] if str(ref).startswith("devref_")]
        if not refs:
            continue
        leads.append({
            "title": str(raw.get("title") or "Device security lead")[:300],
            "rationale": str(raw.get("rationale") or "")[:2000],
            "evidence_refs": refs,
        })
    return {
        "kind": "done",
        "result": {
            "summary": str(done.get("summary") or "")[:5000],
            "leads": leads,
            "next_actions": [str(item)[:1000] for item in list(done.get("next_actions") or [])[:20]],
        },
    }


def seed_state(*, objective: str, safety_profile: str, max_turns: int) -> dict[str, Any]:
    contract = render_contract()
    return {
        "schema_version": "device-agent/v1",
        "objective": str(objective or "Assess the connected device security posture.")[:2000],
        "safety_profile": safety_profile,
        "max_turns": max_turns,
        "turns": 0,
        "actions_used": 0,
        "scans_queued": 0,
        "next_evidence_ref": 1,
        "evidence": {},
        "notes": [],
        "events": [],
        "messages": [
            {"role": "system", "content": contract},
            {"role": "user", "content": str(objective or "Assess the connected device security posture.")[:2000]},
        ],
    }
