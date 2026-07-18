"""ReAct loop core for the autonomous agent (ported from T3MP3ST src/agent/index.ts).

Pure orchestration only: the system-prompt discipline (borrowing the CTF harness cadence
RECON→PLAN→EXECUTE+TRACK→EVIDENCE→SELF-CRITIQUE plus the anti-give-up floor), the four
anti-stall steering messages, HEAD+TAIL tool-output capping, and the reply-interpretation
helpers live here. The async tool execution, LLM calls, and durable persistence live in
api.py (which owns those deps); this module stays dependency-free and host-testable.
"""
from __future__ import annotations

import json
from typing import Any

MAX_TOOL_OUTPUT_CHARS = 4000

# The closed server-derived predicate vocabulary the model may claim for a finding (it
# only *picks* one; the server derives the verdict — the zero-FP invariant).
VERIFIABLE_PREDICATES = (
    "status_differential",
    "cross_principal_equivalent",
    "sensitive_value_present",
    "state_change_persisted",
    "invariant_violated",
)


def build_system_prompt(rendered_tool_contract: str, *, max_iterations: int) -> str:
    return "\n".join(
        [
            "You are an autonomous application-security agent hunting for REAL, NET-NEW "
            "vulnerabilities in an AUTHORIZED, in-scope target under a human-approved "
            "engagement (defensive / responsible-disclosure). You act ONLY by requesting "
            "tools; the harness executes them and returns the output. Never fabricate a result.",
            "",
            "METHOD — follow this cadence, do not skip a step:",
            "1. RECON — use query_kb (endpoints, findings, principals, graph) to learn the "
            "surface AND what is already known. Do NOT re-report known findings; hunt NET-NEW.",
            "2. PLAN — pick ONE concrete hypothesis and state, up front, the FALSIFIER that "
            "would kill it. Favour high-value classes the surface enables: broken access "
            "control (BOLA/IDOR/BFLA), business-logic abuse, mass assignment, auth/JWT flaws, "
            "injection, SSRF, sensitive-data exposure.",
            "3. EXECUTE + TRACK — probe with http_request. To test access control, replay the "
            "SAME request as different principals (as_principal) and diff the responses. Keep a "
            "CONFIRMED / REFUTED / OPEN ledger in your reasoning. If 3 variants of one approach "
            "fail, SWITCH to a different vulnerability class.",
            "4. EVIDENCE — a finding counts ONLY if a tool result proves it (a real "
            "request/response, a diff, a status differential). Cite the exact tool output and, "
            "when you report, name which server predicate could verify it: "
            + ", ".join(VERIFIABLE_PREDICATES)
            + ".",
            "5. SELF-CRITIQUE — before reporting, ask: could this be a false positive? Did I "
            "actually OBSERVE the exploit, or only infer it? Drop anything you did not observe.",
            "",
            f"PERSISTENCE: you have up to {max_iterations} tool-using iterations. Do NOT give up "
            "early — if one vector is dead, pivot to a genuinely different one. Finish only when "
            "you have proven something or genuinely exhausted the surface.",
            "",
            rendered_tool_contract,
        ]
    )


def build_user_message(objective: str, context_text: str) -> str:
    obj = (objective or "").strip() or (
        "Find the highest-value net-new vulnerability you can PROVE on this target."
    )
    return (
        f"## OBJECTIVE\n{obj}\n\n"
        f"## TARGET CONTEXT (from the ShakerScan knowledge base)\n{context_text}\n\n"
        "Begin with RECON, then hunt. Request your first tool(s) now as a "
        '```json {"tool_calls":[...]} ``` block.'
    )


def dup_signature(name: str, arguments: Any) -> str:
    try:
        return f"{name}:{json.dumps(arguments or {}, sort_keys=True, default=str)}"
    except Exception:
        return f"{name}:{arguments}"


def dup_steer_message(name: str, prior: str) -> str:
    return (
        f"Duplicate call — you already ran {name} with these exact arguments. "
        f"Prior result: {prior}. Do NOT repeat it — change the arguments, pick a different "
        "tool, or move to your final debrief."
    )


def no_progress_message(n: int) -> str:
    return (
        f"[System: {n} iterations with no new evidence. Either pursue a GENUINELY different "
        "vector/tool/argument now, or produce your final debrief if the surface is exhausted. "
        "Do not keep repeating the current approach.]"
    )


def hallucinated_tool_message(name: str, available: list[str]) -> str:
    return (
        f'Tool "{name}" is not available. Callable tools: {", ".join(available)}. '
        "Use one of these EXACT names — do not invent tools."
    )


def forced_debrief_message() -> str:
    """The final-summary prompt sent when the iteration cap is hit without a debrief, so the
    model's analysis is captured, not lost (T3MP3ST src/agent/index.ts:264-283). Shared by the
    in-process (configured_ai) loop and the turn-based keyless driver."""
    return (
        "You have reached the maximum number of steps. Reply NOW with ONLY your final "
        'debrief block: {"done":true,"findings":[...],"abstained":bool}. Include only '
        "findings you PROVED with tool evidence, and cite their evidence_refs."
    )


def classify_tool_call(
    name: str, arguments: Any, seen_signatures: Any, callable_names: Any
) -> tuple[str, str]:
    """Pure pre-execution classification of one requested tool call, shared by both loop
    drivers so dedup/hallucination handling can never diverge between them.

    Returns ``(kind, signature)`` where kind is ``"hallucinated"`` (name not callable — feed
    the tool list back), ``"duplicate"`` (this exact name+args already ran — feed the steer
    back), or ``"execute"`` (run it). ``seen_signatures`` is any container supporting ``in``
    keyed by :func:`dup_signature`.
    """
    signature = dup_signature(name, arguments)
    if name not in callable_names:
        return "hallucinated", signature
    if signature in seen_signatures:
        return "duplicate", signature
    return "execute", signature


def format_tool_result(result: Any, *, max_chars: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Serialize a tool result, capped HEAD+TAIL (flags/status often land at the end)."""
    try:
        text = json.dumps(result, default=str, ensure_ascii=False)
    except Exception:
        text = str(result)
    if len(text) <= max_chars:
        return text
    head = int(max_chars * 0.7)
    tail = max_chars - head
    return text[:head] + f"\n… (truncated {len(text) - max_chars} chars) …\n" + text[-tail:]
