"""Text-contract tool-calling shim for keyless / no-native-tool planners.

Ported from T3MP3ST ``src/llm/index.ts`` — ``renderToolContract`` (~835),
``parseTextToolCalls`` (~881), ``balancedObjectSpans`` (~861),
``reframeWithAuthorizedContext`` (~1133), and ``isLikelyRefusal`` (~1112).

**Why this exists.** ShakerScan's default ``planner_mode:"agent"`` is *keyless* (the
coding-agent session is the planner) and ``call_ai_provider()`` is chat/JSON-only with no
``tools=`` / ``tool_choice`` path. A model with no native tool-calling otherwise returns
no tool calls and a ReAct loop takes its final-answer branch on turn 0. This shim closes
that gap the way T3MP3ST does: describe the tools in-prompt, have the model emit a fenced
```json {"tool_calls":[...]} ``` block, and parse it back with a ReDoS-safe,
string-aware, budget-capped scanner. The *same* shim drives both the keyless agent path
and any text/JSON provider (deepseek/grok), so there is one tool-calling contract.

Stdlib only — host-testable, flat-importable (``import agent_text_toolcalls``).
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterator, Optional

# --------------------------------------------------------------------------------------
# 1. Render the tool contract into the system/user prompt (renderToolContract).
# --------------------------------------------------------------------------------------


def render_tool_contract(tools: list[dict[str, Any]]) -> str:
    """Describe ``tools`` in-prompt and state the exact action contract.

    ``tools`` is a list of JSON-schema tool defs:
    ``{name, description, parameters:{type:'object', properties:{k:{type,...}}, required:[...]}}``.
    Required params are marked with ``*`` in the rendered signature.
    """
    if not tools:
        return ""
    lines: list[str] = [
        "\n## ARSENAL — tools the HARNESS runs for you "
        "(you REQUEST them, it EXECUTES and returns the output):"
    ]
    for t in tools:
        params = ((t.get("parameters") or {}).get("properties")) or {}
        required = set((t.get("parameters") or {}).get("required") or [])
        sig = ", ".join(
            f"{k}{'*' if k in required else ''}: {(v or {}).get('type', 'any')}"
            for k, v in params.items()
        )
        lines.append(f"- {t.get('name')}({sig}) — {t.get('description', '')}")
    lines += [
        "",
        "## ACTION CONTRACT — follow EXACTLY:",
        "• To run one or more tools, reply with ONLY this fenced block, nothing else:",
        "```json",
        '{"tool_calls":[{"name":"<tool>","arguments":{ ... }}]}',
        "```",
        "  The harness runs them (scope- and approval-gated) and returns the results as "
        "new messages; then you reason again.",
        "• When the attack surface is exhausted and you are DONE, reply with ONLY this "
        "block (no prose, no tool_calls):",
        "```json",
        '{"done":true,"findings":[{"title":"…","severity":"critical|high|medium|low|info",'
        '"family":"bola|mass_assignment|injection|…","predicate":"one verifiable predicate '
        'or null","route":"/exact/vulnerable/operation","method":"GET|POST|PUT|PATCH|DELETE",'
        '"details":"… cite the exact tool output/receipt that evidences it …",'
        '"evidence_refs":["resp_1"],"cvss":0.0,"cwe":"CWE-…","remediation":"…",'
        '"param":"only for injection","payload":"only for injection"}],'
        '"abstained":false}',
        "```",
        "  evidence_refs are the http_request result refs (e.g. resp_1) that PROVE the "
        "finding. That block is the ONLY finding channel recorded — prose is dropped. Emit "
        'findings:[] + "abstained":true if nothing real was proven.',
        "  For a DAST-VERIFIABLE finding — family xss / sqli / nosqli / ssrf / path_traversal / "
        "open_redirect / ssti / command_injection — ALSO set \"param\" (the vulnerable parameter) "
        "and \"payload\" (the exact value you injected): the server hands these to the deterministic "
        "prover (DOM-exec / DBMS / timing / file-content / Location-header / template-eval) to "
        "PROMOTE the lead; without them it stays a SUSPECTED signal. (family cors needs only the "
        "route — no param/payload.)",
        "• Never run these tools yourself — REQUEST them. Requesting is how you act.",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# 2. ReDoS-safe balanced-object scanner (balancedObjectSpans) + parser (parseTextToolCalls).
# --------------------------------------------------------------------------------------


def balanced_object_spans(text: str) -> Iterator[str]:
    """Yield each top-level ``{...}`` span. Linear, string-aware (braces inside a JSON
    string do not count), and globally bounded (``budget`` char-ops, ``spans`` cap) so it
    is safe on adversarial input. Port of ``balancedObjectSpans`` — replaces a greedy
    ``/\\{[\\s\\S]*\\}/``.
    """
    n = len(text)
    budget = 2_000_000
    spans = 0
    i = 0
    while i < n and spans < 200 and budget > 0:
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        in_str = False
        esc = False
        j = i
        while j < n and budget > 0:
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    spans += 1
                    yield text[i : j + 1]
                    i = j
                    break
            j += 1
            budget -= 1
        i += 1


def _coerce_args(a: Any) -> dict[str, Any]:
    if isinstance(a, str):
        try:
            v = json.loads(a)
        except Exception:
            return {}
        return v if isinstance(v, dict) else {}
    if isinstance(a, dict):
        return a
    return {}


def _build_calls(v: Any) -> list[dict[str, Any]]:
    if isinstance(v, list):
        arr: Any = v
    elif isinstance(v, dict):
        arr = (
            v.get("tool_calls")
            or v.get("toolCalls")
            or v.get("actions")
            or v.get("calls")
            or v.get("tools")
        )
        if not arr and isinstance(v.get("name"), str):
            arr = [v]  # a single un-wrapped call
    else:
        arr = None
    if not isinstance(arr, list):
        return []
    out: list[dict[str, Any]] = []
    for idx, o in enumerate(arr):
        if not isinstance(o, dict) or not isinstance(o.get("name"), str):
            continue
        args = o.get("arguments")
        if args is None:
            args = o.get("args")
        if args is None:
            args = o.get("parameters")
        if args is None:
            args = o.get("input")
        out.append(
            {"id": f"lc_{idx}", "name": o["name"], "arguments": _coerce_args(args)}
        )
    return out


_TRAILING_COMMA = re.compile(r",(\s*[}\]])")
_FENCE = re.compile(r"```(?:json|tool)?\s*([\s\S]*?)```")


def _try_parse(s: str) -> list[dict[str, Any]]:
    try:
        cleaned = _TRAILING_COMMA.sub(r"\1", s.strip())
        return _build_calls(json.loads(cleaned))
    except Exception:
        return []


def parse_text_tool_calls(text: str) -> Optional[list[dict[str, Any]]]:
    """Extract tool calls from a free-text model reply. Returns a list of
    ``{id, name, arguments}`` or ``None`` when the reply is a (prose) final answer.

    Extraction ladder (first that yields calls wins): (1) every fenced ```json|tool```
    block; (2) each balanced ``{...}`` span; (3) the whole reply as a top-level array.
    """
    if not text:
        return None
    for m in _FENCE.finditer(text):
        calls = _try_parse(m.group(1))
        if calls:
            return calls
    for span in balanced_object_spans(text):
        calls = _try_parse(span)
        if calls:
            return calls
    calls = _try_parse(text)
    return calls or None


_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "info"})


def _findings_from_obj(obj: dict[str, Any]) -> list[dict[str, Any]]:
    findings = obj.get("findings")
    if not isinstance(findings, list):
        return []
    out: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict) or not f.get("title"):
            continue
        sev = str(f.get("severity", "")).strip().lower()
        refs = f.get("evidence_refs")
        out.append(
            {
                "title": str(f["title"])[:200],
                "severity": sev if sev in _SEVERITIES else "info",
                "details": str(f.get("details") or f.get("evidence") or "")[:4000],
                "cvss": f.get("cvss") if isinstance(f.get("cvss"), (int, float)) else None,
                "cwe": (str(f.get("cwe"))[:16] if f.get("cwe") else None),
                "family": (str(f.get("family")).strip().lower()[:80] if f.get("family") else None),
                "predicate": (str(f.get("predicate")).strip()[:64] if f.get("predicate") else None),
                "route": (str(f.get("route")).strip()[:500] if f.get("route") else None),
                "method": (str(f.get("method")).strip().upper()[:12] if f.get("method") else None),
                "evidence_refs": (
                    [str(r)[:24] for r in refs if str(r).strip()][:8] if isinstance(refs, list) else []
                ),
                "remediation": (str(f.get("remediation"))[:1000] if f.get("remediation") else None),
                # Injection point for the deterministic DAST prover (xss/sqli/nosqli/ssrf). Kept only
                # so the SUSPECTED lead can be re-executed by the real prover; it never self-verifies.
                "param": (str(f.get("param")).strip()[:500] if f.get("param") else None),
                "payload": (str(f.get("payload"))[:4000] if f.get("payload") else None),
                # Model-asserted in the debrief — NO tool provenance yet. The gate downgrades these.
                "provenance": "model",
            }
        )
    return out


def parse_final_findings(text: str) -> list[dict[str, Any]]:
    """Parse the model's final debrief block. The agent is told to end with a fenced
    ```json {"findings":[…]} ``` block; this is the ONLY prose→data channel honored (no
    substring guessing). Port of ``parseFinalFindings`` (T:src/agent/index.ts:474)."""
    if not text:
        return []
    blocks = [m.group(1) for m in _FENCE.finditer(text)]
    for candidate in (list(reversed(blocks)) if blocks else [text]):
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start == -1 or end <= start:
            continue
        try:
            obj = json.loads(candidate[start : end + 1])
        except Exception:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("findings"), list):
            return _findings_from_obj(obj)
    return []


def interpret_assistant(reply: Any) -> dict[str, Any]:
    """Normalize one assistant turn (a parsed dict from a JSON-mode provider, or raw text
    from a keyless planner) into ``{tool_calls, findings, done, abstained}``. Tool calls =>
    keep acting; no tool calls => natural stop with the debrief findings (T3MP3ST)."""
    if isinstance(reply, dict):
        calls = _build_calls(reply)
        if calls:
            return {"tool_calls": calls, "findings": [], "done": False, "abstained": False}
        findings = _findings_from_obj(reply)
        return {"tool_calls": [], "findings": findings, "done": True, "abstained": bool(reply.get("abstained")) and not findings}
    text = str(reply or "")
    calls = parse_text_tool_calls(text)
    if calls:
        return {"tool_calls": calls, "findings": [], "done": False, "abstained": False}
    findings = parse_final_findings(text)
    # A text turn is TERMINAL only if it actually parsed a debrief structure (findings, or a
    # done/abstained JSON block). Unparseable prose is NOT terminal (done=False) so the caller
    # re-prompts instead of finalizing the hunt on one bad reply (audit N1).
    terminal = bool(findings) or has_terminal_json(text)
    return {
        "tool_calls": [],
        "findings": findings,
        "done": terminal,
        "abstained": (not findings) if terminal else False,
    }


def render_history_tool_request(names: list[str]) -> str:
    """Re-render a prior assistant tool request for replay as ``[requested tools: a, b]``
    rather than echoing its raw ```json``` block. Echoing the block would get re-parsed as
    a fresh live call and defeat termination. Port of ``renderCliMessage`` (T:...:926).
    """
    return f"[requested tools: {', '.join(names)}]" if names else "[requested tools]"


# --------------------------------------------------------------------------------------
# 3. Refusal DETECTION (not override).
#
# T3MP3ST also ships reframeWithAuthorizedContext — restate authorization and retry when the
# model refuses. We deliberately DO NOT port that override. The loop uses is_likely_refusal
# only to DETECT a refusal and then HONORS it (records it and stops), rather than routing
# around the model's own safety signal. Detecting a refusal is useful; auto-overriding it is
# a bypass we will not ship, even in an authorized engagement.
# --------------------------------------------------------------------------------------

_DECLINE = re.compile(
    r"\bi(?:'?m| am)?\b[^.]{0,20}\b(can'?t|cannot|can\s?not|won'?t|will\s+not|unable|"
    r"not\s+able|not\s+going\s+to)\b[^.]{0,40}\b(help|assist|provide|comply|continue|"
    r"proceed|do\s+that|do\s+this|with\s+that|with\s+this)\b",
    re.IGNORECASE,
)
_POLICY = re.compile(
    r"\b(against|violates?|contrary\s+to|not\s+aligned\s+with)\b[^.]{0,30}\b"
    r"(guidelines|policy|policies|terms|principles)\b",
    re.IGNORECASE,
)


_TERMINAL_KEYS = ("done", "abstained", "findings")


def has_terminal_json(text: Optional[str]) -> bool:
    """True if the reply STRUCTURALLY declares a terminal turn — a fenced/balanced JSON object
    carrying a ``done``/``abstained``/``findings`` key. This is how a genuine debrief is told
    apart from unparseable prose (which :func:`parse_final_findings` also yields no findings
    for). Structural, not keyword-based: prose that merely says "I'm done thinking" is NOT a
    terminal turn, so it is re-prompted rather than silently finalizing the hunt (audit N1)."""
    if not text:
        return False
    candidates: list[str] = [m.group(1) for m in _FENCE.finditer(text)]
    candidates.extend(balanced_object_spans(text))
    for span in candidates:
        start = span.find("{")
        end = span.rfind("}")
        if start == -1 or end <= start:
            continue
        try:
            obj = json.loads(_TRAILING_COMMA.sub(r"\1", span[start : end + 1]))
        except Exception:
            continue
        if isinstance(obj, dict) and any(k in obj for k in _TERMINAL_KEYS):
            return True
    return False


def is_likely_refusal(content: Optional[str], finish_reason: Optional[str] = None) -> bool:
    """Heuristic: a content-filter stop, or a short reply with a decline-verb bound to a
    help-class object, or explicit policy language. Long substantive output (>1200 chars)
    is treated as real work, not a refusal. Port of ``isLikelyRefusal``."""
    if finish_reason == "content_filter":
        return True
    c = (content or "").strip()
    if not c or len(c) > 1200:
        return False
    return bool(_DECLINE.search(c) or _POLICY.search(c))
