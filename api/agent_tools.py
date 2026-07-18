"""Agent tool contracts + guards for the autonomous ReAct loop.

The four "try it" tools the LLM can call (docs/autonomous-agent-architecture.md §4).
This module holds the **function-call schemas** (consumed by the text-contract renderer
in :mod:`agent_text_toolcalls`) and the **pure guards** — same-origin path validation,
request-header allowlisting (so the model can never inject an auth header — real auth
comes only from a server-resolved ``as_principal``), method classification, and result
shaping. The async execution (httpx, DB, tool_receipts, principal resolution) lives in
api.py, which owns those dependencies; this layer stays dependency-free and host-testable.

Containment is enforced in code, before every handler (borrow T3MP3ST ``execute()``):
scope (same-origin) and approval (write methods are gated) are checked server-side, never
left to the model.
"""
from __future__ import annotations

import json
from typing import Any

# Methods the model may request. Reads are read-only; writes are credential/active-gated.
READ_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})
WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
ALL_METHODS: frozenset[str] = READ_METHODS | WRITE_METHODS

# Request headers the model may never set. Auth/identity headers come ONLY from a
# server-resolved principal (as_principal); a Host/CL/hop-by-hop header would break
# same-origin or smuggle. Anything matching a sensitive substring is also dropped.
_FORBIDDEN_HEADERS: frozenset[str] = frozenset(
    {
        "authorization", "cookie", "host", "content-length", "connection",
        "transfer-encoding", "proxy-authorization", "x-forwarded-for",
        "x-forwarded-host", "x-real-ip", "forwarded",
    }
)
_SENSITIVE_HEADER_SUBSTR: tuple[str, ...] = (
    "token", "secret", "auth", "session", "cookie", "password", "api-key", "apikey",
    "credential", "bearer",
)

# query_kb read-only surfaces (each maps to a bounded SELECT in api.py).
QUERY_KB_KINDS: frozenset[str] = frozenset(
    {
        "endpoints", "findings", "hypotheses", "principals",
        "graph_nodes", "graph_edges", "tool_receipts", "notes",
    }
)

NOTE_KINDS: frozenset[str] = frozenset({"hypothesis", "observation", "todo"})

AGENT_TOOL_NAMES: frozenset[str] = frozenset({"http_request", "query_kb", "diff", "note"})


# --------------------------------------------------------------------------------------
# Function-call schemas (shape expected by render_tool_contract / native tool APIs).
# The optional ``risk`` field is used by the server gate, ignored by the renderer.
# --------------------------------------------------------------------------------------

AGENT_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "http_request",
        "risk": "active",  # elevated to gated when the method is a write
        "description": (
            "Issue ONE same-origin HTTP request to the target and get a structured "
            "response summary (status, headers, body sample, json keys, sha256, timing). "
            "Set as_principal to a configured principal slot (e.g. 'user1','user2','admin') "
            "to send it authenticated AS that server-managed identity — you never see the "
            "credential. Replay the same request as different principals to test access "
            "control. Reads (GET/HEAD/OPTIONS) run freely; writes (POST/PUT/PATCH/DELETE) "
            "are approval-gated. Returns a 'ref' you can pass to diff."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE"},
                "path": {"type": "string", "description": "absolute same-origin path, must start with / (e.g. /rest/basket/1)"},
                "query": {"type": "object", "description": "optional query params {k:v}"},
                "json_body": {"type": "object", "description": "optional JSON request body"},
                "form_body": {"type": "object", "description": "optional form-encoded body"},
                "headers": {"type": "object", "description": "optional benign request headers (auth headers are forbidden — use as_principal)"},
                "as_principal": {"type": "string", "description": "optional principal slot to authenticate as; omit for anonymous"},
            },
            "required": ["method", "path"],
        },
    },
    {
        "name": "query_kb",
        "risk": "read_only",
        "description": (
            "Read the ShakerScan knowledge base for this target (read-only): "
            f"kind ∈ {sorted(QUERY_KB_KINDS)}. Use 'findings' to see what is ALREADY known "
            "(so you hunt NET-NEW), 'endpoints' for the live attack surface, 'principals' "
            "for available auth identities, 'graph_*' for the application graph, 'notes' for "
            "your own scratchpad."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "description": "one of the allowed kinds"},
                "filter": {"type": "object", "description": "optional {method,path_contains,family,severity,limit}"},
            },
            "required": ["kind"],
        },
    },
    {
        "name": "diff",
        "risk": "read_only",
        "description": (
            "Compare two HTTP response summaries and get a structured differential "
            "(status/length/body change, json keys added/removed, selected-value and "
            "header changes, timing delta). Pass refs returned by http_request (e.g. "
            "'resp_1') or inline summary objects. Use it to prove BOLA (two principals get "
            "the same protected body -> comparison_equivalent) or a persisted state change."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "left": {"type": "string", "description": "ref (e.g. 'resp_1') or inline response summary"},
                "right": {"type": "string", "description": "ref (e.g. 'resp_2') or inline response summary"},
            },
            "required": ["left", "right"],
        },
    },
    {
        "name": "note",
        "risk": "read_only",
        "description": (
            "Record a hypothesis, observation, or TODO to your durable scratchpad so it "
            "survives across steps and is visible to the operator. kind ∈ "
            f"{sorted(NOTE_KINDS)}. A 'hypothesis' note also seeds the lead board."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "description": "hypothesis|observation|todo"},
                "title": {"type": "string", "description": "short title"},
                "detail": {"type": "string", "description": "the note body"},
                "family": {"type": "string", "description": "optional vuln family for a hypothesis (bola,sqli,mass_assignment,...)"},
                "severity": {"type": "string", "description": "optional guessed severity"},
            },
            "required": ["kind", "title"],
        },
    },
]


def tool_schemas(*, include_run_tool: bool = False) -> list[dict[str, Any]]:
    """Return the callable tool schemas (a copy). ``include_run_tool`` is a forward hook
    for the argv-template scanner tool (slice 5)."""
    return [dict(schema) for schema in AGENT_TOOL_SCHEMAS]


# --------------------------------------------------------------------------------------
# Pure guards (host-testable).
# --------------------------------------------------------------------------------------


class AgentToolError(ValueError):
    """Raised by a guard when a tool argument is unsafe or malformed. The loop feeds the
    message back to the model (error-recovery) rather than crashing."""


def coerce_method(method: Any) -> str:
    value = str(method or "GET").strip().upper()
    if value not in ALL_METHODS:
        raise AgentToolError(f"unsupported_method:{value} (allowed: {sorted(ALL_METHODS)})")
    return value


def is_write_method(method: str) -> bool:
    return method.strip().upper() in WRITE_METHODS


def validate_same_origin_path(path: Any) -> str:
    """A same-origin absolute path: starts with a single '/', no control chars, bounded.
    Rejects protocol-relative ('//host') and absolute URLs (SSRF)."""
    text = str(path or "")
    if not text.startswith("/") or text.startswith("//"):
        raise AgentToolError("path must be an absolute same-origin path starting with a single '/'")
    if len(text.encode("utf-8")) > 4000:
        raise AgentToolError("path exceeds size limit")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise AgentToolError("path contains control characters")
    return text


def filter_request_headers(headers: Any) -> dict[str, str]:
    """Drop any header the model must not set (auth/identity/hop-by-hop/sensitive). Real
    auth comes only from a server-resolved principal. Returns the surviving benign headers."""
    out: dict[str, str] = {}
    if not isinstance(headers, dict):
        return out
    for name, value in headers.items():
        lname = str(name).strip().lower()
        if not lname or lname in _FORBIDDEN_HEADERS:
            continue
        if any(sub in lname for sub in _SENSITIVE_HEADER_SUBSTR):
            continue
        sval = str(value)
        if not lname.isascii() or not sval.isascii():
            continue
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name + sval):
            continue
        if len(sval.encode("utf-8")) > 2000:
            continue
        out[str(name)] = sval
    return out


def normalize_principal_slot(value: Any) -> str:
    """A principal slot the model may request. 'anonymous' (or empty) means no auth."""
    slot = str(value or "").strip().lower()
    if slot in ("", "anonymous", "anon", "none"):
        return "anonymous"
    return slot


def coerce_query_kb(args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    kind = str(args.get("kind") or "").strip().lower()
    if kind not in QUERY_KB_KINDS:
        raise AgentToolError(f"unknown query_kb kind:{kind} (allowed: {sorted(QUERY_KB_KINDS)})")
    flt = args.get("filter") if isinstance(args.get("filter"), dict) else {}
    return kind, flt


def coerce_note(args: dict[str, Any]) -> dict[str, Any]:
    kind = str(args.get("kind") or "observation").strip().lower()
    if kind not in NOTE_KINDS:
        raise AgentToolError(f"unknown note kind:{kind} (allowed: {sorted(NOTE_KINDS)})")
    title = str(args.get("title") or "").strip()
    if not title:
        raise AgentToolError("note requires a non-empty title")
    return {
        "kind": kind,
        "title": title[:200],
        "detail": str(args.get("detail") or "")[:4000],
        "family": (str(args.get("family")).strip().lower()[:80] if args.get("family") else None),
        "severity": (str(args.get("severity")).strip().lower()[:16] if args.get("severity") else None),
    }


def http_evidence_item(request_view: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    """Shape an http_request result as a tool-provenance evidence item for the gate.
    ``type='response'`` is one of TOOL_EVIDENCE_KINDS, so this carries real provenance."""
    try:
        content = json.dumps({"request": request_view, "response": summary}, default=str)[:6000]
    except Exception:
        content = str(summary)[:6000]
    return {"type": "response", "content": content}
