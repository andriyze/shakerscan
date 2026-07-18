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
import re
from typing import Any, Optional

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
# Includes run_tool (defined below); used by the loop's hallucinated-tool guard.
CALLABLE_TOOL_NAMES: frozenset[str] = AGENT_TOOL_NAMES | {"run_tool"}


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
            "Record a hypothesis, observation, or TODO to your durable scratchpad (a tool "
            "receipt) so it survives across steps and is visible to the operator. kind ∈ "
            f"{sorted(NOTE_KINDS)}. (A note is scratchpad only — it does not itself seed the "
            "lead board or create a finding.)"
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


# --------------------------------------------------------------------------------------
# run_tool — external scanners via hardcoded argv templates (port of T3MP3ST
# adapter-tools.ts ARG_TEMPLATES). The LLM picks tool + target ONLY; every flag is baked
# into build(); only regex-gated tunables are read by name. No arbitrary shell.
# --------------------------------------------------------------------------------------

_SEV_RE = re.compile(r"^(critical|high|medium|low|info)(,(critical|high|medium|low|info))*$")
_TAGS_RE = re.compile(r"^[a-z0-9][a-z0-9,\-]{0,80}$")


def _tmpl_httpx(url: str, opts: dict[str, Any]) -> list[str]:
    # Passive fingerprint: status, title, tech, redirect chain. No tunables.
    return ["-u", url, "-status-code", "-title", "-tech-detect", "-web-server",
            "-json", "-silent", "-timeout", "10", "-no-color"]


def _tmpl_nuclei(url: str, opts: dict[str, Any]) -> list[str]:
    # Bounded template scan. Severity + tags are the ONLY tunables, both regex-gated.
    severity = str(opts.get("severity") or "").strip().lower()
    if not _SEV_RE.match(severity):
        severity = "high,critical"
    args = ["-target", url, "-severity", severity, "-silent", "-jsonl",
            "-timeout", "8", "-retries", "1", "-no-color", "-disable-update-check"]
    tags = str(opts.get("tags") or "").strip().lower()
    if _TAGS_RE.match(tags):
        args += ["-tags", tags]
    return args


# {tool: {binary, target_param, risk, default_timeout_ms, build}}. Only httpx (passive)
# and a bounded nuclei are loop-safe; slower/intrusive scanners stay off the sync loop.
SCANNER_ARG_TEMPLATES: dict[str, dict[str, Any]] = {
    "httpx": {"binary": "httpx", "risk": "read_only", "default_timeout_ms": 30_000, "build": _tmpl_httpx,
              "desc": "passive HTTP fingerprint (status, title, tech, server) of a same-origin URL"},
    "nuclei": {"binary": "nuclei", "risk": "active", "default_timeout_ms": 90_000, "build": _tmpl_nuclei,
               "desc": "bounded Nuclei template scan (default high,critical) of a same-origin URL; options {severity,tags}"},
}
RUN_TOOL_NAMES: frozenset[str] = frozenset(SCANNER_ARG_TEMPLATES)

RUN_TOOL_SCHEMA: dict[str, Any] = {
    "name": "run_tool",
    "risk": "active",
    "description": (
        "Run a bounded external scanner against a SAME-ORIGIN URL. You pick tool + target "
        f"only; all flags are fixed. Tools: {sorted(RUN_TOOL_NAMES)} — httpx is a passive "
        "fingerprint; nuclei runs bounded templates (options {severity,tags}). Returns the "
        "scanner's JSON/JSONL output (bounded)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "httpx | nuclei"},
            "target": {"type": "string", "description": "same-origin absolute path (/) or URL to scan"},
            "options": {"type": "object", "description": "nuclei: {severity:'high,critical', tags:'cve,exposure'}"},
        },
        "required": ["name", "target"],
    },
}


def tool_schemas(*, include_run_tool: bool = True) -> list[dict[str, Any]]:
    """Return the callable tool schemas (a copy). ``include_run_tool`` adds the
    argv-template scanner tool (slice 5)."""
    schemas = [dict(schema) for schema in AGENT_TOOL_SCHEMAS]
    if include_run_tool:
        schemas.append(dict(RUN_TOOL_SCHEMA))
    return schemas


def coerce_run_tool(args: dict[str, Any]) -> tuple[str, Any, dict[str, Any]]:
    name = str(args.get("name") or "").strip().lower()
    if name not in RUN_TOOL_NAMES:
        raise AgentToolError(f"unknown run_tool:{name} (allowed: {sorted(RUN_TOOL_NAMES)})")
    options = args.get("options") if isinstance(args.get("options"), dict) else {}
    return name, args.get("target"), options


def build_scanner_argv(name: str, url: str, options: dict[str, Any]) -> tuple[str, list[str], int]:
    """Return (binary, argv, timeout_ms) for a scanner run. The binary name is NOT in argv
    (passed separately to the subprocess); every flag is hardcoded in the template."""
    template = SCANNER_ARG_TEMPLATES[name]
    return template["binary"], template["build"](url, options or {}), int(template["default_timeout_ms"])


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


# --------------------------------------------------------------------------------------
# SUSPECTED -> VERIFIED bridge (Gap B): derive the concrete targets for a BOLA family_proof
# verification workflow from a suspected finding's route + each principal's captured object
# references. Pure/host-testable; the workflow assembly + dispatch (the moat) live in api.py.
# --------------------------------------------------------------------------------------

_ID_SEGMENT = re.compile(r"^(\d+|\{[^}]+\}|[0-9a-fA-F-]{8,})$")


def _bola_collection_and_segment(route: Any) -> tuple[Optional[str], str]:
    """Split a finding route into its collection route + the collection's last path segment,
    dropping a trailing object-id segment (numeric, uuid-ish, or ``{id}``)."""
    path = str(route or "").split("?", 1)[0].rstrip("/")
    parts = [p for p in path.split("/") if p]
    if not parts:
        return None, ""
    collection_parts = parts[:-1] if (len(parts) >= 2 and _ID_SEGMENT.match(parts[-1])) else parts
    if not collection_parts:
        return None, ""
    return "/" + "/".join(collection_parts), collection_parts[-1].lower()


def _pick_object_ref(refs: Any, segment: str) -> tuple[Optional[str], Optional[str]]:
    """Choose a principal's own object reference for ``segment`` from its captured references.
    Returns ``(key, value)`` — the ORIGINAL captured-ref key (needed to bind a principal_variable
    that resolves server-side, marking it a managed reference) and its value."""
    if not isinstance(refs, dict) or not refs:
        return None, None
    lower = {str(k).lower(): (k, v) for k, v in refs.items()}
    for candidate in (f"{segment}_id", f"{segment}id", segment, "object_id", "id"):
        pair = lower.get(candidate)
        if pair is not None and str(pair[1]).strip():
            return str(pair[0]), str(pair[1]).strip()
    if len(refs) == 1:  # a single captured ref is unambiguous
        key, value = next(iter(refs.items()))
        text = str(value).strip()
        return (str(key), text) if text else (None, None)
    return None, None


def derive_bola_verification_targets(
    finding_route: Any, user1_refs: Any, user2_refs: Any
) -> Optional[dict[str, Any]]:
    """Return targets for a BOLA verification workflow, or ``None`` when the inputs cannot support
    a SOUND proof:
    ``{collection, owner_object_id, attacker_object_id, owner_ref_key, attacker_ref_key, ref_segment}``.

    The ``*_ref_key`` fields name each principal's captured-ref key so the workflow can bind a
    ``principal_variable`` that resolves the id server-side (a managed reference) — the only form the
    ownership predicate accepts. Requires two *distinct* owned object references (owner=user1,
    attacker=user2); equal or missing refs yield None (the finding stays SUSPECTED)."""
    collection, segment = _bola_collection_and_segment(finding_route)
    if not collection or collection == "/":
        return None
    owner_key, owner_value = _pick_object_ref(user1_refs, segment)
    attacker_key, attacker_value = _pick_object_ref(user2_refs, segment)
    if not owner_value or not attacker_value or owner_value == attacker_value:
        return None
    return {
        "collection": collection,
        "owner_object_id": owner_value,
        "attacker_object_id": attacker_value,
        "owner_ref_key": owner_key,
        "attacker_ref_key": attacker_key,
        "ref_segment": segment,
    }
