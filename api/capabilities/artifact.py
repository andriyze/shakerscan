"""Bounded, target-pinned client-artifact inspection for Hunt.

The planner receives small redacted windows or structured analysis, never an entire bundle and
never a discovered credential value. Network execution remains delegated to the canonical HTTP
executor so scope, DNS pinning, redirects, archiving, and cancellation keep one owner.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from typing import Any, Callable, Mapping

from capabilities.http import WorkerPrivateHTTPResponse, execute_bound_http_request
from runtime.models import TargetBinding

try:
    from redaction import redact_text as _shared_redact_text
except ModuleNotFoundError:
    from scanner.redaction import redact_text as _shared_redact_text

try:
    from runtime.archive_body_masking import (
        MASK, WithheldValues, active_withheld_values, collecting_withheld_values,
        holds_withheld_material, mask_body_text, mask_sql_values, scrub_known_values,
    )
except ModuleNotFoundError:
    from api.runtime.archive_body_masking import (
        MASK, WithheldValues, active_withheld_values, collecting_withheld_values,
        holds_withheld_material, mask_body_text, mask_sql_values, scrub_known_values,
    )
try:
    from capabilities.secret_material import keyed_body_digest
except ModuleNotFoundError:
    from api.capabilities.secret_material import keyed_body_digest


MAX_INSPECT_BYTES = 16_384
MAX_JAVASCRIPT_BYTES = 262_144
MAX_PUBLIC_TEXT = 4_096
_JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])")
_ROUTE_RE = re.compile(
    r"[\"']((?:/api|/rest|/graphql|/rpc|/auth|/admin)(?:/[A-Za-z0-9._~!$&'()*+,;=:@%{}$-]*)*)[\"']"
)
_SUPABASE_RE = re.compile(r"https://[a-z0-9-]{3,80}\.supabase\.co", re.I)
_SOURCE_MAP_RE = re.compile(r"sourceMappingURL\s*=\s*([^\s*]+)")


def _b64_json(segment: str) -> dict[str, Any] | None:
    try:
        padding = "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(segment + padding)
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return None
    return dict(value) if isinstance(value, Mapping) else None


def _bounded_claim(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return str(value)[:300] if isinstance(value, str) else value
    if isinstance(value, list):
        return [_bounded_claim(item) for item in value[:20]]
    return None


def analyze_javascript_bytes(body: bytes) -> dict[str, Any]:
    """Return high-value static signals without exposing token material."""
    text = body.decode("utf-8", errors="replace")
    jwt_observations: list[dict[str, Any]] = []
    seen_tokens: set[str] = set()
    for match in _JWT_RE.finditer(text):
        token = match.group(1)
        digest = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
        if digest in seen_tokens:
            continue
        seen_tokens.add(digest)
        segments = token.split(".")
        header = _b64_json(segments[0]) or {}
        payload = _b64_json(segments[1]) or {}
        selected_claims = {
            key: _bounded_claim(payload.get(key))
            for key in ("iss", "aud", "role", "exp", "iat", "nbf")
            if key in payload
        }
        role = str(payload.get("role") or "").strip().lower()
        classification = (
            "public_anon" if role in {"anon", "anonymous"}
            else "privileged" if role in {"service_role", "service", "admin", "administrator"}
            else "unknown"
        )
        collector = active_withheld_values()
        reference: dict[str, Any] = {}
        if collector is not None:
            marker = collector.marker(token)
            if marker.startswith("[withheld:"):
                reference = {"withheld_ref": collector.reference(int(marker[10:-1])), "marker": marker}
        jwt_observations.append({
            **reference,
            "token_sha256": digest,
            "offset": match.start(),
            "algorithm": str(header.get("alg") or "")[:80] or None,
            "token_type": str(header.get("typ") or "")[:80] or None,
            "claims": selected_claims,
            "classification": classification,
            "token_value_visible": False,
        })
        if len(jwt_observations) >= 20:
            break

    routes = sorted(set(_ROUTE_RE.findall(text)))[:200]
    source_maps = sorted({
        str(_shared_redact_text(value))
        for value in _SOURCE_MAP_RE.findall(text)
    })[:20]
    supabase_origins = sorted(set(_SUPABASE_RE.findall(text)))[:20]
    sink_names = (
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
        "new Function", "postMessage", "localStorage", "sessionStorage",
    )
    sinks = [name.rstrip("(") for name in sink_names if name in text]
    withheld = bool(jwt_observations) or holds_withheld_material(text)
    return {
        "schema_version": "javascript-static-analysis/v1",
        "bytes_analyzed": len(body),
        "content_sha256": keyed_body_digest(body) if withheld else hashlib.sha256(body).hexdigest(),
        "routes": routes,
        "jwt_observations": jwt_observations,
        "supabase_origins": supabase_origins,
        "source_maps": source_maps,
        "client_sink_signals": sinks,
    }


def _jwt_replacement(match: re.Match[str]) -> str:
    """Inside a Hunt worker a found JWT is a usable reference; elsewhere a bare hash."""
    token = match.group(1)
    collector = active_withheld_values()
    if collector is not None:
        return collector.marker(token)
    return f"<jwt:sha256:{hashlib.sha256(token.encode()).hexdigest()[:16]}>"


# A window read at an offset is masked with up to this much of what precedes it: a dump's column
# names, a ``DB_PASSWORD=`` label or a ``value="`` cut just before the window (N56 review).
CONTEXT_BYTES = 65_536
# A SQL dump keeps its CREATE TABLE (the column names that say which value is a password) far
# from later rows: a dump-like resource gets up to this much context, still in one request.
SQL_CONTEXT_BYTES = 1_048_576
_SQL_DUMP_PATH_RE = re.compile(
    r"(?i)(?:\.(?:sql|dump|mysql|pgsql|psql|bak)(?:\.txt)?$|(?:^|/)[^/]*(?:dump|backup)[^/]*$)"
)
_CONTEXT_COLLECTOR_ID = "00000000-0000-4000-8000-000000000000"


def _resource_path(path: str) -> str:
    return urllib.parse.urlsplit(path).path or path


def _context_bytes(path: str) -> int:
    collector = active_withheld_values()
    resource = _resource_path(path)
    if _SQL_DUMP_PATH_RE.search(resource) or (collector is not None and collector.sql_tables.get(resource)):
        return SQL_CONTEXT_BYTES
    return CONTEXT_BYTES


# The values a window can show in part sit just before it; only those are collected.
_NEAR_CONTEXT_BYTES = 65_536


def _context_secrets(context: bytes, body: bytes) -> list[str]:
    """Every value the masking withholds near the window, read with the context before it.

    The whole span is read first for its column names (kept on the action's collector for later
    windows of the dump); the values are then collected from the near context and the window,
    whose rows are parsed with those columns."""
    collector = active_withheld_values()
    shared = (collector.sql_tables, collector.sql_path) if collector is not None else ({}, "context")
    if len(context) > _NEAR_CONTEXT_BYTES:
        learner = WithheldValues(_CONTEXT_COLLECTOR_ID, limit=0)
        learner.sql_tables, learner.sql_path = shared
        with collecting_withheld_values(learner):
            mask_sql_values(context.decode("utf-8", errors="replace"))
    probe = WithheldValues(_CONTEXT_COLLECTOR_ID, limit=16_384)
    probe.sql_tables, probe.sql_path = shared
    with collecting_withheld_values(probe):
        mask_body_text((context[-_NEAR_CONTEXT_BYTES:] + body).decode("utf-8", errors="replace"))
    return probe.values


def _masked_window_text(body: bytes, context: bytes = b"") -> str:
    """The whole window, masked before anything is cut from it.

    The body masking every masked archive view applies (N56): SQL dump rows, markup key/value
    pairs, phpinfo-style table cells, assignments and provider formats. Inside a Hunt worker the
    withheld values become ``[withheld:n]`` markers the planner can bind by reference. With
    ``context`` (the bytes before an offset window) the secrets of the whole span are withheld
    from the window too, whole or cut by its start.
    """
    text = body.decode("utf-8", errors="replace")
    known = _context_secrets(context, body) if context else []
    collector = active_withheld_values()
    if known and collector is not None:
        collector.bind_known(known, found=True)
    elif known:
        text = scrub_known_values(text, known, MASK)
    text = mask_body_text(text)
    text = _JWT_RE.sub(_jwt_replacement, text)
    text = re.sub(r"(?i)(bearer\s+)(?!\[withheld:)[a-z0-9._~+/=-]+", r"\1<redacted>", text)
    return str(_shared_redact_text(text))


def _redacted_text_sample(body: bytes) -> str:
    return _masked_window_text(body)[:MAX_PUBLIC_TEXT]


_CONTENT_RANGE_TOTAL = re.compile(r"\s*bytes\s+\d+-\d+/(\d+)\s*", re.IGNORECASE)
_CONTENT_RANGE_START = re.compile(r"\s*bytes\s+(\d+)-", re.IGNORECASE)


def _range_start(private: WorkerPrivateHTTPResponse) -> int | None:
    match = _CONTENT_RANGE_START.match(private.headers().get("content-range") or "")
    return int(match.group(1)) if match else None


def _resource_bytes(private: WorkerPrivateHTTPResponse) -> int | None:
    """The artifact's full size, when the response establishes it."""
    headers = private.headers()
    if private.status_code == 206:
        match = _CONTENT_RANGE_TOTAL.fullmatch(headers.get("content-range") or "")
        return int(match.group(1)) if match else None
    if not private.body_truncated:
        return len(private.body())
    length = str(headers.get("content-length") or "").strip()
    return int(length) if length.isdigit() and int(length) > len(private.body()) else None


async def _fetch_artifact(
    target_url: str,
    *,
    path: str,
    target: TargetBinding,
    offset: int,
    length: int,
    transaction_recorder: Callable[[dict[str, Any]], None] | None,
) -> tuple[dict[str, Any], WorkerPrivateHTTPResponse | None]:
    captured: list[WorkerPrivateHTTPResponse] = []
    end = offset + length - 1
    result = await execute_bound_http_request(
        target_url,
        {
            "method": "GET",
            "path": path,
            "headers": {"Range": f"bytes={offset}-{end}"},
            "follow_redirects": True,
        },
        target=target,
        allow_write=False,
        transaction_recorder=transaction_recorder,
        timeout_seconds=30,
        allow_bound_origin_redirects=True,
        private_response_sink=captured.append,
        response_body_limit=max(length, MAX_PUBLIC_TEXT),
    )
    return result, captured[-1] if captured else None


async def inspect_target_artifact(
    target_url: str,
    args: Mapping[str, Any],
    *,
    target: TargetBinding,
    transaction_recorder: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    path = str(args.get("path") or "")
    offset = max(0, int(args.get("offset") or 0))
    length = max(1, min(MAX_INSPECT_BYTES, int(args.get("max_bytes") or MAX_PUBLIC_TEXT)))
    # One range from up to CONTEXT_BYTES before the window: the context masks, the window shows.
    collector = active_withheld_values()
    if collector is not None:
        collector.sql_path = _resource_path(path)
    context_start = max(0, offset - _context_bytes(path))
    lead = offset - context_start
    result, private = await _fetch_artifact(
        target_url, path=path, target=target, offset=context_start, length=lead + length,
        transaction_recorder=transaction_recorder,
    )
    if not result.get("ok") or private is None:
        return {
            "ok": False,
            "status": "failed",
            "error": str(result.get("error") or "artifact_response_unavailable"),
            "budget_consumed": {"http_requests": 1, "tool_wall_seconds": 1},
        }
    if private.status_code not in {200, 206}:
        return {
            "ok": False,
            "status": "failed",
            "error": f"artifact_http_status:{private.status_code}",
            "budget_consumed": {"http_requests": 1, "tool_wall_seconds": 1},
        }
    if offset and private.status_code != 206:
        return {
            "ok": False,
            "status": "blocked",
            "error": "artifact_range_not_supported",
            "budget_consumed": {"http_requests": 1, "tool_wall_seconds": 1},
        }
    if context_start and _range_start(private) != context_start:
        return {
            "ok": False,
            "status": "blocked",
            "error": "artifact_range_mismatch",
            "budget_consumed": {"http_requests": 1, "tool_wall_seconds": 1},
        }
    context = private.body()[:lead]
    received = private.body()[lead:]
    body = received[:length]
    resource_bytes = _resource_bytes(private)
    terms = [str(term)[:100] for term in args.get("search_terms") or [] if str(term)][:10]
    raw_text = body.decode("utf-8", errors="replace")
    masked_text = _masked_window_text(body, context)
    text_sample = masked_text[:MAX_PUBLIC_TEXT]
    # Counted over the masked window: a count over raw bytes recovers a withheld value one
    # guessed character at a time.
    lowered = masked_text.lower()
    withheld = masked_text != raw_text
    observation = {
        "kind": "artifact_observation",
        "path": path,
        "offset": offset,
        "returned_bytes": len(body),
        # The resource's full size when the response states it (Content-Range total, or a
        # complete 200 body); None when unknown. A window that may not reach the end of the
        # resource is truncated, so a zero search count is not evidence of absence.
        "resource_bytes": resource_bytes,
        "window_truncated": (
            offset + len(body) < resource_bytes if resource_bytes is not None
            else private.body_truncated or len(received) > length or len(body) >= length
        ),
        # search_matches counts the returned window only, never the rest of the resource.
        "search_scope": "window",
        # A plain digest of a window that held a secret is an offline guessing oracle for it.
        "window_sha256": keyed_body_digest(body) if withheld else hashlib.sha256(body).hexdigest(),
        "content_type": private.headers().get("content-type"),
        "text_sample": text_sample,
        "search_matches": [
            {"term": term, "count": lowered.count(term.lower())}
            for term in terms
        ],
        "secret_values_visible": False,
    }
    withheld = active_withheld_values()
    if withheld is not None:
        # References, masked previews and keyed fingerprints for the markers in the sample; the
        # values stay in the worker (``request_bindings[].withheld_ref`` sends one).
        observation["withheld_values"] = withheld.entries(text_sample)
    return {
        "ok": True,
        "status": "success",
        "observation": observation,
        "budget_consumed": {"http_requests": 1, "tool_wall_seconds": 1},
    }


async def analyze_target_javascript(
    target_url: str,
    args: Mapping[str, Any],
    *,
    target: TargetBinding,
    transaction_recorder: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    path = str(args.get("path") or "")
    length = max(1, min(MAX_JAVASCRIPT_BYTES, int(args.get("max_bytes") or MAX_JAVASCRIPT_BYTES)))
    result, private = await _fetch_artifact(
        target_url, path=path, target=target, offset=0, length=length,
        transaction_recorder=transaction_recorder,
    )
    if not result.get("ok") or private is None or private.status_code not in {200, 206}:
        status = private.status_code if private is not None else None
        return {
            "ok": False,
            "status": "failed",
            "error": str(result.get("error") or f"artifact_http_status:{status}"),
            "budget_consumed": {"http_requests": 1, "tool_wall_seconds": 1},
        }
    body = private.body()[:length]
    analysis = analyze_javascript_bytes(body)
    collector = active_withheld_values()
    if collector is not None:
        analysis["withheld_values"] = collector.entries(json.dumps(analysis["jwt_observations"]))
    analysis.update({
        "kind": "javascript_analysis",
        "path": path,
        "content_type": private.headers().get("content-type"),
        "analysis_complete": len(body) < length,
        "secret_values_visible": False,
    })
    return {
        "ok": True,
        "status": "success",
        "observation": analysis,
        "budget_consumed": {"http_requests": 1, "tool_wall_seconds": 1},
    }


__all__ = [
    "MAX_INSPECT_BYTES", "MAX_JAVASCRIPT_BYTES", "analyze_javascript_bytes",
    "analyze_target_javascript", "inspect_target_artifact",
]
