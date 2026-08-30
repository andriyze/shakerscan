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
from typing import Any, Callable, Mapping

from capabilities.http import WorkerPrivateHTTPResponse, execute_bound_http_request
from runtime.models import TargetBinding


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
        jwt_observations.append({
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
    source_maps = sorted(set(_SOURCE_MAP_RE.findall(text)))[:20]
    supabase_origins = sorted(set(_SUPABASE_RE.findall(text)))[:20]
    sink_names = (
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
        "new Function", "postMessage", "localStorage", "sessionStorage",
    )
    sinks = [name.rstrip("(") for name in sink_names if name in text]
    return {
        "schema_version": "javascript-static-analysis/v1",
        "bytes_analyzed": len(body),
        "content_sha256": hashlib.sha256(body).hexdigest(),
        "routes": routes,
        "jwt_observations": jwt_observations,
        "supabase_origins": supabase_origins,
        "source_maps": source_maps,
        "client_sink_signals": sinks,
    }


def _redacted_text_sample(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace")[:MAX_PUBLIC_TEXT]
    text = _JWT_RE.sub(
        lambda match: f"<jwt:sha256:{hashlib.sha256(match.group(1).encode()).hexdigest()[:16]}>",
        text,
    )
    text = re.sub(
        r"(?i)(bearer\s+)[a-z0-9._~+/=-]+", r"\1<redacted>", text,
    )
    return text


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
    result, private = await _fetch_artifact(
        target_url, path=path, target=target, offset=offset, length=length,
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
    body = private.body()[:length]
    terms = [str(term)[:100] for term in args.get("search_terms") or [] if str(term)][:10]
    lowered = body.decode("utf-8", errors="replace").lower()
    observation = {
        "kind": "artifact_observation",
        "path": path,
        "offset": offset,
        "returned_bytes": len(body),
        "window_sha256": hashlib.sha256(body).hexdigest(),
        "content_type": private.headers().get("content-type"),
        "text_sample": _redacted_text_sample(body),
        "search_matches": [
            {"term": term, "count": lowered.count(term.lower())}
            for term in terms
        ],
        "secret_values_visible": False,
    }
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
