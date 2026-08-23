"""Deterministic cross-principal authorization proof on target-bound HTTP."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import Any, Mapping, Sequence
import urllib.parse

from capabilities.http import WorkerPrivateHTTPResponse, execute_bound_http_request
from runtime.models import TargetBinding

try:
    from scanner_tools.url_redaction import redact_path
except ModuleNotFoundError:
    from scanner.scanner_tools.url_redaction import redact_path


MAX_AUTHZ_ROUTES = 50
MAX_AUTHZ_BODY_CHARACTERS = 262_144


class AuthzVerificationContractError(ValueError):
    """Authorization proof input escaped its target or principal binding."""


def _identity_digest(headers: Mapping[str, str]) -> str:
    payload = [
        (str(name).strip().lower(), str(value))
        for name, value in headers.items()
    ]
    payload.sort()
    return hashlib.sha256(json.dumps(
        payload, separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()


def _normalized_routes(
    base_url: str,
    routes: Sequence[Any],
    *,
    target: TargetBinding,
) -> list[str]:
    if not target.allowed_origins or not target.canonical_host:
        raise AuthzVerificationContractError(
            "authorization proof requires a frozen web target"
        )
    base_origin = target.allowed_origins[0]
    normalized: list[str] = []
    for item in routes:
        raw: Any = item
        method = "GET"
        if isinstance(item, Mapping):
            raw = item.get("url") or item.get("path")
            method = str(item.get("method") or "GET").upper()
        elif isinstance(item, str) and " " in item.strip():
            prefix, remainder = item.strip().split(" ", 1)
            if prefix.upper() in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
                method, raw = prefix.upper(), remainder
        if method != "GET" or not isinstance(raw, str) or not raw.strip():
            continue
        candidate = urllib.parse.urljoin(base_url.rstrip("/") + "/", raw.strip())
        try:
            parsed = urllib.parse.urlsplit(candidate)
            _ = parsed.port
        except ValueError:
            continue
        origin = urllib.parse.urlunsplit((
            parsed.scheme.lower(), parsed.netloc.lower(), "", "", "",
        ))
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.fragment
            or parsed.hostname.lower().rstrip(".") != target.canonical_host
            or origin not in target.allowed_origins
        ):
            continue
        url = urllib.parse.urlunsplit((
            parsed.scheme.lower(), parsed.netloc.lower(),
            parsed.path or "/", parsed.query, "",
        ))
        if url not in normalized:
            normalized.append(url)
        if len(normalized) >= MAX_AUTHZ_ROUTES:
            break
    return normalized


def authz_route_inventory_digest(routes: Sequence[Any]) -> str:
    """Bind an action to exact worker-private route candidates."""
    return hashlib.sha256(json.dumps(
        [str(item) for item in routes],
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()).hexdigest()


def _public_proof_url(
    value: Any,
    *,
    base_origin: str,
    object_id: str | None = None,
) -> str:
    text = str(value or "").strip()
    pieces = text.split(" ", 1)
    if len(pieces) == 2 and pieces[0].upper() in {"GET", "HEAD"}:
        text = pieces[1]
    parsed = urllib.parse.urlsplit(
        urllib.parse.urljoin(base_origin.rstrip("/") + "/", text)
    )
    segments = []
    for segment in (parsed.path or "/").split("/"):
        decoded = urllib.parse.unquote(segment)
        segments.append(
            "<owner-object>" if object_id and decoded == object_id else segment
        )
    path = redact_path("/".join(segments) or "/")
    query = urllib.parse.urlencode([
        (str(name)[:200], "<redacted>")
        for name, _item in urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True,
        )
    ])
    return urllib.parse.urlunsplit((
        parsed.scheme.lower(), parsed.netloc.lower(), path, query, "",
    ))[:2_000]


async def verify_target_bound_object_authorization(
    base_url: str,
    routes: Sequence[Any],
    *,
    target: TargetBinding,
    primary_headers: Mapping[str, str],
    secondary_headers: Mapping[str, str],
) -> dict[str, Any]:
    """Run the existing ownership differential through the canonical HTTP path."""
    primary = dict(primary_headers)
    secondary = dict(secondary_headers)
    if not primary or not secondary:
        raise AuthzVerificationContractError(
            "authorization proof requires two authenticated principals"
        )
    identity_by_digest = {
        _identity_digest(primary): ("primary", primary),
        _identity_digest(secondary): ("secondary", secondary),
    }
    if len(identity_by_digest) != 2:
        return {
            "ok": True,
            "status": "success",
            "observation": {
                "kind": "authz_differential",
                "proof_state": "inconclusive",
                "reason": "principal_contexts_not_distinct",
                "principal_contexts_distinct": False,
                "secret_values_visible": False,
            },
            "budget_consumed": {
                "http_requests": 0,
                "tool_wall_seconds": 0,
            },
        }
    normalized_routes = _normalized_routes(base_url, routes, target=target)
    if not normalized_routes:
        return {
            "ok": True,
            "status": "success",
            "observation": {
                "kind": "authz_differential",
                "proof_state": "inconclusive",
                "reason": "no_target_bound_routes",
                "principal_contexts_distinct": True,
                "secret_values_visible": False,
            },
            "budget_consumed": {
                "http_requests": 0,
                "tool_wall_seconds": 0,
            },
        }

    request_count = 0
    contract_violation: AuthzVerificationContractError | None = None

    async def bounded_fetch(
        url: str,
        method: str = "GET",
        data: Any = None,
        headers: Mapping[str, str] | None = None,
        timeout: int = 10,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        nonlocal contract_violation, request_count
        if str(method).upper() != "GET" or data is not None:
            contract_violation = AuthzVerificationContractError(
                "canonical authorization proof is read-only"
            )
            raise contract_violation
        supplied = dict(headers or {})
        principal = identity_by_digest.get(_identity_digest(supplied))
        if principal is None or principal[1] != supplied:
            contract_violation = AuthzVerificationContractError(
                "authorization proof principal binding changed"
            )
            raise contract_violation
        parsed = urllib.parse.urlsplit(str(url))
        origin = urllib.parse.urlunsplit((
            parsed.scheme.lower(), parsed.netloc.lower(), "", "", "",
        ))
        path = urllib.parse.urlunsplit((
            "", "", parsed.path or "/", parsed.query, "",
        ))
        captured: WorkerPrivateHTTPResponse | None = None

        def retain(response: WorkerPrivateHTTPResponse) -> None:
            nonlocal captured
            captured = response

        result = await execute_bound_http_request(
            origin,
            {"method": "GET", "path": path},
            target=target,
            allow_write=False,
            trusted_headers=supplied,
            principal_slot=principal[0],
            selected_headers=["content-type"],
            timeout_seconds=max(1, min(15, int(timeout))),
            private_response_sink=retain,
        )
        if isinstance(result.get("request"), Mapping):
            request_count += 1
        if str(result.get("error") or "").startswith("scope:"):
            contract_violation = AuthzVerificationContractError(
                "authorization proof destination left its frozen target"
            )
            raise contract_violation
        if captured is None:
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "error": str(result.get("error") or "missing_private_response"),
            }
        return {
            "status_code": captured.status_code,
            "headers": captured.headers(),
            "body": captured.body()[:MAX_AUTHZ_BODY_CHARACTERS].decode(
                "utf-8", errors="replace",
            ),
            "error": None if result.get("ok") else result.get("error"),
        }

    try:
        from scanner_tools.access_control_checks import authz_resource_replay_test
        from scanner_tools.finding_validator import validate_object_authorization
    except ModuleNotFoundError:
        from scanner.scanner_tools.access_control_checks import (
            authz_resource_replay_test,
        )
        from scanner.scanner_tools.finding_validator import (
            validate_object_authorization,
        )

    primary_session = SimpleNamespace(
        config=SimpleNamespace(headers=primary, cookies={}), state=None,
    )
    secondary_session = SimpleNamespace(
        config=SimpleNamespace(headers=secondary, cookies={}), state=None,
    )
    result = await authz_resource_replay_test(
        target.allowed_origins[0],
        normalized_routes,
        primary_session,
        secondary_session,
        max_producers=1,
        max_replays=1,
        timeout=10,
        max_seconds=45,
        fetcher=bounded_fetch,
        allow_write_replays=False,
    )
    if contract_violation is not None:
        raise contract_violation
    finding = next((
        item for item in result.get("findings") or []
        if isinstance(item, Mapping)
        and str((item.get("evidence") or {}).get("proof_type") or "")
        == "cross_principal_replay"
    ), None)
    evidence = (
        dict(finding.get("evidence") or {})
        if isinstance(finding, Mapping) else {}
    )
    validation = (
        validate_object_authorization(dict(finding))
        if isinstance(finding, Mapping) else None
    )
    verified = bool(validation is not None and validation.verified)
    object_id = str(evidence.get("requested_object_id") or "")
    observation: dict[str, Any] = {
        "kind": "authz_differential",
        "proof_state": "verified" if verified else "inconclusive",
        "reason": None if verified else (
            str(result.get("reason") or "ownership_differential_not_proven")[:200]
        ),
        "principal_contexts_distinct": True,
        "route_count": len(normalized_routes),
        "producers_tested": int(result.get("producers_tested") or 0),
        "replays_completed": int(result.get("replays_completed") or 0),
        "write_replays_attempted": int(
            result.get("write_replays_attempted") or 0
        ),
        "secret_values_visible": False,
    }
    if verified:
        accepted = dict(evidence.get("accepted_principal_responses") or {})
        observation.update({
            "method": "GET",
            "producer_url": _public_proof_url(
                evidence.get("producer_endpoint"),
                base_origin=target.allowed_origins[0],
            ),
            "consumer_url": _public_proof_url(
                evidence.get("url") or evidence.get("consumer_endpoint"),
                base_origin=target.allowed_origins[0],
                object_id=object_id,
            ),
            "resource_id_sha256": hashlib.sha256(object_id.encode()).hexdigest(),
            "object_id_key": str(evidence.get("object_id_key") or "")[:120],
            "object_id_location": str(
                evidence.get("object_id_location") or ""
            )[:120],
            "owner_status": int(evidence.get("owner_status") or 0),
            "attacker_status": int(evidence.get("attacker_status") or 0),
            "accepted_principal_responses": {
                str(name)[:80]: int(status)
                for name, status in accepted.items()
                if isinstance(status, int)
            },
            "object_absent_from_secondary_listing": bool(
                evidence.get("object_id_absent_from_attacker_listing")
            ),
            "responses_equivalent": bool(evidence.get("responses_equivalent")),
            "sensitive_field_names": [
                str(name)[:120]
                for name in evidence.get("sensitive_fields") or []
            ][:20],
            "proof_type": "cross_principal_replay",
        })
    return {
        "ok": True,
        "status": "success",
        "observation": observation,
        "budget_consumed": {
            "http_requests": request_count,
            "tool_wall_seconds": 1 if request_count else 0,
        },
    }
