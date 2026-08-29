"""Shared target-bound HTTP execution used by canonical Scan and Hunt."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import sys
import time
from typing import Any, Callable, Mapping, Sequence
import urllib.parse

import agent_tools
from http_experiment import (
    MAX_BODY_BYTES,
    MAX_REDIRECT_HOPS,
    REDIRECT_STATUSES,
    response_summary,
    rewrite_method_for_redirect,
    validate_next_hop,
)
from runtime.models import TargetBinding
from runtime.target_bound_socket import FrozenTargetSocketFactory


@dataclass(frozen=True, repr=False)
class WorkerPrivateHTTPResponse:
    """Raw bounded response material available only inside the executing worker."""

    status_code: int
    final_url: str
    _body: bytes = field(repr=False)
    _headers: Mapping[str, str] = field(repr=False)
    _cookies: Mapping[str, str] = field(repr=False)

    def __repr__(self) -> str:
        return (
            "WorkerPrivateHTTPResponse("
            f"status_code={self.status_code}, body_bytes={len(self._body)}, "
            f"header_names={sorted(self._headers)}, "
            f"cookie_names={sorted(self._cookies)}, values_visible=False)"
        )

    def body(self) -> bytes:
        return bytes(self._body)

    def headers(self) -> dict[str, str]:
        return dict(self._headers)

    def cookies(self) -> dict[str, str]:
        return dict(self._cookies)


# The response headers that describe a target's security posture. Fixed and public: naming them
# here rather than accepting a caller-supplied list keeps the capability's declared input contract
# unchanged while making the posture observable.
_SECURITY_POSTURE_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "server",
    "x-powered-by",
)


async def _read_bounded_response(
    response: Any,
    *,
    deadline: float,
    body_limit: int = MAX_BODY_BYTES,
) -> tuple[bytes, str, int, bool, bool]:
    """Read at most one byte past ``body_limit`` under one absolute deadline.

    httpx read timeouts are idle timeouts: a hostile peer can emit one byte before every
    timeout forever. The outer asyncio deadline bounds total occupation, while observing one
    byte past the body ceiling proves truncation without draining an unbounded response.
    Returned length and digest describe observed bytes; ``truncated`` says they are a prefix.
    """
    retained = bytearray()
    observed = bytearray()
    truncated = False
    deadline_exceeded = False
    remaining_seconds = max(0.001, deadline - time.perf_counter())
    try:
        async with asyncio.timeout(remaining_seconds):
            async for chunk in response.aiter_bytes():
                remaining_observation = max(0, body_limit + 1 - len(observed))
                if remaining_observation:
                    observed.extend(chunk[:remaining_observation])
                remaining_body = max(0, body_limit - len(retained))
                if remaining_body:
                    retained.extend(chunk[:remaining_body])
                if len(observed) > body_limit:
                    truncated = True
                    break
    except TimeoutError:
        truncated = True
        deadline_exceeded = True
    digest = hashlib.sha256(bytes(observed)).hexdigest()
    return bytes(retained), digest, len(observed), truncated, deadline_exceeded


def _origin(value: Any) -> str | None:
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        return None
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    netloc = parsed.hostname.lower()
    if port is not None and port != default_port:
        netloc = f"{netloc}:{port}"
    return f"{parsed.scheme.lower()}://{netloc}"


def _origin_key(value: Any) -> tuple[str, str, int] | None:
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    return (
        parsed.scheme.lower(),
        parsed.hostname.lower().rstrip("."),
        port or (443 if parsed.scheme.lower() == "https" else 80),
    )


def _emit_transaction(
    recorder: Callable[[dict[str, Any]], None],
    *,
    request: Any,
    response: Any,
    body: bytes,
    body_truncated: bool,
    response_body_sha256: str,
    response_body_bytes: int,
    pinned_address: str | None,
    direct_origin: bool,
    principal_slot: str,
    started: float,
    started_at: datetime,
    fallback_method: str,
    fallback_url: str,
) -> None:
    """Hand the archive the wire request and its response.

    ``request`` is httpx's own object for the hop that produced this response, so its URL
    carries the query string and its headers carry everything httpx added. Truncation is
    passed through rather than recomputed: the executor reads only a bounded prefix, and
    letting the archive measure that prefix would report it as the complete body.
    """
    request_headers: dict[str, str] = {}
    request_body: bytes | None = None
    url = fallback_url
    method = fallback_method
    if request is not None:
        method = str(getattr(request, "method", method) or method)
        # The connection is pinned to an address, so the built request's URL carries that
        # address rather than the hostname. Take its path and query -- which the caller's
        # arguments do not have -- and put them back on the logical origin, so an export
        # reads as the application's URL while remaining exactly what was sent.
        built = getattr(request, "url", None)
        if built is not None:
            logical = urllib.parse.urlsplit(url)
            # httpx exposes the query as bytes. Coercing with str() first yielded the
            # literal "b''" and put it in the URL as a parameter.
            query = getattr(built, "query", b"") or b""
            if isinstance(query, (bytes, bytearray)):
                query = bytes(query).decode("ascii", errors="replace")
            query = str(query)
            url = urllib.parse.urlunsplit((
                logical.scheme, logical.netloc,
                str(getattr(built, "path", logical.path) or logical.path),
                query, "",
            ))
        request_headers = {
            str(name).lower(): str(value)
            for name, value in getattr(request, "headers", {}).items()
        }
        request_body = getattr(request, "content", None) or None
    recorder({
        "method": method,
        "url": url,
        "http_version": str(getattr(response, "http_version", "") or ""),
        "status_code": int(response.status_code),
        "request_headers": request_headers,
        "request_body": request_body,
        "response_headers": {
            str(name).lower(): str(value)
            for name, value in response.headers.items()
        },
        "response_body": body,
        "response_body_sha256": response_body_sha256,
        "response_body_bytes": response_body_bytes,
        "response_digest_scope": "prefix" if body_truncated else "complete",
        # The executor stops reading at its own ceiling, so the archive is told the body is
        # a prefix rather than measuring it and concluding it is whole.
        "response_body_truncated": bool(body_truncated),
        "remote_ip": pinned_address,
        "direct_origin": direct_origin,
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "started_at": started_at,
        "principal_slot": str(principal_slot or "anonymous"),
        "fidelity": "wire_request_prefix" if body_truncated else "wire_request",
    })


def _trusted_headers(values: Mapping[str, Any] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_name, raw_value in dict(values or {}).items():
        name, value = str(raw_name).strip(), str(raw_value)
        lower = name.lower()
        if (
            not name
            or lower in {"host", "content-length", "connection", "transfer-encoding"}
            or not name.isascii()
            or not value.isascii()
            or len(name) > 120
            or len(value.encode("utf-8")) > 8_192
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in name + value
            )
        ):
            continue
        result[name] = value
    return result


def _bound_redirect_url(
    current_url: str,
    location: Any,
    *,
    allowed_origin_keys: set[tuple[str, str, int]],
) -> str | None:
    text = str(location or "").strip()
    if not text or any(ord(character) < 32 for character in text):
        return None
    try:
        candidate = urllib.parse.urljoin(current_url, text)
        parsed = urllib.parse.urlsplit(candidate)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or _origin_key(candidate) not in allowed_origin_keys
    ):
        return None
    return urllib.parse.urlunsplit((
        parsed.scheme.lower(), parsed.netloc.lower(),
        parsed.path or "/", parsed.query, "",
    ))


async def execute_bound_http_request(
    base_url: str,
    args: Mapping[str, Any],
    *,
    target: TargetBinding,
    allow_write: bool = False,
    trusted_headers: Mapping[str, Any] | None = None,
    allow_identity_headers: bool = False,
    direct_origin_addresses: Sequence[str] = (),
    # Receives the complete request and response for the archive. Kept separate from
    # private_response_sink, which deliberately hands back only three header names: the
    # archive's whole purpose is the fidelity that projection removes.
    transaction_recorder: Callable[[dict[str, Any]], None] | None = None,
    cookies: Mapping[str, Any] | None = None,
    principal_slot: str = "anonymous",
    selected_headers: list[str] | None = None,
    timeout_seconds: int = 15,
    allow_bound_origin_redirects: bool = False,
    private_response_sink: Callable[[WorkerPrivateHTTPResponse], None] | None = None,
) -> dict[str, Any]:
    """Execute one bounded request while revalidating every destination hop."""
    import httpx

    method = agent_tools.coerce_method(args.get("method"))
    path = agent_tools.validate_same_origin_path(args.get("path"))
    if agent_tools.is_write_method(method) and not allow_write:
        return {
            "ok": False,
            "needs_approval": True,
            "error": f"{method} is a state-changing request and requires approval",
        }
    follow_redirects = args.get("follow_redirects") is True
    if follow_redirects and method not in {"GET", "HEAD", "OPTIONS"}:
        return {
            "ok": False,
            "error": (
                "follow_redirects is only permitted for read methods "
                "(GET/HEAD/OPTIONS)"
            ),
        }
    candidate_origin = _origin(args.get("origin") or base_url)
    allowed_by_key = {
        _origin_key(origin): origin for origin in target.allowed_origins
    }
    request_origin = allowed_by_key.get(_origin_key(candidate_origin))
    if (
        request_origin is None
        or request_origin not in target.allowed_origins
        or urllib.parse.urlsplit(request_origin).hostname != target.canonical_host
    ):
        return {
            "ok": False,
            "error": "scope: HTTP origin is outside the frozen target binding",
        }
    # An operator-confirmed address replaces the resolved one for this request only, while
    # SNI and Host stay the target's. That is what demonstrates an origin is reachable
    # without whatever sits in front of it, rather than only suspecting it from a scan.
    # The planner may name an address but never invent one: it has to be in the list the
    # operator confirmed at hunt start.
    via_address = str(args.get("via_address") or "").strip()
    confirmed = tuple(str(item).strip() for item in direct_origin_addresses if str(item).strip())
    if via_address and via_address not in confirmed:
        return {
            "ok": False,
            "error": "scope: via_address is not an operator-confirmed direct origin",
        }
    frozen_addresses = (via_address,) if via_address else target.allowed_addresses
    if not frozen_addresses:
        return {
            "ok": False,
            "error": "scope: HTTP target has no frozen address",
        }
    try:
        socket_factory = FrozenTargetSocketFactory(
            hostname=target.canonical_host,
            port=(
                urllib.parse.urlsplit(request_origin).port
                or (443 if request_origin.startswith("https://") else 80)
            ),
            frozen_addresses=frozen_addresses,
        )
        pinned_address = socket_factory.primary_address
    except ValueError as exc:
        return {"ok": False, "error": f"scope: {exc}"}

    headers = agent_tools.filter_request_headers(
        args.get("headers"), allow_identity_headers=allow_identity_headers,
    )
    headers.update(_trusted_headers(trusted_headers))
    query = args.get("query") if isinstance(args.get("query"), dict) else None
    json_body = (
        args.get("json_body")
        if isinstance(args.get("json_body"), dict) else None
    )
    form_body = (
        args.get("form_body")
        if isinstance(args.get("form_body"), dict) else None
    )
    url = urllib.parse.urljoin(request_origin + "/", path.lstrip("/"))
    request_view = {
        "method": method,
        "origin": request_origin,
        "path": path,
        "query_keys": sorted(query or {}),
        "as_principal": str(principal_slot or "anonymous")[:80],
        "body_kind": (
            "json" if json_body is not None
            else "form" if form_body is not None else None
        ),
        "pinned_address": pinned_address,
        # Recorded so a reader can always tell whether a response came through the target's
        # resolved address or an operator-confirmed origin. The two are not comparable
        # evidence and must never be conflated in a finding.
        "direct_origin": bool(via_address),
        "address_policy": socket_factory.policy_receipt,
        "follow_redirects": follow_redirects,
    }
    timeout = max(1, min(60, int(timeout_seconds)))
    started = time.perf_counter()
    request_started_at = datetime.now(timezone.utc)
    redirect_chain: list[dict[str, Any]] = []
    body_truncated = False
    hops_followed = 0
    connection_attempts = 0
    connected_addresses: list[str] = []
    response = None
    body = b""
    final_url = url
    request_deadline = time.perf_counter() + max(0.001, float(timeout))
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            current_url = url
            current_method = method
            current_query = query
            current_json_body = json_body
            current_form_body = form_body
            while True:
                final_url = current_url
                hop_started = time.perf_counter()
                hop_started_at = datetime.now(timezone.utc)
                response = None
                for candidate_address in socket_factory.connection_addresses:
                    pinned_url, sni_hostname, host_header = (
                        agent_tools._pinned_scanner_url(
                            current_url, candidate_address,
                        )
                    )
                    request = client.build_request(
                        current_method,
                        pinned_url,
                        params=current_query,
                        headers={**headers, "Host": host_header},
                        cookies=dict(cookies or {}),
                        json=(
                            current_json_body
                            if current_json_body is not None else None
                        ),
                        data=(
                            current_form_body
                            if current_form_body is not None else None
                        ),
                    )
                    request.extensions["sni_hostname"] = sni_hostname
                    connection_attempts += 1
                    try:
                        response = await client.send(request, stream=True)
                    except (httpx.ConnectError, httpx.ConnectTimeout):
                        # Retry only failures that happen before a connection.
                        # A post-connect failure may follow target traffic and
                        # must never duplicate a state-changing request.
                        continue
                    pinned_address = candidate_address
                    connected_addresses.append(candidate_address)
                    break
                if response is None:
                    raise httpx.ConnectError(
                        "all frozen target addresses failed before connect"
                    )
                request_view["pinned_address"] = pinned_address
                try:
                    (
                        body,
                        response_body_sha256,
                        response_bytes,
                        body_truncated,
                        read_deadline_exceeded,
                    ) = await _read_bounded_response(
                        response, deadline=request_deadline,
                    )
                finally:
                    await response.aclose()
                final_url = current_url
                if transaction_recorder is not None:
                    try:
                        _emit_transaction(
                            transaction_recorder,
                            request=getattr(response, "request", None),
                            response=response,
                            body=body,
                            body_truncated=body_truncated,
                            response_body_sha256=response_body_sha256,
                            response_body_bytes=response_bytes,
                            pinned_address=pinned_address,
                            direct_origin=bool(via_address),
                            principal_slot=principal_slot,
                            started=hop_started,
                            started_at=hop_started_at,
                            fallback_method=current_method,
                            fallback_url=current_url,
                        )
                    except Exception as exc:  # pragma: no cover - archive is best effort
                        print(
                            f"[http-archive] transaction not recorded: {type(exc).__name__}",
                            file=sys.stderr, flush=True,
                        )
                if read_deadline_exceeded:
                    # Preserve the status, headers, and bounded prefix, but never continue a
                    # redirect chain after the absolute request deadline was exhausted.
                    break
                if (
                    not follow_redirects
                    or response.status_code not in REDIRECT_STATUSES
                ):
                    break
                location = str(response.headers.get("location") or "").strip()
                if not location:
                    break
                if hops_followed >= MAX_REDIRECT_HOPS:
                    redirect_chain.append({
                        "status": response.status_code,
                        "location": location[:500],
                        "followed": False,
                        "stopped": "max_hops",
                    })
                    break
                next_url = validate_next_hop(current_url, location)
                if next_url is None and allow_bound_origin_redirects:
                    next_url = _bound_redirect_url(
                        current_url,
                        location,
                        allowed_origin_keys={
                            key for key in allowed_by_key if key is not None
                        },
                    )
                if (
                    next_url is None
                    or _origin_key(next_url) not in allowed_by_key
                ):
                    redirect_chain.append({
                        "status": response.status_code,
                        "location": location[:500],
                        "followed": False,
                        "stopped": "cross_origin",
                    })
                    break
                redirect_chain.append({
                    "status": response.status_code,
                    "location": location[:500],
                    "followed": True,
                })
                current_method = rewrite_method_for_redirect(
                    current_method, response.status_code,
                )
                current_query = None
                current_json_body = None
                current_form_body = None
                current_url = next_url
                hops_followed += 1
    except (httpx.InvalidURL, httpx.HTTPError, UnicodeError, ValueError) as exc:
        # A call that never got a response is still a call the scanner made, and it is
        # often the interesting one -- a refused connection to a confirmed origin is how a
        # control proves it works. Archiving only completed responses would leave the
        # archive quietly describing a different, more successful run than the real one.
        if transaction_recorder is not None:
            try:
                # No response means no built request to read, so this records what was
                # attempted and labels the fidelity accordingly. A refused connection is
                # still a call the scanner made and often the one that matters.
                transaction_recorder({
                    "method": method, "url": final_url,
                    "request_headers": dict(headers),
                    "request_body": None,
                    "remote_ip": pinned_address,
                    "direct_origin": bool(via_address),
                    "elapsed_ms": int((time.perf_counter() - started) * 1000),
                    "started_at": request_started_at,
                    "principal_slot": str(principal_slot or "anonymous"),
                    "error": f"request_error:{type(exc).__name__}",
                    "fidelity": "attempted_no_response",
                })
            except Exception:  # pragma: no cover - recording must never mask the error
                pass
        return {
            "ok": False,
            "error": f"request_error:{type(exc).__name__}",
            "request": request_view,
        }
    if response is None:
        return {
            "ok": False,
            "error": "request_error:MissingResponse",
            "request": request_view,
        }
    if private_response_sink is not None:
        private_response_sink(WorkerPrivateHTTPResponse(
            status_code=int(response.status_code),
            final_url=final_url,
            _body=body[:MAX_BODY_BYTES],
            _headers={
                str(name).lower(): str(value)
                for name, value in response.headers.items()
                if str(name).lower() in {
                    "authorization", "content-type", "location",
                }
            },
            _cookies={
                str(name): str(value)
                for name, value in response.cookies.items()
            },
        ))
    summary = response_summary(
        response,
        body,
        selected_headers=[
            str(name).strip().lower()
            for name in selected_headers or []
            if str(name).strip()
        ][:50],
        elapsed_ms=round((time.perf_counter() - started) * 1_000),
    )
    # Security posture headers are recorded on every response rather than being selected by the
    # caller. They are a fixed, public, value-free-by-nature set, and the scan's `http.request`
    # contract accepts only method/path/follow_redirects -- so without this the posture data a DAST
    # exists to report (HSTS, CSP, frame options...) was fetched and then discarded, and the report
    # lost the certificate/header sections operators had in 0.8.18.
    summary["security_headers"] = {
        name: str(response.headers[name])[:2_000]
        for name in _SECURITY_POSTURE_HEADERS
        if name in response.headers
    }
    summary["set_cookie_metadata"] = [
        {
            "secure": "secure" in value.lower(),
            "httponly": "httponly" in value.lower(),
            "samesite": (
                "strict" if "samesite=strict" in value.lower()
                else "lax" if "samesite=lax" in value.lower()
                else "none" if "samesite=none" in value.lower()
                else None
            ),
        }
        for value in response.headers.get_list("set-cookie")[:50]
    ]
    summary["final_url"] = final_url
    summary["http_version"] = str(response.http_version or "")[:20]
    result: dict[str, Any] = {
        "ok": True,
        "request": request_view,
        "response": summary,
        "provenance": "tool",
        "connection_attempts": connection_attempts,
        "connected_addresses": list(connected_addresses),
    }
    if follow_redirects:
        result["redirect_chain"] = redirect_chain
        result["hops_followed"] = hops_followed
    return result
