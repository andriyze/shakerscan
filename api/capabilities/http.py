"""Shared target-bound HTTP execution used by canonical Scan and Hunt."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
import secrets
import sys
import ssl
import re
import time
from typing import Any, Callable, Mapping, Sequence
import urllib.parse

import action_scope
import agent_tools
from http_experiment import (
    LOOKAHEAD_WAIT_SECONDS,
    MAX_BODY_BYTES,
    MAX_REDIRECT_HOPS,
    REDIRECT_STATUSES,
    response_summary,
    rewrite_method_for_redirect,
    validate_next_hop,
)
from runtime.archive_body_masking import (
    CUT_LOOKAHEAD_CHARS, URL_BEARING_HEADERS, active_withheld_values, bounded_public_url,
    mask_public_http_urls,
)
from runtime import origin_pace
from runtime.target_backoff import BACKOFF as TARGET_BACKOFF
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
    # True when the target sent more body than the bounded read kept: ``body()`` is a prefix.
    body_truncated: bool = False

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


_COOKIE_NAME_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}")


def _cookie_name(set_cookie: str) -> str | None:
    """The name of a ``Set-Cookie`` value (RFC 6265 token), or None when it has none."""
    name = str(set_cookie or "").split(";", 1)[0].split("=", 1)[0].strip()
    return name if _COOKIE_NAME_RE.fullmatch(name) else None


def cookie_metadata(set_cookie: str) -> dict[str, Any] | None:
    """Name and security attributes of one ``Set-Cookie`` value; the value never leaves.

    Attributes are read from the attribute list only (after the first ``;``): a cookie whose
    value happens to contain ``secure`` or ``httponly`` is not mistaken for one that sets them.
    """
    name = _cookie_name(set_cookie)
    if name is None:
        return None
    attributes: dict[str, str] = {}
    for part in str(set_cookie or "").split(";")[1:20]:
        key, _sep, value = part.partition("=")
        attributes.setdefault(key.strip().lower(), value.strip().lower())
    samesite = attributes.get("samesite")
    return {
        "name": name,
        "secure": "secure" in attributes,
        "httponly": "httponly" in attributes,
        "samesite": samesite if samesite in {"strict", "lax", "none"} else None,
    }


# The response headers that describe a target's security posture. Fixed and public: naming them
# here rather than accepting a caller-supplied list keeps the capability's declared input contract
# unchanged while making the posture observable.
_CHALLENGE_SCHEMES = frozenset({"basic", "digest", "bearer", "negotiate", "ntlm"})
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
    lookahead: bytearray | None = None,
    lookahead_limit: int = 0,
    lookahead_state: dict[str, bool] | None = None,
) -> tuple[bytes, str, int, bool, bool]:
    """Read at most one byte past ``body_limit`` under one absolute deadline.

    httpx read timeouts are idle timeouts: a hostile peer can emit one byte before every
    timeout forever. The outer asyncio deadline bounds total occupation, while observing one
    byte past the body ceiling proves truncation without draining an unbounded response.
    Returned length and digest describe observed bytes; ``truncated`` says they are a prefix.
    ``lookahead`` receives up to ``lookahead_limit`` bytes past the body: read only to mask the
    body where it is cut, never recorded or digested. ``lookahead_state["complete"]`` says whether
    the stream ended within what was read; when it did not, the masking withholds what the cut
    may have split.
    """
    import httpx

    retained = bytearray()
    observed = bytearray()
    truncated = False
    deadline_exceeded = False
    remaining_seconds = max(0.001, deadline - time.perf_counter())
    chunks = response.aiter_bytes().__aiter__()
    try:
        async with asyncio.timeout(remaining_seconds):
            async for chunk in chunks:
                remaining_observation = max(0, body_limit + 1 - len(observed))
                if remaining_observation:
                    observed.extend(chunk[:remaining_observation])
                remaining_body = max(0, body_limit - len(retained))
                if remaining_body:
                    retained.extend(chunk[:remaining_body])
                if lookahead is not None and len(chunk) > remaining_body:
                    lookahead.extend(chunk[remaining_body:][:max(0, lookahead_limit - len(lookahead))])
                if len(observed) > body_limit:
                    truncated = True
                    break
    except TimeoutError:
        truncated = True
        deadline_exceeded = True
    ended = False
    if truncated and not deadline_exceeded and lookahead is not None and len(lookahead) < lookahead_limit:
        # Within its own short wait, and never past the request deadline: a stream that pauses
        # after the ceiling (a long poll, server-sent events) ends the lookahead, not the request.
        wait = min(LOOKAHEAD_WAIT_SECONDS, deadline - time.perf_counter())
        if wait > 0:
            try:
                async with asyncio.timeout(wait):
                    async for chunk in chunks:
                        lookahead.extend(chunk[:lookahead_limit - len(lookahead)])
                        if len(lookahead) >= lookahead_limit:
                            break
                    else:
                        ended = True
            except (TimeoutError, OSError, httpx.HTTPError):
                pass  # a pause or an error past the ceiling ends the lookahead, not the request
    if lookahead_state is not None:
        lookahead_state["complete"] = not truncated or ended
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
    if ":" in netloc:
        netloc = f"[{netloc}]"
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


def _destination_host(value: Any) -> str:
    try:
        from action_scope import _canonical_host
    except ModuleNotFoundError:
        from ..action_scope import _canonical_host
    return _canonical_host(value)


def granted_destination(policy: Mapping[str, Any], origin: Any) -> Mapping[str, Any] | None:
    """The destination a person authorized for this Hunt (``target.authorize``) matching
    ``origin`` exactly by scheme, host and port, or None."""
    try:
        parsed = urllib.parse.urlsplit(str(origin or "").strip())
        port = parsed.port
    except ValueError:
        return None
    if port == 0:
        # Not "the default port": ``destination_refusal`` refuses port 0 as an invalid origin,
        # and ``parsed.port or 443`` used to read https://h:0 as a grant for https://h:443.
        return None
    port = port or (443 if parsed.scheme == "https" else 80)
    # The spelling the grant was recorded under (``permission_subjects.destination_host``).
    host = _destination_host(parsed.hostname)
    if not host:
        return None
    for item in policy.get("granted_destinations") or ():
        if (isinstance(item, Mapping) and _destination_host(item.get("host")) == host
                and int(item.get("port") or 0) == port and item.get("scheme") == parsed.scheme):
            return item
    return None


def granted_destination_target(target: TargetBinding, granted: Mapping[str, Any], origin: str) -> TargetBinding:
    """The binding for an authorized destination: pinned to the addresses resolved and
    scope-checked when the person allowed it; the Hunt's own host keeps its own addresses."""
    if granted.get("same_host"):
        if _origin_key(origin) in {_origin_key(value) for value in target.allowed_origins}:
            return target
        return replace(target, allowed_origins=(*target.allowed_origins, origin))
    addresses = tuple(str(item) for item in granted.get("addresses") or () if str(item))
    if not addresses:
        raise ValueError("authorized destination has no resolved address")
    host = str(granted["host"])
    return replace(
        target, canonical_host=host, allowed_origins=(origin,), allowed_addresses=addresses,
        allowed_root_domains=(host,),
    )


def resolve_hunt_http_origin(target: TargetBinding, origin: Any, policy: Mapping[str, Any]) -> TargetBinding:
    """Select another service on the same frozen host under existing network authority.

    No new host/address is admitted, and a response redirect cannot expand scope this way.
    Admission and the worker both validate this before credential resolution or traffic.
    """
    if origin is None:
        return target
    text = str(origin).strip()
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("HTTP service origin is invalid") from exc
    if (any(c.isspace() or ord(c) < 32 for c in text) or "\\" in text
            or parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or port == 0):
        raise ValueError("HTTP service origin must be on the Hunt's exact target host")
    # The scope guard's host spelling (``action_scope._canonical_host``: IDNA 2008 with UTS #46,
    # as httpx connects), and the admitted origin is recorded in that ASCII form.
    host = _destination_host(parsed.hostname)
    if not host:
        raise ValueError("HTTP service origin host is not a valid IDNA 2008/UTS #46 name")
    netloc = f"[{host}]" if ":" in host else host
    candidate = _origin(f"{parsed.scheme}://{netloc}" + (f":{port}" if port is not None else ""))
    granted = granted_destination(policy, text)
    if granted is not None:
        return granted_destination_target(target, granted, candidate)
    if host != target.canonical_host:
        raise ValueError("HTTP service origin must be on the Hunt's exact target host")
    if _origin_key(candidate) in {_origin_key(value) for value in target.allowed_origins}:
        return target
    # A different port or scheme on the SAME already-authorized host is another
    # service on the target the operator authorized, not a new destination: the
    # host is pinned above and cannot change here, and a response redirect still
    # cannot widen scope this way. Reaching it needs active testing (which the
    # target's standing authorization grants); network discovery is sufficient
    # but no longer required, so an authorized Hunt is not refused a service that
    # simply listens on another port.
    if policy.get("active_testing") is not True:
        raise ValueError("another service port on this host requires the Hunt's active-testing authority")
    return replace(target, allowed_origins=(*target.allowed_origins, candidate))


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


def bound_virtual_host(value: Any, target: TargetBinding) -> str | None:
    """The canonical name when it lies strictly below an apex the binding declares.

    Only an operator-declared apex (``TargetBinding.declared_apex_roots``) admits other names:
    the registrable domain of a host bound below it (``zendesk.com`` for ``acme.zendesk.com``)
    belongs to a provider, and its other names are other tenants on a shared edge.
    """
    try:
        from scanner_tools.discovered_names import subdomain_of
    except ModuleNotFoundError:  # package import
        from scanner.scanner_tools.discovered_names import subdomain_of
    for root in target.declared_apex_roots():
        name = subdomain_of(value, root)
        if name:
            return name
    return None


def _host_port_suffix(url: str) -> str:
    """``:port`` for a Host header when the URL names a non-default port, else empty."""
    parsed = urllib.parse.urlsplit(url)
    port = parsed.port
    default = 443 if parsed.scheme.lower() == "https" else 80
    return f":{port}" if port is not None and port != default else ""


def request_error_class(exc: BaseException) -> str:
    """Name a failed request by its cause, not just the exception the client wrapped it in.

    httpx reports a certificate the client will not trust as a plain ``ConnectError``. Left
    like that, a self-signed target failed the whole HTTP baseline as an unclassified adapter
    error, while every tool that skips verification carried on. The class is a constant
    token with no target data in it.
    """
    seen: BaseException | None = exc
    for _ in range(8):
        if seen is None:
            break
        if isinstance(seen, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(seen):
            return f"tls_certificate_untrusted:{type(exc).__name__}"
        seen = seen.__cause__ or seen.__context__
    return f"request_error:{type(exc).__name__}"


# The most a caller may read into a worker-private body: a whole JavaScript bundle for
# javascript.analyze (4 MiB, artifact.MAX_JAVASCRIPT_BYTES), which also covers an artifact window
# with the dump context that masks it (artifact.inspect reads up to 1 MiB before a SQL dump window).
MAX_PRIVATE_BODY_BYTES = 4_194_304


# A hold the target asked for (runtime/target_backoff) is waited out inside the request only this
# long: the caller's action holds a reservation with a lease of its own (90 s for http.request),
# and a ban hold lasts up to five minutes. A longer hold sends nothing and says when to retry.
MAX_IN_REQUEST_HOLD_SECONDS = 20.0
_IDENTITY_HEADER = re.compile(r"authorization|cookie|token|api[-_]?key|session|auth", re.I)
# Tags that compare two requests of this process (who sent them, what body they carried) are keyed
# with a key that exists only in this process's memory: they are never stored or shown, and a
# plain digest of a credential or a body would be a guessing oracle wherever it did turn up.
_PROCESS_TAG_KEY = secrets.token_bytes(32)


def _process_tag(data: bytes) -> str:
    return hmac.new(_PROCESS_TAG_KEY, bytes(data), hashlib.sha256).hexdigest()[:32]


def _sender_key(principal_slot: Any, headers: Mapping[str, Any], cookies: Mapping[str, Any] | None,
                trusted: Mapping[str, Any]) -> str:
    """An opaque key for the identity one request is sent as: "" for an anonymous request, else a
    process-keyed tag of the principal slot and the credential material the request carries (a
    rotated credential is another key). Kept in this process's memory only (runtime/target_backoff)."""
    material = sorted(
        [(str(name).lower(), str(value)) for name, value in dict(trusted or {}).items()]
        + [(str(name).lower(), str(value)) for name, value in dict(headers or {}).items()
           if _IDENTITY_HEADER.search(str(name))]
        + [(f"cookie:{name}", str(value)) for name, value in dict(cookies or {}).items()])
    slot = str(principal_slot or "anonymous")
    if not material and slot == "anonymous":
        return ""
    return _process_tag(json.dumps([slot, material]).encode("utf-8", "replace"))


def _held_result(seconds: float, reason: str, request_view: Mapping[str, Any] | None,
                 hops_followed: int) -> dict[str, Any]:
    """The answer for a request not sent because the target is held longer than this request
    may wait. ``target_hold``: nothing reached the target, nothing is charged, and the same
    request may be sent after the hold. ``target_hold_after_redirect``: the hold began after a
    followed redirect, so the hops that were sent are reported and it is not a plain retry."""
    retry = max(1, int(seconds + 0.999))
    why = reason or "a hold another worker observed"
    if request_view is not None and hops_followed:
        return {"ok": False, "retry_after_seconds": retry, "request": dict(request_view),
                "hops_followed": hops_followed,
                "error": (f"target_hold_after_redirect: the target is held for another {retry} s ({why}); "
                          f"the redirect was not followed after {hops_followed} hop(s)")}
    return {"ok": False, "retry_after_seconds": retry,
            "error": (f"target_hold: the target is held for another {retry} s ({why}); "
                      "nothing was sent, retry after it")}


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
    private_response_headers: tuple[str, ...] = (),
    response_body_limit: int = MAX_BODY_BYTES,
    virtual_host: str | None = None,
) -> dict[str, Any]:
    """Execute one bounded request while revalidating every destination hop.

    ``virtual_host`` (virtual-host discovery only) asks the same frozen origin, address and port
    under another name: the Host header and TLS SNI carry it. It must be a DNS name strictly
    below one of the binding's root domains; redirects are never followed for it. It changes
    only which site the bound server is asked for, never where the request goes.
    """
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
    if virtual_host is not None:
        accepted_host = bound_virtual_host(virtual_host, target)
        if accepted_host is None or method not in {"GET", "HEAD"}:
            return {"ok": False, "error": "scope: virtual host is outside the bound root domains"}
        virtual_host = accepted_host
        follow_redirects = False
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
    # Classified again at connect: the confirmed list was judged at Hunt start, under the
    # deployment policy and cloud-service list of that moment.
    via_refusal = action_scope.direct_origin_refusal(via_address) if via_address else None
    if via_refusal is not None:
        return {
            "ok": False,
            "error": f"scope: via_address is refused as a direct origin ({via_refusal})",
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

    headers, rejected_headers = agent_tools.classify_request_headers(
        args.get("headers"), allow_identity_headers=allow_identity_headers,
    )
    accepted_header_names = sorted(str(name).strip().lower() for name in headers)
    headers.update(_trusted_headers(trusted_headers))
    # Declared identification (traffic_attribution): the run header, and the ShakerScan token on
    # the client's own User-Agent. A User-Agent the request sets itself is left as it is.
    # The caller's own headers decide whether a redirect may carry identity elsewhere; the
    # declared identification below is neutral (it names the run, not a principal).
    identity_headers = dict(headers)
    sender_key = _sender_key(principal_slot, headers, cookies, _trusted_headers(trusted_headers))
    present = {str(name).strip().lower() for name in headers}
    for name, value in agent_tools.traffic_attribution.headers().items():
        if name.lower() not in present:
            headers[name] = value
    if "user-agent" not in present:
        headers["User-Agent"] = agent_tools.traffic_attribution.with_user_agent(
            f"python-httpx/{httpx.__version__}")
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
    if _origin_key(url) != _origin_key(request_origin):
        # urljoin resolves a path whose first segment names a scheme ("/http://...") to another
        # URL; the request must stay on the bound origin.
        return {"ok": False, "error": "scope: request path resolves outside the frozen target origin"}
    prefetch_view: dict[str, Any] | None = None
    if args.get("form_prefetch") is True and method == "POST" and form_body is not None:
        # The form's own page first (runtime/form_prefetch): its hidden fields (an anti-CSRF
        # token) and the page's cookies go with this POST; the request's own fields win.
        from runtime import form_prefetch
        page_path = agent_tools.validate_same_origin_path(args.get("form_page") or path)
        if _origin_key(urllib.parse.urljoin(request_origin + "/", page_path.lstrip("/"))) != _origin_key(request_origin):
            return {"ok": False, "error": "scope: form_page resolves outside the frozen target origin"}
        seen: dict[str, Any] = {}

        def keep(private: WorkerPrivateHTTPResponse) -> None:
            seen["body"], seen["cookies"] = private.body(), dict(private.cookies() or {})

        page = await execute_bound_http_request(
            base_url, {"method": "GET", "path": page_path, "follow_redirects": False,
                       **({"origin": args["origin"]} if args.get("origin") else {})},
            target=target, trusted_headers=trusted_headers, allow_identity_headers=allow_identity_headers,
            direct_origin_addresses=direct_origin_addresses, transaction_recorder=transaction_recorder,
            cookies=cookies, principal_slot=principal_slot, timeout_seconds=timeout_seconds,
            private_response_sink=keep, response_body_limit=MAX_PRIVATE_BODY_BYTES)
        page_url = urllib.parse.urljoin(request_origin + "/", page_path.lstrip("/"))
        hidden = form_prefetch.hidden_fields(
            bytes(seen.get("body") or b"").decode("utf-8", "replace"), page_url=page_url, post_url=url)
        added = {name: value for name, value in hidden.items() if name not in form_body}
        form_body = {**form_body, **added}
        cookies = {**dict(seen.get("cookies") or {}), **dict(cookies or {})}
        prefetch_view = {"page": page_path, "status": (page.get("response") or {}).get("status"),
                         "hidden_fields": sorted(added), "cookies": sorted(dict(seen.get("cookies") or {}))}
    request_view = {
        "method": method,
        "origin": request_origin,
        "tls_verification": "not_enforced" if request_origin.startswith("https://") else "not_applicable",
        "path": path,
        "query_keys": sorted(query or {}),
        "as_principal": str(principal_slot or "anonymous")[:80],
        "body_kind": (
            "json" if json_body is not None
            else "form" if form_body is not None else None
        ),
        # Values remain hidden.  Reporting the decision prevents a planner from treating a
        # silently filtered experiment as one that reached the target as proposed.
        "accepted_header_names": accepted_header_names,
        "rejected_headers": dict(sorted(rejected_headers.items())),
        "pinned_address": pinned_address,
        # Recorded so a reader can always tell whether a response came through the target's
        # resolved address or an operator-confirmed origin. The two are not comparable
        # evidence and must never be conflated in a finding.
        "direct_origin": bool(via_address),
        "address_policy": socket_factory.policy_receipt,
        "follow_redirects": follow_redirects,
        **({"virtual_host": virtual_host} if virtual_host is not None else {}),
    }
    timeout = max(1, min(60, int(timeout_seconds)))
    started = time.perf_counter()
    request_started_at = datetime.now(timezone.utc)
    redirect_chain: list[dict[str, Any]] = []
    body_truncated = False
    hops_followed = 0
    connection_attempts = 0
    connected_addresses: list[str] = []
    last_connect_error: Exception | None = None
    response = None
    body = b""
    body_lookahead = bytearray()
    lookahead_state: dict[str, bool] = {"complete": True}
    final_url = url
    request_deadline = time.perf_counter() + max(0.001, float(timeout))
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
            # Targets may deliberately have defective certificates. Assess TLS separately.
            verify=False,
        ) as client:
            current_url = url
            current_method = method
            current_query = query
            current_json_body = json_body
            current_form_body = form_body
            while True:
                final_url = current_url
                # The Hunt's aggregate rate at this origin (runtime/origin_pace; no-op outside Hunts).
                await origin_pace.take(current_url)
                # The target asked to wait (429 Retry-After) or banned us: wait it out, as the
                # scanner tunnels do (runtime/target_backoff).
                # Bounded: a hold longer than this request may wait sends nothing (``_held_result``).
                backoff_origin = origin_pace.origin_of(current_url)
                if backoff_origin:
                    held = await TARGET_BACKOFF.wait_or_refuse(backoff_origin, MAX_IN_REQUEST_HOLD_SECONDS)
                    if held > 0:
                        return _held_result(held, TARGET_BACKOFF.reason(backoff_origin), request_view,
                                            hops_followed)
                hop_started = time.perf_counter()
                hop_started_at = datetime.now(timezone.utc)
                response = None
                for candidate_address in socket_factory.connection_addresses:
                    pinned_url, sni_hostname, host_header = (
                        agent_tools._pinned_scanner_url(
                            current_url, candidate_address,
                        )
                    )
                    if virtual_host is not None:
                        sni_hostname = virtual_host
                        host_header = virtual_host + _host_port_suffix(current_url)
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
                    sent_target = request.url.raw_path.decode("ascii", "replace") or "/"
                    try:
                        sent_body = _process_tag(request.content) if request.content else ""
                    except httpx.RequestNotRead:  # a streamed body: not comparable with another request
                        sent_body = ""
                    connection_attempts += 1
                    try:
                        response = await client.send(request, stream=True)
                    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                        # Retry only failures that happen before a connection.
                        # A post-connect failure may follow target traffic and
                        # must never duplicate a state-changing request.
                        last_connect_error = exc
                        continue
                    except httpx.TimeoutException:
                        # Connected, never answered: a hung or overloaded target.
                        if backoff_origin:
                            TARGET_BACKOFF.observe_silence(backoff_origin)
                        raise
                    pinned_address = candidate_address
                    connected_addresses.append(candidate_address)
                    break
                if response is None:
                    if backoff_origin:
                        TARGET_BACKOFF.observe_silence(backoff_origin)
                    # Keep the real cause on the chain: a certificate the client will not
                    # trust is a different finding from a port nobody answers on.
                    raise httpx.ConnectError(
                        "all frozen target addresses failed before connect"
                    ) from last_connect_error
                request_view["pinned_address"] = pinned_address
                if backoff_origin:
                    retry_after = response.headers.get("retry-after")
                    TARGET_BACKOFF.observe(
                        backoff_origin, int(response.status_code),
                        {b"retry-after": retry_after.encode("latin-1", "replace")} if retry_after else {},
                        # The request as sent, by who sent it: only its own replay, refused, can
                        # read as a ban (another account's 403, another query's, never does).
                        {"method": str(current_method).upper(), "target": sent_target,
                         "principal": sender_key, "fingerprint": sent_body})
                del body_lookahead[:]  # this hop's own
                try:
                    (
                        body,
                        response_body_sha256,
                        response_bytes,
                        body_truncated,
                        read_deadline_exceeded,
                    ) = await _read_bounded_response(
                        response,
                        deadline=request_deadline,
                        body_limit=max(1, min(int(response_body_limit), MAX_PRIVATE_BODY_BYTES)),
                        lookahead=body_lookahead,
                        lookahead_limit=CUT_LOOKAHEAD_CHARS,
                        lookahead_state=lookahead_state,
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
                        "location": bounded_public_url(location, 500),
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
                        "location": bounded_public_url(location, 500),
                        "followed": False,
                        "stopped": "cross_origin",
                    })
                    break
                if _origin_key(next_url) != _origin_key(current_url) and (
                    trusted_headers or cookies or (allow_identity_headers and identity_headers)
                    or getattr(client, "cookies", None)
                ):
                    # Target scope may include several services on one host. It
                    # never authorizes disclosing this request's identity to a
                    # different scheme or port, including cookies just received.
                    redirect_chain.append({
                        "status": response.status_code, "location": bounded_public_url(location, 500),
                        "followed": False, "stopped": "credential_destination",
                    })
                    break
                redirect_chain.append({
                    "status": response.status_code,
                    "location": bounded_public_url(location, 500),
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
        error_class = request_error_class(exc)
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
                    "error": error_class,
                    "fidelity": "attempted_no_response",
                })
            except Exception:  # pragma: no cover - recording must never mask the error
                pass
        return {
            "ok": False,
            "error": error_class,
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
            _body=body[:max(1, min(int(response_body_limit), MAX_PRIVATE_BODY_BYTES))],
            _headers={
                str(name).lower(): str(value)
                for name, value in response.headers.items()
                if str(name).lower() in {
                    "authorization", "content-type", "content-length",
                    "content-range", "accept-ranges", "location", "content-disposition",
                    *private_response_headers,
                }
            },
            _cookies={
                str(name): str(value)
                for name, value in response.cookies.items()
            },
            body_truncated=bool(body_truncated),
        ))
    summary = response_summary(
        response,
        body,
        lookahead=bytes(body_lookahead),
        lookahead_complete=lookahead_state["complete"],
        body_truncated=bool(body_truncated),
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
        # A CSP ``report-uri`` can carry a token: inside a Hunt it is withheld before the cut.
        name: (
            bounded_public_url(str(response.headers[name]), 2_000) if name in URL_BEARING_HEADERS
            else str(response.headers[name])[:2_000]
        )
        for name in _SECURITY_POSTURE_HEADERS
        if name in response.headers
    }
    if response.status_code == 401:
        # Which sign-in a 401 asks for (scheme names from a fixed set; never the realm or a value).
        schemes = sorted({
            scheme.lower() for value in response.headers.get_list("www-authenticate")[:8]
            for scheme in re.findall(r"(?:^|,)\s*([A-Za-z]{4,10})(?=\s|,|$)", str(value)[:1_000])
        } & _CHALLENGE_SCHEMES)
        if schemes:
            summary["challenge_schemes"] = schemes
    summary["set_cookie_metadata"] = [
        cookie for cookie in (
            cookie_metadata(value) for value in response.headers.get_list("set-cookie")[:50]
        ) if cookie is not None
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
    if prefetch_view is not None:
        result["form_prefetch"] = prefetch_view
        result["prefetch_requests"] = 1
    if active_withheld_values() is not None:
        # Inside a Hunt worker the result is the planner's view: every public URL field's secret
        # parameters become references (N56), for a plain GET as for a bound workflow request.
        mask_public_http_urls(result)
    return result
