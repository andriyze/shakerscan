"""Pinned passive web checks for one discovered connected-device origin.

The registered hostname remains the HTTP Host and TLS SNI identity, while every
socket connects to the address resolved and authorized by the parent device
scan. Redirects are observed but never allowed to change the connected host.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import ssl
import time
import urllib.parse
from typing import Any

from .device_postman import (
    SAFE_METHODS,
    STATE_CHANGING_METHODS,
    public_request_url,
    redacted_header_names,
)
from .device_request_formats import resolve_imported_requests


MAX_RESPONSE_BYTES = 256 * 1024
MAX_REDIRECTS = 5
IMPORTED_REQUEST_LIMITS = {"quick": 50, "standard": 200, "deep": 500}
IMPORTED_REQUEST_TIME_BUDGETS = {"quick": 60.0, "standard": 180.0, "deep": 480.0}
PROFILE_PATHS = {
    "quick": ("/",),
    "standard": ("/", "/.well-known/security.txt", "/robots.txt"),
    "deep": ("/", "/.well-known/security.txt", "/robots.txt", "/favicon.ico", "/description.xml", "/system.xml"),
}


class _DeviceWebCancelled(Exception):
    pass


async def _cancelable_request(cancel_check: Any, **kwargs: Any) -> dict[str, Any]:
    task = asyncio.create_task(_request(**kwargs))
    try:
        while not task.done():
            done, _pending = await asyncio.wait({task}, timeout=0.25)
            if done:
                break
            if callable(cancel_check):
                requested = cancel_check()
                if hasattr(requested, "__await__"):
                    requested = await requested
                if requested:
                    task.cancel()
                    try:
                        await task
                    except (asyncio.CancelledError, Exception):
                        pass
                    raise _DeviceWebCancelled()
        return await task
    except BaseException:
        if not task.done():
            task.cancel()
        raise


def _host_header(host: str, port: int, scheme: str) -> str:
    formatted = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    return formatted if port == default else f"{formatted}:{port}"


def _parse_response(data: bytes) -> tuple[int, dict[str, str], bytes]:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    try:
        status = int(lines[0].split(" ", 2)[1])
    except (IndexError, ValueError):
        status = 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    return status, headers, body


async def _read_response(reader: asyncio.StreamReader, timeout: float, *, expect_body: bool = True) -> tuple[int, dict[str, str], bytes, bool]:
    """Read a bounded HTTP/1 response without requiring an embedded server to close."""
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
        partial = getattr(exc, "partial", b"")
        if not partial:
            raise
        head = partial
    status, headers, body = _parse_response(head)
    truncated = False
    if not expect_body or status in {204, 304} or 100 <= status < 200:
        return status, headers, b"", False
    content_length = headers.get("content-length")
    if content_length and content_length.isdigit():
        expected = int(content_length)
        wanted = min(expected, MAX_RESPONSE_BYTES + 1)
        if len(body) < wanted:
            try:
                body += await asyncio.wait_for(reader.readexactly(wanted - len(body)), timeout=timeout)
            except asyncio.IncompleteReadError as exc:
                body += exc.partial
        truncated = expected > MAX_RESPONSE_BYTES or len(body) > MAX_RESPONSE_BYTES
    elif "chunked" in headers.get("transfer-encoding", "").lower():
        chunks = bytearray()
        while len(chunks) <= MAX_RESPONSE_BYTES:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            size_text = line.split(b";", 1)[0].strip()
            if len(size_text) > 16:
                truncated = True
                break
            try:
                size = int(size_text, 16)
            except ValueError:
                break
            if size == 0:
                break
            remaining = MAX_RESPONSE_BYTES + 1 - len(chunks)
            if remaining <= 0:
                truncated = True
                break
            wanted = min(size, remaining)
            chunk = await asyncio.wait_for(reader.readexactly(wanted), timeout=timeout)
            chunks.extend(chunk)
            if size > wanted:
                # Do not consume a device-controlled multi-gigabyte chunk merely
                # to find its terminator. The caller closes this exact socket.
                truncated = True
                break
            await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        body = bytes(chunks)
        truncated = truncated or len(body) > MAX_RESPONSE_BYTES
    else:
        chunks = bytearray(body)
        while len(chunks) <= MAX_RESPONSE_BYTES:
            try:
                chunk = await asyncio.wait_for(reader.read(min(64 * 1024, MAX_RESPONSE_BYTES + 1 - len(chunks))), timeout=0.5)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            chunks.extend(chunk)
        body = bytes(chunks)
        truncated = len(body) > MAX_RESPONSE_BYTES
    return status, headers, body[:MAX_RESPONSE_BYTES], truncated


async def _request(
    *,
    connect_address: str,
    hostname: str,
    port: int,
    scheme: str,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes = b"",
    timeout: float = 8.0,
) -> dict[str, Any]:
    context = None
    if scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            connect_address,
            port,
            ssl=context,
            server_hostname=hostname if scheme == "https" else None,
        ),
        timeout=timeout,
    )
    tls_info: dict[str, Any] | None = None
    get_extra_info = getattr(writer, "get_extra_info", None)
    ssl_object = get_extra_info("ssl_object") if callable(get_extra_info) else None
    if ssl_object is not None:
        peer_der = ssl_object.getpeercert(binary_form=True) or b""
        cipher = ssl_object.cipher()
        tls_info = {
            "protocol": ssl_object.version(),
            "cipher": cipher[0] if cipher else None,
            "peer_certificate_sha256": hashlib.sha256(peer_der).hexdigest() if peer_der else None,
        }
    request_headers = {
        "Host": _host_header(hostname, port, scheme),
        "User-Agent": "ShakerScan-Device/1",
        "Accept": "*/*",
        "Connection": "close",
        **headers,
    }
    if body:
        request_headers["Content-Length"] = str(len(body))
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        + "".join(f"{name}: {value}\r\n" for name, value in request_headers.items())
        + "\r\n"
    ).encode("latin-1", "ignore") + body
    writer.write(request)
    await writer.drain()
    try:
        status, response_headers, response_body, truncated = await _read_response(reader, timeout, expect_body=method.upper() != "HEAD")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return {
        "status": status,
        "headers": response_headers,
        "body": response_body,
        "truncated": truncated,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
        "tls": tls_info,
    }


async def _assess_tls_trust(
    *, connect_address: str, hostname: str, port: int, timeout: float = 8.0,
) -> dict[str, Any]:
    """Perform a separate strict handshake without sending an HTTP request."""
    context = ssl.create_default_context()
    writer: asyncio.StreamWriter | None = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                connect_address, port, ssl=context, server_hostname=hostname,
            ),
            timeout=timeout,
        )
        get_extra_info = getattr(writer, "get_extra_info", None)
        ssl_object = get_extra_info("ssl_object") if callable(get_extra_info) else None
        cipher = ssl_object.cipher() if ssl_object is not None else None
        return {
            "trusted": True,
            "verification_error": None,
            "protocol": ssl_object.version() if ssl_object is not None else None,
            "cipher": cipher[0] if cipher else None,
        }
    except ssl.SSLCertVerificationError as exc:
        return {
            "trusted": False,
            "verification_error": str(exc.verify_message or "certificate verification failed")[:500],
            "verification_code": int(exc.verify_code),
        }
    except Exception as exc:
        return {
            "trusted": False,
            "verification_error": f"strict_tls_handshake_failed:{type(exc).__name__}",
        }
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def request_pinned_device_http(
    *,
    connect_address: str,
    hostname: str,
    port: int,
    scheme: str,
    method: str = "GET",
    path: str = "/",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Send one exact-destination HTTP request for a server-owned device adapter.

    This is deliberately narrower than the imported-request executor.  Callers
    must provide a request selected from ShakerScan's immutable device catalog;
    the socket remains pinned to ``connect_address`` while ``hostname`` is used
    only for Host and TLS SNI.
    """
    normalized_scheme = str(scheme or "").strip().lower()
    normalized_method = str(method or "").strip().upper()
    if normalized_scheme not in {"http", "https"}:
        raise ValueError("device adapter scheme must be http or https")
    if normalized_method not in {"GET", "HEAD", "POST"}:
        raise ValueError("device adapter method is not permitted")
    if not isinstance(path, str) or not path.startswith("/") or "\r" in path or "\n" in path:
        raise ValueError("device adapter path must be one relative HTTP path")
    if not 1 <= int(port) <= 65535:
        raise ValueError("device adapter port is invalid")
    return await _request(
        connect_address=str(connect_address),
        hostname=str(hostname),
        port=int(port),
        scheme=normalized_scheme,
        method=normalized_method,
        path=path,
        headers=dict(headers or {}),
        body=bytes(body),
        timeout=float(timeout),
    )


def _origin_request_path(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    return urllib.parse.urlunsplit(("", "", path, parsed.query, ""))


def _request_matches_origin(
    request: dict[str, Any],
    *,
    origin: str,
    connect_address: str,
    default_origin: bool,
) -> tuple[bool, str | None]:
    if request.get("error"):
        return False, str(request["error"])
    if request.get("unresolved_variables"):
        return False, "unresolved_variables"
    url = str(request.get("url") or "").strip()
    if not url:
        return False, "missing_url"
    try:
        parsed = urllib.parse.urlsplit(url)
        origin_parsed = urllib.parse.urlsplit(origin)
        if parsed.scheme or parsed.netloc:
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return False, "unsupported_url_scheme"
            allowed_hosts = {str(origin_parsed.hostname or "").lower(), connect_address.lower()}
            if str(parsed.hostname).lower() not in allowed_hosts:
                return False, "external_host_blocked"
            request_port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
            origin_port = int(origin_parsed.port or (443 if origin_parsed.scheme == "https" else 80))
            if request_port != origin_port or parsed.scheme != origin_parsed.scheme:
                return False, "different_discovered_origin"
        elif not default_origin:
            return False, "relative_request_bound_to_primary_origin"
    except (TypeError, ValueError):
        return False, "invalid_url"
    return True, None


def _safe_request_headers(headers: dict[str, str]) -> dict[str, str]:
    blocked = {"host", "connection", "content-length", "transfer-encoding", "proxy-authorization"}
    return {
        str(key): str(value)
        for key, value in headers.items()
        if str(key).lower() not in blocked
        and "\r" not in str(key) and "\n" not in str(key)
        and "\r" not in str(value) and "\n" not in str(value)
    }


def _public_response_headers(headers: dict[str, str]) -> dict[str, str]:
    allowed = {
        "server", "content-type", "content-length", "location", "allow",
        "access-control-allow-origin", "access-control-allow-credentials",
        "strict-transport-security", "x-content-type-options", "x-frame-options",
        "content-security-policy", "referrer-policy", "cache-control", "pragma",
    }
    result = {
        key: (public_request_url(value) if key.lower() == "location" else value[:1000])
        for key, value in headers.items() if key.lower() in allowed
    }
    if "set-cookie" in {key.lower() for key in headers}:
        result["set-cookie"] = "<redacted>"
    return result


def _security_header_findings(
    *, origin: str, response_url: str, status: int, headers: dict[str, str], authenticated: bool,
) -> list[dict[str, Any]]:
    """Build contextual embedded-management header findings from one concrete response."""
    if not 200 <= int(status or 0) < 400:
        return []
    normalized = {str(key).lower(): str(value) for key, value in headers.items()}
    content_type = normalized.get("content-type", "").lower()
    html = "text/html" in content_type or "application/xhtml" in content_type
    parsed = urllib.parse.urlsplit(origin)
    findings: list[dict[str, Any]] = []

    def add(title: str, severity: str, description: str, recommendation: str, missing: list[str]) -> None:
        finding = {
            "type": "Device management interface headers",
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "url": public_request_url(response_url),
            "tool": "device_web_headers",
            "source": "device",
            "evidence": {
                "status": int(status),
                "content_type": content_type[:200],
                "missing_headers": missing,
                "authenticated_request": bool(authenticated),
            },
        }
        # One finding per origin/header control, rather than one duplicate per probed path.
        finding["fingerprint"] = hashlib.sha256(
            json.dumps([title, public_request_url(origin)], separators=(",", ":")).encode()
        ).hexdigest()
        findings.append(finding)

    if parsed.scheme == "https" and parsed.hostname:
        try:
            ipaddress.ip_address(parsed.hostname)
            hostname_based = False
        except ValueError:
            hostname_based = True
        if hostname_based and not normalized.get("strict-transport-security"):
            add(
                "Device HTTPS management interface does not declare HSTS", "low",
                "A hostname-based HTTPS management interface omitted Strict-Transport-Security.",
                "After validating certificate deployment and HTTP redirect behavior, enable a bounded HSTS policy for the device hostname.",
                ["strict-transport-security"],
            )
    if html:
        csp = normalized.get("content-security-policy", "")
        if not csp:
            add(
                "Device management page has no Content Security Policy", "low",
                "The HTML management page did not declare a Content-Security-Policy header.",
                "Deploy a restrictive policy based on script nonces or hashes and explicitly constrain object, frame, and connection sources.",
                ["content-security-policy"],
            )
        if not normalized.get("x-frame-options") and "frame-ancestors" not in csp.lower():
            add(
                "Device management page lacks framing protection", "low",
                "The HTML management page declared neither X-Frame-Options nor CSP frame-ancestors.",
                "Set CSP frame-ancestors or X-Frame-Options to prevent unauthorized framing of management actions.",
                ["x-frame-options", "content-security-policy: frame-ancestors"],
            )
        if normalized.get("x-content-type-options", "").lower() != "nosniff":
            add(
                "Device management page allows content-type sniffing", "info",
                "The HTML management response did not declare X-Content-Type-Options: nosniff.",
                "Return X-Content-Type-Options: nosniff on management and API responses.",
                ["x-content-type-options: nosniff"],
            )
    if authenticated:
        cache_control = normalized.get("cache-control", "").lower()
        if "no-store" not in cache_control and "private" not in cache_control:
            add(
                "Authenticated device response lacks private cache controls", "medium",
                "An authenticated management response did not prohibit shared or persistent caching.",
                "Return Cache-Control: no-store for sensitive management responses, or at minimum a suitable private policy.",
                ["cache-control: no-store|private"],
            )
    cookie = normalized.get("set-cookie", "")
    if cookie:
        missing_cookie = []
        lower_cookie = cookie.lower()
        if parsed.scheme == "https" and "secure" not in lower_cookie:
            missing_cookie.append("Secure")
        if "httponly" not in lower_cookie:
            missing_cookie.append("HttpOnly")
        if "samesite=" not in lower_cookie:
            missing_cookie.append("SameSite")
        if missing_cookie:
            add(
                "Device management cookie lacks protective attributes", "medium",
                "A management response issued a cookie without all expected transport, script-access, and cross-site protections.",
                "Mark session cookies Secure on HTTPS, HttpOnly, and with an appropriate SameSite policy.",
                [f"set-cookie: {item}" for item in missing_cookie],
            )
    return findings


def _request_finding(
    *, title: str, severity: str, description: str, recommendation: str,
    url: str, collection_id: str, request_id: str, evidence: dict[str, Any],
) -> dict[str, Any]:
    finding = {
        "type": "Device API request assessment",
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "url": public_request_url(url),
        "tool": "device_request_dast",
        "source": "device",
        "evidence": {
            "collection_id": collection_id,
            "request_id": request_id,
            **evidence,
        },
    }
    finding["fingerprint"] = hashlib.sha256(
        json.dumps([title, collection_id, request_id, finding["url"]], separators=(",", ":")).encode()
    ).hexdigest()
    return finding


async def _run_imported_requests(
    *,
    origin_info: dict[str, Any],
    request_collections: list[dict[str, Any]],
    profile: str,
    allow_state_changing_requests: bool,
    default_origin: bool,
    base_headers: dict[str, str] | None,
    tls_assessment: dict[str, Any] | None,
    allow_untrusted_tls_credentials: bool,
    deadline: float,
    cancel_check: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    origin = str(origin_info.get("origin") or "")
    parsed_origin = urllib.parse.urlsplit(origin)
    hostname = str(parsed_origin.hostname or "")
    scheme = str(parsed_origin.scheme or "")
    port = int(parsed_origin.port or (443 if scheme == "https" else 80))
    connect_address = str(origin_info.get("connect_address") or "")
    limit = IMPORTED_REQUEST_LIMITS.get(profile, IMPORTED_REQUEST_LIMITS["standard"])
    observations: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    attempted = 0
    for collection in request_collections:
        collection_id = str(collection.get("collection_id") or "")
        collection_name = str(collection.get("name") or "Imported requests")
        try:
            requests = resolve_imported_requests(collection.get("payload") or {})
        except Exception as exc:
            skipped.append({"collection_id": collection_id, "reason": f"collection_resolution_failed:{type(exc).__name__}"})
            continue
        for imported in requests:
            if time.monotonic() >= deadline:
                skipped.append({"collection_id": collection_id, "request_id": imported.get("id"), "reason": "profile_time_budget"})
                continue
            if attempted >= limit:
                skipped.append({"collection_id": collection_id, "request_id": imported.get("id"), "reason": "profile_request_limit"})
                continue
            method = str(imported.get("method") or "GET").upper()
            matches, reason = _request_matches_origin(
                imported, origin=origin, connect_address=connect_address, default_origin=default_origin,
            )
            if not matches:
                skipped.append({"collection_id": collection_id, "request_id": imported.get("id"), "name": imported.get("name"), "method": method, "reason": reason})
                continue
            if method not in SAFE_METHODS and method not in STATE_CHANGING_METHODS:
                skipped.append({"collection_id": collection_id, "request_id": imported.get("id"), "name": imported.get("name"), "method": method, "reason": "unsupported_method"})
                continue
            if method in STATE_CHANGING_METHODS and not allow_state_changing_requests:
                skipped.append({"collection_id": collection_id, "request_id": imported.get("id"), "name": imported.get("name"), "method": method, "reason": "state_changing_request_not_confirmed"})
                continue
            if callable(cancel_check):
                requested = cancel_check()
                if hasattr(requested, "__await__"):
                    requested = await requested
                if requested:
                    return {
                        "schema_version": "device-request-dast/v1", "origin": origin,
                        "executed": len(observations), "skipped": len(skipped), "cancelled": True,
                        "observations": observations, "skipped_requests": skipped[:500],
                    }, findings
            headers = dict(base_headers or {})
            headers.update(dict(imported.get("headers") or {}))
            headers = _safe_request_headers(headers)
            has_sensitive_material = bool(imported.get("has_sensitive_material")) or any(
                str(key).lower() in {"authorization", "cookie", "x-api-key", "api-key"} for key in headers
            )
            if (
                scheme == "https" and has_sensitive_material
                and tls_assessment is not None and not tls_assessment.get("trusted")
                and not allow_untrusted_tls_credentials
            ):
                skipped.append({
                    "collection_id": collection_id,
                    "request_id": imported.get("id"),
                    "name": imported.get("name"),
                    "method": method,
                    "reason": "untrusted_tls_credentials_not_confirmed",
                })
                continue
            attempted += 1
            body = imported.get("body") if isinstance(imported.get("body"), bytes) else b""
            path = _origin_request_path(str(imported.get("url") or ""))
            try:
                remaining = max(0.1, deadline - time.monotonic())
                response = await _cancelable_request(
                    cancel_check,
                    connect_address=connect_address, hostname=hostname, port=port, scheme=scheme,
                    method=method, path=path, headers=headers, body=body,
                    timeout=min(8.0, remaining),
                )
            except _DeviceWebCancelled:
                return {
                    "schema_version": "device-request-dast/v1", "origin": origin,
                    "executed": len(observations), "skipped": len(skipped), "cancelled": True,
                    "observations": observations, "skipped_requests": skipped[:500],
                }, findings
            except Exception as exc:
                skipped.append({"collection_id": collection_id, "request_id": imported.get("id"), "name": imported.get("name"), "method": method, "reason": f"request_failed:{type(exc).__name__}"})
                continue
            response_body = bytes(response.get("body") or b"")
            observation = {
                "collection_id": collection_id,
                "collection_name": collection_name,
                "request_id": imported.get("id"),
                "name": imported.get("name"),
                "folder": imported.get("folder"),
                "method": method,
                "url": public_request_url(str(imported.get("url") or "")),
                "request_header_names": redacted_header_names(headers),
                "request_body_bytes": len(body),
                "status": int(response.get("status") or 0),
                "response_headers": _public_response_headers(dict(response.get("headers") or {})),
                "response_body_bytes": len(response_body),
                "response_sha256": hashlib.sha256(response_body).hexdigest(),
                "truncated": bool(response.get("truncated")),
                "elapsed_ms": response.get("elapsed_ms"),
            }
            observations.append(observation)
            request_url = urllib.parse.urlunsplit((scheme, parsed_origin.netloc, path.split("?", 1)[0], path.partition("?")[2], ""))
            response_headers = {str(key).lower(): str(value) for key, value in dict(response.get("headers") or {}).items()}
            if scheme == "http" and has_sensitive_material:
                findings.append(_request_finding(
                    title="Sensitive imported API request uses cleartext HTTP", severity="high",
                    description="A saved API request containing authentication or another sensitive header was replayed over unencrypted HTTP.",
                    recommendation="Move the device API to HTTPS or isolate it on a tightly controlled management network.",
                    url=request_url, collection_id=collection_id, request_id=str(imported.get("id") or ""),
                    evidence={"method": method, "status": observation["status"], "request_header_names": observation["request_header_names"]},
                ))
            if (
                scheme == "https" and has_sensitive_material
                and tls_assessment is not None and not tls_assessment.get("trusted")
                and allow_untrusted_tls_credentials
            ):
                findings.append(_request_finding(
                    title="Sensitive API request sent over unverified TLS", severity="high",
                    description="The operator explicitly permitted a saved request containing authentication material to be sent even though the device certificate could not be verified.",
                    recommendation="Pin a trusted device certificate or isolate the management path before sending reusable secrets.",
                    url=request_url, collection_id=collection_id, request_id=str(imported.get("id") or ""),
                    evidence={
                        "method": method,
                        "status": observation["status"],
                        "tls_verification_error": tls_assessment.get("verification_error"),
                        "operator_override": True,
                    },
                ))
            if response_headers.get("access-control-allow-origin") == "*" and response_headers.get("access-control-allow-credentials", "").lower() == "true":
                findings.append(_request_finding(
                    title="Device API returns an invalid wildcard credentialed CORS policy", severity="low",
                    description="The API combines a wildcard origin with credential allowance. Browsers reject this combination, so it is a configuration defect rather than proof of cross-origin credential theft.",
                    recommendation="Allow only explicitly trusted management origins and verify that untrusted Origin values are never reflected with credentials.",
                    url=request_url, collection_id=collection_id, request_id=str(imported.get("id") or ""),
                    evidence={"method": method, "status": observation["status"], "acao": "*", "credentials": True},
                ))
            set_cookie = response_headers.get("set-cookie", "")
            if set_cookie and scheme == "https" and "secure" not in set_cookie.lower():
                findings.append(_request_finding(
                    title="Device API cookie lacks the Secure attribute", severity="medium",
                    description="The HTTPS API issued a cookie without the Secure attribute.",
                    recommendation="Mark authentication and session cookies Secure, HttpOnly, and with an appropriate SameSite policy.",
                    url=request_url, collection_id=collection_id, request_id=str(imported.get("id") or ""),
                    evidence={"method": method, "status": observation["status"], "cookie_value_redacted": True},
                ))

            # Standard/deep: compare safe authenticated requests without credentials.
            if profile in {"standard", "deep"} and method in SAFE_METHODS and imported.get("has_sensitive_material") and 200 <= observation["status"] < 300:
                sensitive_names = {
                    "authorization", "cookie", "x-api-key", "api-key",
                    *[str(name).lower() for name in imported.get("sensitive_header_names") or []],
                }
                stripped_headers = {key: value for key, value in headers.items() if key.lower() not in sensitive_names}
                try:
                    anonymous = await _cancelable_request(
                        cancel_check,
                        connect_address=connect_address, hostname=hostname, port=port, scheme=scheme,
                        method=method, path=path, headers=stripped_headers, body=body,
                        timeout=min(8.0, max(0.1, deadline - time.monotonic())),
                    )
                    anonymous_body = bytes(anonymous.get("body") or b"")
                    if (
                        200 <= int(anonymous.get("status") or 0) < 300
                        and hashlib.sha256(anonymous_body).digest() == hashlib.sha256(response_body).digest()
                        and len(anonymous_body) == len(response_body)
                    ):
                        negative_path = (
                            "/.shakerscan-auth-negative-"
                            + hashlib.sha256(
                                f"{collection_id}:{imported.get('id')}".encode()
                            ).hexdigest()[:16]
                        )
                        negative = await _cancelable_request(
                            cancel_check,
                            connect_address=connect_address, hostname=hostname, port=port, scheme=scheme,
                            method="GET", path=negative_path, headers=stripped_headers, body=b"",
                            timeout=min(8.0, max(0.1, deadline - time.monotonic())),
                        )
                        negative_body = bytes(negative.get("body") or b"")
                        negative_differs = bool(
                            int(negative.get("status") or 0) != int(anonymous.get("status") or 0)
                            or hashlib.sha256(negative_body).digest() != hashlib.sha256(anonymous_body).digest()
                        )
                        findings.append(_request_finding(
                            title="Imported authenticated request also succeeds without credentials", severity="medium",
                            description="Removing imported authorization material produced the same successful response. This may indicate a public endpoint or missing access control and requires review.",
                            recommendation="Confirm whether this endpoint is intentionally public; otherwise enforce authentication and authorization server-side.",
                            url=request_url, collection_id=collection_id, request_id=str(imported.get("id") or ""),
                            evidence={
                                "method": method,
                                "authenticated_status": observation["status"],
                                "anonymous_status": int(anonymous.get("status") or 0),
                                "response_match": True,
                                "authenticated_body_sha256": hashlib.sha256(response_body).hexdigest(),
                                "anonymous_body_sha256": hashlib.sha256(anonymous_body).hexdigest(),
                                "negative_control_status": int(negative.get("status") or 0),
                                "negative_control_differs": negative_differs,
                                "generic_response_shell": not negative_differs,
                                "verdict": "review_required",
                            },
                        ))
                except Exception:
                    pass

    return {
        "schema_version": "device-request-dast/v1",
        "origin": origin,
        "profile": profile,
        "request_limit": limit,
        "time_budget_seconds": IMPORTED_REQUEST_TIME_BUDGETS.get(profile, IMPORTED_REQUEST_TIME_BUDGETS["standard"]),
        "executed": len(observations),
        "skipped": len(skipped),
        "skipped_actionable": sum(1 for item in skipped if item.get("reason") not in {"different_discovered_origin", "relative_request_bound_to_primary_origin"}),
        "routed_elsewhere": sum(1 for item in skipped if item.get("reason") in {"different_discovered_origin", "relative_request_bound_to_primary_origin"}),
        "cancelled": False,
        "allow_state_changing_requests": allow_state_changing_requests,
        "allow_untrusted_tls_credentials": allow_untrusted_tls_credentials,
        "observations": observations,
        "skipped_requests": skipped[:500],
        "findings_count": len(findings),
    }, findings


async def run_pinned_device_web_scan(
    origin_info: dict[str, Any],
    *,
    profile: str,
    credential: dict[str, Any] | None = None,
    request_collections: list[dict[str, Any]] | None = None,
    allow_state_changing_requests: bool = False,
    allow_untrusted_tls_credentials: bool = False,
    default_origin: bool = False,
    cancel_check: Any = None,
) -> dict[str, Any]:
    origin = str(origin_info.get("origin") or "").strip()
    parsed = urllib.parse.urlsplit(origin)
    hostname = str(parsed.hostname or "").strip().lower()
    scheme = str(parsed.scheme or "").lower()
    connect_address = str(origin_info.get("connect_address") or "").strip()
    if scheme not in {"http", "https"} or not hostname:
        raise ValueError("device web origin must be one absolute HTTP(S) origin")
    try:
        ipaddress.ip_address(connect_address)
    except ValueError as exc:
        raise ValueError("device web child requires one pinned IP address") from exc
    port = int(parsed.port or (443 if scheme == "https" else 80))
    if int(origin_info.get("port") or port) != port:
        raise ValueError("device web origin port does not match pinned discovery evidence")
    raw_host_header = str(origin_info.get("host_header") or "").strip()
    expected_host = str(urllib.parse.urlsplit(f"//{raw_host_header}").hostname or "").lower()
    if expected_host and expected_host != hostname:
        raise ValueError("device web origin hostname does not match pinned discovery evidence")

    request_headers: dict[str, str] = {}
    tls_assessment = await _assess_tls_trust(
        connect_address=connect_address, hostname=hostname, port=port,
    ) if scheme == "https" else None
    tls_findings: list[dict[str, Any]] = []
    if tls_assessment is not None and not tls_assessment.get("trusted"):
        tls_finding = {
            "type": "Device TLS assessment",
            "title": "Device HTTPS trust could not be established",
            "severity": "medium",
            "description": "The strict TLS handshake or certificate verification failed for this device web interface. Non-secret assessment remains available, but credentials are withheld unless the operator explicitly accepts the interception risk.",
            "recommendation": "Install or pin a certificate trusted for the device hostname, or isolate the management interface on a trusted network.",
            "url": public_request_url(origin),
            "tool": "device_tls",
            "source": "device",
            "evidence": {
                "verification_error": tls_assessment.get("verification_error"),
                "credentials_withheld_by_default": True,
            },
        }
        tls_finding["fingerprint"] = hashlib.sha256(
            json.dumps([tls_finding["title"], tls_finding["url"]], separators=(",", ":")).encode()
        ).hexdigest()
        tls_findings.append(tls_finding)
    credentials_attempted = False
    credentials_withheld = False
    authentication_succeeded = False
    cancelled = False
    if (
        credential and scheme == "https" and tls_assessment is not None
        and not tls_assessment.get("trusted") and not allow_untrusted_tls_credentials
    ):
        credentials_withheld = True
    elif credential:
        kind = str(credential.get("auth_kind") or "")
        secret = str(credential.get("secret") or "")
        if kind == "web_authorization_header":
            request_headers["Authorization"] = secret
            credentials_attempted = True
        elif kind == "web_cookie":
            request_headers["Cookie"] = secret
            credentials_attempted = True
        elif kind == "web_form":
            login_path = str(credential.get("login_path") or "/login")
            if not login_path.startswith("/") or "//" in login_path or any(ch in login_path for ch in "\r\n"):
                raise ValueError("device web login path must be one relative path")
            form_body = urllib.parse.urlencode({
                "username": str(credential.get("username") or ""),
                "password": secret,
            }).encode()
            try:
                login = await _cancelable_request(
                    cancel_check,
                    connect_address=connect_address,
                    hostname=hostname,
                    port=port,
                    scheme=scheme,
                    method="POST",
                    path=login_path,
                    headers={},
                    body=form_body,
                )
            except _DeviceWebCancelled:
                login = {"status": 0, "headers": {}}
                cancelled = True
            credentials_attempted = True
            authentication_succeeded = 200 <= int(login.get("status") or 0) < 400
            cookie = str((login.get("headers") or {}).get("set-cookie") or "").split(";", 1)[0]
            if cookie:
                request_headers["Cookie"] = cookie

    observations: list[dict[str, Any]] = []
    header_findings: dict[str, dict[str, Any]] = {}
    redirect_chain: list[str] = []
    final_url = origin
    for path in (() if cancelled else PROFILE_PATHS.get(profile, PROFILE_PATHS["standard"])):
        if callable(cancel_check):
            requested = cancel_check()
            if hasattr(requested, "__await__"):
                requested = await requested
            if requested:
                cancelled = True
                break
        current_path = path
        for _redirect in range(MAX_REDIRECTS + 1):
            try:
                response = await _cancelable_request(
                    cancel_check,
                    connect_address=connect_address,
                    hostname=hostname,
                    port=port,
                    scheme=scheme,
                    method="GET",
                    path=current_path,
                    headers=request_headers,
                )
            except _DeviceWebCancelled:
                cancelled = True
                break
            response_url = urllib.parse.urlunsplit((scheme, parsed.netloc, current_path, "", ""))
            observations.append({
                "url": response_url,
                "path": current_path,
                "status": response["status"],
                "headers": _public_response_headers(response["headers"]),
                "body_bytes": len(response["body"]),
                "truncated": response["truncated"],
                "elapsed_ms": response["elapsed_ms"],
            })
            for finding in _security_header_findings(
                origin=origin,
                response_url=response_url,
                status=int(response["status"]),
                headers=dict(response["headers"]),
                authenticated=bool(request_headers),
            ):
                header_findings.setdefault(str(finding["fingerprint"]), finding)
            if tls_assessment is not None and isinstance(response.get("tls"), dict):
                tls_assessment.update({
                    key: value for key, value in response["tls"].items()
                    if value is not None
                })
            location = str(response["headers"].get("location") or "")
            if response["status"] not in {301, 302, 303, 307, 308} or not location:
                final_url = response_url
                break
            next_url = urllib.parse.urljoin(response_url, location)
            redirect_chain.append(next_url)
            next_parsed = urllib.parse.urlsplit(next_url)
            if (
                str(next_parsed.hostname or "").lower() != hostname
                or str(next_parsed.scheme or "").lower() != scheme
                or int(next_parsed.port or (443 if scheme == "https" else 80)) != port
            ):
                final_url = next_url
                break
            current_path = urllib.parse.urlunsplit(("", "", next_parsed.path or "/", next_parsed.query, ""))
        if cancelled:
            break

    root = next((item for item in observations if item.get("path") == "/"), observations[0] if observations else {})
    status_code = int(root.get("status") or 0)
    if credentials_attempted and not authentication_succeeded:
        authentication_succeeded = 200 <= status_code < 400 and status_code not in {401, 403}
    imported_result = None
    imported_findings: list[dict[str, Any]] = []
    if request_collections and not cancelled:
        request_deadline = time.monotonic() + IMPORTED_REQUEST_TIME_BUDGETS.get(
            profile, IMPORTED_REQUEST_TIME_BUDGETS["standard"],
        )
        imported_result, imported_findings = await _run_imported_requests(
            origin_info=origin_info,
            request_collections=request_collections,
            profile=profile,
            allow_state_changing_requests=allow_state_changing_requests,
            default_origin=default_origin,
            base_headers=request_headers,
            tls_assessment=tls_assessment,
            allow_untrusted_tls_credentials=allow_untrusted_tls_credentials,
            deadline=request_deadline,
            cancel_check=cancel_check,
        )
        cancelled = cancelled or bool(imported_result.get("cancelled"))
    error = "Cancelled by user" if cancelled else None
    return {
        "http": {
            "request_url": origin,
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "remote_ip": connect_address,
            "pinned_address": connect_address,
            "host_header": _host_header(hostname, port, scheme),
            "sni": hostname if scheme == "https" else None,
            "status_code": status_code,
        },
        "result": {"score": None, "grade": None},
        "findings": tls_findings + list(header_findings.values()) + imported_findings,
        "device_web": {
            "schema_version": "device-web-pinned/v1",
            "origin": origin,
            "connect_address": connect_address,
            "profile": profile,
            "observations": observations,
            "credentials_attempted": credentials_attempted,
            "credentials_withheld": credentials_withheld,
            "authentication_succeeded": authentication_succeeded,
            "tls_assessment": tls_assessment,
            "imported_requests": imported_result,
        },
        "scan_metadata": {
            "run_kind": "device_web_dast",
            "active_testing": bool(allow_state_changing_requests),
            "state_changing_requests_authorized": bool(allow_state_changing_requests),
            "credentials_attempted": credentials_attempted,
            "credentials_withheld": credentials_withheld,
            "allow_untrusted_tls_credentials": allow_untrusted_tls_credentials,
            "pinned_destination": True,
        },
        "error": error,
    }
