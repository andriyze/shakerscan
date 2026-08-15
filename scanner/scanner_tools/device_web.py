"""Pinned passive web checks for one discovered connected-device origin.

The registered hostname remains the HTTP Host and TLS SNI identity, while every
socket connects to the address resolved and authorized by the parent device
scan. Redirects are observed but never allowed to change the connected host.
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
import time
import urllib.parse
from typing import Any


MAX_RESPONSE_BYTES = 256 * 1024
MAX_REDIRECTS = 5
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
    data = await asyncio.wait_for(reader.read(MAX_RESPONSE_BYTES + 1), timeout=timeout)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    truncated = len(data) > MAX_RESPONSE_BYTES
    status, response_headers, response_body = _parse_response(data[:MAX_RESPONSE_BYTES])
    return {
        "status": status,
        "headers": response_headers,
        "body": response_body,
        "truncated": truncated,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
    }


async def run_pinned_device_web_scan(
    origin_info: dict[str, Any],
    *,
    profile: str,
    credential: dict[str, Any] | None = None,
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
    credentials_attempted = False
    authentication_succeeded = False
    cancelled = False
    if credential:
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
                "headers": response["headers"],
                "body_bytes": len(response["body"]),
                "truncated": response["truncated"],
                "elapsed_ms": response["elapsed_ms"],
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
        "findings": [],
        "device_web": {
            "schema_version": "device-web-pinned/v1",
            "origin": origin,
            "connect_address": connect_address,
            "profile": profile,
            "observations": observations,
            "credentials_attempted": credentials_attempted,
            "authentication_succeeded": authentication_succeeded,
        },
        "scan_metadata": {
            "run_kind": "device_web_dast",
            "active_testing": False,
            "credentials_attempted": credentials_attempted,
            "pinned_destination": True,
        },
        "error": error,
    }
