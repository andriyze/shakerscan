"""Metered HTTP for the existing NSE checks; never a second target/approval path.

Only the worker constructs this transport, from its revalidated prepared command.
The NSE process can select a saved port and script, not an address or credential.
Same-asset service redirects reuse the admitted network authority and frozen IP.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import replace
import hashlib
import ipaddress
import re
from typing import Any, Mapping
from urllib.parse import urljoin, urlsplit, urlunsplit

from runtime.models import TargetBinding
from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
from runtime.request_replay_executor import ReplayExecutionError
try:
    from scanner_tools.request_replay import ReplayRequest
    from scanner_tools.url_redaction import redact_url
except ModuleNotFoundError:
    from scanner.scanner_tools.request_replay import ReplayRequest
    from scanner.scanner_tools.url_redaction import redact_url

HTTP_SCRIPT_LIMITS = {"http-methods": 6, "http-security-headers": 3, "http-trace": 2}
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
# The two detector requests are HEAD; the native method script can also send
# one POST and one randomly named method. No test-all/retest argv is accepted.
METHOD_WRITE_LIMIT = 2


def http_envelope(scripts: tuple[str, ...], ports: int, *, allow_write: bool) -> dict[str, int]:
    http = [name for name in scripts if name in HTTP_SCRIPT_LIMITS]
    return {
        "http_requests": ports * (2 + sum(HTTP_SCRIPT_LIMITS[name] for name in http)) if http else 0,
        "state_changing_requests": ports * METHOD_WRITE_LIMIT if allow_write and "http-methods" in http else 0,
    }


def normalized_host(value: str) -> str:
    return value.encode("idna").decode("ascii").lower().rstrip(".")


class NseHttpTransport:
    """One native command's serialized, bounded HTTP exchange service."""
    def __init__(self, *, target: TargetBinding, ports: tuple[int, ...], scripts: tuple[str, ...],
                 allow_write: bool, cancelled: Any, heartbeat: Any) -> None:
        self.target, self.ports, self.scripts = target, ports, scripts
        self.allow_write, self.cancelled, self.heartbeat = allow_write, cancelled, heartbeat
        self.limits = http_envelope(scripts, len(ports), allow_write=allow_write)
        self.actual = {key: 0 for key in self.limits}
        self.errors: list[str] = []
        self.exchanges: list[dict[str, Any]] = []
        self.services: dict[int, str | None] = {}
        self.lock = asyncio.Lock()
        self.closed = False

    def destination(self, value: str, *, base: str) -> str:
        if not isinstance(value, str) or len(value) > 4096 or "\\" in value or any(ord(c) <= 32 or ord(c) == 127 for c in value):
            raise ReplayExecutionError("nse_invalid_destination")
        p = urlsplit(urljoin(base, value))
        if (p.scheme not in {"http", "https"} or not p.hostname or p.port == 0
                or p.username is not None or p.password is not None):
            raise ReplayExecutionError("nse_invalid_destination")
        host = normalized_host(p.hostname)
        # An IP spelling is accepted only for this same frozen address, not a
        # second asset resolved by DNS. Host/SNI remain the actual requested host.
        if host != normalized_host(self.target.canonical_host or "") and host not in self.target.allowed_addresses:
            raise ReplayExecutionError("nse_redirect_outside_asset")
        authority = f"[{host}]" if ":" in host else host
        if p.port and p.port != (443 if p.scheme == "https" else 80):
            authority += f":{p.port}"
        return urlunsplit((p.scheme, authority, p.path or "/", p.query, ""))

    def _error(self, code: str) -> dict[str, Any]:
        if code not in self.errors:
            self.errors.append(code)
        return {"error": code, "header": {}, "rawheader": [], "body_base64": ""}

    async def _send(self, url: str, method: str, *, port: int, script: str, phase: str) -> dict[str, Any]:
        if self.closed or self.cancelled():
            raise asyncio.CancelledError
        changing = method not in READ_METHODS
        if changing and not self.allow_write:
            return self._error("nse_optional_method_not_authorized")
        attempt = {"script_id": script, "requested_port": port, "method": method,
                   "url": redact_url(url), "phase": phase, "http_requests": 0,
                   "state_changing_requests": 0, "address": self.target.allowed_addresses[0]}

        async def before_headers(_method: str, _url: str) -> None:
            if self.closed or self.cancelled():
                raise asyncio.CancelledError
            # Runs before every header-write attempt, including a library retry.
            # No await separates checking and spending the already reserved grant.
            if self.actual["http_requests"] >= self.limits["http_requests"]:
                raise ReplayExecutionError("nse_http_budget_reached")
            if changing and self.actual["state_changing_requests"] >= self.limits["state_changing_requests"]:
                raise ReplayExecutionError("nse_state_changing_budget_reached")
            self.actual["http_requests"] += 1
            attempt["http_requests"] += 1
            if changing:
                self.actual["state_changing_requests"] += 1
                attempt["state_changing_requests"] += 1

        origin = urlunsplit((*urlsplit(url)[:2], "", "", ""))
        target = replace(self.target, allowed_origins=(origin,))
        request = ReplayRequest("nse", 0, "NSE service check", "", method, url,
                                (("User-Agent", "ShakerScan-NSE"),), b"", "none", "none", False)
        transport = PinnedAiohttpReplayTransport(
            verify_tls=False, tolerate_incomplete_body=True, before_request_headers=before_headers,
        )
        self.exchanges.append(attempt)
        try:
            response = await transport.send(request, target=target, timeout_seconds=15,
                                            follow_redirects=False)
            attempt.update(status_code=response.status_code, error=response.error_code,
                           response_sha256=hashlib.sha256(response.response_body).hexdigest())
            if response.error_code and phase == "script":
                self._error("nse_http_" + response.error_code)
            headers = {}
            header_bytes = 0
            for key, value in response.response_headers.items():
                header_bytes += len(key) + len(value.encode("utf-8"))
                if header_bytes > 65536:
                    self._error("nse_http_headers_truncated")
                    break
                headers[key.lower()] = value
            if len(response.response_body) > 65536:
                self._error("nse_http_body_truncated")
            return {"status": response.status_code, "header": headers,
                    "rawheader": [key + ": " + value for key, value in headers.items()],
                    "body_base64": base64.b64encode(response.response_body[:65536]).decode("ascii"),
                    "ssl": url.startswith("https:"), "error": response.error_code,
                    "status-line": f"HTTP/1.1 {response.status_code or 0}", "final_url": url}
        except ReplayExecutionError as exc:
            # Fixed error codes only, never an origin's response values.
            code = str(exc) if re.fullmatch(r"nse_[a-z_]+", str(exc)) else "nse_http_transport_error"
            attempt["error"] = code
            return self._error(code)
        finally:
            await self.heartbeat()

    async def service(self, port: int, script: str) -> str | None:
        if port in self.services:
            return self.services[port]
        host = self.target.canonical_host or self.target.allowed_addresses[0]
        host = f"[{host}]" if ":" in host else host
        saved = [urlsplit(o).scheme for o in self.target.allowed_origins
                 if (urlsplit(o).port or (443 if o.startswith("https:") else 80)) == port]
        schemes = list(dict.fromkeys(saved + (["https", "http"] if port in {443, 8443} else ["http", "https"])))
        for scheme in schemes:
            origin = self.destination(f"{scheme}://{host}:{port}/", base="")
            result = await self._send(origin, "HEAD", port=port, script=script, phase="service_detection")
            if result.get("status") is not None:
                self.services[port] = origin
                return origin
        self.services[port] = None
        return None

    async def request(self, data: Mapping[str, Any]) -> dict[str, Any]:
        script, port, method = data.get("script"), data.get("port"), data.get("method")
        if (script not in self.scripts or script not in HTTP_SCRIPT_LIMITS
                or type(port) is not int or port not in self.ports
                or not isinstance(method, str) or not re.fullmatch(r"[A-Z]{3,12}", method)):
            return self._error("nse_invalid_bridge_request")
        async with self.lock:
            base = await self.service(port, script)
            if base is None:
                return self._error("nse_http_service_unavailable")
            try:
                url = self.destination(data.get("path", "/"), base=base)
                for hop in range(3):
                    result = await self._send(url, method, port=port, script=script, phase="script")
                    location = result.get("header", {}).get("location")
                    if (data.get("redirects") is not True or method not in READ_METHODS
                            or result.get("status") not in {301, 302, 303, 307, 308} or not location):
                        return result
                    # Keep the real redirect response even when the next asset is
                    # not admitted. Other scripts/ports continue; the run is partial.
                    try:
                        destination = self.destination(location, base=url)
                    except ReplayExecutionError as exc:
                        self._error(str(exc))
                        return result
                    if hop == 2:
                        self._error("nse_redirect_hop_limit")
                        return result
                    url = destination
            except ReplayExecutionError as exc:
                return self._error(str(exc))
        return self._error("nse_http_no_result")
