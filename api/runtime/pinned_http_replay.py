"""Worker-only HTTP transport for exact, frozen-address request replay."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from typing import Any
import urllib.parse

import aiohttp

from .models import TargetBinding
from .request_replay_executor import (
    MAX_REPLAY_RESPONSE_BODY_BYTES,
    ReplayExecutionError,
    ReplayTransportResult,
)

try:
    from scanner_tools.request_replay import ReplayRequest
except ModuleNotFoundError:  # package import when scanner is installed as a package
    from scanner.scanner_tools.request_replay import ReplayRequest


class _FrozenAddressResolver(aiohttp.abc.AbstractResolver):
    """Resolve one exact hostname to one server-authorized address."""

    def __init__(self, *, hostname: str, address: str) -> None:
        self.hostname = str(hostname or "").strip().lower().rstrip(".")
        self.address = str(ipaddress.ip_address(str(address or "").strip()))

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_UNSPEC,
    ) -> list[dict[str, Any]]:
        normalized = str(host or "").strip().lower().rstrip(".")
        if normalized != self.hostname:
            raise OSError("replay resolver refused an unbound hostname")
        address = ipaddress.ip_address(self.address)
        resolved_family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        if family not in {socket.AF_UNSPEC, resolved_family}:
            raise OSError("replay resolver address family mismatch")
        return [{
            "hostname": self.hostname,
            "host": self.address,
            "port": int(port),
            "family": resolved_family,
            "proto": 0,
            "flags": 0,
        }]

    async def close(self) -> None:
        return None


def _pinned_address(request: ReplayRequest, target: TargetBinding) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(request.url)
    hostname = str(parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        raise ReplayExecutionError("replay request has no hostname")
    allowed = tuple(str(ipaddress.ip_address(item)) for item in target.allowed_addresses)
    if not allowed:
        raise ReplayExecutionError("replay target has no frozen addresses")
    try:
        literal = str(ipaddress.ip_address(hostname))
    except ValueError:
        literal = None
    if literal is not None:
        if literal not in allowed:
            raise ReplayExecutionError("replay IP literal is outside the frozen address set")
        return hostname, literal
    return hostname, allowed[0]


def _insecure_tls_context() -> ssl.SSLContext:
    """Preserve TLS/SNI for DAST targets while accepting untrusted target certificates."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class PinnedAiohttpReplayTransport:
    """Send exact imported requests without performing runtime DNS resolution."""

    async def send(
        self,
        request: ReplayRequest,
        *,
        target: TargetBinding,
        timeout_seconds: float,
        follow_redirects: bool,
    ) -> ReplayTransportResult:
        if follow_redirects:
            raise ReplayExecutionError("exact replay transport cannot follow redirects")
        hostname, address = _pinned_address(request, target)
        resolver = _FrozenAddressResolver(hostname=hostname, address=address)
        connector = aiohttp.TCPConnector(
            resolver=resolver,
            use_dns_cache=False,
            ssl=_insecure_tls_context(),
            limit=1,
            force_close=True,
        )
        timeout = aiohttp.ClientTimeout(total=float(timeout_seconds))
        started = asyncio.get_running_loop().time()
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                trust_env=False,
                auto_decompress=False,
                skip_auto_headers={"User-Agent", "Accept", "Accept-Encoding"},
            ) as client:
                async with client.request(
                    request.method,
                    request.url,
                    headers=list(request.headers),
                    data=request.body or None,
                    allow_redirects=False,
                ) as response:
                    body = await response.content.read(MAX_REPLAY_RESPONSE_BODY_BYTES + 1)
                    if len(body) > MAX_REPLAY_RESPONSE_BODY_BYTES:
                        raise ReplayExecutionError(
                            "transport response body exceeds the capture limit"
                        )
                    elapsed_ms = max(
                        0,
                        int((asyncio.get_running_loop().time() - started) * 1_000),
                    )
                    return ReplayTransportResult(
                        status_code=response.status,
                        connected_address=address,
                        final_url=str(response.url),
                        response_headers=dict(response.headers),
                        response_body=body,
                        elapsed_ms=elapsed_ms,
                    )
        except asyncio.CancelledError:
            raise
        except ReplayExecutionError:
            raise
        except (aiohttp.ClientError, OSError, asyncio.TimeoutError) as exc:
            elapsed_ms = max(
                0,
                int((asyncio.get_running_loop().time() - started) * 1_000),
            )
            pre_connect = isinstance(
                exc,
                (aiohttp.ClientConnectorError, aiohttp.ConnectionTimeoutError),
            )
            timed_out = isinstance(exc, (asyncio.TimeoutError, aiohttp.ServerTimeoutError))
            return ReplayTransportResult(
                status_code=None,
                connected_address=None if pre_connect else address,
                final_url=request.url,
                response_headers={},
                response_body=b"",
                elapsed_ms=elapsed_ms,
                error_code="timeout" if timed_out else "transport_error",
                timed_out=timed_out,
            )

