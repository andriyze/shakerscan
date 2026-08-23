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
from .target_bound_socket import FrozenTargetSocketFactory
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
    """Expose every admitted address without consulting DNS."""

    def __init__(self, *, factory: FrozenTargetSocketFactory) -> None:
        self.factory = factory
        self.hostname = factory.hostname

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_UNSPEC,
    ) -> list[dict[str, Any]]:
        normalized = str(host or "").strip().lower().rstrip(".")
        if normalized != self.hostname:
            raise OSError("replay resolver refused an unbound hostname")
        records = []
        for endpoint in self.factory.endpoints():
            if family not in {socket.AF_UNSPEC, endpoint.family}:
                continue
            records.append({
                "hostname": self.hostname,
                "host": endpoint.address,
                "port": int(port),
                "family": endpoint.family,
                "proto": socket.IPPROTO_TCP,
                "flags": 0,
            })
        if not records:
            raise OSError("replay resolver address family mismatch")
        return records

    async def close(self) -> None:
        return None


def _pinned_factory(
    request: ReplayRequest, target: TargetBinding,
) -> FrozenTargetSocketFactory:
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
        allowed = (literal,)
    return FrozenTargetSocketFactory(
        hostname=hostname,
        port=parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
        frozen_addresses=allowed,
    )


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
        factory = _pinned_factory(request, target)
        address = factory.addresses[0]
        resolver = _FrozenAddressResolver(factory=factory)
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
