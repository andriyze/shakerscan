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

    def __init__(self, *, verify_tls: bool = False,
                 reject_duplicate_response_headers: bool = False,
                 tolerate_incomplete_body: bool = False) -> None:
        self.verify_tls = verify_tls
        self.reject_duplicate_response_headers = reject_duplicate_response_headers
        # When set, a body read cut short after a valid status line keeps the
        # bytes already received instead of failing the whole capture. Content
        # disclosure detection wants this (a truncated directory index is still
        # a real finding); a login or proof boundary must not, so it stays off
        # by default and a truncated response fails closed as before.
        self.tolerate_incomplete_body = tolerate_incomplete_body

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
        attempted_addresses: list[str] = []
        connected_addresses: list[str] = []

        class TrackedSocket(socket.socket):
            def _capture_peer(self) -> None:
                try:
                    peername = super().getpeername()
                    address = str(ipaddress.ip_address(str(peername[0])))
                except (OSError, ValueError, IndexError, TypeError):
                    return
                if address not in connected_addresses:
                    connected_addresses.append(address)

            def connect(self, address):
                try:
                    result = super().connect(address)
                except (BlockingIOError, InterruptedError):
                    raise
                self._capture_peer()
                return result

            def getsockopt(self, level, option, *args):
                result = super().getsockopt(level, option, *args)
                if (
                    level == socket.SOL_SOCKET
                    and option == socket.SO_ERROR
                    and result == 0
                ):
                    self._capture_peer()
                return result

        def tracked_socket_factory(addr_info):
            family, type_, proto, _canonical_name, sockaddr = addr_info
            address = str(ipaddress.ip_address(str(sockaddr[0])))
            if address not in attempted_addresses:
                attempted_addresses.append(address)
            return TrackedSocket(family=family, type=type_, proto=proto)

        resolver = _FrozenAddressResolver(factory=factory)
        connector = aiohttp.TCPConnector(
            resolver=resolver,
            use_dns_cache=False,
            ssl=ssl.create_default_context() if self.verify_tls else _insecure_tls_context(),
            limit=1,
            force_close=True,
            happy_eyeballs_delay=0.25,
            interleave=0,
            socket_factory=tracked_socket_factory,
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
                    if not connected_addresses:
                        raise ReplayExecutionError(
                            "transport could not prove its connected target address"
                        )
                    connected_address = connected_addresses[-1]
                    if connected_address not in factory.connection_addresses:
                        raise ReplayExecutionError(
                            "transport connected outside its frozen fallback set"
                        )
                    if self.reject_duplicate_response_headers:
                        names = [name.lower() for name, _ in response.raw_headers]
                        if len(names) != len(set(names)):
                            raise ReplayExecutionError("transport response contains unsupported repeated headers")
                    # StreamReader.read(n) may return a short chunk before EOF.
                    # Returning that chunk used to silently truncate JS/HTML.
                    retained = bytearray()
                    body_incomplete = False
                    try:
                        async for chunk in response.content.iter_chunked(65536):
                            retained.extend(chunk[:MAX_REPLAY_RESPONSE_BODY_BYTES + 1 - len(retained)])
                            if len(retained) > MAX_REPLAY_RESPONSE_BODY_BYTES:
                                break
                    except (aiohttp.ClientPayloadError, asyncio.TimeoutError):
                        # A server that overstates Content-Length, frames a chunked
                        # body incorrectly, or stalls/closes after sending most of it
                        # still delivered the bytes already received, and those bytes
                        # are a real, classifiable response -- e.g. a directory index
                        # whose middleware mis-sets Content-Length and then withholds
                        # the last few bytes. Discarding the whole capture as a
                        # transport failure drops a proven disclosure. Keep what
                        # arrived and mark the capture partial. A read that yielded
                        # nothing usable is still a genuine failure and re-raises to
                        # the transport-error path below, as does any caller that has
                        # not opted into tolerating a partial body.
                        if not retained or not self.tolerate_incomplete_body:
                            raise
                        body_incomplete = True
                    body = bytes(retained)
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
                        connected_address=connected_address,
                        attempted_addresses=tuple(attempted_addresses),
                        final_url=str(response.url),
                        response_headers=dict(response.headers),
                        response_body=body,
                        elapsed_ms=elapsed_ms,
                        error_code="incomplete_read" if body_incomplete else None,
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
                connected_address=None,
                attempted_addresses=tuple(attempted_addresses),
                final_url=request.url,
                response_headers={},
                response_body=b"",
                elapsed_ms=elapsed_ms,
                error_code="timeout" if timed_out else "transport_error",
                timed_out=timed_out,
            )
