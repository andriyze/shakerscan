"""Per-job SOCKS5 broker that preserves hostname semantics while pinning network egress."""

from __future__ import annotations

import asyncio
import re
import contextlib
import ipaddress
import struct
from typing import Any, Iterable

from runtime.target_bound_socket import FrozenTargetSocketFactory


_REQUEST_LINE = re.compile(rb"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT) \S+ HTTP/1\.[01]$")
_MAX_HEADER_BYTES = 64 * 1024


class RequestCounter:
    """Count HTTP/1 requests in the bytes one client connection sends toward the target.

    Requests are counted only at message boundaries: a request line, then headers, then the body
    the headers frame (Content-Length or chunked), then the next request line. A request-shaped
    string inside a body or a header value is data, not a request -- nuclei's smuggling templates
    send exactly such payloads, and the first counter, which matched anywhere in the stream,
    turned one POST carrying 120 of them into 121 "requests", failed a 120-request hold on one real
    message, and charged the full hold. A count that can exceed the real number of messages is
    not a lower bound.

    Anything that is not well-formed HTTP/1 -- a TLS handshake, another protocol, malformed
    framing -- is unmeasurable: the counter keeps what it has already counted, which remains a
    true lower bound, sets ``measurable`` to False and never adds to the count again.
    """

    def __init__(self) -> None:
        self.count = 0
        self.measurable = True
        self._buffer = b""
        self._state = "request_line"
        self._body_remaining = 0

    def _fail(self) -> int:
        self.measurable = False
        self._state = "opaque"
        self._buffer = b""
        return 0

    def feed(self, chunk: bytes) -> int:
        """Consume bytes; return how many complete requests began in this chunk."""
        if self._state == "opaque":
            return 0
        self._buffer += chunk
        counted = 0
        while True:
            if self._state == "request_line":
                if not self._buffer:
                    return counted
                if b"\r\n" not in self._buffer:
                    if len(self._buffer) > 8192 or not _REQUEST_LINE.match(self._buffer.split(b"\r")[0] + b"") and not self._plausible_prefix():
                        self._fail()
                    return counted
                line, rest = self._buffer.split(b"\r\n", 1)
                if not _REQUEST_LINE.match(line):
                    self._fail()
                    return counted
                self.count += 1
                counted += 1
                self._buffer = rest
                self._state = "headers"
            if self._state == "headers":
                idx = self._buffer.find(b"\r\n\r\n")
                if idx < 0:
                    if len(self._buffer) > _MAX_HEADER_BYTES:
                        self._fail()
                    return counted
                header_block, self._buffer = self._buffer[:idx], self._buffer[idx + 4:]
                length, chunked = 0, False
                for raw in header_block.split(b"\r\n"):
                    name, sep, value = raw.partition(b":")
                    if not sep:
                        continue
                    key = name.strip().lower()
                    if key == b"content-length":
                        try:
                            length = int(value.strip())
                        except ValueError:
                            self._fail()
                            return counted
                    elif key == b"transfer-encoding" and b"chunked" in value.lower():
                        chunked = True
                if chunked:
                    self._state = "chunk_size"
                elif length > 0:
                    self._body_remaining = length
                    self._state = "body"
                else:
                    self._state = "request_line"
            if self._state == "body":
                take = min(self._body_remaining, len(self._buffer))
                self._buffer = self._buffer[take:]
                self._body_remaining -= take
                if self._body_remaining > 0:
                    return counted
                self._state = "request_line"
            if self._state == "chunk_size":
                if b"\r\n" not in self._buffer:
                    return counted
                size_line, rest = self._buffer.split(b"\r\n", 1)
                try:
                    size = int(size_line.split(b";", 1)[0].strip() or b"0", 16)
                except ValueError:
                    self._fail()
                    return counted
                if size == 0:
                    # trailer section ends with an empty line
                    idx = rest.find(b"\r\n")
                    if idx < 0:
                        return counted
                    self._buffer = rest[idx + 2:]
                    self._state = "request_line"
                    continue
                self._body_remaining = size + 2  # data plus its CRLF
                self._buffer = rest
                self._state = "chunk_data"
            if self._state == "chunk_data":
                take = min(self._body_remaining, len(self._buffer))
                self._buffer = self._buffer[take:]
                self._body_remaining -= take
                if self._body_remaining > 0:
                    return counted
                self._state = "chunk_size"

    def _plausible_prefix(self) -> bool:
        head = self._buffer[:8].upper()
        return any(head.startswith(m[: len(head)] if len(head) < len(m) else m) for m in
                   (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"TRACE ", b"CONNECT "))


class PinnedSocksProxy:
    """A minimal CONNECT-only SOCKS5 server bound to loopback.

    Clients address the original hostname, which preserves Host and TLS SNI. The broker never
    resolves that name: after validating the exact host and port, it connects to the frozen IP.
    """

    def __init__(
        self, *, hostname: str, pinned_address: str | None = None,
        pinned_addresses: Iterable[str] | None = None, port: int,
        max_connections: int | None = None,
    ) -> None:
        self.hostname = str(hostname or "").strip().lower().rstrip(".")
        self.port = int(port)
        if not self.hostname:
            raise ValueError("pinned SOCKS proxy requires a hostname")
        if not 1 <= self.port <= 65535:
            raise ValueError("pinned SOCKS proxy requires a valid port")
        supplied = list(pinned_addresses or ())
        if pinned_address is not None:
            supplied.append(str(pinned_address))
        self.socket_factory = FrozenTargetSocketFactory(
            hostname=self.hostname,
            port=self.port,
            frozen_addresses=supplied,
        )
        self.pinned_addresses = self.socket_factory.addresses
        self.pinned_address = self.socket_factory.primary_address
        self.max_connections = (
            None if max_connections is None else max(1, int(max_connections))
        )
        self._server: asyncio.AbstractServer | None = None
        self._connections: set[asyncio.Task[Any]] = set()
        self.connection_attempts = 0
        self.connections_opened = 0
        self.http_requests_observed = 0
        self.wire_requests_measurable = True
        self.connections_rejected = 0
        self.upstream_connection_attempts = 0
        self.address_attempts = {
            address: 0 for address in self.socket_factory.connection_addresses
        }
        self.address_connections = {
            address: 0 for address in self.socket_factory.connection_addresses
        }
        self.bytes_to_target = 0
        self.bytes_from_target = 0
        self.limit_exceeded = asyncio.Event()

    @property
    def proxy_url(self) -> str:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("pinned SOCKS proxy is not running")
        port = int(self._server.sockets[0].getsockname()[1])
        return f"socks5://127.0.0.1:{port}"

    async def start(self) -> "PinnedSocksProxy":
        if self._server is None:
            self._server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        return self

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        tasks = list(self._connections)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def __aenter__(self) -> "PinnedSocksProxy":
        return await self.start()

    async def __aexit__(self, *_args: Any) -> None:
        await self.close()

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connection_attempts += 1
        if (
            self.max_connections is not None
            and self.connection_attempts > self.max_connections
        ):
            self.connections_rejected += 1
            self.limit_exceeded.set()
            writer.close()
            return
        task = asyncio.create_task(self._handle(reader, writer))
        self._connections.add(task)
        task.add_done_callback(self._connections.discard)

    async def _reply(self, writer: asyncio.StreamWriter, code: int) -> None:
        writer.write(bytes((5, code, 0, 1)) + b"\x00\x00\x00\x00\x00\x00")
        await writer.drain()

    async def _read_destination(self, reader: asyncio.StreamReader, atyp: int) -> str:
        if atyp == 1:
            return str(ipaddress.ip_address(await reader.readexactly(4)))
        if atyp == 4:
            return str(ipaddress.ip_address(await reader.readexactly(16)))
        if atyp == 3:
            length = (await reader.readexactly(1))[0]
            if not length:
                raise ValueError("empty SOCKS hostname")
            return (await reader.readexactly(length)).decode("ascii").lower().rstrip(".")
        raise ValueError("unsupported SOCKS address type")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            version, method_count = await asyncio.wait_for(reader.readexactly(2), timeout=3)
            if version != 5 or not 1 <= method_count <= 32:
                return
            methods = await asyncio.wait_for(reader.readexactly(method_count), timeout=3)
            if 0 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x00")
            await writer.drain()

            version, command, _reserved, atyp = await asyncio.wait_for(
                reader.readexactly(4), timeout=3,
            )
            if version != 5 or command != 1:
                await self._reply(writer, 7)
                return
            destination = await asyncio.wait_for(self._read_destination(reader, atyp), timeout=3)
            requested_port = struct.unpack("!H", await reader.readexactly(2))[0]
            allowed_hosts = {self.hostname, *self.pinned_addresses}
            if destination not in allowed_hosts or requested_port != self.port:
                await self._reply(writer, 2)
                return
            candidate_addresses = (
                (destination,)
                if destination in self.pinned_addresses
                else self.socket_factory.connection_addresses
            )
            deadline = asyncio.get_running_loop().time() + 5.0
            connected_address = None
            for address in candidate_addresses:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                self.upstream_connection_attempts += 1
                self.address_attempts[address] = self.address_attempts.get(address, 0) + 1
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(address, self.port),
                        timeout=min(2.0, remaining),
                    )
                except (OSError, asyncio.TimeoutError):
                    continue
                connected_address = address
                self.address_connections[address] = (
                    self.address_connections.get(address, 0) + 1
                )
                break
            if connected_address is None:
                await self._reply(writer, 5)
                return
            self.connections_opened += 1
            await self._reply(writer, 0)

            async def relay(
                source: asyncio.StreamReader,
                target: asyncio.StreamWriter,
                *,
                toward_target: bool,
            ) -> None:
                counter = RequestCounter()
                try:
                    while chunk := await source.read(65536):
                        if toward_target:
                            self.bytes_to_target += len(chunk)
                            self.http_requests_observed += counter.feed(chunk)
                            if not counter.measurable:
                                self.wire_requests_measurable = False
                        else:
                            self.bytes_from_target += len(chunk)
                        target.write(chunk)
                        await target.drain()
                except (OSError, ConnectionError, asyncio.CancelledError):
                    pass
                finally:
                    with contextlib.suppress(OSError):
                        target.close()

            left = asyncio.create_task(
                relay(reader, upstream_writer, toward_target=True)
            )
            right = asyncio.create_task(
                relay(upstream_reader, writer, toward_target=False)
            )
            await asyncio.gather(left, right, return_exceptions=True)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, UnicodeError, ValueError, OSError):
            pass
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                with contextlib.suppress(OSError):
                    await upstream_writer.wait_closed()
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
