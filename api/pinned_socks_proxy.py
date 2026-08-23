"""Per-job SOCKS5 broker that preserves hostname semantics while pinning network egress."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import struct
from typing import Any


class PinnedSocksProxy:
    """A minimal CONNECT-only SOCKS5 server bound to loopback.

    Clients address the original hostname, which preserves Host and TLS SNI. The broker never
    resolves that name: after validating the exact host and port, it connects to the frozen IP.
    """

    def __init__(
        self, *, hostname: str, pinned_address: str, port: int,
        max_connections: int | None = None,
    ) -> None:
        self.hostname = str(hostname or "").strip().lower().rstrip(".")
        self.pinned_address = str(ipaddress.ip_address(str(pinned_address or "").strip()))
        self.port = int(port)
        if not self.hostname:
            raise ValueError("pinned SOCKS proxy requires a hostname")
        if not 1 <= self.port <= 65535:
            raise ValueError("pinned SOCKS proxy requires a valid port")
        self.max_connections = (
            None if max_connections is None else max(1, int(max_connections))
        )
        self._server: asyncio.AbstractServer | None = None
        self._connections: set[asyncio.Task[Any]] = set()
        self.connection_attempts = 0
        self.connections_opened = 0
        self.connections_rejected = 0
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
            allowed_hosts = {self.hostname, self.pinned_address}
            if destination not in allowed_hosts or requested_port != self.port:
                await self._reply(writer, 2)
                return
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(self.pinned_address, self.port), timeout=5,
                )
            except (OSError, asyncio.TimeoutError):
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
                try:
                    while chunk := await source.read(65536):
                        if toward_target:
                            self.bytes_to_target += len(chunk)
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
