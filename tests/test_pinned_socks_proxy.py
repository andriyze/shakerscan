import asyncio
import struct
import sys
import urllib.parse
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from pinned_socks_proxy import PinnedSocksProxy  # noqa: E402


async def _socks_connect(proxy_url: str, host: str, port: int):
    proxy_port = urllib.parse.urlsplit(proxy_url).port
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    encoded = host.encode("ascii")
    writer.write(b"\x05\x01\x00\x03" + bytes((len(encoded),)) + encoded + struct.pack("!H", port))
    await writer.drain()
    reply = await reader.readexactly(10)
    return reader, writer, reply[1]


def test_pinned_socks_proxy_relays_only_the_exact_hostname_and_port():
    async def scenario():
        observed = []

        async def echo(reader, writer):
            payload = await reader.readexactly(4)
            observed.append(payload)
            writer.write(payload.upper())
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        try:
            upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("the unit-test sandbox forbids loopback listeners")
        upstream_port = upstream.sockets[0].getsockname()[1]
        async with PinnedSocksProxy(
            hostname="owned-device.local", pinned_address="127.0.0.1", port=upstream_port,
        ) as proxy:
            reader, writer, code = await _socks_connect(
                proxy.proxy_url, "owned-device.local", upstream_port,
            )
            assert code == 0
            writer.write(b"ping")
            await writer.drain()
            assert await reader.readexactly(4) == b"PING"
            writer.close()
            await writer.wait_closed()

            _reader, blocked_writer, blocked_code = await _socks_connect(
                proxy.proxy_url, "not-owned.local", upstream_port,
            )
            assert blocked_code == 2
            blocked_writer.close()
            await blocked_writer.wait_closed()

            _reader, port_writer, port_code = await _socks_connect(
                proxy.proxy_url, "owned-device.local", upstream_port + 1,
            )
            assert port_code == 2
            port_writer.close()
            await port_writer.wait_closed()

        upstream.close()
        await upstream.wait_closed()
        assert observed == [b"ping"]

    asyncio.run(scenario())


def test_pinned_socks_proxy_closes_and_signals_at_connection_ceiling():
    async def scenario():
        async def echo(reader, writer):
            await reader.read()
            writer.close()

        try:
            upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("the unit-test sandbox forbids loopback listeners")
        upstream_port = upstream.sockets[0].getsockname()[1]
        async with PinnedSocksProxy(
            hostname="owned.local",
            pinned_address="127.0.0.1",
            port=upstream_port,
            max_connections=1,
        ) as proxy:
            _reader, first, code = await _socks_connect(
                proxy.proxy_url, "owned.local", upstream_port,
            )
            assert code == 0
            _reader2, second = await asyncio.open_connection(
                "127.0.0.1", urllib.parse.urlsplit(proxy.proxy_url).port,
            )
            second.write(b"\x05\x01\x00")
            await second.drain()
            assert await _reader2.read() == b""
            assert proxy.limit_exceeded.is_set()
            assert proxy.connection_attempts == 2
            assert proxy.connections_opened == 1
            assert proxy.connections_rejected == 1
            first.close()
            second.close()
        upstream.close()
        await upstream.wait_closed()

    asyncio.run(scenario())


def test_pinned_socks_proxy_uses_stable_preconnect_address_fallback():
    async def scenario():
        observed = []

        async def echo(reader, writer):
            observed.append(await reader.readexactly(4))
            writer.write(b"PONG")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        try:
            upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("the unit-test sandbox forbids loopback listeners")
        upstream_port = upstream.sockets[0].getsockname()[1]
        async with PinnedSocksProxy(
            hostname="fallback.local",
            pinned_addresses=("127.0.0.1", "127.0.0.0"),
            port=upstream_port,
        ) as proxy:
            reader, writer, code = await _socks_connect(
                proxy.proxy_url, "fallback.local", upstream_port,
            )
            assert code == 0
            writer.write(b"ping")
            await writer.drain()
            assert await reader.readexactly(4) == b"PONG"
            writer.close()
            await writer.wait_closed()
            assert proxy.pinned_addresses == ("127.0.0.0", "127.0.0.1")
            assert proxy.upstream_connection_attempts == 2
            assert proxy.address_attempts == {"127.0.0.0": 1, "127.0.0.1": 1}
            assert proxy.address_connections == {"127.0.0.0": 0, "127.0.0.1": 1}

        upstream.close()
        await upstream.wait_closed()
        assert observed == [b"ping"]

    asyncio.run(scenario())
