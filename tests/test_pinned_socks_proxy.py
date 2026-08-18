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
