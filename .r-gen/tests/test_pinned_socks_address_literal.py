"""A hostname target's pinned proxy refuses the target's address written as the host.

Every scanner on the V2 path addresses the proxy by hostname (remote DNS): checked in the
worker image with a recording SOCKS5 server for sqlmap, katana, katana headless, nuclei, dalfox,
httpx and ffuf. A connection to the pinned address itself can only come from a redirect or a
page reference to that address as another origin, which would carry the session headers that
browsers and some tools add to every request. It is refused and counted on the receipt. A target
whose host is an address is reached by that address as before.
"""
from __future__ import annotations

import asyncio
import socket
import struct
import sys
import urllib.parse
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pinned_socks_proxy import PinnedSocksProxy  # noqa: E402
from tests.test_pinned_socks_proxy import _socks_connect  # noqa: E402


async def _socks_connect_ipv4(proxy_url: str, address: str, port: int) -> int:
    reader, writer = await asyncio.open_connection("127.0.0.1", urllib.parse.urlsplit(proxy_url).port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    writer.write(b"\x05\x01\x00\x01" + socket.inet_aton(address) + struct.pack("!H", port))
    await writer.drain()
    reply = await reader.readexactly(10)
    writer.close()
    return reply[1]


async def _upstream():
    async def echo(reader, writer):
        writer.close()
    try:
        server = await asyncio.start_server(echo, "127.0.0.1", 0)
    except PermissionError:
        pytest.skip("the unit-test sandbox forbids loopback listeners")
    return server, server.sockets[0].getsockname()[1]


def test_a_hostname_target_refuses_its_address_as_a_destination():
    async def scenario():
        server, port = await _upstream()
        async with PinnedSocksProxy(hostname="app.fixture.invalid", pinned_address="127.0.0.1", port=port) as proxy:
            _r, writer, by_name = await _socks_connect(proxy.proxy_url, "app.fixture.invalid", port)
            writer.close()
            _r, writer, as_domain = await _socks_connect(proxy.proxy_url, "127.0.0.1", port)
            writer.close()
            as_ipv4 = await _socks_connect_ipv4(proxy.proxy_url, "127.0.0.1", port)
            receipt = proxy.receipt()
        server.close()
        return by_name, as_domain, as_ipv4, receipt

    by_name, as_domain, as_ipv4, receipt = asyncio.run(scenario())
    assert by_name == 0
    assert as_domain == 2 and as_ipv4 == 2
    assert receipt["address_literal_destinations_refused"] == 2


def test_an_address_target_is_still_reached_by_its_address():
    async def scenario():
        server, port = await _upstream()
        async with PinnedSocksProxy(hostname="127.0.0.1", pinned_address="127.0.0.1", port=port) as proxy:
            code = await _socks_connect_ipv4(proxy.proxy_url, "127.0.0.1", port)
        server.close()
        return code

    assert asyncio.run(scenario()) == 0
