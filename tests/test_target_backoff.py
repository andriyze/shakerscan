"""The tunnel reads the target's answers and waits when the target says to (429, a WAF ban)."""
import asyncio
from collections import deque
import struct
import sys
import urllib.parse
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pinned_socks_proxy import PinnedSocksProxy  # noqa: E402
from runtime import target_backoff  # noqa: E402
from runtime.target_backoff import ResponseReader, TargetBackoff, retry_after_seconds  # noqa: E402
from runtime.target_pacing import assess  # noqa: E402

ORIGIN = "http://shop.example.test:80"


def _read(stream: bytes, methods=("GET",) * 8, *, split: int | None = None):
    seen = []
    queue = deque({"method": m, "target": f"/{i}"} for i, m in enumerate(methods))
    reader = ResponseReader(queue, lambda status, headers, request: seen.append((status, request and request["target"])))
    if split:
        for i in range(0, len(stream), split):
            reader.feed(stream[i:i + split])
    else:
        reader.feed(stream)
    return seen, reader


def test_each_answer_is_paired_with_its_request_and_a_status_inside_a_body_is_data():
    body = b"HTTP/1.1 429 Too Many Requests\r\n\r\n"  # a page quoting a status line
    stream = (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body
              + b"HTTP/1.1 100 Continue\r\n\r\n"
              + b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHTTP/\r\n0\r\n\r\n"
              + b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"  # HEAD: no body follows
              + b"HTTP/1.1 204 No Content\r\n\r\n"
              + b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\nContent-Length: 0\r\n\r\n")
    methods = ("GET", "POST", "HEAD", "DELETE", "GET")
    for split in (None, 1, 7):
        seen, reader = _read(stream, methods, split=split)
        assert seen == [(200, "/0"), (404, "/1"), (200, "/2"), (204, "/3"), (429, "/4")], split
        assert reader.readable


def test_tls_or_a_close_delimited_body_stops_the_reader_with_what_it_read():
    assert _read(b"\x16\x03\x01\x02\x00")[0] == []
    seen, reader = _read(b"HTTP/1.0 200 OK\r\n\r\nHTTP/1.1 429 x\r\nContent-Length: 0\r\n\r\n")
    assert seen == [(200, "/0")] and not reader.readable


def test_retry_after_is_seconds_or_an_http_date():
    assert retry_after_seconds("30") == 30.0
    assert retry_after_seconds("Wed, 21 Oct 2015 07:28:30 GMT", now=1445412480) == 30.0
    assert retry_after_seconds("soon") is None and retry_after_seconds("") is None


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _answer(backoff, status, target="/", method="GET", retry=None):
    headers = {b"retry-after": retry.encode()} if retry else {}
    return backoff.observe(ORIGIN, status, headers, {"method": method, "target": target})


def test_a_429_holds_the_origin_for_the_retry_after_the_target_asked_for():
    clock = _Clock()
    backoff = TargetBackoff(clock)
    assert _answer(backoff, 200) is None and backoff.remaining(ORIGIN) == 0
    assert _answer(backoff, 429, retry="30") == "throttled"
    assert backoff.remaining(ORIGIN) == 30
    clock.now += 31
    assert backoff.remaining(ORIGIN) == 0
    # Without Retry-After: an exponential backoff, capped.
    assert _answer(backoff, 429) == "throttled" and backoff.remaining(ORIGIN) == 10  # the 2nd in a row
    assert _answer(backoff, 429, retry="99999") == "throttled"
    assert backoff.remaining(ORIGIN) == target_backoff.MAX_HOLD_SECONDS
    # A 503 holds only when it says how long; an ordinary 503 is the pacing's business.
    other = TargetBackoff(clock)
    assert _answer(other, 503) is None and other.remaining(ORIGIN) == 0
    assert _answer(other, 503, retry="5") == "throttled" and other.remaining(ORIGIN) == 5


def test_a_waf_blocking_attacks_is_not_a_ban_but_refusing_what_it_served_before_is():
    backoff = TargetBackoff(_Clock())
    _answer(backoff, 200, "/search?q=shoes")
    for i in range(40):  # every attack blocked, ordinary pages still served
        assert _answer(backoff, 403, f"/search?q=<script>{i}") is None
        if i % 10 == 0:
            _answer(backoff, 200, "/")
    assert backoff.remaining(ORIGIN) == 0
    assert _answer(backoff, 403, "/search?q=shoes") == "banned"
    assert backoff.remaining(ORIGIN) == target_backoff.BAN_BASE_SECONDS


def test_a_long_run_of_403s_across_paths_is_a_ban():
    backoff = TargetBackoff(_Clock())
    verdicts = [_answer(backoff, 403, f"/p{i % 4}?x={i}") for i in range(target_backoff.BAN_STREAK)]
    assert verdicts[-1] == "banned" and not any(verdicts[:-1])
    # One path refused many times is that path's access control, not a ban.
    single = TargetBackoff(_Clock())
    assert not any(_answer(single, 403, f"/admin?x={i}") for i in range(60))


def test_a_423_refuses_that_sign_in_route_and_nothing_else():
    clock = _Clock()
    backoff = TargetBackoff(clock)
    assert _answer(backoff, 401, "/login", "POST") is None
    assert _answer(backoff, 423, "/login", "POST") == "locked"
    assert backoff.is_locked(ORIGIN, {"method": "POST", "target": "/login?next=/"})
    assert not backoff.is_locked(ORIGIN, {"method": "GET", "target": "/login"})
    assert not backoff.is_locked(ORIGIN, {"method": "POST", "target": "/search"})
    assert backoff.remaining(ORIGIN) == 0  # the rest of the application is not held
    clock.now += target_backoff.LOCK_HOLD_SECONDS + 1
    assert not backoff.is_locked(ORIGIN, {"method": "POST", "target": "/login"})


def test_unread_tunnel_answers_are_not_degraded_answers():
    unread = [{"status_code": None, "elapsed_ms": None, "error": None}] * 40
    assert assess(unread).state == "normal"
    ok = [{"status_code": 200, "elapsed_ms": 30, "error": None}] * 2
    throttled = [{"status_code": 429, "elapsed_ms": 30, "error": None}] * 8
    assert assess(unread + ok + throttled).state != "normal"


async def _socks_connect(proxy_url: str, host: str, port: int):
    reader, writer = await asyncio.open_connection("127.0.0.1", urllib.parse.urlsplit(proxy_url).port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    encoded = host.encode("ascii")
    writer.write(b"\x05\x01\x00\x03" + bytes((len(encoded),)) + encoded + struct.pack("!H", port))
    await writer.drain()
    assert (await reader.readexactly(10))[1] == 0
    return reader, writer


def test_the_tunnel_waits_out_a_retry_after_before_it_relays_the_next_request():
    target_backoff.BACKOFF.reset()

    async def scenario():
        arrivals = []

        async def app(reader, writer):
            while line := await reader.readline():
                if line.startswith(b"GET "):
                    arrivals.append(asyncio.get_running_loop().time())
                if line == b"\r\n":
                    if len(arrivals) == 1:
                        writer.write(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n")
                    else:
                        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    await writer.drain()
            writer.close()

        try:
            upstream = await asyncio.start_server(app, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("the unit-test sandbox forbids loopback listeners")
        port = upstream.sockets[0].getsockname()[1]
        async with PinnedSocksProxy(hostname="shop.example.test", pinned_address="127.0.0.1", port=port,
                                    scheme="http") as proxy:
            reader, writer = await _socks_connect(proxy.proxy_url, "shop.example.test", port)
            writer.write(b"GET /a HTTP/1.1\r\nHost: shop.example.test\r\n\r\n")
            await writer.drain()
            assert b"429" in await reader.readuntil(b"\r\n\r\n")
            writer.write(b"GET /b HTTP/1.1\r\nHost: shop.example.test\r\n\r\n")
            await writer.drain()
            assert b"200" in await asyncio.wait_for(reader.readuntil(b"ok"), 5)
            writer.close()
            record = proxy.receipt()
        upstream.close()
        await upstream.wait_closed()
        return arrivals, record

    arrivals, record = asyncio.run(scenario())
    target_backoff.BACKOFF.reset()
    assert len(arrivals) == 2 and arrivals[1] - arrivals[0] >= 0.9
    assert record["status_counts"] == {"200": 1, "429": 1}
    assert record["holds"] == {"throttled": 1} and record["held_seconds"] >= 0.9
    assert [line.get("status") for line in record["request_lines"]] == [429, 200]
