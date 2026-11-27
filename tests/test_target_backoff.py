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


class _Store:
    """The two Redis calls the shared hold uses, on a fake clock."""

    def __init__(self, clock):
        self.clock, self.keys = clock, {}

    def eval(self, _script, _n, key, ms, _reason):
        left = self.pttl(key)
        if left < int(ms):
            self.keys[key] = self.clock() + int(ms) / 1000

    def pttl(self, key):
        until = self.keys.get(key)
        return int((until - self.clock()) * 1000) if until and until > self.clock() else -2


def test_a_hold_one_worker_sets_holds_the_others_through_the_shared_store():
    clock = _Clock()
    store = _Store(clock)
    worker_a, worker_b = TargetBackoff(clock), TargetBackoff(clock)
    worker_a.share(store)
    worker_b.share(store)
    assert _answer(worker_a, 429, retry="30") == "throttled"
    assert worker_b.remaining(ORIGIN) == pytest.approx(30, abs=0.01)
    _answer(worker_b, 429, retry="5")  # a shorter hold does not shorten the shared one
    clock.now += 10
    worker_b._shared.clear()
    assert worker_b.remaining(ORIGIN) == pytest.approx(20, abs=0.01)
    clock.now += 21
    assert worker_b.remaining(ORIGIN) == 0


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


def test_the_engines_own_http_client_waits_out_a_retry_after():
    """exposure, identify and GraphQL checks use the engine's HTTP client, not the tunnel: in the
    finding zoo they kept sending through the Retry-After the tunnel already honoured."""
    from uuid import UUID
    from capabilities.http import execute_bound_http_request
    from runtime.models import TargetBinding

    target_backoff.BACKOFF.reset()

    async def scenario():
        arrivals = []

        async def app(reader, writer):
            while line := await reader.readline():
                if line.startswith(b"GET "):
                    arrivals.append(asyncio.get_running_loop().time())
                if line == b"\r\n":
                    answer = (b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n"
                              if len(arrivals) == 1 else b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    writer.write(answer)
                    await writer.drain()
            writer.close()

        try:
            server = await asyncio.start_server(app, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("the unit-test sandbox forbids loopback listeners")
        base = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        target = TargetBinding(target_id=str(UUID(int=2)), target_kind="web", canonical_host="127.0.0.1",
                               allowed_origins=(base,), allowed_addresses=("127.0.0.1",),
                               allowed_root_domains=("127.0.0.1",), environment="lab", scope_receipt_id=str(UUID(int=3)))
        first = await execute_bound_http_request(base, {"method": "GET", "path": "/a"}, target=target)
        second = await execute_bound_http_request(base, {"method": "GET", "path": "/b"}, target=target)
        server.close()
        await server.wait_closed()
        return arrivals, first, second

    arrivals, first, second = asyncio.run(scenario())
    target_backoff.BACKOFF.reset()
    assert first["ok"] and second["ok"]
    assert len(arrivals) == 2 and arrivals[1] - arrivals[0] >= 0.9


def test_a_target_that_stops_answering_is_held_and_any_answer_clears_the_streak():
    """A hung application (a lab app deadlocked by one request) was sent 25 minutes of requests
    that could only time out. Five unanswered requests in a row hold the origin, doubling."""
    clock = _Clock()
    backoff = TargetBackoff(clock)
    for _ in range(target_backoff.SILENT_STREAK - 1):
        assert backoff.observe_silence(ORIGIN) is None
    _answer(backoff, 500)  # an error page is still an answer
    for _ in range(target_backoff.SILENT_STREAK - 1):
        assert backoff.observe_silence(ORIGIN) is None
    assert backoff.remaining(ORIGIN) == 0
    assert backoff.observe_silence(ORIGIN) == "unreachable"
    assert backoff.remaining(ORIGIN) == target_backoff.SILENT_BASE_SECONDS
    clock.now += 100
    for _ in range(target_backoff.SILENT_STREAK):
        backoff.observe_silence(ORIGIN)
    assert backoff.remaining(ORIGIN) == 2 * target_backoff.SILENT_BASE_SECONDS
    for _ in range(10 * target_backoff.SILENT_STREAK):
        backoff.observe_silence(ORIGIN)
    assert backoff.remaining(ORIGIN) <= target_backoff.MAX_HOLD_SECONDS
    clock.now += 1000
    _answer(backoff, 200)
    for _ in range(target_backoff.SILENT_STREAK):
        backoff.observe_silence(ORIGIN)
    assert backoff.remaining(ORIGIN) == target_backoff.SILENT_BASE_SECONDS  # the answer reset the doubling


def test_the_tunnel_counts_requests_a_hung_target_never_answers():
    target_backoff.BACKOFF.reset()

    async def scenario():
        async def app(reader, writer):  # accepts and reads, never answers
            while await reader.read(4096):
                pass
            writer.close()

        try:
            upstream = await asyncio.start_server(app, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("the unit-test sandbox forbids loopback listeners")
        port = upstream.sockets[0].getsockname()[1]
        async with PinnedSocksProxy(hostname="shop.example.test", pinned_address="127.0.0.1", port=port,
                                    scheme="http") as proxy:
            for index in range(target_backoff.SILENT_STREAK):
                reader, writer = await _socks_connect(proxy.proxy_url, "shop.example.test", port)
                writer.write(f"GET /{index} HTTP/1.1\r\nHost: shop.example.test\r\n\r\n".encode())
                await writer.drain()
                await asyncio.sleep(0.05)
                writer.close()  # the client gives up
                await writer.wait_closed()
            await asyncio.sleep(0.2)
            record = proxy.receipt()
            held = target_backoff.BACKOFF.remaining(proxy.paced_origin)
        upstream.close()
        await upstream.wait_closed()
        return record, held

    record, held = asyncio.run(scenario())
    target_backoff.BACKOFF.reset()
    assert record["holds"] == {"unreachable": 1}
    assert held > 0


def test_the_engines_own_http_client_counts_a_timeout_as_silence():
    from uuid import UUID
    from capabilities.http import execute_bound_http_request
    from runtime.models import TargetBinding

    target_backoff.BACKOFF.reset()

    async def scenario():
        async def app(reader, writer):
            while await reader.read(4096):
                pass
            writer.close()

        try:
            server = await asyncio.start_server(app, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("the unit-test sandbox forbids loopback listeners")
        base = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        target = TargetBinding(target_id=str(UUID(int=2)), target_kind="web", canonical_host="127.0.0.1",
                               allowed_origins=(base,), allowed_addresses=("127.0.0.1",),
                               allowed_root_domains=("127.0.0.1",), environment="lab", scope_receipt_id=str(UUID(int=3)))
        result = await execute_bound_http_request(base, {"method": "GET", "path": "/a"}, target=target,
                                                  timeout_seconds=1)
        state = target_backoff.BACKOFF._origins.get(target_backoff.BACKOFF._origins and
                                                    next(iter(target_backoff.BACKOFF._origins)))
        server.close()
        await server.wait_closed()
        return result, state

    result, state = asyncio.run(scenario())
    target_backoff.BACKOFF.reset()
    assert not result["ok"]
    assert state is not None and state.silent == 1
