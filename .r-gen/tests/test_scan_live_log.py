"""Numbered Scan log lines (api/scan/live_log.py) and ``after_seq`` on GET /scans/{id}/logs.

Runs against an in-memory stand-in (a unit fixture: list, counter and MULTI semantics only) and,
when ``SHAKERSCAN_TEST_REDIS_URL`` names a disposable Redis, against Redis itself.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from scan import live_log  # noqa: E402


class FakeRedis:
    """Unit fixture: the list/counter commands the log uses, applied at ``execute`` like MULTI."""

    def __init__(self):
        self.lists: dict[str, list] = {}
        self.values: dict[str, int] = {}

    def pipeline(self, transaction=True):
        return _Pipe(self)

    def lrange(self, key, start, stop):
        items = self.lists.get(key, [])
        n = len(items)
        start = max(0, n + start if start < 0 else start)
        stop = n + stop if stop < 0 else stop
        return items[start:stop + 1]

    def delete(self, key):
        self.lists.pop(key, None)
        self.values.pop(key, None)


class _Pipe:
    def __init__(self, redis):
        self.redis, self.ops = redis, []

    def __getattr__(self, name):
        def queue(*args):
            self.ops.append((name, args))
            return self
        return queue

    def execute(self):
        out = []
        r = self.redis
        for name, args in self.ops:
            if name == "rpush":
                r.lists.setdefault(args[0], []).extend(args[1:])
                out.append(len(r.lists[args[0]]))
            elif name == "ltrim":
                key, start, stop = args
                r.lists[key] = r.lrange(key, start, stop)
                out.append(True)
            elif name == "incrby":
                r.values[args[0]] = r.values.get(args[0], 0) + args[1]
                out.append(r.values[args[0]])
            elif name == "get":
                value = r.values.get(args[0])
                out.append(None if value is None else str(value).encode())
            elif name == "llen":
                out.append(len(r.lists.get(args[0], [])))
            elif name == "lrange":
                out.append(r.lrange(*args))
            elif name == "expire":
                out.append(True)
            else:
                raise AssertionError(name)
        return out


def _backends():
    params = [pytest.param("fake", id="unit-fixture")]
    params.append(pytest.param("redis", id="redis", marks=pytest.mark.skipif(
        not os.environ.get("SHAKERSCAN_TEST_REDIS_URL"),
        reason="set SHAKERSCAN_TEST_REDIS_URL to a disposable Redis to run against Redis itself")))
    return params


@pytest.fixture(params=_backends())
def redis_client(request):
    if request.param == "fake":
        return FakeRedis()
    import redis as redis_lib
    return redis_lib.Redis.from_url(os.environ["SHAKERSCAN_TEST_REDIS_URL"])


def _text(lines):
    return [line.decode() if isinstance(line, bytes) else line for line in lines]


def test_after_seq_returns_only_new_lines_and_numbers_them(redis_client):
    scan = uuid.uuid4()
    live_log.append_scan_log_lines(redis_client, scan, ["[scan] a", "[scan] b"], tail=5, ttl_seconds=60)
    first = live_log.read_scan_log(redis_client, scan, limit=200)
    assert first["seq_supported"] and first["next_seq"] == 2 and first["first_seq"] == 1
    assert _text(first["lines"]) == ["[scan] a", "[scan] b"] and not first["truncated"]

    live_log.append_scan_log_lines(redis_client, scan, ["[scan] c"], tail=5, ttl_seconds=60)
    delta = live_log.read_scan_log(redis_client, scan, limit=200, after_seq=first["next_seq"])
    assert _text(delta["lines"]) == ["[scan] c"] and delta["next_seq"] == 3 and delta["first_seq"] == 3
    assert not delta["truncated"]

    idle = live_log.read_scan_log(redis_client, scan, limit=200, after_seq=3)
    assert idle["lines"] == [] and idle["next_seq"] == 3 and not idle["truncated"]


def test_lines_trimmed_between_polls_are_reported_as_truncated(redis_client):
    scan = uuid.uuid4()
    live_log.append_scan_log_lines(redis_client, scan, [f"[scan] {i}" for i in range(3)], tail=4, ttl_seconds=60)
    seen = live_log.read_scan_log(redis_client, scan, limit=200)["next_seq"]
    live_log.append_scan_log_lines(redis_client, scan, [f"[scan] {i}" for i in range(3, 10)], tail=4, ttl_seconds=60)
    delta = live_log.read_scan_log(redis_client, scan, limit=200, after_seq=seen)
    assert delta["truncated"]
    assert _text(delta["lines"]) == ["[scan] 6", "[scan] 7", "[scan] 8", "[scan] 9"]
    assert delta["first_seq"] == 7 and delta["next_seq"] == 10
    # More new lines than the limit: the newest ``limit``, also truncated.
    # ("[scan] 9" is line 10.)
    capped = live_log.read_scan_log(redis_client, scan, limit=2, after_seq=8)
    assert _text(capped["lines"]) == ["[scan] 8", "[scan] 9"] and capped["truncated"] is False
    capped = live_log.read_scan_log(redis_client, scan, limit=2, after_seq=7)
    assert _text(capped["lines"]) == ["[scan] 8", "[scan] 9"] and capped["truncated"] is True


def test_a_list_without_a_counter_has_no_numbering(redis_client):
    scan = uuid.uuid4()
    pipe = redis_client.pipeline(transaction=True)
    pipe.rpush(live_log.log_key(scan), "[scan] old writer")
    pipe.execute()
    body = live_log.read_scan_log(redis_client, scan, limit=200, after_seq=5)
    assert body["seq_supported"] is False and _text(body["lines"]) == ["[scan] old writer"]
    redis_client.delete(live_log.log_key(scan))


def test_logs_route_serves_after_seq(monkeypatch):
    import api as api_module
    if hasattr(api_module, "__path__"):
        import importlib
        api_module = importlib.import_module("api.api")
    fake = FakeRedis()
    monkeypatch.setattr(api_module, "get_redis", lambda: fake)
    scan = str(uuid.uuid4())
    live_log.append_scan_log_lines(fake, scan, ["[scan] one", "[scan] two"], tail=200, ttl_seconds=60)
    body = asyncio.run(api_module.get_scan_logs(scan, limit=200, after_seq=None))
    assert body["lines"] == ["[scan] one", "[scan] two"] and body["next_seq"] == 2 and body["seq_supported"]
    live_log.append_scan_log_lines(fake, scan, ["[scan] three"], tail=200, ttl_seconds=60)
    body = asyncio.run(api_module.get_scan_logs(scan, limit=200, after_seq=2))
    assert body["lines"] == ["[scan] three"] and body["count"] == 1 and body["next_seq"] == 3



def test_a_rewound_counter_returns_the_replacement_tail(redis_client):
    scan = uuid.uuid4()
    live_log.append_scan_log_lines(redis_client, scan, ["new first", "new second"], tail=5, ttl_seconds=60)
    reply = live_log.read_scan_log(redis_client, scan, limit=5, after_seq=100)
    assert reply["truncated"] and reply["next_seq"] == 2
    assert _text(reply["lines"]) == ["new first", "new second"]
    assert reply["first_seq"] == 1
