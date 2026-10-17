"""Bounded reads behind the background loops (2.11): each test fails against the unbounded version.

Unit fixtures: the Redis and PostgreSQL objects here are labelled doubles that record the calls a
loop makes; the real-database counterparts are in tests/test_background_loops_postgres.py.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json

import pytest

from api.job_queue import scan_queue_job_ids
from api.loop_leader import LoopLeadership, loop_lock_key
from api.runtime import loop_scale_indexes
from api.scan import action_budget_reconciliation as reconciliation
from api.scan.job_hash_lookup import UNKNOWN, JobHashFallback, load_scan_job_hashes


class StreamRedis:
    """Double of a Redis with one stream queue (and optional legacy list). ``xrange`` without a
    COUNT, the whole-stream read the bounded scan replaces, fails the test."""

    def __init__(self, job_ids, *, leased=(), legacy=(), fail_after_pages=None):
        self.entries = [(f"{index + 1}-0", {"payload": json.dumps({"job_id": job_id})})
                        for index, job_id in enumerate(job_ids)]
        self.leased = set(leased)
        self.legacy = [json.dumps({"job_id": job_id}) for job_id in legacy]
        self.pages = 0
        self.fail_after_pages = fail_after_pages

    # Presence of these makes job_queue treat the client as stream-capable.
    def xadd(self, *_args, **_kwargs):
        raise AssertionError("read-only")

    def xreadgroup(self, *_args, **_kwargs):
        raise AssertionError("read-only")

    def smembers(self, _key):
        return set()

    def xrange(self, key, min="-", max="+", count=None):
        assert count is not None, "an unbounded XRANGE reads the whole backlog at once"
        self.pages += 1
        if self.fail_after_pages is not None and self.pages > self.fail_after_pages:
            raise ConnectionError("redis went away")
        start = 0
        if min.startswith("("):
            start = next(i + 1 for i, (mid, _f) in enumerate(self.entries) if mid == min[1:])
        return self.entries[start:start + count]

    def xpending_range(self, key, group, min="-", max="+", count=None):
        assert count is not None
        rows = [{"message_id": mid} for mid, fields in self.entries
                if json.loads(fields["payload"])["job_id"] in self.leased]
        start = 0
        if min.startswith("("):
            start = next(i + 1 for i, row in enumerate(rows) if row["message_id"] == min[1:])
        return rows[start:start + count]

    def lrange(self, key, start, end):
        assert end != -1, "an unbounded LRANGE reads the whole legacy list at once"
        return self.legacy[start:end + 1]


def test_queue_scan_reads_in_pages_and_reports_a_complete_read():
    redis = StreamRedis([f"job-{i}" for i in range(7)], legacy=["legacy-job"])
    seen = scan_queue_job_ids(redis, "scan_jobs", page_size=2)
    assert seen.complete and not seen.error
    assert seen.job_ids == {f"job-{i}" for i in range(7)} | {"legacy-job"}
    assert redis.pages == 4  # 2+2+2+1 entries
    assert seen.presence("job-3") is True and seen.presence("absent") is False


def test_queue_scan_stops_once_every_wanted_job_was_seen():
    redis = StreamRedis([f"job-{i}" for i in range(100)])
    seen = scan_queue_job_ids(redis, "scan_jobs", wanted={"job-1", "job-2"}, page_size=2)
    assert seen.presence("job-1") is True and seen.presence("job-2") is True
    assert redis.pages == 2


def test_queue_scan_past_its_bound_is_unknown_never_absent():
    redis = StreamRedis([f"job-{i}" for i in range(100)])
    seen = scan_queue_job_ids(redis, "scan_jobs", max_entries=10, page_size=5)
    assert not seen.complete
    assert seen.presence("job-99") is None  # beyond the bound: not proof of a lost handoff
    assert redis.pages == 2


def test_queue_scan_failure_is_reported_as_an_error():
    redis = StreamRedis([f"job-{i}" for i in range(10)], fail_after_pages=1)
    seen = scan_queue_job_ids(redis, "scan_jobs", page_size=3)
    assert seen.error and not seen.complete
    assert seen.presence("job-9") is None


def test_queue_scan_tracks_leased_entries_separately():
    redis = StreamRedis(["waiting", "leased"], leased={"leased"})
    seen = scan_queue_job_ids(redis, "scan_jobs", track_unleased=True, page_size=1)
    assert seen.job_ids == {"waiting", "leased"}
    assert seen.unleased_job_ids == {"waiting"}
    assert seen.leased_complete


class KeyspaceRedis:
    """Double of a keyspace walked with SCAN; ``keys`` (blocking KEYS) fails the test."""

    def __init__(self, hashes, *, page=2):
        self.hashes = hashes
        self.order = list(hashes)
        self.page = page
        self.scanned = 0

    def keys(self, _pattern):
        raise AssertionError("KEYS job:* must never run")

    def scan(self, cursor=0, match=None, count=None):
        cursor = int(cursor)
        chunk = self.order[cursor:cursor + self.page]
        self.scanned += len(chunk)
        following = cursor + self.page
        return (0 if following >= len(self.order) else following), chunk

    def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))


def test_job_hash_fallback_is_unknown_until_a_full_walk_since_the_miss():
    hashes = {f"job:other-{i}": {"scan_id": f"other-{i}"} for i in range(10)}
    redis = KeyspaceRedis(hashes, page=2)
    fallback = JobHashFallback(keys_per_tick=4)
    verdicts = []
    for _tick in range(8):
        verdicts.append(fallback.resolve(redis, ["missing-scan"])["missing-scan"])
        assert redis.scanned <= 4 * (_tick + 1)  # bounded per tick
    assert verdicts[0] is UNKNOWN
    assert None in verdicts  # absent once a complete walk has passed since the miss
    assert verdicts.index(None) >= 2


def test_job_hash_lookup_reads_the_recorded_job_first_and_falls_back_by_scan_id():
    redis = KeyspaceRedis({
        "job:j1": {"scan_id": "s1", "heartbeat": "h1"},
        "job:legacy": {"scan_id": "s2", "heartbeat": "h2"},
    })
    found = load_scan_job_hashes(
        redis, [{"id": "s1", "job_id": "j1"}, {"id": "s2", "job_id": "j2"}],
        decode=lambda raw: dict(raw or {}), fallback=JobHashFallback())
    assert found["s1"]["heartbeat"] == "h1"
    assert found["s2"]["heartbeat"] == "h2"


class LockServer:
    """Session advisory locks shared by the connections of several fake pools."""

    def __init__(self):
        self.owner = {}


class LockConn:
    def __init__(self, server):
        self.server = server
        self.alive = True

    async def fetchval(self, query, *args):
        if not self.alive:
            raise ConnectionError("connection lost")
        if "pg_try_advisory_lock" in query:
            key = args
            holder = self.server.owner.get(key)
            if holder is None or not holder.alive:
                self.server.owner[key] = self
                return True
            return holder is self
        return 1

    async def execute(self, query, *args):
        if "pg_advisory_unlock_all" in query:
            self.server.owner = {k: v for k, v in self.server.owner.items() if v is not self}


class LockPool:
    def __init__(self, server):
        self.server = server
        self.out = []

    async def acquire(self):
        conn = LockConn(self.server)
        self.out.append(conn)
        return conn

    async def release(self, conn):
        self.out.remove(conn)


def test_one_process_leads_a_loop_and_a_follower_holds_no_connection():
    server = LockServer()
    first_pool, second_pool = LockPool(server), LockPool(server)
    first, second = LoopLeadership(first_pool), LoopLeadership(second_pool)

    async def scenario():
        assert await first.lead("stale_scan_checker") is True
        assert await second.lead("stale_scan_checker") is False
        assert second_pool.out == []  # a follower gives its connection back
        assert await first.lead("stale_scan_checker") is True  # leadership is kept
        assert len(first_pool.out) == 1
        # The leader's connection dies: its session locks end, a follower takes over.
        first_pool.out[0].alive = False
        assert await second.lead("stale_scan_checker") is True
        assert await first.lead("stale_scan_checker") is False
        await second.close()
        assert second_pool.out == []

    asyncio.run(scenario())


def test_loop_lock_keys_are_stable_signed_32_bit_values():
    assert loop_lock_key("asm_dispatcher") == loop_lock_key("asm_dispatcher")
    assert loop_lock_key("asm_dispatcher") != loop_lock_key("schedule_runner")
    for name in ("stale_scan_checker", "asm_dispatcher", "sweep_stale_budget_reservations"):
        assert -2**31 <= loop_lock_key(name) < 2**31


class RepairConn:
    """Double of the two queries of one incremental repair batch."""

    def __init__(self, rows, locked):
        self.rows = rows
        self.locked = locked
        self.updated = []
        self.batch_args = None

    async def fetch(self, query, *args):
        if "WITH batch AS" in query:
            assert "::text =" not in query and "scan_id::text" not in query  # sargable probe
            assert "LIMIT $3" in query
            self.batch_args = args
            return self.rows
        if "FOR UPDATE SKIP LOCKED" in query:
            return [{"id": action} for action in args[0] if action in self.locked]
        if "UPDATE scan_capability_actions" in query:
            self.updated.extend(args[0])
            return [{"id": action} for action in args[0]]
        raise AssertionError(query)


def _settled(index, *, open_action=None, passable=True):
    return {"id": f"r{index}", "updated_at": datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index),
            "passable": passable, "reservation_status": "released", "failure_reason": None,
            "execution_uncertain": False, "open_action": open_action}


def test_incremental_repair_terminalizes_open_actions_and_advances_its_cursor():
    rows = [_settled(1), _settled(2, open_action="a2"), _settled(3)]
    conn = RepairConn(rows, locked={"a2"})
    repaired, cursor, examined = asyncio.run(
        reconciliation.repair_terminal_reservation_actions_incremental(conn, cursor=None, limit=3))
    assert (repaired, examined) == (1, 3)
    assert conn.updated == ["a2"]
    assert cursor == (rows[2]["updated_at"], "r3")


def test_incremental_repair_stops_before_a_busy_action_and_a_too_recent_reservation():
    rows = [_settled(1), _settled(2, open_action="busy"), _settled(3)]
    _repaired, cursor, _examined = asyncio.run(reconciliation.repair_terminal_reservation_actions_incremental(
        RepairConn(rows, locked=set()), cursor=None, limit=3))
    assert cursor == (rows[0]["updated_at"], "r1")  # the busy one is looked at again next sweep

    rows = [_settled(1), _settled(2, passable=False)]
    _repaired, cursor, _examined = asyncio.run(reconciliation.repair_terminal_reservation_actions_incremental(
        RepairConn(rows, locked=set()), cursor=None, limit=3))
    assert cursor == (rows[0]["updated_at"], "r1")  # within the clock-skew margin: not passed


def test_incremental_repair_rejects_unbounded_limits():
    with pytest.raises(ValueError, match="between 1 and 1000"):
        asyncio.run(reconciliation.repair_terminal_reservation_actions_incremental(
            RepairConn([], set()), cursor=None, limit=1001))


class CursorRedis:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value):
        self.values[key] = value


class SimplePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        conn = self.conn

        class Acquire:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *_exc):
                return False

        return Acquire()


class TxConn(RepairConn):
    def transaction(self):
        class Tx:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return False

        return Tx()


def test_repair_cursor_is_shared_through_redis_so_a_new_leader_resumes():
    rows = [_settled(1), _settled(2)]
    redis = CursorRedis()
    asyncio.run(reconciliation.repair_settled_reservation_actions(
        SimplePool(TxConn(rows, set())), redis, batch_size=5))
    stored = redis.values[reconciliation.REPAIR_CURSOR_KEY]
    assert stored.endswith("|r2")
    conn = TxConn([], set())
    asyncio.run(reconciliation.repair_settled_reservation_actions(SimplePool(conn), redis, batch_size=5))
    assert conn.batch_args[1] == "r2"  # the next leader starts after what was examined


class IndexConn:
    def __init__(self, states, *, in_transaction=False, lock_free=True):
        self.states = states  # index name -> True/False/None
        self.statements = []
        self.in_tx = in_transaction
        self.lock_free = lock_free

    def is_in_transaction(self):
        return self.in_tx

    async def fetchval(self, query, *args):
        if "pg_try_advisory_lock" in query:
            return self.lock_free
        if "SHOW statement_timeout" in query:
            return "30s"
        if "to_regclass" in query:
            return args[0]
        if "indisvalid" in query:
            return self.states.get(args[0])
        raise AssertionError(query)

    async def execute(self, query, *args):
        self.statements.append(query)


def test_loop_indexes_build_concurrently_and_rebuild_an_interrupted_build():
    names = [name for name, _table, _definition in loop_scale_indexes.LOOP_SCALE_INDEXES]
    states = {name: True for name in names}
    states[names[0]] = False  # an interrupted CONCURRENTLY build leaves an invalid index
    states[names[1]] = None
    conn = IndexConn(states)
    built = asyncio.run(loop_scale_indexes.ensure_loop_scale_indexes(SimplePool(conn)))
    assert built == names[:2]
    creates = [s for s in conn.statements if s.startswith("CREATE INDEX")]
    assert creates and all("CONCURRENTLY" in s for s in creates)
    assert any(s.startswith(f"DROP INDEX CONCURRENTLY IF EXISTS {names[0]}") for s in conn.statements)
    assert conn.statements[0] == "SET statement_timeout = 0"
    assert conn.statements[-2] == "SET statement_timeout = '30s'"  # the session's own limit is restored


def test_loop_indexes_are_left_to_the_builder_and_never_built_inside_a_transaction():
    for conn in (IndexConn({}, lock_free=False), IndexConn({}, in_transaction=True)):
        assert asyncio.run(loop_scale_indexes.ensure_loop_scale_indexes(SimplePool(conn))) == []
        assert not any(s.startswith("CREATE INDEX") for s in conn.statements)


def test_fallback_resolves_rotating_batches_of_lost_hashes_in_a_large_keyspace_within_bounded_ticks():
    """600 running scans (rotating stale-check batches of 500) whose hashes are lost, among 30k
    unrelated job hashes: each gets its verdict within a few ticks; rotation never restarts it."""
    hashes = {f"job:old-{i}": {"scan_id": f"other-{i}"} for i in range(30_000)}
    redis = KeyspaceRedis(hashes, page=1000)
    fallback = JobHashFallback(keys_per_tick=20_000)
    lost = [f"lost-{i:04d}" for i in range(600)]
    verdicts: dict[str, object] = {}
    offset = 0
    for tick in range(8):
        batch = (lost + lost)[offset:offset + 500]
        offset = (offset + 500) % len(lost)
        fallback.retain(lost)  # all still running
        verdicts.update(fallback.resolve(redis, batch))
        assert redis.scanned <= 20_000 * (tick + 1)
    assert all(verdicts[sid] is None for sid in lost)


def test_fallback_forgets_a_found_hash_that_no_longer_names_the_scan():
    redis = KeyspaceRedis({"job:legacy": {"scan_id": "s1", "heartbeat": "h"}})
    fallback = JobHashFallback()
    scans = [{"id": "s1", "job_id": "missing"}]
    assert load_scan_job_hashes(redis, scans, decode=lambda raw: dict(raw or {}), fallback=fallback)["s1"]["heartbeat"] == "h"
    del redis.hashes["job:legacy"]
    redis.order.remove("job:legacy")
    seen = [load_scan_job_hashes(redis, scans, decode=lambda raw: dict(raw or {}), fallback=fallback)["s1"]
            for _tick in range(4)]
    assert seen[0] is UNKNOWN  # not trusted any more, not yet proven absent
    assert seen[-1] is None  # a complete walk since then found nothing
    fallback.retain([])  # the scan stopped running: nothing is tracked for it any more
    assert fallback.tracked() == set()


def test_a_busy_leader_still_runs_its_led_loop():
    """The worker's budget sweep is its own task: a leader busy with a long job still sweeps."""
    from api.loop_leader import run_led_loop

    server = LockServer()
    pool = LockPool(server)
    ticks = []

    async def tick():
        ticks.append(1)

    async def scenario():
        sweep = asyncio.create_task(run_led_loop(pool, "sweep", tick, interval=0.01, timeout=5))
        await asyncio.sleep(0.2)  # "a long job" occupying the worker's main loop
        sweep.cancel()
        with pytest.raises(asyncio.CancelledError):
            await sweep

    asyncio.run(scenario())
    assert len(ticks) >= 5


def test_a_hung_tick_gives_up_leadership_so_another_process_takes_over():
    from api import loop_leader

    server = LockServer()
    first_pool, second_pool = LockPool(server), LockPool(server)

    async def hang():
        await asyncio.sleep(3600)

    class TerminatingConn(LockConn):
        def terminate(self):
            self.alive = False  # the server ends the session: its locks go with it

    async def acquire_terminating():
        conn = TerminatingConn(server)
        first_pool.out.append(conn)
        return conn

    first_pool.acquire = acquire_terminating
    ran = []

    async def scenario():
        assert await loop_leader.run_tick(first_pool, "loop", hang, timeout=0.05) is True
        assert first_pool.out == []  # the hung session was closed and given back

        async def tick():
            ran.append(1)
        assert await loop_leader.run_tick(second_pool, "loop", tick, timeout=1) is True

    asyncio.run(scenario())
    assert ran == [1]


def test_the_leader_session_asks_the_server_for_tcp_keepalives():
    from api.loop_leader import LEADER_KEEPALIVE_SQL

    server = LockServer()
    executed = []

    class RecordingConn(LockConn):
        async def execute(self, query, *args):
            executed.append(query)
            await super().execute(query, *args)

    class RecordingPool(LockPool):
        async def acquire(self):
            conn = RecordingConn(self.server)
            self.out.append(conn)
            return conn

    assert asyncio.run(LoopLeadership(RecordingPool(server)).lead("loop")) is True
    assert LEADER_KEEPALIVE_SQL in executed and "tcp_keepalives_idle" in LEADER_KEEPALIVE_SQL
