"""The bounded background loops against real PostgreSQL and Redis (2.11).

LOOPS_TEST_DATABASE_URL must address localhost/shakerscan_loops_test (the schema is rebuilt from
db/init.sql and the startup migrations); LOOPS_TEST_REDIS_URL a disposable Redis database, which
is flushed. Targets use the reserved .invalid domain; nothing is contacted.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
from uuid import uuid4

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("LOOPS_TEST_DATABASE_URL")
REDIS_URL = os.environ.get("LOOPS_TEST_REDIS_URL")
REQUIRED = os.environ.get("LOOPS_POSTGRES_REQUIRED") == "1"
pytestmark = pytest.mark.skipif(
    not (DSN and REDIS_URL) and not REQUIRED,
    reason="Requires an explicit disposable loops database and Redis")
if REQUIRED:
    import asyncpg
    import redis as redis_lib
else:
    asyncpg = pytest.importorskip("asyncpg")
    redis_lib = pytest.importorskip("redis")
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "api"), str(ROOT / "scanner")]

import asm_dispatch_selection as selection  # noqa: E402
import asm_inventory  # noqa: E402
import job_queue  # noqa: E402
from operations import queue_health  # noqa: E402
from runtime import loop_scale_indexes  # noqa: E402
from scan import action_budget_reconciliation as reconciliation  # noqa: E402
from scan import job_hash_lookup  # noqa: E402
from scan import queue_recovery  # noqa: E402
from schedules.router import fetch_due_schedules  # noqa: E402

DIGEST = "d" * 64


@pytest.fixture(scope="module", autouse=True)
def schema():
    require_disposable_database(DSN or "", "shakerscan_loops_test")

    async def initialize():
        from retest_contract import run_schema_migrations
        async with asyncpg.create_pool(DSN, min_size=1, max_size=3) as pool:
            async with pool.acquire() as conn:
                await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
                await conn.execute((ROOT / "db/init.sql").read_text())
            await run_schema_migrations(pool)
    asyncio.run(initialize())


@pytest.fixture
def redis_client():
    client = redis_lib.from_url(REDIS_URL, decode_responses=True)
    client.flushdb()
    yield client
    client.flushdb()


def run(scenario):
    async def work():
        async with asyncpg.create_pool(DSN, min_size=1, max_size=4) as pool:
            await scenario(pool)
    asyncio.run(work())


async def _target(conn, *, root="loops.invalid", asm=True):
    target = uuid4()
    await conn.execute(
        "INSERT INTO targets(id,url,root_domain,asm_enabled) VALUES($1,$2,$3,$4)",
        target, f"https://{target}.{root}", root, asm)
    return target


async def _scan(conn, target, *, status, created_minutes_ago=0, job_id=None, started=False):
    scan = uuid4()
    await conn.execute(
        """INSERT INTO scans(id,target_id,target_url,job_id,status,created_at,started_at)
           VALUES($1,$2,'https://loops.invalid',$3,$4,NOW()-make_interval(mins => $5),
                  CASE WHEN $6 THEN NOW()-make_interval(mins => $5) END)""",
        scan, target, job_id or uuid4().hex, status, created_minutes_ago, started)
    return scan


def test_startup_builds_the_loop_indexes_and_rebuilds_an_interrupted_one():
    async def scenario(pool):
        async with pool.acquire() as conn:
            for name, _table, _definition in loop_scale_indexes.LOOP_SCALE_INDEXES:
                assert await conn.fetchval(
                    "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)", name) is True, name
            name = loop_scale_indexes.LOOP_SCALE_INDEXES[0][0]
            # What a CREATE INDEX CONCURRENTLY interrupted by a restart leaves behind.
            await conn.execute("UPDATE pg_index SET indisvalid = false WHERE indexrelid = to_regclass($1)", name)
        assert await loop_scale_indexes.ensure_loop_scale_indexes(pool) == [name]
        async with pool.acquire() as conn:
            assert await conn.fetchval(
                "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)", name) is True
            # The session limit the pool set is restored after the unbounded build.
            assert await conn.fetchval("SHOW statement_timeout") in {"0", "30s"}
    run(scenario)


async def _action(conn, scan, action_id, status):
    await conn.execute(
        """INSERT INTO scan_capability_actions(
               scan_id, action_id, stage, ordinal, capability_name, adapter_name, adapter_version,
               output_schema, action_digest, execution_plan_digest, target_binding_digest,
               input_binding_digest, requested_budget, placement_json, required, supporting, status,
               receipt_hash, result_digest)
           VALUES($1,$2,'probe',$3,'http.request','fixture','1','fixture/v1',$4::text,$4::text,$4::text,
                  $4::text,'{}'::jsonb,'{}'::jsonb,true,false,$5,
                  CASE WHEN $5 IN ('success','partial','failed','timed_out') THEN $4::text END,
                  CASE WHEN $5 IN ('success','partial','failed','timed_out') THEN $4::text END)""",
        scan, action_id, abs(hash(action_id)) % 500, DIGEST, status)


async def _settled(conn, owner_kind, owner, action_id, status, minutes_ago):
    await conn.execute(
        """INSERT INTO budget_reservations(id,owner_kind,owner_id,action_id,action_digest,capability_name,
               status,hold_applied,finished_at,failure_reason,version,state_digest,state_json,requested_json,
               created_at,updated_at)
           VALUES($1,$2,$3,$4,$5,'http.request',$6,true,NOW(),$7,1,$5,'{}'::jsonb,'{}'::jsonb,
                  NOW()-make_interval(mins => $8),NOW()-make_interval(mins => $8))""",
        uuid4().hex, owner_kind, str(owner), action_id, DIGEST, status,
        "lease_expired" if status == "failed" else None, minutes_ago)


class CursorStore:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value):
        self.values[key] = value


def test_incremental_repair_terminalizes_exactly_the_open_actions_of_settled_reservations():
    async def scenario(pool):
        async with pool.acquire() as conn:
            target = await _target(conn)
            scan = await _scan(conn, target, status="running", started=True)
            await _action(conn, scan, "released-open", "leased")
            await _action(conn, scan, "failed-open", "running")
            await _action(conn, scan, "already-done", "success")
            await _action(conn, scan, "settled-just-now", "leased")
            await _settled(conn, "scan", scan, "released-open", "released", 60)
            await _settled(conn, "scan", scan, "failed-open", "failed", 30)
            await _settled(conn, "scan", scan, "already-done", "released", 40)
            await _settled(conn, "scan", scan, "settled-just-now", "released", 1)
            await _settled(conn, "hunt", uuid4(), "released-open", "released", 60)  # not a Scan's
        cursor_store = CursorStore()
        repaired = await reconciliation.repair_settled_reservation_actions(pool, cursor_store, batch_size=2)
        assert repaired == 2
        async with pool.acquire() as conn:
            statuses = {row["action_id"]: row["status"] for row in await conn.fetch(
                "SELECT action_id, status FROM scan_capability_actions WHERE scan_id=$1", scan)}
        assert statuses == {"released-open": "blocked", "failed-open": "failed",
                            "already-done": "success", "settled-just-now": "leased"}
        stamp, _sep, _id = cursor_store.values[reconciliation.REPAIR_CURSOR_KEY].partition("|")
        # The cursor passed what it examined, but never a reservation inside the skew margin.
        assert datetime.fromisoformat(stamp) < datetime.now(timezone.utc) - timedelta(minutes=15)
        assert await reconciliation.repair_settled_reservation_actions(pool, cursor_store) == 0
    run(scenario)


def test_lost_handoff_sweep_walks_waiting_scans_in_bounded_batches(redis_client):
    async def scenario(pool):
        async with pool.acquire() as conn:
            await conn.execute("UPDATE scans SET status='completed' WHERE status IN ('pending','queued')")
            target = await _target(conn)
            old = [await _scan(conn, target, status="pending", created_minutes_ago=30 + i) for i in range(5)]
            await _scan(conn, target, status="pending", created_minutes_ago=1)  # too recent to judge
            queued = await _scan(conn, target, status="pending", created_minutes_ago=40, job_id="in-queue")
        job_queue.enqueue_job(redis_client, "loops_scan_jobs", {"job_id": "in-queue"})
        state = {}

        async def resend(_conn, _redis, _row):
            return "limit"  # keep them all on the conservative "unknown" path

        for _sweep in range(3):
            await queue_recovery.sweep_lost_queue_handoffs(
                pool, redis_client, now=datetime.now(timezone.utc),
                queue_membership=lambda r, wanted: job_queue.scan_queue_job_ids(r, "loops_scan_jobs", wanted=wanted),
                decode_hash=lambda raw: dict(raw or {}), resend=resend, state=state, limit=2)
        async with pool.acquire() as conn:
            flagged = {row["id"] for row in await conn.fetch(
                "SELECT id FROM scans WHERE current_phase='queue_handoff_unknown'")}
        assert flagged == set(old)  # every old one, over several bounded sweeps; never the queued one
        assert queued not in flagged
    run(scenario)


def test_asm_batched_counts_equal_the_per_target_counts():
    async def scenario(pool):
        async with pool.acquire() as conn:
            a = await _target(conn, root="shared.invalid")
            b = await _target(conn, root="shared.invalid")
            c = await _target(conn, root="other.invalid")
            await _target(conn, asm=False)
            await _scan(conn, a, status="running", started=True)
            rows = [
                (a, "untested", None), (a, "stale", None), (a, "tested", 45 * 24 * 60),
                (a, "tested", 30), (b, "tested", 10), (b, "tested", 3 * 60), (c, "untested", None),
            ]
            for index, (target, status, minutes_ago) in enumerate(rows):
                await conn.execute(
                    """INSERT INTO target_endpoints(target_id,path,fingerprint,test_status,last_tested_at)
                       VALUES($1,$2,$3,$4,CASE WHEN $5::int IS NULL THEN NULL
                                              ELSE NOW()-make_interval(mins => $5::int) END)""",
                    target, f"/p{index}", f"fp{index}", status, minutes_ago)
            schedule = selection.AsmDueSchedule()
            due = await selection.load_due_targets(conn, schedule, now=datetime.now(timezone.utc), limit=10)
            assert {a, b, c} <= {row["id"] for row in due}
            due = [row for row in due if row["id"] in {a, b, c}]
            counts = await selection.load_counts(conn, due, stale_days={str(a): 30, str(b): 30, str(c): 30})
            for target in (a, b, c):
                tid = str(target)
                assert counts["claimable"].get(tid, 0) == await asm_inventory.claimable_count(conn, tid, stale_days=30)
                assert counts["tested_today"].get(tid, 0) == await asm_inventory.tested_recently_count(conn, tid, hours=24)
                active = await conn.fetchval(
                    "SELECT COUNT(*) FROM scans WHERE target_id=$1 AND status IN ('pending','queued','running')", target)
                assert counts["active"].get(tid, 0) == active
            for root in ("shared.invalid", "other.invalid"):
                assert counts["domain_used"].get(root, 0) == await asm_inventory.domain_tested_recently_count(
                    conn, root, hours=1)
            # Bounded: a tick takes at most `limit` due targets.
            assert len(await selection.load_due_targets(
                conn, selection.AsmDueSchedule(), now=datetime.now(timezone.utc), limit=2)) == 2
    run(scenario)


def test_queue_stats_and_job_hash_repair_against_real_redis(redis_client):
    async def scenario(pool):
        async with pool.acquire() as conn:
            await conn.execute("UPDATE scans SET status='completed' WHERE status IN ('pending','queued','running')")
            target = await _target(conn)
            await _scan(conn, target, status="running", started=True, job_id="live-job")
            await _scan(conn, target, status="pending", job_id="waiting-job")
            await _scan(conn, target, status="pending", job_id="leased-job")
        queue = "loops_stats_jobs"
        job_queue.enqueue_job(redis_client, queue, {"job_id": "leased-job"})
        job_queue.enqueue_job(redis_client, queue, {"job_id": "waiting-job"})
        # A worker leases the oldest message (leased-job) and has not acknowledged it yet.
        redis_client.xreadgroup(job_queue.CONSUMER_GROUP, "w1", {job_queue.stream_key(queue): ">"}, count=1)
        redis_client.hset("job:live-job", mapping={"status": "running", "heartbeat": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()})
        redis_client.hset("job:gone-job", mapping={"status": "running"})
        redis_client.hset("job:waiting-job", mapping={"status": "queued"})
        redis_client.hset("job:leased-job", mapping={"status": "queued"})
        redis_client.hset("job:orphan-queued", mapping={"status": "queued"})
        redis_client.hset("retest_job:r1", mapping={"status": "completed"})
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        stats = await queue_health.compute_queue_stats(
            pool, redis_client, now=now, hidden_roles={"shard"}, queue_name=queue,
            scan_queue_job_ids=job_queue.scan_queue_job_ids, pending_depth=job_queue.pending_depth,
            retest_queue_name="loops_retests", broker_queue_name="loops_broker",
            heartbeat_timeout_minutes=10, retest_timeout_minutes=30)
        assert stats["running"] == 1 and stats["pending"] == 2
        assert stats["work_running"] == 1 and stats["retest_completed"] == 1
        assert stats["queued"] == 1  # waiting, not the leased one
        assert stats["queue_consistency"]["complete"] is True
        assert stats["queue_consistency"]["stale_running_job_hashes"] == 1
        assert stats["queue_consistency"]["stale_queued_job_hashes"] == 1
        assert stats["queue_consistency"]["active_scan_without_queue_entry"] == 0
        assert redis_client.hget("job:gone-job", "status") == "running"  # the GET wrote nothing

        repaired = await queue_health.reconcile_job_hashes(
            pool, redis_client, state={}, now=now, queue_name=queue,
            scan_queue_job_ids=job_queue.scan_queue_job_ids,
            heartbeat_timeout_minutes=10, retest_timeout_minutes=30, keys_per_tick=100)
        assert repaired == 2
        assert redis_client.hget("job:gone-job", "status") == "orphaned"
        assert redis_client.hget("job:orphan-queued", "status") == "orphaned"
        assert redis_client.hget("job:waiting-job", "status") == "queued"
        assert redis_client.hget("job:live-job", "status") == "running"
    run(scenario)


def test_queue_scan_pages_real_streams_routes_and_leases(redis_client):
    queue = "loops_paged_jobs"
    for index in range(7):
        job_queue.enqueue_job(redis_client, queue, {"job_id": f"job-{index}"})
    job_queue.enqueue_job(redis_client, queue, {"job_id": "routed", "placement": {"node_scope": "local"}})
    redis_client.xreadgroup(job_queue.CONSUMER_GROUP, "w1", {job_queue.stream_key(queue): ">"}, count=2)
    seen = job_queue.scan_queue_job_ids(redis_client, queue, track_unleased=True, page_size=2)
    assert seen.complete and not seen.error
    assert seen.job_ids == {f"job-{i}" for i in range(7)} | {"routed"}
    assert seen.unleased_job_ids == seen.job_ids - {"job-0", "job-1"}
    bounded = job_queue.scan_queue_job_ids(redis_client, queue, max_entries=3, page_size=2)
    assert not bounded.complete and bounded.presence("routed") is None


def test_running_scan_batches_cover_every_running_scan_across_ticks():
    async def scenario(pool):
        async with pool.acquire() as conn:
            await conn.execute("UPDATE scans SET status='completed' WHERE status='running'")
            target = await _target(conn)
            running = {await _scan(conn, target, status="running", started=True) for _ in range(5)}
            state, seen = {}, []
            for _tick in range(3):
                seen.append({row["id"] for row in await job_hash_lookup.fetch_running_scan_batch(conn, state, limit=2)})
            assert all(len(batch) == 2 for batch in seen)
            assert set().union(*seen) == running
    run(scenario)


def test_due_schedules_are_bounded_and_most_overdue_first():
    async def scenario(pool):
        async with pool.acquire() as conn:
            await conn.execute("UPDATE schedules SET is_active=false")
            target = await _target(conn)
            ids = []
            for minutes in (5, 50, 20):
                ids.append(await conn.fetchval(
                    """INSERT INTO schedules(target_id,frequency,next_run_at)
                       VALUES($1,'daily',NOW()-make_interval(mins => $2)) RETURNING id""", target, minutes))
        due = await fetch_due_schedules(pool, now=datetime.now(timezone.utc), limit=2)
        assert [row["id"] for row in due] == [ids[1], ids[2]]
    run(scenario)


def _sql_between(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin:source.index(end, begin) + len(end)]


def test_research_loop_queries_compare_retest_ids_as_uuids_and_plan():
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
    candidate = _sql_between(source, "WITH candidate AS (", "RETURNING re.*")
    orphaned = _sql_between(source, "SELECT re.id AS episode_id, fv.id, fv.job_id, fv.finding_id", "LIMIT 25")
    for query in (candidate, orphaned):
        assert "fv.id::text" not in query
        assert re.search(r"fv\.id=\(CASE WHEN", query)

    async def scenario(pool):
        async with pool.acquire() as conn:
            await conn.fetch("EXPLAIN " + candidate, "owner", 30)
            await conn.fetch("EXPLAIN " + orphaned)
            # A non-UUID retest id is not an error: it matches nothing.
            await conn.fetchval(
                "SELECT (CASE WHEN $1 ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' "
                "THEN $1::uuid END) IS NULL", "not-a-uuid")
    run(scenario)


def test_unconfirmed_handoff_index_matches_the_reconciler_query():
    """The partial index predicate must be implied by the query's WHERE, or it is never used."""
    async def scenario(pool):
        async with pool.acquire() as conn:
            await conn.execute("SET enable_seqscan = off")
            plan = "\n".join(row[0] for row in await conn.fetch(
                """EXPLAIN SELECT id, campaign_id FROM scans
                   WHERE status='pending' AND options->>'queue_handoff_confirmed'='false'
                     AND created_at < NOW() - INTERVAL '5 minutes'
                   ORDER BY created_at ASC LIMIT 25"""))
            assert "idx_scans_unconfirmed_handoff_created" in plan
    run(scenario)


def test_json_round_trip_keeps_asm_decisions_comparable():
    stored = json.loads(json.dumps({"action": "none", "blocked_by": "min_interval", "claimable": 3,
                                    "recorded_at": "2026-10-14T00:00:00"}))
    assert selection.same_decision(stored, {"action": "none", "blocked_by": "min_interval", "claimable": 3,
                                            "recorded_at": "later"})
