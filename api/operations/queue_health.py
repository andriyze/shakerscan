"""Queue statistics from bounded reads, and the job-hash repairs that used to happen in a GET (2.11).

``GET /queue/stats`` read every queue entry (twice), walked every ``job:*`` and ``retest_job:*``
hash with HGETALL and wrote repairs into them while answering. It now reads at most a bounded
number of hashes (the fields it needs, pipelined), the queue in bounded pages, and the database with
aggregates, and writes nothing but its five-second cache. When a bound was reached the answer says
so (``queue_consistency.complete``) instead of guessing.

The repairs the GET made (a running hash with no active Scan marked orphaned, a silent worker's
hash marked failed, a queued hash with no queued Scan marked orphaned, an overdue retest hash
marked failed) are made by ``reconcile_job_hashes``, a bounded slice per stale-check tick, by the
stale-check loop's leader, with the same rules.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import os
from typing import Any, Callable, Iterable

JOB_HASH_PATTERN = "job:*"
RETEST_HASH_PATTERN = "retest_job:*"
HASH_FIELDS = ("status", "heartbeat", "started_at")
ORPHAN_EXPIRE_SECONDS = 86400


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "") or default))
    except ValueError:
        return default


STATS_MAX_HASH_KEYS = _int_env("SHAKERSCAN_QUEUE_STATS_MAX_KEYS", 20_000)
STATS_MAX_ACTIVE_SCANS = _int_env("SHAKERSCAN_QUEUE_STATS_MAX_ACTIVE", 20_000)
RECONCILE_KEYS_PER_TICK = _int_env("SHAKERSCAN_JOB_HASH_RECONCILE_KEYS", 20_000)
_PIPELINE_CHUNK = 500


def _text(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return "" if value is None else str(value)


def scan_hashes(
    redis_client: Any, pattern: str, *, cursor: int = 0, max_keys: int,
) -> tuple[list[tuple[str, dict[str, str]]], int, bool]:
    """Up to ``max_keys`` hashes matching ``pattern`` from ``cursor``: (rows, next cursor, wrapped).

    SCAN never blocks Redis the way KEYS does; only ``HASH_FIELDS`` are read, pipelined."""
    keys: list[str] = []
    next_cursor = int(cursor or 0)
    wrapped = False
    while len(keys) < max_keys:
        next_cursor, raw = redis_client.scan(
            cursor=next_cursor, match=pattern, count=min(1000, max(1, max_keys - len(keys))))
        keys.extend(_text(key) for key in raw or [])
        next_cursor = int(next_cursor or 0)
        if next_cursor == 0:
            wrapped = True
            break
    keys = list(dict.fromkeys(keys))  # SCAN may return a key twice
    rows: list[tuple[str, dict[str, str]]] = []
    for start in range(0, len(keys), _PIPELINE_CHUNK):
        chunk = keys[start:start + _PIPELINE_CHUNK]
        pipeline_factory = getattr(redis_client, "pipeline", None)
        if callable(pipeline_factory):
            pipe = pipeline_factory(transaction=False)
            for key in chunk:
                pipe.hmget(key, list(HASH_FIELDS))
            values = pipe.execute()
        else:
            values = [redis_client.hmget(key, list(HASH_FIELDS)) for key in chunk]
        for key, fields in zip(chunk, values):
            if not fields or all(value is None for value in fields):
                continue  # expired between SCAN and read
            rows.append((key, {name: _text(value) for name, value in zip(HASH_FIELDS, fields)}))
    return rows, next_cursor, wrapped


def _job_id(key: str, prefix: str) -> str:
    return key.split(prefix, 1)[-1]


def _heartbeat_overdue(heartbeat: str, *, now: datetime, minutes: float) -> bool:
    if not heartbeat:
        return False
    try:
        return now - datetime.fromisoformat(heartbeat) > timedelta(minutes=minutes)
    except (TypeError, ValueError):
        return False


def classify_job_hashes(
    rows: Iterable[tuple[str, dict[str, str]]],
    *,
    now: datetime,
    active_job_status: dict[str, str],
    queue_presence: Callable[[str], bool | None],
    unleased: Callable[[str], bool | None],
    heartbeat_timeout_minutes: float,
) -> tuple[dict[str, int], list[tuple[str, dict[str, str], bool, str]]]:
    """Counts and repairs for ``job:*`` hashes, by the rules the GET applied.

    ``active_job_status`` maps the job id of every active Scan among these hashes to its status
    (pending, queued or running). ``queue_presence`` says whether a job is in the scan queue
    (True/False, or None when the bounded read cannot tell); ``unleased`` whether it is waiting
    rather than leased. A hash is only repaired when the evidence is certain."""
    counts = {"running": 0, "completed": 0, "failed": 0, "queued": 0,
              "stale_running_job_hashes": 0, "stale_queued_job_hashes": 0, "unknown": 0}
    repairs: list[tuple[str, dict[str, str], bool, str]] = []
    for key, data in rows:
        status = data.get("status", "")
        job_id = _job_id(key, "job:")
        if status == "running":
            if job_id not in active_job_status:
                counts["stale_running_job_hashes"] += 1
                repairs.append((key, {
                    "status": "orphaned",
                    "error": "Running job hash has no matching running scan",
                }, True, status))
                continue
            if _heartbeat_overdue(data.get("heartbeat", ""), now=now, minutes=heartbeat_timeout_minutes):
                repairs.append((key, {"status": "failed", "error": "Worker stopped responding"}, False, status))
                counts["failed"] += 1
                continue
            counts["running"] += 1
        elif status == "completed":
            counts["completed"] += 1
        elif status == "queued":
            if active_job_status.get(job_id) not in {"pending", "queued"}:
                in_queue: bool | None = False  # no queued Scan: not a valid handoff either way
            else:
                in_queue = queue_presence(job_id)
            if in_queue is None:
                counts["unknown"] += 1
            elif in_queue:
                # A leased message is valid work but no longer waiting. Keep the queued
                # headline limited to unleased handoffs.
                if unleased(job_id):
                    counts["queued"] += 1
            else:
                counts["stale_queued_job_hashes"] += 1
                repairs.append((key, {
                    "status": "orphaned",
                    "error": "Queued job hash has no matching queued scan",
                }, True, status))
        elif status == "failed":
            counts["failed"] += 1
    return counts, repairs


def classify_retest_hashes(
    rows: Iterable[tuple[str, dict[str, str]]], *, now: datetime, timeout_minutes: float,
) -> tuple[dict[str, int], list[tuple[str, dict[str, str], bool, str]]]:
    counts = {"retest_running": 0, "retest_completed": 0, "retest_queued": 0, "retest_failed": 0}
    repairs: list[tuple[str, dict[str, str], bool, str]] = []
    for key, data in rows:
        status = data.get("status", "")
        if status == "running":
            if _heartbeat_overdue(data.get("started_at", ""), now=now, minutes=timeout_minutes):
                repairs.append((key, {
                    "status": "failed",
                    "error": "Retest worker did not complete in time",
                }, False, status))
                counts["retest_failed"] += 1
                continue
            counts["retest_running"] += 1
        elif status == "completed":
            counts["retest_completed"] += 1
        elif status == "queued":
            counts["retest_queued"] += 1
        elif status == "failed":
            counts["retest_failed"] += 1
    return counts, repairs


# Compare-and-set: the repair applies only while the hash still has the status it was judged on.
# A Scan that finished between the read and the repair has a fresh status ("completed", ...),
# which must not be overwritten with "orphaned".
_REPAIR_IF_UNCHANGED_LUA = """
if redis.call('HGET', KEYS[1], 'status') ~= ARGV[1] then
  return 0
end
for i = 3, #ARGV, 2 do
  redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
end
if tonumber(ARGV[2]) > 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 1
"""


def apply_repairs(redis_client: Any, repairs: Iterable[tuple[str, dict[str, str], bool, str]]) -> int:
    applied = 0
    evaluate = getattr(redis_client, "eval", None)
    for key, mapping, expire, expected_status in repairs:
        ttl = ORPHAN_EXPIRE_SECONDS if expire else 0
        if callable(evaluate):
            fields = [item for pair in mapping.items() for item in pair]
            applied += int(evaluate(_REPAIR_IF_UNCHANGED_LUA, 1, key, expected_status, ttl, *fields) or 0)
            continue
        # Clients without scripting (test doubles): the same check, not atomic.
        if _text(redis_client.hget(key, "status")) != expected_status:
            continue
        redis_client.hset(key, mapping=mapping)
        if ttl:
            redis_client.expire(key, ttl)
        applied += 1
    return applied


async def _active_job_status(conn: Any, job_ids: list[str]) -> dict[str, str]:
    if not job_ids:
        return {}
    rows = await conn.fetch(
        """SELECT job_id, status FROM scans
           WHERE job_id = ANY($1::text[]) AND status IN ('pending','queued','running')""",
        job_ids,
    )
    return {str(row["job_id"]): str(row["status"]) for row in rows}


def _jobs_needing_status(rows: Iterable[tuple[str, dict[str, str]]]) -> list[str]:
    return [_job_id(key, "job:") for key, data in rows if data.get("status") in {"running", "queued"}]


async def compute_queue_stats(
    pool: Any,
    redis_client: Any,
    *,
    now: datetime,
    hidden_roles: set[str],
    queue_name: str,
    scan_queue_job_ids: Callable[..., Any],
    pending_depth: Callable[[Any, str], int],
    retest_queue_name: str,
    broker_queue_name: str,
    heartbeat_timeout_minutes: float,
    retest_timeout_minutes: float,
    max_keys: int = STATS_MAX_HASH_KEYS,
    max_active: int = STATS_MAX_ACTIVE_SCANS,
) -> dict[str, Any]:
    """The ``/queue/stats`` body, read-only and bounded."""
    async with pool.acquire() as conn:
        grouped = await conn.fetch(
            """SELECT status, scan_role, COUNT(*) AS n FROM scans
               WHERE status IN ('pending','queued','running') AND job_id IS NOT NULL
               GROUP BY status, scan_role"""
        )
        active_pending_rows = await conn.fetch(
            """SELECT job_id FROM scans
               WHERE status IN ('pending','queued') AND job_id IS NOT NULL
               LIMIT $1""",
            max_active + 1,
        )
    logical_pending = sum(
        int(row["n"]) for row in grouped
        if row["status"] in {"pending", "queued"} and str(row["scan_role"] or "") not in hidden_roles
    )
    logical_running = sum(
        int(row["n"]) for row in grouped
        if row["status"] == "running" and str(row["scan_role"] or "") not in hidden_roles
    )
    active_complete = len(active_pending_rows) <= max_active
    active_scan_job_ids = {str(row["job_id"]) for row in active_pending_rows[:max_active]}

    def redis_reads() -> tuple[Any, Any, Any, dict[str, int]]:
        queue = scan_queue_job_ids(redis_client, queue_name, track_unleased=True)
        job_rows, _cursor, job_wrapped = scan_hashes(redis_client, JOB_HASH_PATTERN, max_keys=max_keys)
        retest_rows, _cursor, retest_wrapped = scan_hashes(redis_client, RETEST_HASH_PATTERN, max_keys=max_keys)
        depths = {
            "work_pending": pending_depth(redis_client, queue_name),
            "retest_pending": pending_depth(redis_client, retest_queue_name),
            "broker_ingest_pending": pending_depth(redis_client, broker_queue_name),
        }
        return queue, (job_rows, job_wrapped), (retest_rows, retest_wrapped), depths

    queue, (job_rows, job_complete), (retest_rows, retest_complete), depths = await asyncio.to_thread(redis_reads)
    async with pool.acquire() as conn:
        active_job_status = await _active_job_status(conn, _jobs_needing_status(job_rows))

    def unleased(job_id: str) -> bool | None:
        if job_id in queue.unleased_job_ids:
            return True
        return False if queue.leased_complete else None

    job_counts, _repairs = classify_job_hashes(
        job_rows, now=now, active_job_status=active_job_status,
        queue_presence=queue.presence, unleased=unleased,
        heartbeat_timeout_minutes=heartbeat_timeout_minutes)
    retest_counts, _retest_repairs = classify_retest_hashes(
        retest_rows, now=now, timeout_minutes=retest_timeout_minutes)

    handoff_job_ids = queue.job_ids
    complete = bool(queue.complete and active_complete and job_complete and retest_complete
                    and job_counts["unknown"] == 0)
    sets_complete = bool(queue.complete and active_complete)
    queue_without_active = len(handoff_job_ids - active_scan_job_ids) if sets_complete else None
    active_without_queue = len(active_scan_job_ids - handoff_job_ids) if sets_complete else None
    reconciled = (
        not queue.malformed and not queue_without_active and not active_without_queue
        and not job_counts["stale_queued_job_hashes"] and not job_counts["stale_running_job_hashes"]
    ) if complete else None
    return {
        # Dashboard/CLI headline counts are logical user-visible scans. Parallel
        # discovery, shards, and ASM implementation rows are work units, not
        # extra scans. Keep both views explicit for operations and diagnostics.
        "pending": logical_pending,
        "queued": job_counts["queued"],
        "running": logical_running,
        "work_pending": depths["work_pending"],
        "work_running": job_counts["running"],
        "completed": job_counts["completed"],
        "failed": job_counts["failed"],
        "retest_pending": depths["retest_pending"],
        "broker_ingest_pending": depths["broker_ingest_pending"],
        "retest_queued": retest_counts["retest_queued"],
        "retest_running": retest_counts["retest_running"],
        "retest_completed": retest_counts["retest_completed"],
        "retest_failed": retest_counts["retest_failed"],
        "queue_consistency": {
            "reconciled": reconciled,
            "malformed_entries": queue.malformed,
            "queue_without_active_scan": queue_without_active,
            "active_scan_without_queue_entry": active_without_queue,
            "stale_queued_job_hashes": job_counts["stale_queued_job_hashes"],
            "stale_running_job_hashes": job_counts["stale_running_job_hashes"],
            # False when a read bound was reached: the counts then cover only what was read.
            "complete": complete,
        },
    }


async def reconcile_job_hashes(
    pool: Any,
    redis_client: Any,
    *,
    state: dict[str, Any],
    now: datetime,
    queue_name: str,
    scan_queue_job_ids: Callable[..., Any],
    heartbeat_timeout_minutes: float,
    retest_timeout_minutes: float,
    keys_per_tick: int = RECONCILE_KEYS_PER_TICK,
) -> int:
    """Apply the job-hash repairs to one bounded slice of ``job:*`` and ``retest_job:*`` hashes,
    resuming each walk where the previous tick stopped. Returns how many hashes were repaired."""

    def read() -> tuple[list[tuple[str, dict[str, str]]], list[tuple[str, dict[str, str]]]]:
        job_rows, state["job_cursor"], _ = scan_hashes(
            redis_client, JOB_HASH_PATTERN, cursor=state.get("job_cursor", 0), max_keys=keys_per_tick)
        retest_rows, state["retest_cursor"], _ = scan_hashes(
            redis_client, RETEST_HASH_PATTERN, cursor=state.get("retest_cursor", 0), max_keys=keys_per_tick)
        return job_rows, retest_rows

    job_rows, retest_rows = await asyncio.to_thread(read)
    async with pool.acquire() as conn:
        active_job_status = await _active_job_status(conn, _jobs_needing_status(job_rows))
    waiting = {
        _job_id(key, "job:") for key, data in job_rows
        if data.get("status") == "queued"
        and active_job_status.get(_job_id(key, "job:")) in {"pending", "queued"}
    }
    queue = await asyncio.to_thread(scan_queue_job_ids, redis_client, queue_name, wanted=waiting)
    _counts, repairs = classify_job_hashes(
        job_rows, now=now, active_job_status=active_job_status,
        queue_presence=queue.presence, unleased=lambda _job_id: None,
        heartbeat_timeout_minutes=heartbeat_timeout_minutes)
    _retest_counts, retest_repairs = classify_retest_hashes(
        retest_rows, now=now, timeout_minutes=retest_timeout_minutes)
    return await asyncio.to_thread(apply_repairs, redis_client, [*repairs, *retest_repairs])


__all__ = [
    "apply_repairs",
    "classify_job_hashes",
    "classify_retest_hashes",
    "compute_queue_stats",
    "reconcile_job_hashes",
    "scan_hashes",
]
