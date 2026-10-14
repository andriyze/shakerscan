"""Sending a never-started Scan whose queue entry was lost to the queue again (2.10).

A Redis that lost its data (reset after a damaged append-only file, or a disk-full upgrade) left
every waiting Scan "pending" forever. The API's sweep (cleanup_orphaned_scan_queue_handoffs) asks
this module to resend a Scan that provably never started (still pending, no start time, no worker,
no capability action past "planned") from its persisted canonical job (scans.scan_job_payload, the
bytes the worker verifies), with the routing it was first queued with (options.queue_routing,
recorded at submission), at most QUEUE_LOSS_REQUEUE_LIMIT times and never twice at once. A Scan
that may have run is never resent: an unknown outcome is not replaced.

The queue functions are passed in by the API (this module never imports the monolith).
"""
from __future__ import annotations

import asyncio
from datetime import timedelta
import json
import logging
from typing import Any, Awaitable, Callable, Mapping

from .jobs import CanonicalScanJob, CanonicalScanJobError

logger = logging.getLogger(__name__)

QUEUE_LOSS_REQUEUE_LIMIT = 3
GUARD_SECONDS = 900


def queue_routing(placement: Any, parallel_worker_count: int | None) -> dict[str, Any]:
    """What submission records of the routing a job is queued with (options.queue_routing)."""
    return {
        "placement": dict(placement) if isinstance(placement, Mapping) and placement else None,
        "parallel_worker_count": parallel_worker_count,
    }


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _guard_key(scan_id: str) -> str:
    return f"scan:queue-loss-requeue:{scan_id}"


async def requeue_scan_lost_from_queue(
    conn: Any, redis_client: Any, row: Mapping[str, Any], *,
    enqueue: Callable[[Any, str, dict[str, Any]], Any],
    configure_plan_job: Callable[[dict[str, Any], int | None], None],
    normalize_placement: Callable[[Any], Any],
    queue_name: str,
) -> str:
    """Resend one never-started Scan. Returns "requeued"; "already_resent" (another sweep did, or
    it started meanwhile: leave it alone); or "enqueue_failed", "limit", "not_rebuildable" (the
    caller keeps its conservative flag for those)."""
    if str(row.get("scan_generation") or "") != "v2" or str(row.get("scan_role") or "") not in {
        "standalone", "parent",
    }:
        return "not_rebuildable"
    options = _object(row.get("options"))
    attempts = int(options.get("queue_loss_requeues") or 0)
    if attempts >= QUEUE_LOSS_REQUEUE_LIMIT:
        return "limit"
    routing = options.get("queue_routing") if isinstance(options.get("queue_routing"), Mapping) else None
    parent = str(row.get("scan_role")) == "parent"
    try:
        job = CanonicalScanJob.from_payload(_object(row.get("scan_job_payload")))
        if routing is not None:
            # The routing recorded when it was first queued (Scans submitted by 2.10 and later).
            placement = routing.get("placement") if isinstance(routing.get("placement"), Mapping) else None
            worker_count = routing.get("parallel_worker_count")
        else:
            # Earlier Scans: the same normalisation the submit route applies.
            placement = None if parent else (normalize_placement(options.get("placement") or {}) or None)
            worker_count = int(options.get("worker_fleet_size_at_submit") or 0) or None
        payload = job.queue_payload(placement=placement)
    except (CanonicalScanJobError, ValueError, TypeError):
        return "not_rebuildable"
    if parent:
        configure_plan_job(payload, int(worker_count) if worker_count is not None else None)
    scan_id = str(row["id"])
    if not redis_client.set(_guard_key(scan_id), "1", nx=True, ex=GUARD_SECONDS):
        return "already_resent"
    claimed = await conn.fetchval(
        """UPDATE scans
           SET options = jsonb_set(COALESCE(options, '{}'::jsonb), '{queue_loss_requeues}', to_jsonb($2::int)),
               current_phase = 'queued_again', error_message = NULL
           WHERE id=$1 AND status IN ('pending','queued') AND started_at IS NULL AND worker_id IS NULL
           RETURNING id""",
        row["id"], attempts + 1,
    )
    if not claimed:
        return "already_resent"  # started, or claimed by another sweep, meanwhile
    try:
        enqueue(redis_client, queue_name, payload)
    except Exception:
        logger.exception("Could not queue Scan %s again after a queue loss", scan_id)
        redis_client.delete(_guard_key(scan_id))
        return "enqueue_failed"
    return "requeued"


# One sweep reads at most this many pending Scans (oldest first, resuming where the last sweep
# stopped), and only the columns the decision needs; a resend loads its persisted job by id.
LOST_HANDOFF_SWEEP_LIMIT = 1000

_LOST_HANDOFF_ROWS_SQL = """
    SELECT s.id, s.job_id, s.parent_scan_id, s.created_at,
           (s.started_at IS NULL AND s.worker_id IS NULL AND NOT EXISTS (
               SELECT 1 FROM scan_capability_actions a
               WHERE a.scan_id=s.id AND a.status <> 'planned')) AS never_started
    FROM scans s
    WHERE s.status IN ('pending','queued')
      AND COALESCE(s.run_kind, 'web_dast') NOT IN ('device_posture','device_probe','device_web_dast')
      AND s.created_at < $1
      AND ($2::timestamptz IS NULL OR (s.created_at, s.id) > ($2::timestamptz, $3::uuid))
    ORDER BY s.created_at, s.id
    LIMIT $4"""

_RESEND_ROW_SQL = """
    SELECT id, job_id, parent_scan_id, scan_role, scan_generation, options, scan_job_payload
    FROM scans WHERE id=$1"""


async def _lost_handoff_candidates(conn: Any, *, cutoff: Any, state: dict[str, Any], limit: int) -> list[Any]:
    after = state.get("after")
    rows = list(await conn.fetch(
        _LOST_HANDOFF_ROWS_SQL, cutoff, after[0] if after else None, after[1] if after else None, limit))
    if len(rows) < limit and after:
        # The end was reached: wrap so the older Scans before the cursor are covered this sweep too.
        seen = {row["id"] for row in rows}
        rows.extend(row for row in await conn.fetch(_LOST_HANDOFF_ROWS_SQL, cutoff, None, None, limit - len(rows))
                    if row["id"] not in seen)
    state["after"] = (rows[-1]["created_at"], rows[-1]["id"]) if len(rows) >= limit else None
    return rows


def _job_states(redis_client: Any, job_ids: list[str], decode_hash: Callable[[Any], dict[str, str]]) -> dict[str, dict[str, str]]:
    pipeline_factory = getattr(redis_client, "pipeline", None)
    if callable(pipeline_factory) and job_ids:
        pipe = pipeline_factory(transaction=False)
        for job_id in job_ids:
            pipe.hgetall(f"job:{job_id}")
        raw = pipe.execute()
    else:
        raw = [redis_client.hgetall(f"job:{job_id}") for job_id in job_ids]
    return {job_id: decode_hash(value) for job_id, value in zip(job_ids, raw)}


async def sweep_lost_queue_handoffs(
    pool: Any, redis_client: Any, *, now: Any,
    queue_membership: Callable[[Any, set[str]], Any],
    decode_hash: Callable[[Any], dict[str, str]],
    resend: Callable[[Any, Any, Mapping[str, Any]], Awaitable[str]],
    state: dict[str, Any] | None = None,
    limit: int = LOST_HANDOFF_SWEEP_LIMIT,
) -> int:
    """For pending Scans older than ten minutes that are in neither the queue nor a live job
    record: resend those that provably never started (``resend``), and flag the others "queue
    handoff unknown" without claiming non-execution or freeing capacity.

    ``queue_membership(redis, job_ids)`` answers ``presence(job_id)`` from a bounded queue read
    (``job_queue.scan_queue_job_ids``, at most 20,000 entries by default): a job it could not
    confirm absent (an unreadable queue, or a backlog past the bound) is left alone, so during a
    backlog larger than the bound a lost handoff waits until the backlog drains below it."""
    state = state if state is not None else {}
    flagged = requeued = 0
    async with pool.acquire() as conn:
        rows = await _lost_handoff_candidates(
            conn, cutoff=now - timedelta(minutes=10), state=state, limit=max(1, int(limit)))
        if not rows:
            return 0
        job_ids = [str(row.get("job_id") or "") for row in rows if row.get("job_id")]
        def redis_view() -> tuple[dict[str, dict[str, str]], Any]:
            states = _job_states(redis_client, job_ids, decode_hash)
            unsettled = {
                job_id for job_id in job_ids
                if not (str(states.get(job_id, {}).get("status") or "") == "running"
                        and states.get(job_id, {}).get("heartbeat"))
            }
            return states, queue_membership(redis_client, unsettled)

        try:
            states, membership = await asyncio.to_thread(redis_view)
        except Exception:
            # Even successful queue visibility is only a snapshot, not proof that
            # no execution occurred. An unavailable snapshot cannot diagnose a handoff.
            return 0
        for row in rows:
            job_id = str(row.get("job_id") or "")
            if job_id:
                job_state = states.get(job_id, {})
                if str(job_state.get("status") or "") == "running" and job_state.get("heartbeat"):
                    continue
                if membership.presence(job_id) is not False:
                    continue  # queued, or not provably absent from a bounded read
            if row.get("never_started"):
                full = await conn.fetchrow(_RESEND_ROW_SQL, row["id"])
                outcome = await resend(conn, redis_client, full) if full else "already_resent"
                if outcome == "requeued":
                    requeued += 1
                    continue
                if outcome == "already_resent":
                    continue  # queued again moments ago, or started: never flag it "unknown"
            updated = await conn.fetchrow(
                """UPDATE scans
                   SET current_phase='queue_handoff_unknown',
                       error_message='Queue handoff could not be confirmed. Execution outcome remains unknown; do not submit a replacement.'
                   WHERE id=$1 AND status IN ('pending','queued')
                     AND current_phase IS DISTINCT FROM 'queue_handoff_unknown'
                   RETURNING id, parent_scan_id""",
                row["id"],
            )
            if updated:
                flagged += 1
    if flagged:
        print(f"[cleanup] flagged {flagged} uncertain pending Scan handoff(s)", flush=True)
    if requeued:
        print(f"[cleanup] queued {requeued} never-started Scan(s) lost from the queue again", flush=True)
    return flagged + requeued
