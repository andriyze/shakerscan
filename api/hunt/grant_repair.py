"""Startup repair of Hunt authority that 2.8.0 revocations left behind (R1, external release
audit, 2026-10-09).

2.8.0 restored a whole-policy snapshot when a grant was revoked. A Hunt granted something then has
no recorded baseline; its authority is rebuilt once from its grant rows (``grant_authority``),
each Hunt in its own short transaction, outside the startup schema transaction.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from .cancellation import signal_cancelled_jobs
from .grant_authority import POLICY_GRANT_KINDS, authority_diff, rebuild_authority
from .permission_grants import FINISHED_STATUSES
from .run_service import (
    cancel_hunt_rows,
    cancel_hunt_scans,
    request_hunt_job_cancellation,
)

logger = logging.getLogger(__name__)


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    return dict(value or {})


async def _repair_one(conn: Any, hunt_id: Any) -> bool:
    async with conn.transaction():
        row = await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", hunt_id)
        if row is None:
            return False
        run = dict(row)
        before = _object(run.get("policy_json"))
        after = await rebuild_authority(conn, run)
        if after == before:
            return False
        context = _object(run.get("context_pack"))
        context["allowed_capabilities"] = list(after.get("allowed_capabilities") or [])
        await conn.execute(
            "UPDATE hunt_runs SET policy_json=$2::jsonb, context_pack=$3::jsonb, updated_at=NOW() WHERE id=$1",
            run["id"], json.dumps(after), json.dumps(context, default=str),
        )
        logger.warning("Hunt %s: permission authority rebuilt from its live grants (%s)",
                       run["id"], json.dumps(authority_diff(before, after), sort_keys=True))
        return True


REPAIR_FAILED_STOP_REASON = "permission_authority_unrepaired"


async def _fail_closed(conn: Any, hunt_id: Any) -> list[str]:
    """End a Hunt whose authority could not be rebuilt exactly as a cancellation does: it stops
    (in-flight work watches for ``cancelled``), its withheld private HTTP results are dropped,
    its permission requests are settled, its scans are cancelled and a durable cancel is
    requested for its queued jobs. It never runs on unrepaired authority.

    The stop itself commits first, on its own; cancelling scans and jobs follows, so a failure
    there (logged) never leaves the Hunt running. Returns the job ids still to be signalled,
    which ``signal_repair_cancellations`` does after the startup lock is released."""
    async with conn.transaction():
        row = await cancel_hunt_rows(conn, hunt_id, stop_reason=REPAIR_FAILED_STOP_REASON,
                                     source="authority_repair_failed")
    if row is None:
        return []
    try:
        async with conn.transaction():
            await cancel_hunt_scans(conn, hunt_id)
            return await request_hunt_job_cancellation(conn, hunt_id)
    except Exception as exc:  # noqa: BLE001 - the Hunt is already stopped; workers see `cancelled`
        logger.error("Hunt %s: its queued work could not all be cancelled (%s)", hunt_id, type(exc).__name__)
        return []


async def rebuild_or_cancel(conn: Any) -> tuple[list[str], dict[Any, list[str]]]:
    """Rebuild the authority of every unfinished Hunt granted something before baselines existed.

    Run outside any transaction: each Hunt is repaired in its own short transaction, so no row
    stays locked for the rest of startup. A Hunt whose repair fails is logged (its id and the
    error class only) and cancelled with stop reason ``permission_authority_unrepaired``, as
    ``HuntRunService.cancel`` would, so it cannot run on unrepaired authority; the other Hunts
    and the API start normally. Idempotent and safe to run concurrently: a Hunt is repaired once,
    when its baseline is recorded, and a cancellation only matches a live Hunt.

    Returns the Hunts whose stored policy changed, and the queued jobs of each cancelled Hunt
    that still need their cancel signal. Nothing here touches Redis.
    """
    candidates = await conn.fetch(
        """SELECT DISTINCT g.hunt_run_id FROM hunt_permission_grants g
           JOIN hunt_runs r ON r.id = g.hunt_run_id
           WHERE g.kind = ANY($1::text[]) AND r.completed_at IS NULL AND r.status <> ALL($2::text[])
             AND NOT EXISTS (SELECT 1 FROM hunt_permission_baselines b WHERE b.hunt_run_id = g.hunt_run_id)
           ORDER BY g.hunt_run_id""",
        list(POLICY_GRANT_KINDS), sorted(FINISHED_STATUSES),
    )
    changed: list[str] = []
    cancelled: dict[Any, list[str]] = {}
    for candidate in candidates:
        hunt_id = candidate["hunt_run_id"]
        try:
            if await _repair_one(conn, hunt_id):
                changed.append(str(hunt_id))
        except Exception as exc:  # noqa: BLE001 - one Hunt never stops startup
            logger.error("Hunt %s: permission authority could not be rebuilt (%s); the Hunt is cancelled",
                         hunt_id, type(exc).__name__)
            try:
                cancelled[hunt_id] = await _fail_closed(conn, hunt_id)
            except Exception as failure:  # noqa: BLE001
                logger.error("Hunt %s: could not be cancelled after a failed authority repair (%s)",
                             hunt_id, type(failure).__name__)
    return changed, cancelled


# Each Redis signal runs off the event loop and is bounded: an unreachable Redis must not stall
# startup (the API's and the worker's clients also carry connect and socket timeouts).
REDIS_SIGNAL_TIMEOUT_SECONDS = 5.0


async def signal_repair_cancellations(
    conn: Any, redis_provider: Any, cancelled: dict[Any, list[str]],
) -> list[str]:
    """Set the cancel flag of the queued jobs of each Hunt the repair cancelled, and record the
    durable ones signalled. Call it after releasing the startup lock. A Hunt whose signal fails
    or times out keeps its durable cancel request (``hunt_cancellable_jobs.cancel_requested_at``)
    and is already ``cancelled``, which the workers' dispatch check and in-flight watch refuse."""
    if redis_provider is None or not cancelled:
        return []
    reached: list[str] = []
    for hunt_id, durable_job_ids in cancelled.items():
        def signal(hunt_id: Any = hunt_id, durable_job_ids: list[str] = durable_job_ids) -> list[str]:
            return signal_cancelled_jobs(redis_provider(), hunt_id, job_ids=durable_job_ids)

        try:
            signalled = await asyncio.wait_for(asyncio.to_thread(signal), REDIS_SIGNAL_TIMEOUT_SECONDS)
        except Exception as exc:  # noqa: BLE001 - Redis is unreachable; the Hunt is cancelled either way
            logger.error("Hunt %s: its queued jobs could not be signalled (%s); their cancel is recorded",
                         hunt_id, type(exc).__name__)
            break  # the same Redis would stall every other Hunt too
        durable = sorted(set(signalled).intersection(durable_job_ids))
        if durable:
            await conn.execute(
                """UPDATE hunt_cancellable_jobs SET signal_state='signalled', signalled_at=NOW(), updated_at=NOW()
                   WHERE hunt_id=$1 AND job_id = ANY($2::uuid[])""",
                hunt_id, [uuid.UUID(item) for item in durable],
            )
        reached.extend(signalled)
    return reached


async def repair_grant_authority(conn: Any, *, redis_provider: Any = None) -> list[str]:
    """``rebuild_or_cancel`` and then ``signal_repair_cancellations``; returns the Hunts whose
    stored policy changed. Startup runs the two apart, signalling after its lock is released."""
    changed, cancelled = await rebuild_or_cancel(conn)
    await signal_repair_cancellations(conn, redis_provider, cancelled)
    return changed


__all__ = [
    "REDIS_SIGNAL_TIMEOUT_SECONDS", "REPAIR_FAILED_STOP_REASON", "rebuild_or_cancel", "repair_grant_authority",
    "signal_repair_cancellations",
]
