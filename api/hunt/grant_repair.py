"""Startup repair of Hunt authority that 2.8.0 revocations left behind (R1, external release
audit, 2026-10-09).

2.8.0 restored a whole-policy snapshot when a grant was revoked. A Hunt granted something then has
no recorded baseline; its authority is rebuilt once from its grant rows (``grant_authority``),
each Hunt in its own short transaction, outside the startup schema transaction.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from .grant_authority import POLICY_GRANT_KINDS, authority_diff, rebuild_authority
from .permission_grants import FINISHED_STATUSES
from .run_service import (
    cancel_hunt_rows,
    cancel_hunt_scans,
    request_hunt_job_cancellation,
    signal_hunt_jobs,
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


class _BoundPool:
    """The startup connection, as the pool the shared cancellation helpers expect."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self._conn


async def _fail_closed(conn: Any, hunt_id: Any, redis_provider: Any) -> None:
    """End a Hunt whose authority could not be rebuilt exactly as a cancellation does: it stops
    (in-flight work watches for ``cancelled``), its withheld private HTTP results are dropped,
    its permission requests are settled, its scans are cancelled and its queued jobs are told
    to stop. It never runs on unrepaired authority.

    The stop itself commits first, on its own; cancelling scans and jobs follows, so a failure
    there (logged) never leaves the Hunt running."""
    async with conn.transaction():
        row = await cancel_hunt_rows(conn, hunt_id, stop_reason=REPAIR_FAILED_STOP_REASON,
                                     source="authority_repair_failed")
    if row is None:
        return
    durable_job_ids: list[str] = []
    try:
        async with conn.transaction():
            await cancel_hunt_scans(conn, hunt_id)
            durable_job_ids = await request_hunt_job_cancellation(conn, hunt_id)
        pool = _BoundPool(conn)
        await signal_hunt_jobs(lambda: pool, redis_provider, hunt_id, durable_job_ids)
    except Exception as exc:  # noqa: BLE001 - the Hunt is already stopped; workers see `cancelled`
        logger.error("Hunt %s: its queued work could not all be cancelled (%s)", hunt_id, type(exc).__name__)


async def repair_grant_authority(conn: Any, *, redis_provider: Any = None) -> list[str]:
    """Rebuild the authority of every unfinished Hunt granted something before baselines existed.

    Run outside any transaction: each Hunt is repaired in its own short transaction, so no row
    stays locked for the rest of startup. A Hunt whose repair fails is logged (its id and the
    error class only) and cancelled with stop reason ``permission_authority_unrepaired`` (as
    ``HuntRunService.cancel`` would, signalling its queued jobs through ``redis_provider`` when
    given), so it cannot run on unrepaired authority; the other Hunts and the API start normally. Idempotent: a Hunt is repaired once, when its baseline is
    recorded. Returns the Hunts whose stored policy changed.
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
    for candidate in candidates:
        hunt_id = candidate["hunt_run_id"]
        try:
            if await _repair_one(conn, hunt_id):
                changed.append(str(hunt_id))
        except Exception as exc:  # noqa: BLE001 - one Hunt never stops startup
            logger.error("Hunt %s: permission authority could not be rebuilt (%s); the Hunt is ended",
                         hunt_id, type(exc).__name__)
            try:
                await _fail_closed(conn, hunt_id, redis_provider)
            except Exception as failure:  # noqa: BLE001
                logger.error("Hunt %s: could not be ended after a failed authority repair (%s)",
                             hunt_id, type(failure).__name__)
    return changed


__all__ = ["REPAIR_FAILED_STOP_REASON", "repair_grant_authority"]
