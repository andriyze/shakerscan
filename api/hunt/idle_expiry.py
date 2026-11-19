"""End Hunts nobody has driven for a long time.

A Hunt advances only when its driver (the operator's terminal agent) calls the next capability,
and stays live until something calls finish or cancel. When the agent session ends without
closing its Hunt (a crash, a lost connection, an operator who walks away), the Hunt stayed
``active`` forever: one engine held 738 live Hunts, most untouched for weeks, which made the
Hunt list useless for seeing what was really running.

A live Hunt with no activity for ``SHAKERSCAN_HUNT_IDLE_EXPIRY_HOURS`` (default 72 hours: far
beyond any pause in a working session, and three times the longest Hunt budget) is now ended
exactly as a cancellation ends it, with stop reason ``idle_expired``. Activity is any write to the
Hunt (an action, a budget or context update) and any action started or finished. A Hunt with an
action still reserved or running is never expired here: that action ends first (or the worker's
reservation sweep recovers it), and the idle clock counts from then. What the Hunt learned stays
in the target's knowledge (candidates, leads, evidence) for the next Hunt.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from .grant_repair import signal_repair_cancellations
from .run_service import cancel_hunt_rows, cancel_hunt_scans, request_hunt_job_cancellation

logger = logging.getLogger(__name__)

IDLE_EXPIRY_ENV = "SHAKERSCAN_HUNT_IDLE_EXPIRY_HOURS"
DEFAULT_IDLE_EXPIRY_HOURS = 72
IDLE_STOP_REASON = "idle_expired"
BATCH_LIMIT = 200

_IDLE_HUNTS_SQL = """
SELECT r.id
  FROM hunt_runs r
 WHERE r.status IN ('created','active','awaiting_planner','budget_exhausted')
   AND r.completed_at IS NULL
   AND r.updated_at < NOW() - make_interval(hours => $1)
   AND NOT EXISTS (
       SELECT 1 FROM hunt_actions a
        WHERE a.hunt_run_id = r.id
          AND (a.status IN ('reserved','running')
               OR GREATEST(a.started_at, a.completed_at) >= NOW() - make_interval(hours => $1)))
 ORDER BY r.updated_at
 LIMIT $2"""


def idle_expiry_hours(environ: dict[str, str] | None = None) -> int:
    """The configured idle limit in whole hours; anything not a positive integer is the default."""
    raw = str((os.environ if environ is None else environ).get(IDLE_EXPIRY_ENV) or "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else DEFAULT_IDLE_EXPIRY_HOURS


async def expire_idle_hunts(pool: Any, redis_provider: Any = None, *, hours: int | None = None) -> list[str]:
    """End every live Hunt idle longer than the limit (at most ``BATCH_LIMIT`` per call, oldest
    first). Each Hunt stops in its own transaction; returns the ids ended. It never raises: it
    runs inside the API's maintenance tick, and a failure here must not skip the steps after it."""
    try:
        return await _expire_idle_hunts(pool, redis_provider, hours or idle_expiry_hours())
    except Exception as exc:  # noqa: BLE001
        logger.error("Idle Hunt expiry skipped this tick (%s)", type(exc).__name__)
        return []


async def _expire_idle_hunts(pool: Any, redis_provider: Any, limit_hours: int) -> list[str]:
    async with pool.acquire() as conn:
        candidates = [row["id"] for row in await conn.fetch(_IDLE_HUNTS_SQL, limit_hours, BATCH_LIMIT)]
        expired: list[str] = []
        pending_signals: dict[Any, list[str]] = {}
        for hunt_id in candidates:
            try:
                async with conn.transaction():
                    # Re-checked under the row update: a driver that came back since the select
                    # keeps its Hunt (cancel_hunt_rows only matches a live row; the idle test is
                    # repeated here so a fresh write wins).
                    still_idle = await conn.fetchval(
                        "SELECT 1 FROM hunt_runs WHERE id=$1 AND updated_at < NOW() - make_interval(hours => $2) FOR UPDATE",
                        hunt_id, limit_hours)
                    if not still_idle:
                        continue
                    row = await cancel_hunt_rows(conn, hunt_id, stop_reason=IDLE_STOP_REASON, source="hunt_idle_expired")
                    if row is None:
                        continue
                    await cancel_hunt_scans(conn, hunt_id)
                    pending_signals[hunt_id] = await request_hunt_job_cancellation(conn, hunt_id)
                expired.append(str(hunt_id))
            except Exception as exc:  # noqa: BLE001 - one Hunt never stops the sweep
                logger.error("Hunt %s: idle expiry failed (%s)", hunt_id, type(exc).__name__)
        if expired:
            logger.info("Ended %d Hunt(s) idle for more than %d hours (stop reason %s)",
                        len(expired), limit_hours, IDLE_STOP_REASON)
            await signal_repair_cancellations(conn, redis_provider, {k: v for k, v in pending_signals.items() if v})
    return expired
