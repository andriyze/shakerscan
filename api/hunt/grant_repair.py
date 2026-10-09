"""Startup repair of Hunt authority that 2.8.0 revocations left behind (R1, external release
audit, 2026-10-09).

2.8.0 restored a whole-policy snapshot when a grant was revoked. A Hunt granted something then has
no recorded baseline; its authority is rebuilt once from its grant rows (``grant_authority``),
each Hunt in its own short transaction, outside the startup schema transaction.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from .grant_authority import POLICY_GRANT_KINDS, authority_diff, rebuild_authority
from .permission_grants import FINISHED_STATUSES, settle_for_ended_hunt

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


async def _fail_closed(conn: Any, hunt_id: Any) -> None:
    """End a Hunt whose authority could not be rebuilt: it never runs on unrepaired authority."""
    async with conn.transaction():
        await conn.execute(
            """UPDATE hunt_runs SET status='failed', stop_reason=$2, completed_at=COALESCE(completed_at, NOW()),
                      updated_at=NOW() WHERE id=$1""",
            hunt_id, REPAIR_FAILED_STOP_REASON,
        )
        await settle_for_ended_hunt(conn, hunt_id, actor="startup", source="authority_repair_failed")


async def repair_grant_authority(conn: Any) -> list[str]:
    """Rebuild the authority of every unfinished Hunt granted something before baselines existed.

    Run outside any transaction: each Hunt is repaired in its own short transaction, so no row
    stays locked for the rest of startup. A Hunt whose repair fails is logged (its id and the
    error class only) and ended ``failed`` so it cannot run on unrepaired authority; the other
    Hunts and the API start normally. Idempotent: a Hunt is repaired once, when its baseline is
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
                await _fail_closed(conn, hunt_id)
            except Exception as failure:  # noqa: BLE001
                logger.error("Hunt %s: could not be ended after a failed authority repair (%s)",
                             hunt_id, type(failure).__name__)
    return changed


__all__ = ["REPAIR_FAILED_STOP_REASON", "repair_grant_authority"]
