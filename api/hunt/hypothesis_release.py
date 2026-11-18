"""Release the leads a Hunt still holds when it ends.

A Hunt claims a lead on the target's lead board for a lease (default 15 minutes) and moves it to
``testing``. When the Hunt finished or was cancelled first, the claim outlived it: the next Hunt
on the target was refused ``hypothesis_not_claimable`` until the lease ran out, and a lead left in
``claimed`` or ``testing`` was never offered as an open lead again (the continue ranking and the
briefing list open leads). Ending a Hunt now gives its claims back, in the same transaction:
``claimed`` and ``testing`` return to ``open`` (the lead was not settled), any other state keeps
its status and only loses the claim. The Hunt's test records stay on the lead for the next one.
Plain SQL over the ``hypotheses`` lead board.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


async def release_hunt_claims(conn: Any, hunt_id: Any, *, reason: str) -> int:
    """Give back every claim the ended Hunt holds; return how many leads were released.

    Housekeeping never decides whether a Hunt ends: the release runs in a savepoint, and a failure
    (a store without the lead board) is logged and leaves the claims to expire with their lease."""
    owner = f"hunt:{hunt_id}"
    note = json.dumps({"hunt_id": str(hunt_id), "reason": reason, "at": datetime.now(timezone.utc).isoformat()})
    try:
        async with conn.transaction():
            rows = await _release(conn, owner, note)
    except Exception as exc:  # noqa: BLE001 - the Hunt still ends; the lease frees the claims later
        logger.warning("Hunt %s ended; its lead claims were not released (%s)", hunt_id, type(exc).__name__)
        return 0
    return len(rows)


async def _release(conn: Any, owner: str, note: str) -> Any:
    return await conn.fetch(
        """UPDATE hypotheses
              SET status = CASE WHEN status IN ('claimed','testing') THEN 'open' ELSE status END,
                  claim_owner = NULL, claim_lease_expires_at = NULL,
                  metadata_json = COALESCE(metadata_json, '{}'::jsonb)
                                  || jsonb_build_object('released_at_hunt_end', $2::jsonb),
                  version = version + 1, updated_at = NOW()
            WHERE claim_owner = $1
           RETURNING id""",
        owner, note)


__all__ = ["release_hunt_claims"]
