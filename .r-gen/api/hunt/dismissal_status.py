"""A finding dismissal ends when the finding's status leaves the dismissed statuses elsewhere.

Kept free of product imports: the finding routes call it after their own status changes, and
the startup migration after a rollback may have let an earlier engine change statuses.
"""
from __future__ import annotations

from typing import Any
import uuid

DISMISSED_STATUSES = ("false_positive", "accepted_risk")
STATUS_CHANGE_WRITER = "system:finding-status"


async def reconcile_dismissals(conn: Any, finding_ids: list[Any] | None = None) -> int:
    """Mark an active dismissal ``reopened`` once its finding's status is no longer
    false_positive or accepted_risk (the finding routes, a bulk update, or an earlier engine)."""
    result = await conn.execute("""UPDATE target_interpretations i SET status='reopened', status_changed_by=$2,
            status_changed_at=NOW(), status_note='The finding status changed outside the dismissal.'
        FROM findings f
        WHERE i.finding_id=f.id AND i.negative_state='finding_dismissed' AND i.status='active'
          AND f.status <> ALL($1::text[]) AND ($3::uuid[] IS NULL OR f.id = ANY($3::uuid[]))""",
        list(DISMISSED_STATUSES), STATUS_CHANGE_WRITER,
        [uuid.UUID(str(item)) for item in finding_ids] if finding_ids is not None else None)
    try:
        return int(str(result).rsplit(" ", 1)[-1])
    except ValueError:
        return 0
