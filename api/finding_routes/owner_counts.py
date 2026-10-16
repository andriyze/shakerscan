"""Shared owner-count reconciliation for triage and guarded decision reversal."""
from __future__ import annotations

from typing import Any, Sequence


async def _refresh_web_active_finding_counts(conn: Any, target_ids: Sequence[Any]) -> None:
    normalized = sorted({item for item in target_ids if item is not None}, key=str)
    if not normalized:
        return
    await conn.execute(
        """UPDATE targets t
           SET active_findings_count=(
               SELECT COUNT(*) FROM findings f
               WHERE f.target_id=t.id AND f.status='active'
           ), updated_at=NOW()
           WHERE t.id=ANY($1::uuid[])""",
        normalized,
    )


async def _refresh_finding_owner_counts(conn: Any, rows: Sequence[Any]) -> None:
    await _refresh_web_active_finding_counts(
        conn, [row["target_id"] for row in rows]
    )
    await _refresh_device_active_finding_counts(
        conn, [row["device_target_id"] for row in rows]
    )


async def _refresh_device_active_finding_counts(conn: Any, device_ids: Sequence[Any]) -> None:
    normalized = sorted({item for item in device_ids if item is not None}, key=str)
    if not normalized:
        return
    await conn.execute(
        """UPDATE device_targets d
           SET active_findings_count=(
               SELECT COUNT(*) FROM findings f
               WHERE f.device_target_id=d.id AND f.status='active'
           ), updated_at=NOW()
           WHERE d.id=ANY($1::uuid[])""",
        normalized,
    )
