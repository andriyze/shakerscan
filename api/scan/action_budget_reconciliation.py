"""Content-free cross-table health for Scan action budget authority."""

from __future__ import annotations

from typing import Any, Mapping


_RECONCILIATION_SQL = r"""
SELECT
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
         WHERE a.receipt_json->>'budget_reservation_id' IS NOT NULL
           AND a.reservation_id IS NULL
    ) AS receipt_link_missing,
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
          JOIN budget_reservations r ON r.id=a.reservation_id
         WHERE r.owner_kind <> 'scan'
            OR r.owner_id <> a.scan_id::text
            OR r.action_id <> a.action_id
            OR r.action_digest <> a.action_digest
            OR r.capability_name <> a.capability_name
            OR (
                a.status IN ('success','partial','failed','timed_out')
                AND (
                    r.status NOT IN ('committed','released','failed')
                    OR r.execution_receipt_hash IS DISTINCT FROM a.receipt_hash
                )
            )
    ) AS linked_authority_mismatch,
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
         WHERE a.status IN ('leased','running')
           AND a.reservation_id IS NULL
           AND a.capability_name <> 'scan.execute'
           AND a.updated_at < now() - INTERVAL '30 seconds'
    ) AS stale_execution_without_hold,
    (
        SELECT COUNT(*)
          FROM budget_reservations r
          JOIN scan_capability_actions a
            ON r.owner_kind='scan'
           AND r.owner_id=a.scan_id::text
           AND r.action_id=a.action_id
           AND r.action_digest=a.action_digest
         WHERE r.status IN ('committed','released','failed')
           AND a.status NOT IN (
               'success','partial','skipped','blocked','failed','cancelled','timed_out'
           )
           AND r.updated_at < now() - INTERVAL '5 minutes'
    ) AS stale_terminal_reservation_without_action,
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
         WHERE a.reservation_id IS NOT NULL
    ) AS linked_action_count
"""


def _count(row: Mapping[str, Any], name: str) -> int:
    try:
        return max(0, int(row.get(name) or 0))
    except (TypeError, ValueError):
        return 0


async def scan_action_budget_reconciliation(conn: Any) -> dict[str, Any]:
    """Return bounded metrics without targets, receipts, or action identifiers."""
    raw = await conn.fetchrow(_RECONCILIATION_SQL)
    row = dict(raw or {})
    metrics = {
        name: _count(row, name)
        for name in (
            "receipt_link_missing",
            "linked_authority_mismatch",
            "stale_execution_without_hold",
            "stale_terminal_reservation_without_action",
            "linked_action_count",
        )
    }
    inconsistent = sum(
        metrics[name]
        for name in (
            "receipt_link_missing",
            "linked_authority_mismatch",
            "stale_execution_without_hold",
            "stale_terminal_reservation_without_action",
        )
    )
    return {
        "status": "ok" if inconsistent == 0 else "degraded",
        "inconsistent_count": inconsistent,
        **metrics,
    }


__all__ = ["scan_action_budget_reconciliation"]
