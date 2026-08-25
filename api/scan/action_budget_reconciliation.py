"""Content-free cross-table health for Scan action budget authority."""

from __future__ import annotations

from typing import Any, Mapping


_RECONCILIATION_SQL = r"""
WITH cutover AS (
    SELECT COALESCE(
        (SELECT applied_at FROM app_schema_migrations
          WHERE name='v2_scan_action_budget_link_v1'),
        'epoch'::timestamptz
    ) AS applied_at
)
SELECT
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
         CROSS JOIN cutover c
         WHERE a.receipt_json->>'budget_reservation_id' IS NOT NULL
           AND a.reservation_id IS NULL
           AND a.updated_at >= c.applied_at
    ) AS receipt_link_missing,
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
          JOIN budget_reservations r ON r.id=a.reservation_id
         CROSS JOIN cutover c
         WHERE a.updated_at >= c.applied_at
           AND (r.owner_kind <> 'scan'
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
            ))
    ) AS linked_authority_mismatch,
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
          JOIN budget_reservations r ON r.id=a.reservation_id
         CROSS JOIN cutover c
         WHERE a.updated_at < c.applied_at
           AND (r.owner_kind <> 'scan'
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
            ))
    ) AS legacy_historical_mismatch,
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
            "legacy_historical_mismatch",
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


async def repair_terminal_reservation_actions(conn: Any, *, limit: int = 1000) -> int:
    """Terminalize stale Scan actions whose linked reservation already settled."""
    if limit < 1 or limit > 1000:
        raise ValueError("repair limit must be between 1 and 1000")
    rows = await conn.fetch(
        r"""
        WITH candidates AS (
            SELECT a.id, r.status AS reservation_status,
                   r.failure_reason, r.execution_uncertain
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
             ORDER BY r.updated_at, a.id
             FOR UPDATE OF a SKIP LOCKED
             LIMIT $1
        )
        UPDATE scan_capability_actions a
           SET status=CASE WHEN c.reservation_status='released' THEN 'blocked' ELSE 'failed' END,
               reason_code=COALESCE(NULLIF(c.failure_reason, ''), 'terminal_reservation_reconciled'),
               result_json=COALESCE(a.result_json, '{}'::jsonb) || jsonb_build_object(
                   'error', 'terminal_reservation_reconciled',
                   'reservation_status', c.reservation_status,
                   'execution_uncertain', c.execution_uncertain
               ),
               finished_at=COALESCE(a.finished_at, NOW()),
               updated_at=NOW()
          FROM candidates c
         WHERE a.id=c.id
        RETURNING a.id
        """,
        limit,
    )
    return len(rows)


__all__ = ["repair_terminal_reservation_actions", "scan_action_budget_reconciliation"]
