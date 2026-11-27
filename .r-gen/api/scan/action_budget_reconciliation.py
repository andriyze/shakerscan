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
         WHERE a.reservation_id IS NULL
           AND a.receipt_json->>'budget_reservation_id' IS NOT NULL
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
        -- Driven from the few open actions (planned, leased or running: every status that is not
        -- terminal) through the reservations' unique (owner_kind, owner_id, action_id) key, not
        -- from every settled reservation in history through a text cast.
        SELECT COUNT(*)
          FROM scan_capability_actions a
          JOIN budget_reservations r
            ON r.owner_kind='scan'
           AND r.owner_id=a.scan_id::text
           AND r.action_id=a.action_id
           AND r.action_digest=a.action_digest
         WHERE a.status IN ('planned','leased','running')
           AND r.status IN ('committed','released','failed')
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


# Settled reservations are immutable, and an action never leaves a terminal status, so a settled
# reservation whose action was already terminal never needs another look. The incremental repair
# walks settled Scan reservations once, in (updated_at, id) order from a cursor, probing each one's
# action through its unique key, instead of joining every settled reservation in history to its
# action through a text cast on every sweep. Rows newer than the settle delay plus a clock-skew
# margin are examined but never passed by the cursor, so a late writer cannot be skipped.
#
# The margin exists because ``budget_reservations.updated_at`` comes from the writing process's
# clock, not the database's: it is part of the reservation's content-addressed state (its
# ``state_digest``), so it cannot simply be set by ``now()``. The cursor compares it with the
# database clock, so a worker host whose clock runs behind the database by more than the margin
# could settle a reservation "before" the cursor and have its action skipped. Thirty minutes is far
# beyond the drift of an NTP-synchronised host; rows inside the margin are re-examined on every
# sweep (within the batch bound), so the margin costs latency only for hosts that are that far off.
REPAIR_SETTLE_DELAY = "5 minutes"
REPAIR_CURSOR_MARGIN = "30 minutes"

_SETTLED_BATCH_SQL = r"""
WITH batch AS (
    SELECT r.id, r.updated_at, r.owner_id, r.action_id, r.action_digest,
           r.status, r.failure_reason, r.execution_uncertain,
           r.updated_at < now() - INTERVAL '""" + REPAIR_CURSOR_MARGIN + r"""' AS passable
      FROM budget_reservations r
     WHERE r.owner_kind='scan'
       AND r.status IN ('committed','released','failed')
       AND r.updated_at < now() - INTERVAL '""" + REPAIR_SETTLE_DELAY + r"""'
       AND ($1::timestamptz IS NULL OR (r.updated_at, r.id) > ($1::timestamptz, $2::text))
     ORDER BY r.updated_at, r.id
     LIMIT $3
)
SELECT b.id, b.updated_at, b.passable, b.status AS reservation_status,
       b.failure_reason, b.execution_uncertain, a.id AS open_action
  FROM batch b
  LEFT JOIN scan_capability_actions a
    ON a.scan_id = CASE
           WHEN b.owner_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
           THEN b.owner_id::uuid END
   AND a.action_id = b.action_id
   AND a.action_digest = b.action_digest
   AND a.status IN ('planned','leased','running')
 ORDER BY b.updated_at, b.id
"""

_TERMINALIZE_SQL = r"""
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
  FROM unnest($1::uuid[], $2::text[], $3::text[], $4::boolean[])
       AS c(id, reservation_status, failure_reason, execution_uncertain)
 WHERE a.id=c.id AND a.status IN ('planned','leased','running')
RETURNING a.id
"""


async def repair_terminal_reservation_actions_incremental(
    conn: Any, *, cursor: tuple[Any, str] | None, limit: int = 1000,
) -> tuple[int, tuple[Any, str] | None, int]:
    """Terminalize open Scan actions of the next batch of settled reservations (in the caller's
    transaction). Returns (repaired, next cursor, reservations examined). An action locked by
    another transaction stops the cursor before its reservation, so the next sweep looks again."""
    if limit < 1 or limit > 1000:
        raise ValueError("repair limit must be between 1 and 1000")
    rows = await conn.fetch(
        _SETTLED_BATCH_SQL, cursor[0] if cursor else None, cursor[1] if cursor else None, limit)
    open_ids = [row["open_action"] for row in rows if row["open_action"] is not None]
    locked: set[Any] = set()
    if open_ids:
        locked = {
            row["id"] for row in await conn.fetch(
                "SELECT id FROM scan_capability_actions WHERE id = ANY($1::uuid[]) "
                "AND status IN ('planned','leased','running') FOR UPDATE SKIP LOCKED",
                open_ids,
            )
        }
    repair = [row for row in rows if row["open_action"] in locked]
    repaired = 0
    if repair:
        repaired = len(await conn.fetch(
            _TERMINALIZE_SQL,
            [row["open_action"] for row in repair],
            [str(row["reservation_status"]) for row in repair],
            [row["failure_reason"] for row in repair],
            [bool(row["execution_uncertain"]) for row in repair],
        ))
    next_cursor = cursor
    for row in rows:
        if not row["passable"]:
            break  # too recent to pass: a skewed clock could still write behind it
        if row["open_action"] is not None and row["open_action"] not in locked:
            break  # busy elsewhere: look at it again next sweep
        next_cursor = (row["updated_at"], str(row["id"]))
    return repaired, next_cursor, len(rows)


REPAIR_CURSOR_KEY = "scan:budget-reservation-repair:cursor"


def _load_cursor(redis_client: Any) -> tuple[Any, str] | None:
    from datetime import datetime

    try:
        raw = redis_client.get(REPAIR_CURSOR_KEY)
        if not raw:
            return None
        stamp, _sep, reservation_id = (raw.decode() if isinstance(raw, bytes) else str(raw)).partition("|")
        return (datetime.fromisoformat(stamp), reservation_id) if reservation_id else None
    except Exception:
        return None  # walk from the start: slower, never wrong


def _save_cursor(redis_client: Any, cursor: tuple[Any, str] | None) -> None:
    if cursor is None:
        return
    try:
        redis_client.set(REPAIR_CURSOR_KEY, f"{cursor[0].isoformat()}|{cursor[1]}")
    except Exception:
        pass


async def repair_settled_reservation_actions(
    pool: Any, redis_client: Any, *, batch_size: int = 1000, max_batches: int = 20,
) -> int:
    """Run the incremental repair for up to ``max_batches`` batches, each in its own transaction,
    resuming from (and saving) the shared cursor so a new leader continues where the last stopped."""
    cursor = _load_cursor(redis_client)
    repaired = 0
    for _batch in range(max(1, int(max_batches))):
        async with pool.acquire() as conn:
            async with conn.transaction():
                count, next_cursor, examined = await repair_terminal_reservation_actions_incremental(
                    conn, cursor=cursor, limit=batch_size)
        repaired += count
        if next_cursor != cursor:
            _save_cursor(redis_client, next_cursor)
        if next_cursor == cursor or examined < batch_size:
            break
        cursor = next_cursor
    return repaired


__all__ = [
    "repair_settled_reservation_actions",
    "repair_terminal_reservation_actions_incremental",
    "scan_action_budget_reconciliation",
]
