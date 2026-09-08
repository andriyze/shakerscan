"""Durable managed scheduler intent. Opt-in; not a standalone scheduler replacement."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from uuid import UUID, uuid4

SCHEMA = """
CREATE TABLE IF NOT EXISTS managed_schedule_occurrences (
    id UUID PRIMARY KEY,
    schedule_id UUID NOT NULL,
    gateway_origin TEXT NOT NULL,
    payload JSONB NOT NULL,
    due_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','accepted','denied')),
    lease_id UUID,
    lease_until TIMESTAMPTZ,
    scan_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS managed_schedule_one_pending
ON managed_schedule_occurrences(schedule_id) WHERE state='pending';
"""


async def initialize(pool):
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA)


async def fetch_dispatchable(pool, *, now):
    """Include unresolved active intent even if its next cadence was edited.

    Paused schedules are not dispatched: a retry may still create work at the
    gateway. Their pending receipts require a future read-only reconciliation path.
    """
    async with pool.acquire() as conn:
        return list(await conn.fetch(
            """SELECT s.*, t.url AS target_url FROM schedules s
            JOIN targets t ON t.id=s.target_id
            WHERE s.is_active=true AND (s.next_run_at <= $1 OR EXISTS (
                SELECT 1 FROM managed_schedule_occurrences o
                WHERE o.schedule_id=s.id AND o.state='pending'
            ))""",
            now,
        ))


async def claim(pool, schedule_id, gateway_origin, validated_payload, *, now):
    """Freeze a validated, opaque-reference-only public Scan request once.

    An unresolved occurrence keeps its original payload and gateway across config
    edits and retries. Callers must use the returned fields, not their new input.
    No token or raw target credential belongs in validated_payload. It may be a
    synchronous validation factory, invoked only for a new occurrence, never to
    reinterpret already-persisted intent after an edit.
    """
    schedule_id = UUID(str(schedule_id))
    if now.tzinfo is None:
        raise ValueError("An aware UTC-compatible timestamp is required")
    async with pool.acquire() as conn, conn.transaction():
        schedule = await conn.fetchrow(
            "SELECT is_active,next_run_at FROM schedules WHERE id=$1 FOR UPDATE",
            schedule_id,
        )
        if not schedule or not schedule["is_active"]:
            return None
        row = await conn.fetchrow(
            "SELECT * FROM managed_schedule_occurrences WHERE schedule_id=$1 AND state='pending'",
            schedule_id,
        )
        if row and row["gateway_origin"] != gateway_origin:
            raise ValueError("Pending occurrence requires original gateway reconciliation")
        if row and row["lease_until"] and row["lease_until"] > now:
            return None
        created = row is None
        if not row:
            if not schedule["next_run_at"] or schedule["next_run_at"] > now:
                return None
            payload = validated_payload() if callable(validated_payload) else validated_payload
            row = await conn.fetchrow(
                """INSERT INTO managed_schedule_occurrences
                (id,schedule_id,gateway_origin,payload,due_at,state)
                VALUES($1,$2,$3,$4,$5,'pending') RETURNING *""",
                uuid4(),
                schedule_id,
                gateway_origin,
                json.dumps(payload),
                schedule["next_run_at"],
            )
        row = await conn.fetchrow(
            """UPDATE managed_schedule_occurrences SET lease_id=$1,lease_until=$2
            WHERE id=$3 RETURNING *""",
            uuid4(),
            now + timedelta(minutes=2),
            row["id"],
        )
        result = dict(row)
        result["new_occurrence"] = created
        if isinstance(result["payload"], str):
            result["payload"] = json.loads(result["payload"])
        return result


async def settle(
    pool, occurrence_id, lease_id, *, state, next_run_at=None, scan_id=None
):
    """Commit receipt and cadence together; uncertain outcomes remain pending.

    A stale lease cannot settle work claimed by another process. Deleting a
    schedule does not delete this durable receipt. Never fall back to local enqueue.
    """
    if state not in {"retry", "accepted", "denied"}:
        raise ValueError("Invalid occurrence outcome")
    if state != "retry" and (
        not isinstance(next_run_at, datetime) or next_run_at.tzinfo is None
    ):
        raise ValueError("Terminal outcomes require the next scheduled time")
    if state == "accepted" and not scan_id:
        raise ValueError("Accepted admission requires a scan ID")
    identifier = UUID(str(scan_id)) if scan_id else None
    async with pool.acquire() as conn, conn.transaction():
        owner = await conn.fetchval(
            "SELECT schedule_id FROM managed_schedule_occurrences WHERE id=$1",
            UUID(str(occurrence_id)),
        )
        if owner is None:
            return False
        # Same lock order as claim: schedule first, then occurrence.
        await conn.fetchrow("SELECT id FROM schedules WHERE id=$1 FOR UPDATE", owner)
        row = await conn.fetchrow(
            """UPDATE managed_schedule_occurrences
            SET state=$1,scan_id=$2,lease_id=NULL,lease_until=NULL
            WHERE id=$3 AND lease_id=$4 AND state='pending' RETURNING schedule_id""",
            "pending" if state == "retry" else state,
            identifier,
            UUID(str(occurrence_id)),
            UUID(str(lease_id)),
        )
        if not row:
            return False
        if state != "retry":
            await conn.execute(
                """UPDATE schedules SET next_run_at=$1,updated_at=NOW(),
                last_run_at=CASE WHEN $3 THEN NOW() ELSE last_run_at END
                WHERE id=$2""",
                next_run_at,
                row["schedule_id"],
                state == "accepted",
            )
        return True
