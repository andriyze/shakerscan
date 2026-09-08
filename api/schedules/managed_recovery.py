"""Read-only admission reconciliation for paused or deleted schedules."""

from uuid import UUID


async def pending(pool, origin, now):
    async with pool.acquire() as conn:
        return await conn.fetch(
            """SELECT o.id,o.schedule_id FROM managed_schedule_occurrences o
            LEFT JOIN schedules s ON s.id=o.schedule_id
            WHERE o.state='pending' AND o.gateway_origin=$1
            AND (o.lease_until IS NULL OR o.lease_until <= $2)
            AND (s.id IS NULL OR s.is_active=false)
            ORDER BY o.created_at LIMIT 100""",
            origin, now,
        )


async def record(pool, occurrence, origin, outcome, now):
    if outcome.state not in {"accepted", "denied"}:
        return False
    scan_id = UUID(outcome.scan_id) if outcome.state == "accepted" else None
    async with pool.acquire() as conn, conn.transaction():
        # Match claim/settle lock order; resume racing with this read wins.
        schedule = await conn.fetchrow(
            "SELECT is_active FROM schedules WHERE id=$1 FOR UPDATE",
            occurrence["schedule_id"],
        )
        if schedule and schedule["is_active"]:
            return False
        row = await conn.fetchrow(
            """UPDATE managed_schedule_occurrences
            SET state=$1,scan_id=$2,lease_id=NULL,lease_until=NULL
            WHERE id=$3 AND schedule_id=$4 AND gateway_origin=$5
            AND state='pending' AND (lease_until IS NULL OR lease_until <= $6)
            RETURNING id""",
            outcome.state, scan_id, occurrence["id"], occurrence["schedule_id"], origin, now,
        )
        if row and scan_id and schedule:
            await conn.execute(
                "UPDATE schedules SET last_run_at=NOW(),updated_at=NOW() WHERE id=$1",
                occurrence["schedule_id"],
            )
        return row is not None


async def reconcile(pool, dispatcher, now):
    # Only the configured origin receives the token. Never contact a historical
    # host from the database after operator configuration changes.
    for occurrence in await pending(pool, dispatcher.origin, now):
        outcome = await dispatcher.lookup(str(occurrence["schedule_id"]), str(occurrence["id"]))
        await record(pool, occurrence, dispatcher.origin, outcome, now)
