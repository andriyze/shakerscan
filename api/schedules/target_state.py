"""Target-state lock shared by standalone and managed schedule admission."""


async def lock_active_schedule_target(conn, schedule_id):
    # Take the target lock BEFORE schedule locks, like archive. A successful claim
    # is the admission boundary; archive does not cancel already-admitted work.
    return await conn.fetchrow("""SELECT t.id,t.url FROM targets t
        JOIN schedules s ON s.target_id=t.id
        WHERE s.id=$1 AND t.is_active=true FOR SHARE OF t""", schedule_id)