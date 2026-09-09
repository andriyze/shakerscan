"""Archive inventory without erasing history or cancelling admitted execution."""
from uuid import UUID
from fastapi import HTTPException


async def archive(pool, target_id: UUID):
    async with pool.acquire() as conn, conn.transaction():
        # Target first, then schedules: shared with schedule admission. Concurrent
        # creates referencing this target wait for the FK/row lock to settle.
        target = await conn.fetchval('SELECT id FROM targets WHERE id=$1 FOR UPDATE', target_id)
        if target is None:
            raise HTTPException(404, 'Target not found')
        await conn.execute("UPDATE targets SET is_active=false, asm_enabled=false, updated_at=NOW() WHERE id=$1", target_id)
        paused = await conn.fetch("""UPDATE schedules SET is_active=false, next_run_at=NULL, updated_at=NOW()
            WHERE target_id=$1 AND (is_active=true OR next_run_at IS NOT NULL) RETURNING id""", target_id)
    return {'id': str(target_id), 'status': 'archived', 'records_deleted': False,
            'schedules_paused': len(paused), 'running_work_cancelled': False}