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
        members = await conn.fetch("""SELECT id FROM targets
            WHERE id=$1 OR (asset_owner_id=$1 AND target_asset_access_owner(id)=$1)
            ORDER BY id FOR UPDATE""", target_id)
        ids = [row['id'] for row in members]
        paused = await conn.fetch("""UPDATE schedules SET is_active=false, next_run_at=NULL, updated_at=NOW()
            WHERE target_id=ANY($1::uuid[]) AND (is_active=true OR next_run_at IS NOT NULL) RETURNING id""", ids)
        await conn.execute("UPDATE targets SET is_active=false, asm_enabled=false, updated_at=NOW() WHERE id=ANY($1::uuid[])", ids)
    return {'id': str(target_id), 'status': 'archived', 'records_deleted': False,
            'schedules_paused': len(paused), 'targets_archived': len(ids), 'running_work_cancelled': False}
