"""Archive inventory without erasing history or cancelling admitted execution."""
import json
from uuid import UUID
from fastapi import HTTPException

# Members archived together with their host carry the host's id, so restoring the host brings
# back exactly what its archive covered and never a service that was archived on its own.
ARCHIVED_WITH_KEY = 'archived_with'


async def archive(pool, target_id: UUID):
    async with pool.acquire() as conn, conn.transaction():
        # Target first, then schedules: shared with schedule admission. Concurrent
        # creates referencing this target wait for the FK/row lock to settle.
        target = await conn.fetchval('SELECT id FROM targets WHERE id=$1 FOR UPDATE', target_id)
        if target is None:
            raise HTTPException(404, 'Target not found')
        members = await conn.fetch("""SELECT id, is_active FROM targets
            WHERE id=$1 OR (asset_owner_id=$1 AND target_asset_access_owner(id)=$1)
            ORDER BY id FOR UPDATE""", target_id)
        ids = [row['id'] for row in members]
        # Only services active now are archived *with* the host; one archived on its own keeps
        # its own state and is not brought back when the host is restored.
        together = [row['id'] for row in members if row['is_active'] and row['id'] != target_id]
        paused = await conn.fetch("""UPDATE schedules SET is_active=false, next_run_at=NULL, updated_at=NOW()
            WHERE target_id=ANY($1::uuid[]) AND (is_active=true OR next_run_at IS NOT NULL) RETURNING id""", ids)
        await conn.execute("""UPDATE targets SET asm_enabled=false
            WHERE id=ANY($1::uuid[]) AND is_active=false AND id<>$2""", ids, target_id)
        await conn.execute("""UPDATE targets SET is_active=false, asm_enabled=false, updated_at=NOW(),
                metadata_json=CASE WHEN id=ANY($2::uuid[])
                    THEN COALESCE(metadata_json,'{}'::jsonb) || $3::jsonb ELSE metadata_json END
            WHERE id=$1 OR id=ANY($2::uuid[])""",
            target_id, together, json.dumps({ARCHIVED_WITH_KEY: str(target_id)}))
    return {'id': str(target_id), 'status': 'archived', 'records_deleted': False,
            'schedules_paused': len(paused), 'targets_archived': len(ids), 'running_work_cancelled': False}


# Run before the host itself is reactivated: members archived before the stamp existed are
# recognised by sharing the archived host's transaction timestamp.
RESTORE_ARCHIVED_MEMBERS_SQL = """UPDATE targets member
    SET is_active=true, updated_at=NOW(),
        metadata_json=COALESCE(member.metadata_json,'{}'::jsonb) - $2::text
    FROM targets host
    WHERE host.id=$1 AND member.asset_owner_id=$1 AND member.is_active=false
      AND target_asset_locator(member.url)=target_asset_locator(host.url)
      AND (member.metadata_json->>$2 = $1::text
           OR (member.metadata_json->>$2 IS NULL AND host.is_active=false
               AND member.updated_at=host.updated_at))
    RETURNING member.id"""


async def restore_archived_members(conn, target_id: UUID) -> int:
    """Reactivate the linked services archived together with ``target_id``.

    Archiving a host covers the host and its web apps, but Restore reactivated only the host and
    left its web app archived, so the restored host showed 0 origins. Schedules stay paused, as
    for the host: an operator resumes automatic work explicitly.
    """
    restored = await conn.fetch(RESTORE_ARCHIVED_MEMBERS_SQL, target_id, ARCHIVED_WITH_KEY)
    return len(restored)
