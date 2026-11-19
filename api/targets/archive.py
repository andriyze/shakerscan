"""Archive inventory without erasing history or cancelling admitted execution."""
import json
import re
from uuid import UUID

import asyncpg
from fastapi import HTTPException

# Members archived together with their host carry the host's id, so restoring the host brings
# back exactly what its archive covered and never a service that was archived on its own.
ARCHIVED_WITH_KEY = 'archived_with'

# An archived host's stored URL carries ``#retired=<its id>`` (targets_set_canonical_key): the URL
# and the canonical key are unique, and the suffix frees both so the same host can be added again.
# Readers are shown the host's own URL; ``is_active`` already says it is archived.
_RETIRED_SUFFIX = re.compile(r'#retired=[0-9a-fA-F-]{36}$')


def public_target_url(url):
    """The URL a person registered, without the archive bookkeeping suffix."""
    return _RETIRED_SUFFIX.sub('', url) if isinstance(url, str) else url


# The host a web app belongs to is archived with it when that app was the host's last active
# service and the host is one the inventory created for it: archiving the last web app on a host
# left an active host with no origins, counted in the inventory total. A host a person added
# (``declared``) or one with other active services stays.
_ARCHIVE_EMPTIED_HOST_SQL = """UPDATE targets host
    SET is_active=false, asm_enabled=false, updated_at=NOW(),
        metadata_json=COALESCE(host.metadata_json,'{}'::jsonb) || $2::jsonb
    FROM targets app
    WHERE app.id=$1 AND host.id=app.asset_owner_id AND host.is_active
      AND host.discovery_source='host'
      AND host.metadata_json->>'declared' IS DISTINCT FROM 'true'
      AND NOT EXISTS (SELECT 1 FROM targets other WHERE other.asset_owner_id=host.id
                      AND other.is_active AND other.id<>$1)
    RETURNING host.id"""


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
        host = await conn.fetchval(_ARCHIVE_EMPTIED_HOST_SQL, target_id,
                                   json.dumps({ARCHIVED_WITH_KEY: str(target_id)}))
        if host is not None:
            paused += await conn.fetch("""UPDATE schedules SET is_active=false, next_run_at=NULL, updated_at=NOW()
                WHERE target_id=$1 AND (is_active=true OR next_run_at IS NOT NULL) RETURNING id""", host)
    result = {'id': str(target_id), 'status': 'archived', 'records_deleted': False,
              'schedules_paused': len(paused), 'targets_archived': len(ids) + (host is not None),
              'running_work_cancelled': False}
    if host is not None:
        result['host_archived'] = str(host)
    return result


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
    # The host archived with this web app (its last service) comes back with it. A host with the
    # same locator added since keeps the identity; this one then stays archived.
    host = await conn.fetchrow("""SELECT host.id FROM targets app JOIN targets host ON host.id=app.asset_owner_id
        WHERE app.id=$1 AND NOT host.is_active AND host.metadata_json->>$2 = $1::text""",
        target_id, ARCHIVED_WITH_KEY)
    if host is not None:
        try:
            async with conn.transaction():
                await conn.execute("""UPDATE targets SET is_active=true, updated_at=NOW(),
                    metadata_json=COALESCE(metadata_json,'{}'::jsonb) - $2::text WHERE id=$1""",
                    host['id'], ARCHIVED_WITH_KEY)
        except asyncpg.UniqueViolationError:
            pass
    return len(restored)
