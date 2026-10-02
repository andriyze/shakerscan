"""Versioned repairs for databases already converted by early target-unification builds."""
from typing import Any

from .asset_schema import ASSET_VIEW_SQL
from .asset_inputs_schema import INPUTS_SCHEMA_SQL

MIGRATION = 'unified_target_asset_compatibility_v3'

async def repair_candidate_target_constraint(conn: Any) -> None:
    if await conn.fetchval("SELECT to_regclass('investigation_candidates')"):
        await conn.execute("""ALTER TABLE investigation_candidates
        DROP CONSTRAINT IF EXISTS investigation_candidates_target_check;
        UPDATE investigation_candidates SET target_id=device_target_id
          WHERE plane='device' AND target_id IS NULL;
        ALTER TABLE investigation_candidates ADD CONSTRAINT investigation_candidates_target_check CHECK (
            (plane='web' AND target_id IS NOT NULL AND device_target_id IS NULL) OR
            (plane='device' AND target_id IS NOT NULL AND device_target_id=target_id)
        );""")

async def migrate_asset_compatibility(conn: Any) -> None:
    if await conn.fetchval('SELECT 1 FROM app_schema_migrations WHERE name=$1', MIGRATION):
        return
    await conn.execute("""UPDATE targets t SET metadata_json=COALESCE(t.metadata_json,'{}'::jsonb)
        || jsonb_build_object('environment',p.environment,'cohort',p.environment)
        FROM target_device_profiles p WHERE p.target_id=t.id
          AND NOT (COALESCE(t.metadata_json,'{}'::jsonb) ? 'environment')
          AND NOT (COALESCE(t.metadata_json,'{}'::jsonb) ? 'cohort')""")
    await conn.execute(ASSET_VIEW_SQL)
    await conn.execute(INPUTS_SCHEMA_SQL)
    from .asset_invariants import _install_host_key
    await _install_host_key(conn)
    # Early converted builds used double-escaped IPv6 regexes. Repair existing
    # keys as well as future inserts; retain UUIDs and refuse an ambiguous collision.
    rows = await conn.fetch("""SELECT id FROM targets WHERE url ~* '^https?://\\['
        AND canonical_key LIKE 'web:[%' ORDER BY id""")
    for row in rows:
        try:
            await conn.execute('UPDATE targets SET url=url WHERE id=$1',row['id'])
        except Exception as exc:
            if type(exc).__name__ != 'UniqueViolationError':
                raise
            raise RuntimeError(f"IPv6 target {row['id']} conflicts with an existing canonical service; migration rolled back") from exc
    await repair_candidate_target_constraint(conn)
    await conn.reload_schema_state()
    await conn.execute('INSERT INTO app_schema_migrations(name) VALUES($1)', MIGRATION)
