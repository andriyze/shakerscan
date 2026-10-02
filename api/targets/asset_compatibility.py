"""Versioned repairs for databases already converted by early target-unification builds."""
from typing import Any

from .asset_schema import ASSET_VIEW_SQL
from .asset_inputs_schema import INPUTS_SCHEMA_SQL

MIGRATION = 'unified_target_asset_compatibility_v2'


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
    await conn.reload_schema_state()
    await conn.execute('INSERT INTO app_schema_migrations(name) VALUES($1)', MIGRATION)
