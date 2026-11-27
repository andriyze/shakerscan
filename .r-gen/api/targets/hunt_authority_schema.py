"""Keep canonical collection visibility tied to current operator sharing authority."""

MIGRATION = 'target_hunt_delegation_v1'
SCHEMA_SQL = r"""
-- This is a newly reserved operator-owned field. Pre-upgrade generic metadata
-- cannot constitute delegation, even if a planner happened to populate it.
UPDATE targets SET metadata_json=metadata_json-'hunt_authority'
WHERE metadata_json ? 'hunt_authority';
CREATE OR REPLACE FUNCTION target_collection_visible(collection uuid, consumer uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT COALESCE((
        SELECT b.is_active AND (
            target_asset_access_owner(c.target_id)=target_asset_access_owner(consumer)
            OR (t.is_active AND t.metadata_json->'hunt_authority'->>'target_url'=t.url
                AND COALESCE(t.metadata_json->'hunt_authority'->'collection_ids','[]'::jsonb)
                    ? collection::text)
        )
        FROM request_collection_bindings b JOIN request_collections c ON c.id=b.collection_id
        JOIN targets t ON t.id=target_asset_access_owner(consumer)
        WHERE b.collection_id=collection AND b.target_id=consumer
        ORDER BY b.updated_at DESC,b.id LIMIT 1
    ), (
        SELECT target_asset_access_owner(c.target_id)=target_asset_access_owner(consumer)
        FROM request_collections c WHERE c.id=collection
    ), false)
$$;
"""


async def migrate_hunt_authority(conn):
    if await conn.fetchval('SELECT 1 FROM app_schema_migrations WHERE name=$1', MIGRATION):
        return
    await conn.execute(SCHEMA_SQL)
    await conn.execute('INSERT INTO app_schema_migrations(name) VALUES($1)', MIGRATION)
