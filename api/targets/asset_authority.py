"""Reuse one host authorization through verified current asset membership.

No copied approval rows and no client-supplied inheritance flags. An origin's
own authorization or explicit revocation overrides inherited host authority.
"""
from __future__ import annotations

from typing import Any
import uuid

MIGRATION = 'unified_target_asset_authority_v1'
SCHEMA = r"""
ALTER TABLE request_collection_bindings DROP CONSTRAINT IF EXISTS request_collection_bindings_target_kind_check;
ALTER TABLE request_collection_bindings ADD CONSTRAINT request_collection_bindings_target_kind_check
    CHECK (target_kind IN ('web','api','network','device'));
CREATE OR REPLACE FUNCTION retire_asset_members() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.is_active AND NOT NEW.is_active AND NEW.asset_owner_id IS NULL THEN
        UPDATE targets SET is_active=false,updated_at=NOW() WHERE asset_owner_id=NEW.id AND is_active;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER target_asset_retirement AFTER UPDATE OF is_active ON targets
FOR EACH ROW EXECUTE FUNCTION retire_asset_members();
ALTER TABLE targets ADD COLUMN IF NOT EXISTS authorization_inheritance BOOLEAN NOT NULL DEFAULT true;
CREATE OR REPLACE FUNCTION target_effective_authorization_target(consumer uuid) RETURNS uuid
LANGUAGE sql STABLE STRICT AS $$
    SELECT CASE WHEN t.authorization_inheritance
                     AND target_asset_access_owner(t.id) <> t.id
                     AND NOT EXISTS (
                         SELECT 1 FROM approval_receipts a JOIN scope_receipts s ON s.id=a.scope_receipt_id
                         WHERE s.target_id=t.id AND a.action_name='target.authorization'
                     )
                THEN target_asset_access_owner(t.id) ELSE t.id END
    FROM targets t WHERE t.id=consumer AND t.is_active
$$;
"""


async def migrate_asset_authority(conn: Any) -> None:
    if await conn.fetchval('SELECT 1 FROM app_schema_migrations WHERE name=$1', MIGRATION):
        return
    await conn.execute(SCHEMA)
    await conn.reload_schema_state()
    await conn.execute('INSERT INTO app_schema_migrations(name) VALUES($1)', MIGRATION)


async def resolve_target_authorization(conn: Any, target_id: Any, exact_reader: Any):
    try:
        consumer = uuid.UUID(str(target_id))
    except (ValueError, TypeError, AttributeError):
        return None
    owner = await conn.fetchval('SELECT target_effective_authorization_target($1)', consumer)
    if owner is None:
        return None
    authorization = await exact_reader(conn, owner)
    if authorization is None:
        return None
    return {**authorization, 'target_id': str(consumer), 'authority_target_id': str(owner),
            'inherited': str(owner) != str(consumer)}


async def standing_authorization_matches_target(
    conn: Any, *, target_id: Any, scope_target_id: Any, approval_receipt_id: Any,
) -> bool:
    """Only a freshly resolved standing receipt may cross a parent/service boundary."""
    try:
        target = uuid.UUID(str(target_id))
        scope_target = uuid.UUID(str(scope_target_id))
        approval = uuid.UUID(str(approval_receipt_id))
    except (ValueError, TypeError, AttributeError):
        return False
    if target == scope_target:
        return True
    effective = await conn.fetchval('SELECT target_effective_authorization_target($1)', target)
    if effective != scope_target:
        return False
    try:
        from target_authorization import current_target_authorization
    except ModuleNotFoundError:
        from ..target_authorization import current_target_authorization
    current = await current_target_authorization(conn, target)
    return bool(current and current.get('inherited')
                and str(current.get('approval_receipt_id')) == str(approval))
