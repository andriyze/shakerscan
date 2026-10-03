"""Read models over one target inventory, with service-level attribution preserved."""
from __future__ import annotations

from typing import Any
import uuid

from fastapi import HTTPException

try:
    from runtime.credential_store import PostgresCredentialProfileStore
except ModuleNotFoundError:
    from ..runtime.credential_store import PostgresCredentialProfileStore


# The inventory listing lives in asset_inventory; this module keeps detail and history.
from .asset_inventory import (  # noqa: F401  (re-exported for existing callers)
    ROOT_COLUMNS, ROOT_FROM, ROOT_WHERE, list_assets, public_asset,
)


async def resolve_asset_id(conn: Any, target_id: Any) -> uuid.UUID:
    try:
        target_uuid = uuid.UUID(str(target_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(400, 'Invalid target id') from exc
    asset = await conn.fetchval('SELECT COALESCE(asset_owner_id,id) FROM targets WHERE id=$1', target_uuid)
    if asset is None:
        raise HTTPException(404, 'Target not found')
    return asset


HISTORY = {
    'scans': ('scans', "r.id,r.target_id,r.target_url,r.status,r.run_kind,r.scan_type,r.score,r.grade,r.created_at,r.completed_at", "AND (r.scan_role IS NULL OR r.scan_role <> 'shard')"),
    'findings': ('findings', 'r.id,r.target_id,r.title,r.severity,r.status,r.tool,r.created_at,r.updated_at', ''),
    'hunts': ('hunt_runs', "r.id,r.target_id,r.target_kind,to_jsonb(r)->>'status' AS status,r.created_at", ''),
}


async def asset_history(conn: Any, target_id: Any, *, kind: str = 'scans', limit: int = 50, offset: int = 0) -> dict[str, Any]:
    if kind not in HISTORY:
        raise HTTPException(400, 'Unknown history kind')
    owner = await resolve_asset_id(conn, target_id)
    table, columns, extra = HISTORY[kind]
    where = f"r.target_id IN (SELECT id FROM targets WHERE id=$1 OR asset_owner_id=$1) {extra}"
    total = await conn.fetchval(f'SELECT count(*) FROM {table} r WHERE {where}', owner)
    records = await conn.fetch(f'SELECT {columns} FROM {table} r WHERE {where} ORDER BY r.created_at DESC,r.id DESC LIMIT $2 OFFSET $3', owner, limit, offset)
    return {'asset_id': owner, 'kind': kind, 'items': [dict(row) for row in records],
            'total': int(total), 'limit': limit, 'offset': offset}


async def asset_detail(conn: Any, target_id: Any) -> dict[str, Any]:
    from .asset_services import asset_service_knowledge
    owner = await resolve_asset_id(conn, target_id)
    row = await conn.fetchrow(f'SELECT {ROOT_COLUMNS} FROM {ROOT_FROM} WHERE t.id=$1', owner)
    origins = await conn.fetch("""SELECT id,url,name,is_active,last_scanned_at,last_score,last_grade,
        active_findings_count,(target_asset_access_owner(id)=$1) AS current_membership
        FROM targets WHERE asset_owner_id=$1 ORDER BY url,id""", owner)
    services = await conn.fetch("""SELECT id,transport,port,state,service_name,product,version,cpe,
        encrypted,web_origin,policy_disposition,first_seen_at,last_seen_at,scan_id
        FROM device_services WHERE target_id=$1 ORDER BY transport,port LIMIT 1000""", owner)
    profiles = await PostgresCredentialProfileStore().list_profiles(
        conn, target_kind='network', target_id=owner, include_inactive=True,
    )
    collections = await conn.fetch("""SELECT id,name,format,target_id AS home_target_id,
        request_count,safe_request_count,potentially_mutating_request_count,is_active,updated_at
        FROM request_collections WHERE target_collection_visible(id,$1)
          OR target_asset_access_owner(target_id)=$1 ORDER BY lower(name),id""", owner)
    finding_counts = await conn.fetch("""SELECT severity,count(*) AS count FROM findings
        WHERE status='active' AND target_id IN (SELECT id FROM targets WHERE id=$1 OR asset_owner_id=$1)
        GROUP BY severity""", owner)
    try:
        from target_authorization import current_target_authorization
    except ModuleNotFoundError:
        from ..target_authorization import current_target_authorization
    return {
        'authorization': await current_target_authorization(conn,owner),
        'target': public_asset(row), 'requested_target_id': str(target_id),
        'origins': [dict(item) for item in origins], 'services': [dict(item) for item in services],
        'service_intelligence': await asset_service_knowledge(conn,owner),
        'services_limit': 1000,
        'credentials': [profile.public_dict() for profile in profiles],
        'request_collections': [dict(item) for item in collections],
        'active_findings': {item['severity']: int(item['count']) for item in finding_counts},
        'history': await asset_history(conn, owner),
    }
