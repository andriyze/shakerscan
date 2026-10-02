"""Device compatibility writes use the shared encrypted request-collection models."""
from __future__ import annotations

import json
from typing import Any
import uuid

from fastapi import HTTPException

try:
    from scanner_tools.request_collections import redacted_index
except ModuleNotFoundError:
    from scanner.scanner_tools.request_collections import redacted_index


async def require_collection_owner(conn: Any, collection_id: Any, device_id: Any) -> dict[str, Any]:
    row = await conn.fetchrow('SELECT * FROM request_collections WHERE id=$1 FOR UPDATE', uuid.UUID(str(collection_id)))
    if not row:
        raise HTTPException(404, 'Request collection not found')
    owned = await conn.fetchval('SELECT target_asset_access_owner($1)=target_asset_access_owner($2)',
                               row['target_id'], uuid.UUID(str(device_id)))
    if not owned:
        raise HTTPException(409, 'Manage this shared collection from its owning target or the collection library')
    return dict(row)


async def collection_view(conn: Any, device_id: Any, collection_id: Any) -> dict[str, Any]:
    row = await conn.fetchrow('SELECT * FROM device_request_collections WHERE id=$1 AND device_target_id=$2',
                             uuid.UUID(str(collection_id)), uuid.UUID(str(device_id)))
    if not row:
        raise HTTPException(404, 'Request collection is not available to this target')
    payload = dict(row)
    summary = payload.get('summary_json') or {}
    if isinstance(summary, str):
        summary = json.loads(summary)
    requests = await conn.fetch('''SELECT request_id,folder,name,method,redacted_url,normalized_path,
        body_mode,auth_type,tags_json AS tags,content_type,body_field_names_json AS body_field_names,safe_method,supported
        FROM request_collection_requests WHERE collection_id=$1 ORDER BY ordinal LIMIT 200''', uuid.UUID(str(collection_id)))
    payload['summary_json'] = {**summary, 'requests': [dict(item) for item in requests],
                               'requests_total': int(summary.get('request_count') or 0)}
    return payload


async def save_device_collection(
    conn: Any, device_id: Any, *, summary: dict[str, Any], encrypted_payload: str,
    collection_id: Any = None, expected_digest: str | None = None,
) -> dict[str, Any]:
    """Atomic canonical write; legacy routes do not have their own document store."""
    device_uuid = uuid.UUID(str(device_id))
    if not encrypted_payload.startswith('enc:fernet:'):
        raise HTTPException(503, 'Encrypted collection storage is required')
    async with conn.transaction():
        if collection_id is not None:
            current = await require_collection_owner(conn, collection_id, device_uuid)
            if expected_digest is not None and current['payload_sha256'] != expected_digest:
                raise HTTPException(409, 'Request collection changed while being edited; refresh before saving')
            owner = current['target_id']
            collection_uuid = current['id']
        else:
            owner = device_uuid
            current = await conn.fetchrow('SELECT * FROM request_collections WHERE target_id=$1 AND name=$2 FOR UPDATE',
                                         owner, str(summary['name']))
            if current and current['is_active']:
                raise HTTPException(409, 'This target already has an active request collection with that name')
            collection_uuid = current['id'] if current else uuid.uuid4()
        indexed = [dict(row) if row.get('request_id') else redacted_index([row])[0]
                   for row in summary.get('requests') or []]
        metadata = {key: value for key, value in summary.items() if key != 'requests'}
        metadata['environment_stored_separately'] = False
        await conn.execute('''INSERT INTO request_collections (
            id,target_id,device_target_id,name,format,encrypted_payload,payload_sha256,
            request_count,safe_request_count,potentially_mutating_request_count,metadata_json,is_active
        ) VALUES($1,$2,CASE WHEN EXISTS(SELECT 1 FROM target_device_profiles WHERE target_id=$2) THEN $2 END,
            $3,$4,$5,$6,$7,$8,$9,$10,true)
        ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,format=EXCLUDED.format,
            encrypted_payload=EXCLUDED.encrypted_payload,payload_sha256=EXCLUDED.payload_sha256,
            request_count=EXCLUDED.request_count,safe_request_count=EXCLUDED.safe_request_count,
            potentially_mutating_request_count=EXCLUDED.potentially_mutating_request_count,
            metadata_json=EXCLUDED.metadata_json,is_active=true,updated_at=NOW()''',
            collection_uuid,owner,str(summary['name']),str(summary['format']),encrypted_payload,
            str(summary['document_sha256']),int(summary.get('request_count') or len(indexed)),
            sum(bool(row.get('safe_method')) for row in indexed),sum(not row.get('safe_method') for row in indexed),json.dumps(metadata))
        await conn.execute('DELETE FROM request_collection_requests WHERE collection_id=$1', collection_uuid)
        if indexed:
            await conn.executemany('''INSERT INTO request_collection_requests (
                collection_id,request_id,ordinal,folder,name,method,redacted_url,normalized_path,
                body_mode,auth_type,tags_json,content_type,body_field_names_json,safe_method,supported
            ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)''', [(
                collection_uuid,row['request_id'],ordinal,row.get('folder'),row.get('name'),row['method'],
                row.get('redacted_url'),row.get('normalized_path') or '/',row.get('body_mode'),row.get('auth_type'),
                json.dumps(row.get('tags') or []),row.get('content_type'),json.dumps(row.get('body_field_names') or []),
                bool(row.get('safe_method')),row.get('supported') is not False,
            ) for ordinal,row in enumerate(indexed)])
        if current and current['payload_sha256'] != str(summary['document_sha256']):
            await conn.execute('''UPDATE request_collection_selections SET is_active=false,
                revoked_at=COALESCE(revoked_at,NOW()),updated_at=NOW() WHERE collection_id=$1''', collection_uuid)
        return await collection_view(conn, device_uuid, collection_uuid)


async def deactivate_device_collection(conn: Any, device_id: Any, collection_id: Any) -> dict[str, Any]:
    async with conn.transaction():
        current = await require_collection_owner(conn, collection_id, device_id)
        await conn.execute('UPDATE request_collections SET is_active=false,updated_at=NOW() WHERE id=$1', current['id'])
        await conn.execute('''UPDATE request_collection_selections SET is_active=false,
            revoked_at=COALESCE(revoked_at,NOW()),updated_at=NOW() WHERE collection_id=$1''',current['id'])
        return await collection_view(conn, device_id, collection_id)
