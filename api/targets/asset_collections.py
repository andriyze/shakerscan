"""Asset-level collection ownership with exact, separately selected execution origins."""
from __future__ import annotations

from typing import Any, Mapping, Sequence
import urllib.parse
import uuid

from fastapi import HTTPException

try:
    from runtime.request_collection_store import canonical_collection_origins, canonical_collection_origin, RequestCollectionContractError
except ModuleNotFoundError:
    from ..runtime.request_collection_store import canonical_collection_origins, canonical_collection_origin, RequestCollectionContractError


async def asset_collection_binding(
    conn: Any, collection: Mapping[str, Any], *, target_kind: str,
    target_id: uuid.UUID, allowed_origins: Sequence[str],
    authorize_cross_asset: bool = False,
) -> tuple[str, ...]:
    if target_kind not in {'web','api','network','device'}:
        raise HTTPException(422, 'Unsupported collection target kind')
    consumer = await conn.fetchrow('SELECT id,url,is_active FROM targets WHERE id=$1',target_id)
    owner = collection.get('target_id') or collection.get('device_target_id')
    same_asset = consumer and consumer['is_active'] and await conn.fetchval(
        'SELECT target_asset_access_owner($1)=target_asset_access_owner($2)',owner,target_id,
    )
    if not consumer or not consumer['is_active']:
        raise HTTPException(422, 'Execution target is unavailable')
    if not same_asset and not authorize_cross_asset:
        raise HTTPException(422, 'Request collection and execution binding must belong to the same current asset')
    try:
        origins = canonical_collection_origins(list(allowed_origins))
    except RequestCollectionContractError as exc:
        raise HTTPException(422, str(exc)) from exc
    parsed = urllib.parse.urlsplit(str(consumer['url']))
    host = str(parsed.hostname or '').lower().rstrip('.')
    if not host or any(str(urllib.parse.urlsplit(origin).hostname or '').lower().rstrip('.') != host for origin in origins):
        raise HTTPException(422, 'Request collection binding origin is outside the exact target host')
    if parsed.scheme in {'http','https'}:
        exact = canonical_collection_origin(f'{parsed.scheme}://{parsed.netloc}')
        if any(origin != exact for origin in origins):
            raise HTTPException(422, 'An application binding must use its exact origin; select the host asset to bind additional services')
    return origins
