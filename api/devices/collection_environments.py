"""Freeze shared collection environments at queue time and revalidate them at dispatch."""
from __future__ import annotations

import hashlib
import json
from typing import Any
import uuid

from fastapi import HTTPException
try:
    from secret_store import decrypt_secret
except ModuleNotFoundError:
    from ..secret_store import decrypt_secret


async def bind_environments(conn: Any, refs: list[dict[str, Any]], choices: dict[str, str | None]) -> list[dict[str, Any]]:
    selected = {str(ref['collection_id']) for ref in refs}
    if set(choices) - selected:
        raise HTTPException(422, 'An environment was supplied for an unselected request collection')
    result = []
    for ref in refs:
        environment_id = choices.get(str(ref['collection_id']))
        if not environment_id:
            result.append({**ref, 'environment_id': None, 'environment_sha256': None})
            continue
        try:
            environment_uuid = uuid.UUID(environment_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise HTTPException(422, 'Invalid request collection environment id') from exc
        row = await conn.fetchrow('''SELECT id,payload_sha256 FROM request_collection_environments
            WHERE id=$1 AND collection_id=$2 AND is_active''', environment_uuid, uuid.UUID(ref['collection_id']))
        if not row:
            raise HTTPException(422, 'Selected environment is inactive or belongs to another collection')
        result.append({**ref, 'environment_id': str(row['id']), 'environment_sha256': row['payload_sha256']})
    return result


async def hydrate_environment(conn: Any, ref: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    environment_id = ref.get('environment_id')
    if not environment_id:
        if ref.get('environment_sha256'):
            raise ValueError('Collection environment digest has no environment id')
        return payload
    row = await conn.fetchrow('''SELECT encrypted_payload,payload_sha256 FROM request_collection_environments
        WHERE id=$1 AND collection_id=$2 AND is_active''',
        uuid.UUID(str(environment_id)), uuid.UUID(str(ref['collection_id'])))
    expected = str(ref.get('environment_sha256') or '')
    if not row or row['payload_sha256'] != expected:
        raise ValueError('Collection environment changed or was deactivated after the scan was queued')
    raw = str(decrypt_secret(row['encrypted_payload']) or '')
    if not raw or raw.startswith('enc:fernet:') or len(raw.encode()) > 7 * 1024 * 1024:
        raise ValueError('Collection environment cannot be decrypted within the worker size limit')
    try:
        environment = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError('Invalid collection environment payload') from exc
    if not isinstance(environment, dict):
        raise ValueError('Collection environment must be an object')
    digest = hashlib.sha256(json.dumps(environment, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    if digest != expected:
        raise ValueError('Collection environment failed its worker integrity check')
    return {**payload, 'environment': environment}
