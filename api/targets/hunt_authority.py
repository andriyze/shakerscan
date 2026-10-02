"""Current target Hunt settings and revocable sharing authority.

Kept independent of API routers so installed SSH execution imports only its runtime.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from uuid import UUID

from fastapi import HTTPException


def object_value(value):
    return json.loads(value) if isinstance(value, str) else dict(value or {})


def authority_from_row(row) -> dict:
    saved = object_value(row['metadata_json']).get('hunt_authority') or {}
    # A changed URL/asset relationship must never silently carry delegated authority.
    active = bool(row['is_active'])
    current = bool(active and saved.get('target_url') == row['url'])
    return {
        'target_id': str(row['id']), 'revision': int(saved.get('revision') or 0),
        'metadata_changes': active if not saved else current and saved.get('metadata_changes', True) is True,
        'credential_profile_ids': list(saved.get('credential_profile_ids') or []) if current else [],
        'collection_ids': list(saved.get('collection_ids') or []) if current else [],
        'ssh_host_keys': list(saved.get('ssh_host_keys') or []) if current else [],
        'ssh_trust_first_contact': current and saved.get('ssh_trust_first_contact') is True,
        'recorded_by': saved.get('recorded_by'), 'updated_at': saved.get('updated_at'),
    }


async def authority_row(conn, target_id, *, lock=False):
    try:
        target_uuid = UUID(str(target_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(400, 'Invalid target id') from exc
    owner = await conn.fetchval('SELECT target_asset_access_owner($1)', target_uuid)
    row = await conn.fetchrow('SELECT id,url,is_active,metadata_json FROM targets WHERE id=$1' +
                              (' FOR UPDATE' if lock else ''), owner)
    if row is None:
        raise HTTPException(404, 'Target not found')
    return row


async def read_hunt_authority(conn, target_id):
    return authority_from_row(await authority_row(conn, target_id))


async def pin_authorized_first_contact(conn, target_id, port, fingerprint):
    async with conn.transaction():
        row = await authority_row(conn, target_id, lock=True)
        authority = authority_from_row(row)
        existing = next((key['fingerprint'] for key in authority['ssh_host_keys'] if key['port'] == port), None)
        if existing:
            if existing != fingerprint:
                raise HTTPException(403, 'SSH host key changed during first-contact verification')
            return
        if not authority['ssh_trust_first_contact']:
            raise HTTPException(403, 'First-contact SSH trust was revoked')
        if len(authority['ssh_host_keys']) >= 32:
            raise HTTPException(422, 'Save at most 32 SSH host keys per target')
        authority['ssh_host_keys'].append({'port':port, 'fingerprint':fingerprint,
                                          'source':'authorized_first_contact'})
        authority['revision'] += 1
        await save_authority(conn, row, authority, recorded_by=authority['recorded_by'])


async def save_authority(conn, row, values: dict, *, recorded_by: str):
    saved = {**values, 'target_url': row['url'], 'updated_at': datetime.now(timezone.utc).isoformat(),
             'recorded_by': recorded_by}
    await conn.execute("""UPDATE targets SET metadata_json=jsonb_set(
        COALESCE(metadata_json,'{}'::jsonb),'{hunt_authority}',$2::jsonb),updated_at=NOW()
        WHERE id=$1""", row['id'], json.dumps(saved))
    return saved


async def require_hunt_delegation(conn, run, name, values):
    row = await authority_row(conn, run.get('device_target_id') or run['target_id'], lock=True)
    authority = authority_from_row(row)
    if name.startswith('targets.') and not authority['metadata_changes']:
        raise HTTPException(403, 'Enable Hunt metadata changes in this target’s Hunt permissions')
    if name == 'credentials.grant' and str(values.get('profile_id')) not in authority['credential_profile_ids']:
        raise HTTPException(403, 'The operator has not delegated sharing this credential profile with this target')
    return row, authority


async def record_collection_share(conn, target_id, collection_id, *, recorded_by):
    """Called only by the operator binding route, never the Hunt executor."""
    row = await authority_row(conn, target_id, lock=True)
    values = authority_from_row(row)
    values['collection_ids'] = list(dict.fromkeys([*values['collection_ids'], str(collection_id)]))
    if len(values['collection_ids']) > 64:
        raise HTTPException(422, 'A target may authorize at most 64 shared collections')
    values['revision'] += 1
    await save_authority(conn, row, values, recorded_by=recorded_by)
