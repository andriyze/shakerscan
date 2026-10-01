"""Device endpoints use the canonical encrypted credential store.

The router owns approval and command receipts. This adapter owns no second
credential record and never returns plaintext in public control-plane objects.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any
import uuid

from fastapi import HTTPException

try:
    from runtime.credential_store import PostgresCredentialProfileStore, CredentialStoreError
    from runtime.credentials import (
        build_credential_secret, parse_credential_secret, public_credential_configuration,
        immediate_http_headers, IMMEDIATE_HTTP_HEADER_KINDS, SSH_CREDENTIAL_KINDS,
    )
    from secret_store import decrypt_secret, encrypt_secret
except ModuleNotFoundError:
    from ..runtime.credential_store import PostgresCredentialProfileStore, CredentialStoreError
    from ..runtime.credentials import (
        build_credential_secret, parse_credential_secret, public_credential_configuration,
        immediate_http_headers, IMMEDIATE_HTTP_HEADER_KINDS, SSH_CREDENTIAL_KINDS,
    )
    from ..secret_store import decrypt_secret, encrypt_secret

STORE = PostgresCredentialProfileStore()
LEGACY_KIND = {
    'ssh_password': 'ssh_password', 'ssh_private_key': 'ssh_private_key',
    'web_authorization_header': 'authorization_header', 'web_cookie': 'cookie',
    'web_form': 'form_login',
}


async def device_profile_view(conn: Any, device_id: Any, profile_id: Any) -> dict[str, Any]:
    row = await conn.fetchrow(
        'SELECT * FROM device_credential_profiles WHERE id=$1 AND device_target_id=$2',
        uuid.UUID(str(profile_id)), uuid.UUID(str(device_id)),
    )
    if not row:
        raise HTTPException(404, 'Credential profile is not available to this target')
    return dict(row)


async def require_profile_owner(conn: Any, device_id: Any, profile_id: Any):
    """A cross-asset use grant does not authorize editing its owner's secret."""
    profile = await STORE.get_profile(conn, profile_id=profile_id)
    same_asset = await conn.fetchval(
        'SELECT target_asset_access_owner($1)=target_asset_access_owner($2)',
        uuid.UUID(profile.target_id), uuid.UUID(str(device_id)),
    )
    if not same_asset:
        raise HTTPException(409, 'Manage this shared credential from its owning target or the credential library')
    return profile


async def create_device_profile(conn: Any, device_id: Any, request: Any) -> dict[str, Any]:
    kind = LEGACY_KIND[str(request.auth_kind)]
    if kind == 'ssh_private_key' and request.secondary_secret:
        kind = 'ssh_private_key_with_passphrase'
    material = build_credential_secret(
        kind, secret=request.secret, username=request.username,
        secondary_secret=request.secondary_secret, endpoint_url=request.login_path,
    )
    profile = await STORE.create_profile(
        conn, target_kind='device', target_id=device_id, name=request.name,
        auth_kind=kind, principal_slot='ssh' if kind in SSH_CREDENTIAL_KINDS else 'primary',
        principal_label=None, configuration=public_credential_configuration(json.loads(material)),
        encrypted_secret=encrypt_secret(material),
        encrypted_metadata=encrypt_secret(json.dumps({'source': 'device_compatibility_api'})),
        expires_at=request.expires_at,
        allowed_capabilities=['device.ssh.propose'] if kind in SSH_CREDENTIAL_KINDS else ['device.http.probe', 'request.replay'],
        created_by='device_credential_endpoint', now=datetime.now(timezone.utc),
    )
    await conn.execute('UPDATE credential_profiles SET service_port=$2 WHERE id=$1', uuid.UUID(profile.profile_id), request.port)
    return await device_profile_view(conn, device_id, profile.profile_id)


async def rotate_device_profile(conn: Any, device_id: Any, profile_id: Any, request: Any) -> dict[str, Any]:
    profile = await require_profile_owner(conn, device_id, profile_id)
    version = await conn.fetchrow(
        'SELECT encrypted_secret,encrypted_metadata FROM credential_profile_versions WHERE profile_id=$1 AND version=$2',
        uuid.UUID(profile.profile_id), profile.current_version,
    )
    material = parse_credential_secret(profile.auth_kind, decrypt_secret(version['encrypted_secret']))
    material['secret'] = request.secret
    material['secondary_secret'] = request.secondary_secret
    encoded = build_credential_secret(profile.auth_kind, **{
        key: material.get(key) for key in (
            'secret','username','secondary_secret','header_name','endpoint_url','client_id','scopes',
            'parameter_name','browser_storage_key','browser_login',
        )
    }, custom_headers=material.get('custom_headers') if profile.auth_kind == 'custom_headers' else None)
    await STORE.rotate_profile(
        conn, profile_id=profile.profile_id, target_kind=profile.target_kind, target_id=profile.target_id,
        expected_record_version=profile.record_version, encrypted_secret=encrypt_secret(encoded),
        encrypted_metadata=version['encrypted_metadata'], configuration=public_credential_configuration(json.loads(encoded)),
        expires_at=None if request.clear_expiry else request.expires_at or profile.expires_at,
        created_by='device_credential_endpoint', now=datetime.now(timezone.utc),
    )
    return await device_profile_view(conn, device_id, profile_id)


async def deactivate_device_profile(conn: Any, device_id: Any, profile_id: Any) -> dict[str, Any]:
    profile = await require_profile_owner(conn, device_id, profile_id)
    await STORE.deactivate_profile(conn, profile_id=profile.profile_id, target_kind=profile.target_kind,
                                   target_id=profile.target_id, now=datetime.now(timezone.utc))
    return await device_profile_view(conn, device_id, profile_id)


def device_execution_capability(role: str, allowed: Any) -> str:
    permitted = set(allowed or ())
    candidates = ('device.ssh.propose',) if role == 'ssh' else ('device.http.probe', 'http.request', 'request.replay')
    return next((capability for capability in candidates if capability in permitted), '')


def worker_material(kind: str, material: dict[str, Any]) -> dict[str, Any]:
    """Project a canonical secret into pinned protocol executors, in worker memory."""
    if kind in SSH_CREDENTIAL_KINDS:
        return {
            'auth_kind': 'ssh_password' if kind == 'ssh_password' else 'ssh_private_key',
            'username': material.get('username'), 'secret': material.get('secret'),
            'secondary_secret': material.get('secondary_secret'),
        }
    if kind in IMMEDIATE_HTTP_HEADER_KINDS:
        return {'auth_kind': 'web_headers', 'headers': immediate_http_headers({**material, "auth_kind": kind})}
    if kind == 'form_login':
        return {'auth_kind': 'web_form', 'username': material.get('username'),
                'secret': material.get('secret'), 'login_path': material.get('endpoint_url')}
    raise CredentialStoreError(f'{kind} requires the shared application authentication workflow; select the service web scan with this same profile')


async def resolve_device_credential(conn: Any, device_id: Any, ref: dict[str, Any]) -> dict[str, Any]:
    view = await device_profile_view(conn, device_id, ref['profile_id'])
    capabilities = view.get('allowed_capabilities') or []
    if isinstance(capabilities, str):
        capabilities = json.loads(capabilities)
    capability = str(ref.get('capability') or device_execution_capability(str(ref['role']), capabilities))
    if not capability or capability != device_execution_capability(str(ref['role']), [capability]):
        raise CredentialStoreError('Credential profile has no applicable device capability grant')
    resolved = await STORE.load_for_worker(conn, profile_id=ref['profile_id'], target_kind='device',
                                          target_id=device_id, capability=capability)
    for field in ('current_version', 'record_version'):
        if ref.get(field) is not None and int(ref[field]) != getattr(resolved.metadata, field):
            raise CredentialStoreError('Credential profile changed after this scan was queued; start a new scan')
    material = parse_credential_secret(resolved.metadata.auth_kind, decrypt_secret(resolved.encrypted_secret))
    if (ref['role'] == 'ssh') != (resolved.metadata.auth_kind in SSH_CREDENTIAL_KINDS):
        raise CredentialStoreError('Credential profile protocol does not match its selected role')
    return {'role': ref['role'], 'profile_id': str(ref['profile_id']),
            'port': resolved.metadata.service_port, **worker_material(resolved.metadata.auth_kind, material)}
