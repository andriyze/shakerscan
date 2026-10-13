"""Operator routes for a target's discovered secrets: list (metadata only), revoke, reactivate,
change expiry, purge.

No route returns a value: a Hunt sends one by reference and the worker resolves it. Each route
refuses a request that arrived through the planner ingress (operator_identity).
"""
from __future__ import annotations

from typing import Literal
import uuid

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

try:
    from hunt import discovered_secrets as secrets_store
except ModuleNotFoundError:  # package import
    from ..hunt import discovered_secrets as secrets_store
from .operator_identity import operator_identity as _operator

router = APIRouter(tags=['targets'])


class SecretState(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['active', 'revoked_by_operator']


class SecretGrant(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_id: str = Field(min_length=36, max_length=36)


class SecretPromotion(BaseModel):
    """The credential profile the value moves into; the value itself comes from the store."""
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=120)
    auth_kind: str = Field(min_length=1, max_length=40)
    target_kind: Literal['web', 'api'] = 'web'
    principal_slot: Literal['primary', 'secondary', 'service'] = 'primary'
    principal_label: str | None = Field(default=None, max_length=120)
    username: str | None = Field(default=None, max_length=1_000)
    header_name: str | None = Field(default=None, max_length=200)
    parameter_name: str | None = Field(default=None, max_length=200)
    allowed_capabilities: list[str] = Field(default_factory=list, max_length=128)


class SecretExpiry(BaseModel):
    model_config = ConfigDict(extra='forbid')
    days: int = Field(ge=1, le=secrets_store.MAX_TTL_DAYS)


def pool():
    from .asset_router import pool as configured_pool
    return configured_pool()


def _uuid(value: str, name: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise HTTPException(404, f'{name} not found') from None


@router.get('/targets/{target_id}/discovered-secrets')
async def get_discovered_secrets(target_id: str, request: Request, usable_only: bool = False):
    _operator(request)
    target = _uuid(target_id, 'target')
    async with pool().acquire() as conn:
        if not await conn.fetchval('SELECT 1 FROM targets WHERE id=$1', target):
            raise HTTPException(404, 'target not found')
        secrets = await secrets_store.list_for_target(conn, target, usable_only=usable_only)
    return {'target_id': str(target), 'secrets': secrets, 'count': len(secrets), 'values_visible': False}


@router.post('/targets/{target_id}/discovered-secrets/{secret_id}/state')
async def post_discovered_secret_state(target_id: str, secret_id: str, body: SecretState, request: Request):
    actor = _operator(request)
    async with pool().acquire() as conn:
        changed = await secrets_store.set_state(
            conn, target_id=_uuid(target_id, 'target'), secret_id=_uuid(secret_id, 'secret'),
            state=body.state, actor=actor)
    if not changed:
        raise HTTPException(404, 'secret not found on this target')
    return {'status': body.state}


@router.post('/targets/{target_id}/discovered-secrets/{secret_id}/expiry')
async def post_discovered_secret_expiry(target_id: str, secret_id: str, body: SecretExpiry, request: Request):
    actor = _operator(request)
    async with pool().acquire() as conn:
        changed = await secrets_store.set_expiry(
            conn, target_id=_uuid(target_id, 'target'), secret_id=_uuid(secret_id, 'secret'),
            days=body.days, actor=actor)
    if not changed:
        raise HTTPException(404, 'secret not found on this target')
    return {'status': 'expiry_changed', 'days': body.days}


@router.post('/targets/{target_id}/discovered-secrets/{secret_id}/grants', status_code=201)
async def post_discovered_secret_grant(target_id: str, secret_id: str, body: SecretGrant, request: Request):
    """Let Hunts of another target use this secret by reference. It never widens a Hunt's scope."""
    actor = _operator(request)
    async with pool().acquire() as conn:
        try:
            async with conn.transaction():  # the secret's row stays locked while it is counted
                granted = await secrets_store.grant(
                    conn, target_id=_uuid(target_id, 'target'), secret_id=_uuid(secret_id, 'secret'),
                    to_target_id=_uuid(body.target_id, 'target'), actor=actor)
        except LookupError:
            raise HTTPException(404, 'target not found') from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
    if not granted:
        raise HTTPException(404, 'secret not found on this target')
    return {'status': 'granted', 'target_id': body.target_id}


@router.delete('/targets/{target_id}/discovered-secrets/{secret_id}/grants/{grant_target_id}')
async def delete_discovered_secret_grant(target_id: str, secret_id: str, grant_target_id: str,
                                         request: Request):
    _operator(request)
    async with pool().acquire() as conn:
        revoked = await secrets_store.revoke_grant(
            conn, target_id=_uuid(target_id, 'target'), secret_id=_uuid(secret_id, 'secret'),
            to_target_id=_uuid(grant_target_id, 'target'))
    if not revoked:
        raise HTTPException(404, 'grant not found')
    return {'status': 'revoked'}


@router.post('/targets/{target_id}/discovered-secrets/{secret_id}/promote', status_code=201)
async def post_discovered_secret_promote(target_id: str, secret_id: str, body: SecretPromotion,
                                         request: Request):
    """Move the value into a new credential profile of this target (checked like any typed
    profile); the discovered secret becomes ``superseded`` and points at the profile."""
    actor = _operator(request)
    try:
        from credential_api import CredentialProfileCreate, create_profile_in_transaction
        from runtime.credential_store import CredentialStoreError
    except ModuleNotFoundError:
        from ..credential_api import CredentialProfileCreate, create_profile_in_transaction
        from ..runtime.credential_store import CredentialStoreError
    from pydantic import SecretStr, ValidationError
    target, secret = _uuid(target_id, 'target'), _uuid(secret_id, 'secret')
    async with pool().acquire() as conn:
        async with conn.transaction():
            refusal = await secrets_store.promotable(conn, target_id=target, secret_id=secret)
            if refusal == 'absent':
                raise HTTPException(404, 'secret not found on this target')
            if refusal:
                raise HTTPException(409, refusal)
            value = await secrets_store.value_for_operator(
                conn, target_id=target, secret_id=secret, actor=actor, purpose='promote')
            if value is None:
                raise HTTPException(404, 'secret not found on this target')
            try:
                payload = CredentialProfileCreate(
                    target_kind=body.target_kind, target_id=target, name=body.name,
                    auth_kind=body.auth_kind, principal_slot=body.principal_slot,
                    principal_label=body.principal_label, secret=SecretStr(value),
                    username=SecretStr(body.username) if body.username else None,
                    header_name=body.header_name, parameter_name=body.parameter_name,
                    allowed_capabilities=body.allowed_capabilities, created_by=actor[:120])
                profile = await create_profile_in_transaction(conn, payload)
            except ValidationError as exc:
                raise HTTPException(422, [{'loc': e['loc'], 'msg': e['msg']} for e in exc.errors()]) from None
            except CredentialStoreError as exc:
                raise HTTPException(400, str(exc)) from None
            finally:
                value = ''
            await secrets_store.mark_promoted(conn, target_id=target, secret_id=secret,
                                              profile_id=profile['id'], actor=actor)
    return {'status': 'promoted', 'profile': profile}


@router.post('/targets/{target_id}/discovered-secrets/{secret_id}/reveal')
async def post_discovered_secret_reveal(target_id: str, secret_id: str, request: Request):
    """The value, to a person. Recorded with who revealed it. Never a planner (refused by
    operator_identity); through the Enterprise gateway it needs a per-decision step-up."""
    actor = _operator(request)
    async with pool().acquire() as conn:
        value = await secrets_store.value_for_operator(
            conn, target_id=_uuid(target_id, 'target'), secret_id=_uuid(secret_id, 'secret'),
            actor=actor, purpose='reveal')
    if value is None:
        raise HTTPException(404, 'secret not found on this target')
    from fastapi.responses import JSONResponse
    return JSONResponse({'value': value}, headers={'cache-control': 'no-store'})


@router.delete('/targets/{target_id}/discovered-secrets')
async def delete_discovered_secrets(target_id: str, request: Request):
    """Delete every discovered secret of the target (and its use records)."""
    _operator(request)
    async with pool().acquire() as conn:
        deleted = await secrets_store.purge_target(conn, target_id=_uuid(target_id, 'target'))
    return {'status': 'purged', 'deleted': deleted}
