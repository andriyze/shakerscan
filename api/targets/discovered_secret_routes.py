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


@router.delete('/targets/{target_id}/discovered-secrets')
async def delete_discovered_secrets(target_id: str, request: Request):
    """Delete every discovered secret of the target (and its use records)."""
    _operator(request)
    async with pool().acquire() as conn:
        deleted = await secrets_store.purge_target(conn, target_id=_uuid(target_id, 'target'))
    return {'status': 'purged', 'deleted': deleted}
