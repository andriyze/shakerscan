"""Canonical target inventory routes. Connected Devices is a projection of these IDs."""
from __future__ import annotations

import json
from typing import Any, Literal
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .asset_migration import host_url
from .asset_store import asset_detail, asset_history, list_assets, resolve_asset_id

router = APIRouter(tags=['targets'])
_pool_provider: Any = None


def configure_asset_router(pool_provider: Any) -> None:
    global _pool_provider
    _pool_provider = pool_provider


def pool():
    value = _pool_provider() if callable(_pool_provider) else None
    if value is None:
        raise HTTPException(503, 'Database not ready')
    return value


class HostTargetCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    locator: str = Field(min_length=1, max_length=253)
    name: str | None = Field(default=None, max_length=255)
    environment: Literal['production', 'staging', 'development', 'lab'] = 'production'
    approved_by: str | None = Field(default=None, min_length=1, max_length=120)
    port_hints: list[int] = Field(default_factory=list,max_length=128)

    @field_validator('port_hints', mode='before')
    @classmethod
    def ports(cls, values):
        if not isinstance(values,list) or any(type(port) is not int or not 1 <= port <= 65535 for port in values):
            raise ValueError('Port hints must be integers between 1 and 65535')
        return list(dict.fromkeys(values))


class DeviceProfileCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    device_class: Literal['generic','media','camera','printer','router','nas','conference','building','industrial'] = 'generic'
    manufacturer: str | None = Field(default=None, max_length=255)
    model: str | None = Field(default=None, max_length=255)
    firmware_version: str | None = Field(default=None, max_length=255)


@router.get('/targets/inventory')
async def target_inventory(search: str = Query('', max_length=500), connected_only: bool = False,
                           include_inactive: bool = False, include_services: bool = False,
                           limit: int = Query(100, ge=1, le=500),
                           offset: int = Query(0, ge=0)):
    async with pool().acquire() as conn:
        return await list_assets(conn, search=search, connected_only=connected_only,
                                 include_inactive=include_inactive, include_services=include_services,
                                 limit=limit, offset=offset)


@router.post('/targets/hosts')
async def create_host_target(request: HostTargetCreate):
    try:
        from scanner_tools.device_posture import normalize_device_locator
    except ModuleNotFoundError:
        from scanner.scanner_tools.device_posture import normalize_device_locator
    try:
        locator = normalize_device_locator(request.locator)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    async with pool().acquire() as conn, conn.transaction():
        row = await conn.fetchrow("""INSERT INTO targets(url,name,discovery_source,metadata_json)
            VALUES($1,$2,'host',$3) ON CONFLICT(canonical_key) DO UPDATE SET
                metadata_json=CASE WHEN $4::boolean THEN targets.metadata_json || jsonb_build_object('port_hints',$3::jsonb->'port_hints') ELSE targets.metadata_json END
            RETURNING id,url,name,(xmax=0) AS created""",host_url(locator),request.name or locator,
            json.dumps({'environment':request.environment,'cohort':request.environment,
                        'port_hints':request.port_hints}),bool(request.port_hints))
        result = {'id':str(row['id']), 'asset_id':str(row['id']), 'url':row['url'],
                  'status':'created' if row['created'] else 'already_exists'}
        if request.approved_by:
            try:
                import target_authorization
            except ModuleNotFoundError:
                from .. import target_authorization
            try:
                result['authorization'] = await target_authorization.authorize_target(
                    conn,row['id'],approved_by=request.approved_by,
                )
            except target_authorization.TargetAuthorizationError as exc:
                raise HTTPException(400,str(exc)) from exc
        return result


@router.get('/targets/{target_id}/asset')
async def get_target_asset(target_id: str):
    async with pool().acquire() as conn:
        return await asset_detail(conn, target_id)


@router.get('/targets/{target_id}/history')
async def get_asset_history(target_id: str, kind: Literal['scans','findings','hunts'] = 'scans',
                            limit: int = Query(50,ge=1,le=500), offset: int = Query(0,ge=0)):
    async with pool().acquire() as conn:
        return await asset_history(conn,target_id,kind=kind,limit=limit,offset=offset)


async def ensure_device_profile(conn: Any, target_id: Any, request: DeviceProfileCreate) -> uuid.UUID:
    owner = await resolve_asset_id(conn,target_id)
    target = await conn.fetchrow('SELECT id,is_active,metadata_json FROM targets WHERE id=$1 FOR UPDATE',owner)
    if not target['is_active']:
        raise HTTPException(409,'Reactivate this target before enabling network scans')
    metadata = target['metadata_json'] or {}
    if isinstance(metadata,str):
        metadata = json.loads(metadata)
    await conn.execute("""INSERT INTO target_device_profiles(target_id,device_class,manufacturer,model,firmware_version,environment)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(target_id) DO NOTHING""",owner,request.device_class,
        request.manufacturer,request.model,request.firmware_version,
        str(metadata.get('environment') or metadata.get('cohort') or 'production'))
    return owner


@router.post('/targets/{target_id}/device-profile')
async def enable_device_profile(target_id: str, request: DeviceProfileCreate):
    async with pool().acquire() as conn, conn.transaction():
        owner = await ensure_device_profile(conn,target_id,request)
    return {'asset_id':str(owner),'device_id':str(owner),'view':f'/devices/{owner}'}


try:
    from devices.router import DeviceScanRequest
except ModuleNotFoundError:
    from ..devices.router import DeviceScanRequest


@router.post('/targets/{target_id}/network-scans')
async def start_target_network_scan(target_id: str, request: DeviceScanRequest):
    """Canonical entry point; same executor, queue, and ledger as the device view."""
    try:
        from devices.router import scan_device
    except ModuleNotFoundError:
        from ..devices.router import scan_device
    async with pool().acquire() as conn, conn.transaction():
        owner = await ensure_device_profile(conn,target_id,DeviceProfileCreate())
        metadata = await conn.fetchval('SELECT metadata_json FROM targets WHERE id=$1',owner)
        if isinstance(metadata,str):
            metadata = json.loads(metadata)
        if not request.port_hints and (metadata or {}).get('port_hints'):
            request = request.model_copy(update={'port_hints':HostTargetCreate.ports(metadata['port_hints'])})
    return await scan_device(str(owner),request)
