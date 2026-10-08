"""Read, decide and revoke Hunt permission requests.

There is no create route: requests come only from server refusals. The planner ingress
(``hunt/planner_gateway.py``) delegates the reads only, and no MCP tool decides. On OSS the
decision and revoke routes are protected by the engine's existing API authentication alone: the
trust boundary is the host, so any local process that can reach the API could decide. In
Enterprise the gateway is the only caller of the decision route and sets ``decided_by`` to the
person who passed step-up (PR G1).
"""
from __future__ import annotations

import asyncio
from typing import Any, Literal
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from .permission_grants import decide, revoke_grant
from .permission_store import (
    REQUEST_STATUSES,
    expire_due,
    list_events,
    list_grants,
    list_requests,
    load_request,
    public_preauthorization,
    public_request,
)

router = APIRouter()
MAX_WAIT_SECONDS = 25
_POLL_SECONDS = 0.5


class PermissionDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["allow", "deny"]
    scope: Literal["hunt", "target"] = "hunt"
    subject_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    choice: dict[str, int] = Field(default_factory=dict, max_length=4)
    idempotency_key: str = Field(min_length=8, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    # Set by the Enterprise gateway to the person who passed step-up; on OSS, who confirmed.
    decided_by: str = Field(default="local-operator", min_length=1, max_length=200)
    decision_via: Literal["terminal_stepup", "approver_session", "ui_session", "local_confirm"] = "local_confirm"


class PermissionRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revoked_by: str = Field(default="local-operator", min_length=1, max_length=200)


_pool_provider: Any = None


def configure_permission_router(pool_provider: Any) -> None:
    global _pool_provider
    _pool_provider = pool_provider


def _pool() -> Any:
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool


def _uuid(value: str, label: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid {label}") from exc


async def _hunt_exists(conn: Any, hunt_id: uuid.UUID) -> None:
    if await conn.fetchval("SELECT 1 FROM hunt_runs WHERE id=$1", hunt_id) is None:
        raise HTTPException(status_code=404, detail="Hunt not found")


@router.get("/hunts/{hunt_id}/permission-requests", tags=["Hunt"])
async def list_hunt_permission_requests(hunt_id: str, status: str | None = Query(None)):
    """Every permission request of this Hunt, with server-rendered title, effect and choices."""
    hunt_uuid = _uuid(hunt_id, "hunt id")
    if status is not None and status not in REQUEST_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {', '.join(REQUEST_STATUSES)}")
    async with _pool().acquire() as conn:
        await _hunt_exists(conn, hunt_uuid)
        async with conn.transaction():
            await expire_due(conn, hunt_uuid)
        return {"hunt_id": str(hunt_uuid), "requests": await list_requests(conn, hunt_uuid, status=status)}


@router.get("/hunts/{hunt_id}/permission-requests/{request_id}", tags=["Hunt"])
async def get_hunt_permission_request(
    hunt_id: str, request_id: str,
    wait_seconds: int = Query(0, ge=0, le=MAX_WAIT_SECONDS),
):
    """One request; with ``wait_seconds`` it returns as soon as a pending request changes."""
    hunt_uuid, request_uuid = _uuid(hunt_id, "hunt id"), _uuid(request_id, "request id")
    deadline = asyncio.get_running_loop().time() + wait_seconds
    while True:
        async with _pool().acquire() as conn:
            async with conn.transaction():
                await expire_due(conn, hunt_uuid)
            row = await load_request(conn, hunt_uuid, request_uuid)
        if row is None:
            raise HTTPException(status_code=404, detail="Permission request not found in this Hunt")
        if row["status"] != "pending" or asyncio.get_running_loop().time() >= deadline:
            return {**public_request(row), "waited": wait_seconds > 0}
        await asyncio.sleep(_POLL_SECONDS)


@router.post("/hunts/{hunt_id}/permission-requests/{request_id}/decision", tags=["Hunt"])
async def decide_hunt_permission_request(hunt_id: str, request_id: str, body: PermissionDecisionRequest):
    """A person's allow or deny. Not delegated to the planner; no MCP tool calls it."""
    hunt_uuid, request_uuid = _uuid(hunt_id, "hunt id"), _uuid(request_id, "request id")
    async with _pool().acquire() as conn:
        async with conn.transaction():
            return await decide(conn, hunt_uuid, request_uuid, body.model_dump())


@router.get("/hunts/{hunt_id}/permission-grants", tags=["Hunt"])
async def list_hunt_permission_grants(hunt_id: str):
    hunt_uuid = _uuid(hunt_id, "hunt id")
    async with _pool().acquire() as conn:
        await _hunt_exists(conn, hunt_uuid)
        return {"hunt_id": str(hunt_uuid), "grants": await list_grants(conn, hunt_uuid)}


@router.post("/hunts/{hunt_id}/permission-grants/{grant_id}/revoke", tags=["Hunt"])
async def revoke_hunt_permission_grant(hunt_id: str, grant_id: str, body: PermissionRevokeRequest):
    hunt_uuid, grant_uuid = _uuid(hunt_id, "hunt id"), _uuid(grant_id, "grant id")
    async with _pool().acquire() as conn:
        async with conn.transaction():
            return await revoke_grant(conn, hunt_uuid, grant_uuid, revoked_by=body.revoked_by)


@router.get("/hunts/{hunt_id}/preauthorization", tags=["Hunt"])
async def get_hunt_preauthorization(hunt_id: str):
    hunt_uuid = _uuid(hunt_id, "hunt id")
    async with _pool().acquire() as conn:
        await _hunt_exists(conn, hunt_uuid)
        rows = await conn.fetch(
            "SELECT * FROM hunt_preauthorizations WHERE hunt_run_id=$1 ORDER BY created_at, id", hunt_uuid,
        )
        return {"hunt_id": str(hunt_uuid), "preauthorizations": [public_preauthorization(row) for row in rows]}


@router.get("/hunts/{hunt_id}/permission-events", tags=["Hunt"])
async def list_hunt_permission_events(hunt_id: str, limit: int = Query(500, ge=1, le=2000)):
    """The append-only audit: every request, decision, grant, use, expiry and revocation."""
    hunt_uuid = _uuid(hunt_id, "hunt id")
    async with _pool().acquire() as conn:
        await _hunt_exists(conn, hunt_uuid)
        return {"hunt_id": str(hunt_uuid), "events": await list_events(conn, hunt_uuid, limit=limit)}


__all__ = [
    "PermissionDecisionRequest", "PermissionRevokeRequest", "configure_permission_router", "router",
]
