"""Public router for durable Hunt run reads and terminal transitions."""

from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from .run_service import HuntRunService


class HuntFinishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=20_000)
    next_actions: list[str] = Field(default_factory=list, max_length=100)


router = APIRouter()
_service_provider: Callable[[], HuntRunService] | None = None


def configure_hunt_run_router(
    service_provider: Callable[[], HuntRunService],
) -> None:
    global _service_provider
    _service_provider = service_provider


def _service() -> HuntRunService:
    service = _service_provider() if _service_provider is not None else None
    if service is None:
        raise HTTPException(status_code=503, detail="Hunt service is not ready")
    return service


@router.get("/hunts/{hunt_id}")
async def get_hunt(hunt_id: str):
    return await _service().get(hunt_id)


@router.get("/hunts")
async def list_hunts(
    target_id: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    return await _service().list(
        target_id=target_id, status=status, limit=limit
    )


@router.post("/hunts/{hunt_id}/finish")
async def finish_hunt(hunt_id: str, request: HuntFinishRequest):
    return await _service().finish(
        hunt_id, summary=request.summary, next_actions=request.next_actions
    )


@router.post("/hunts/{hunt_id}/cancel")
async def cancel_hunt(hunt_id: str):
    return await _service().cancel(hunt_id)


@router.post("/hunts/{hunt_id}/resume")
async def resume_hunt(hunt_id: str):
    return await _service().resume(hunt_id)


__all__ = [
    "HuntFinishRequest",
    "cancel_hunt",
    "configure_hunt_run_router",
    "finish_hunt",
    "get_hunt",
    "list_hunts",
    "resume_hunt",
    "router",
]
