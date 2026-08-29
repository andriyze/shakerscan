"""Public router for canonical Hunt admission, reads, and transitions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
import json
from typing import Any, Literal, Mapping

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .run_service import HuntRunService
from .skills import HuntSkillError, skill_library
from .start_contract import (
    HUNT_START_SCHEMA,
    MAX_HUNT_BODY_BYTES,
    HuntStartContract,
    HuntStartContractError,
    hunt_start_public_contract,
    normalize_hunt_start_payload,
)


class HuntStartV2PolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active_testing: bool = False
    allow_state_changing_http: bool = False
    network_discovery: bool = False
    allow_oob_interactions: bool = False
    allow_identity_headers: bool = False
    authorization_confirmed: bool = False
    approval_receipt_id: str | None = Field(default=None, max_length=256)
    scope_receipt_id: str | None = Field(default=None, max_length=256)


class HuntStartV2Request(BaseModel):
    """Typed public request for the one native Hunt start boundary."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["hunt-start/v2"] = HUNT_START_SCHEMA
    target_id: str = Field(min_length=1, max_length=256)
    target_kind: Literal["web", "api", "device", "network"]
    goal: str | None = Field(default=None, max_length=20_000)
    objective: str | None = Field(default=None, max_length=20_000)
    budget_profile: Literal["fast", "balanced", "thorough"] | None = None
    policy_profile: Literal["fast", "balanced", "thorough"] | None = None
    budgets: dict[str, int] = Field(default_factory=dict, max_length=32)
    policy: HuntStartV2PolicyRequest
    credential_refs: dict[str, str] = Field(default_factory=dict, max_length=16)
    capabilities: list[str] = Field(default_factory=list, max_length=128)
    request_collection_ids: list[str] = Field(default_factory=list, max_length=32)
    skill_ids: list[str] = Field(default_factory=list, max_length=4)
    approval_receipt_id: str | None = Field(default=None, max_length=256)
    scope_receipt_id: str | None = Field(default=None, max_length=256)


class HuntStartV2Response(BaseModel):
    """Stable Hunt-start response with room for additive public metadata."""

    model_config = ConfigDict(extra="allow")
    hunt_id: str | None = None
    target_kind: str | None = None
    target_id: str | None = None
    objective: str | None = None
    status: str | None = None
    budget_profile: str | None = None
    policy: dict[str, Any] = Field(default_factory=dict)
    budget: dict[str, Any] = Field(default_factory=dict)
    budget_used: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[dict[str, Any]] = Field(default_factory=list)
    skills: list[dict[str, Any]] = Field(default_factory=list)
    context_pack: dict[str, Any] = Field(default_factory=dict)


class HuntFinishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=20_000)
    next_actions: list[str] = Field(default_factory=list, max_length=100)


router = APIRouter()
_service_provider: Callable[[], HuntRunService] | None = None
_start_handler: Callable[[HuntStartContract], Awaitable[dict[str, Any]]] | None = None
_metrics_provider: Callable[[], Mapping[str, Any]] | None = None


def configure_hunt_run_router(
    service_provider: Callable[[], HuntRunService],
    *,
    start_handler: Callable[[HuntStartContract], Awaitable[dict[str, Any]]] | None = None,
    metrics_provider: Callable[[], Mapping[str, Any]] | None = None,
) -> None:
    global _metrics_provider, _service_provider, _start_handler
    _service_provider = service_provider
    _start_handler = start_handler
    _metrics_provider = metrics_provider


def _service() -> HuntRunService:
    service = _service_provider() if _service_provider is not None else None
    if service is None:
        raise HTTPException(status_code=503, detail="Hunt service is not ready")
    return service


async def parse_hunt_start_body(request: Request) -> HuntStartV2Request:
    raw_body = await request.body()
    if len(raw_body) > MAX_HUNT_BODY_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "error": "request_body_too_large",
                "message": "Hunt request body exceeds the public API limit.",
                "max_bytes": MAX_HUNT_BODY_BYTES,
            },
        )
    try:
        decoded = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_json",
                "message": "Hunt request body must be valid JSON.",
            },
        ) from exc
    if not isinstance(decoded, Mapping):
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_request_shape",
                "message": "Hunt request body must be an object.",
            },
        )
    if "policy" not in decoded:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "explicit_v2_policy_required",
                "message": "Hunt starts must include the hunt-start/v2 policy object",
                "schema_version": HUNT_START_SCHEMA,
            },
        )
    try:
        return HuntStartV2Request.model_validate(decoded)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


@router.post(
    "/hunts",
    response_model=HuntStartV2Response,
    tags=["Hunt"],
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": HuntStartV2Request.model_json_schema(),
                },
            },
        },
    },
)
async def start_hunt(request: Request, response: Response):
    """Create one target-kind-aware Hunt through the native V2 authority boundary."""
    if _start_handler is None:
        raise HTTPException(status_code=503, detail="Hunt start service is not ready")
    parsed = await parse_hunt_start_body(request)
    try:
        contract = normalize_hunt_start_payload(
            parsed.model_dump(mode="python", exclude_none=True)
        )
        result = await _start_handler(contract)
    except HuntStartContractError as exc:
        raise HTTPException(
            status_code=422,
            detail={"message": str(exc), "schema_version": HUNT_START_SCHEMA},
        ) from exc
    response.headers["x-shakerscan-hunt-contract"] = "v2"
    return result


@router.get("/hunts/contract", tags=["Hunt"])
async def get_hunt_contract():
    return hunt_start_public_contract()


@router.get("/hunt/skills", tags=["Hunt"])
async def list_hunt_skills(
    target_kind: str | None = Query(None),
    support: str | None = Query(None),
):
    """List the testing methodology a hunt can bind, with an honest support level.

    Unbindable skills are listed too. ShakerScan has no capability for several adapters the
    methodology assumes, and naming that gap here is what stops a planner committing to a
    procedure it cannot execute.
    """
    library = skill_library()
    try:
        specs = library.list(target_kind=target_kind, support=support)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "skills": [spec.public() for spec in specs],
        "count": len(specs),
        "bindable_count": sum(1 for spec in specs if spec.bindable),
    }


@router.get("/hunt/skills/{skill_id}", tags=["Hunt"])
async def get_hunt_skill(skill_id: str, include_methodology: bool = Query(True)):
    """Return one skill, with its methodology text unless the caller opts out."""
    try:
        spec = skill_library().require(skill_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"unknown skill {skill_id}") from exc
    try:
        return spec.public(include_body=include_methodology)
    except (OSError, HuntSkillError) as exc:
        raise HTTPException(
            status_code=503, detail="skill methodology is unavailable"
        ) from exc


@router.get("/hunts/lifecycle-metrics", tags=["Hunt"])
async def get_hunt_lifecycle_metrics():
    if _metrics_provider is None:
        raise HTTPException(status_code=503, detail="Hunt lifecycle metrics are not ready")
    return dict(_metrics_provider())


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
    "HuntStartV2PolicyRequest",
    "HuntStartV2Request",
    "HuntStartV2Response",
    "cancel_hunt",
    "configure_hunt_run_router",
    "finish_hunt",
    "get_hunt",
    "get_hunt_contract",
    "get_hunt_lifecycle_metrics",
    "get_hunt_skill",
    "list_hunt_skills",
    "list_hunts",
    "parse_hunt_start_body",
    "resume_hunt",
    "router",
    "start_hunt",
]
