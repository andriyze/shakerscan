"""Public router for canonical Hunt admission, reads, and transitions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
import json
from typing import Any, Literal, Mapping

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .run_service import HuntRunService
from .skills import HuntSkillError, skill_library
from .start_contract import (
    HUNT_START_SCHEMA,
    MAX_CAPABILITIES,
    MAX_COLLECTIONS,
    MAX_CREDENTIAL_REFS,
    MAX_DIRECT_ORIGIN_ADDRESSES,
    MAX_GOAL_CHARS,
    MAX_HUNT_BODY_BYTES,
    MAX_SKILLS,
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
    allow_direct_origin: bool = False
    authorization_confirmed: bool = False
    approval_receipt_id: str | None = Field(default=None, max_length=256)
    scope_receipt_id: str | None = Field(default=None, max_length=256)


class HuntStartV2Request(BaseModel):
    """Typed public request for the one native Hunt start boundary."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["hunt-start/v2"] = HUNT_START_SCHEMA
    target_id: str = Field(min_length=1, max_length=256)
    target_kind: Literal["web", "api", "device", "network"]
    # Every bound below is the authority constant itself, never a copy of its value. A literal
    # here silently became the real limit: the request model rejected a fifth skill and a ninth
    # direct-origin address before the contract that owns those limits ever saw the request, so
    # raising them in one place changed nothing a caller could observe.
    goal: str | None = Field(default=None, max_length=MAX_GOAL_CHARS)
    objective: str | None = Field(default=None, max_length=MAX_GOAL_CHARS)
    budget_profile: Literal["fast", "balanced", "thorough"] | None = None
    policy_profile: Literal["fast", "balanced", "thorough"] | None = None
    budgets: dict[str, int] = Field(default_factory=dict, max_length=32)
    policy: HuntStartV2PolicyRequest
    credential_refs: dict[str, str] = Field(
        default_factory=dict, max_length=MAX_CREDENTIAL_REFS,
    )
    capabilities: list[str] = Field(default_factory=list, max_length=MAX_CAPABILITIES)
    request_collection_ids: list[str] = Field(
        default_factory=list, max_length=MAX_COLLECTIONS,
    )
    skill_ids: list[str] = Field(default_factory=list, max_length=MAX_SKILLS)
    direct_origin_addresses: list[str] = Field(
        default_factory=list, max_length=MAX_DIRECT_ORIGIN_ADDRESSES,
    )
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


class HuntSkillSuggestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signals: list[str] = Field(default_factory=list, max_length=20)


class HuntSkillBindRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="", max_length=500)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)


class HuntSkillUsageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: Literal["used", "completed", "deferred"]
    action_id: str | None = Field(default=None, max_length=256)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    reason: str = Field(default="", max_length=500)


router = APIRouter()
_service_provider: Callable[[], HuntRunService] | None = None
_start_handler: Callable[[HuntStartContract], Awaitable[dict[str, Any]]] | None = None
_metrics_provider: Callable[[], Mapping[str, Any]] | None = None
_standing_authorization_resolver: Callable[[str], Awaitable[Mapping[str, Any] | None]] | None = None

PRIVILEGED_POLICY_FLAGS = (
    "active_testing", "allow_state_changing_http", "network_discovery",
    "allow_oob_interactions", "allow_identity_headers", "allow_direct_origin",
)


def configure_hunt_run_router(
    service_provider: Callable[[], HuntRunService],
    *,
    start_handler: Callable[[HuntStartContract], Awaitable[dict[str, Any]]] | None = None,
    metrics_provider: Callable[[], Mapping[str, Any]] | None = None,
    standing_authorization_resolver: (
        Callable[[str], Awaitable[Mapping[str, Any] | None]] | None
    ) = None,
) -> None:
    global _metrics_provider, _service_provider, _start_handler, _standing_authorization_resolver
    _service_provider = service_provider
    _start_handler = start_handler
    _metrics_provider = metrics_provider
    _standing_authorization_resolver = standing_authorization_resolver


async def apply_standing_authorization(
    payload: dict[str, Any],
    resolver: Callable[[str], Awaitable[Mapping[str, Any] | None]] | None,
) -> dict[str, Any]:
    """Fill a privileged Hunt policy from the target's standing authorization.

    Authorize once per target: when the policy asks for active, network, mutation, OOB,
    identity-header or direct-origin authority without naming a receipt, the target's standing
    authorization (recorded through the target authorization endpoint) supplies the approval
    and scope receipt ids and stands as the confirmed authorization, including credentials
    explicitly selected for this target. A policy naming its own receipt is left untouched.
    """
    policy = payload.get("policy")
    if (resolver is None or not isinstance(policy, dict) or policy.get("approval_receipt_id")
            or payload.get("approval_receipt_id")):
        return payload
    if not payload.get("credential_refs") and not any(policy.get(flag) for flag in PRIVILEGED_POLICY_FLAGS):
        return payload
    target_id = str(payload.get("target_id") or "").strip()
    if not target_id:
        return payload
    standing = await resolver(target_id)
    if not standing or not standing.get("approval_receipt_id"):
        return payload
    policy = dict(policy)
    policy["approval_receipt_id"] = str(standing["approval_receipt_id"])
    if standing.get("scope_receipt_id"):
        policy["scope_receipt_id"] = str(standing["scope_receipt_id"])
    policy["authorization_confirmed"] = True
    return {**payload, "policy": policy}


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
        payload = await apply_standing_authorization(
            parsed.model_dump(mode="python", exclude_none=True),
            _standing_authorization_resolver,
        )
        contract = normalize_hunt_start_payload(payload)
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
    goal: str | None = Query(None, max_length=2000),
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
    result = {
        "skills": [spec.catalog_entry() for spec in specs],
        "count": len(specs),
        "bindable_count": sum(1 for spec in specs if spec.bindable),
        "catalog": library.health(),
    }
    if goal is not None:
        result["suggested"] = list(library.suggest(
            goal=goal, target_kind=target_kind or "web",
        ))
        result["suggestions_are_advisory"] = True
    return result


@router.get("/hunt/skills/{skill_id}", tags=["Hunt"])
async def get_hunt_skill(skill_id: str, include_methodology: bool = Query(True)):
    """Return one skill, with its methodology text unless the caller opts out."""
    try:
        spec = skill_library().require(skill_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"unknown skill {skill_id}") from exc
    try:
        return spec.public(include_body=include_methodology)
    except (OSError, UnicodeError, HuntSkillError) as exc:
        raise HTTPException(
            status_code=503, detail="skill methodology is unavailable"
        ) from exc


@router.get("/hunts/lifecycle-metrics", tags=["Hunt"])
async def get_hunt_lifecycle_metrics():
    if _metrics_provider is None:
        raise HTTPException(status_code=503, detail="Hunt lifecycle metrics are not ready")
    return dict(_metrics_provider())


@router.post("/hunts/{hunt_id}/skills/suggestions", tags=["Hunt"])
async def suggest_hunt_skills(
    hunt_id: str, request: HuntSkillSuggestionRequest,
):
    """Return a compact, evidence-aware shortlist without loading skill bodies."""
    return await _service().skill_suggestions(hunt_id, signals=request.signals)


@router.post("/hunts/{hunt_id}/skills/{skill_id}/read", tags=["Hunt"])
async def read_hunt_skill(hunt_id: str, skill_id: str):
    """Load exactly one methodology and record the explicit context spend."""
    return await _service().read_skill(hunt_id, skill_id)


@router.post("/hunts/{hunt_id}/skills/{skill_id}/bind", tags=["Hunt"])
async def bind_hunt_skill(
    hunt_id: str, skill_id: str, request: HuntSkillBindRequest,
):
    return await _service().bind_skill(
        hunt_id, skill_id, reason=request.reason,
        evidence_refs=request.evidence_refs,
    )


@router.delete("/hunts/{hunt_id}/skills/{skill_id}", tags=["Hunt"])
async def unbind_hunt_skill(
    hunt_id: str, skill_id: str,
    reason: str = Query("", max_length=500),
):
    return await _service().unbind_skill(hunt_id, skill_id, reason=reason)


@router.post("/hunts/{hunt_id}/skills/{skill_id}/usage", tags=["Hunt"])
async def record_hunt_skill_usage(
    hunt_id: str, skill_id: str, request: HuntSkillUsageRequest,
):
    return await _service().record_skill_usage(
        hunt_id, skill_id, state=request.state, action_id=request.action_id,
        evidence_refs=request.evidence_refs, reason=request.reason,
    )


@router.get("/hunts/{hunt_id}")
async def get_hunt(hunt_id: str):
    return await _service().get(hunt_id)


@router.get("/hunts/{hunt_id}/record", tags=["Hunt"])
async def export_hunt_record(hunt_id: str):
    """Download the redacted explicit decision trace plus archived HTTP calls."""
    document = await _service().export_record(hunt_id)
    return JSONResponse(
        document,
        headers={
            "content-disposition": f'attachment; filename="shakerscan-hunt-{hunt_id}.json"',
            "x-shakerscan-trace-kind": "explicit_decision_trace",
        },
    )


@router.get("/hunts")
async def list_hunts(
    target_id: str | None = Query(None),
    status: str | None = Query(None),
    target_kind: str | None = Query(None),
    budget_profile: str | None = Query(None),
    root_domain: str | None = Query(None),
    search: str | None = Query(None, max_length=200),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List hunts across every target, filtered, sorted and paged."""
    return await _service().list(
        target_id=target_id, status=status, target_kind=target_kind,
        budget_profile=budget_profile, root_domain=root_domain, search=search,
        sort_by=sort_by, sort_order=sort_order, limit=limit, offset=offset,
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
    "HuntSkillBindRequest",
    "HuntSkillSuggestionRequest",
    "HuntSkillUsageRequest",
    "bind_hunt_skill",
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
    "read_hunt_skill",
    "record_hunt_skill_usage",
    "router",
    "start_hunt",
    "suggest_hunt_skills",
    "unbind_hunt_skill",
]


from .authorization_router import router as _authorization_router

router.include_router(_authorization_router)
