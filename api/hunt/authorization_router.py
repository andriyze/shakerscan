"""Reference-only API for assisted GET authorization investigations."""
from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from .authorization_candidate import ensure_authorization_candidate
from .authorization_evidence import AuthorizationWorkflowError
from .authorization_service import AuthorizationInvestigationService


router = APIRouter(tags=["Hunt"])


class AuthorizationInvestigateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capture_id: UUID
    baseline_capture_id: UUID
    primary_session_ref: UUID
    secondary_session_ref: UUID
    baseline_kind: Literal["collection", "own_object"] = "collection"
    expected_access: Literal["unknown", "denied", "allowed"] = "unknown"


class AuthorizationApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    confirm: StrictBool
    attempt: int = Field(default=1, strict=True, ge=1, le=20)
    retry_settled: StrictBool = False

    @model_validator(mode="after")
    def require_confirmation(self):
        if self.confirm is not True:
            raise ValueError("Approve only after reviewing the exact proposal")
        return self


def authorization_service() -> AuthorizationInvestigationService:
    # Lazy imports avoid a second runtime, pool or configuration path and keep
    # router composition free of cycles. These are the existing live collaborators.
    from . import interaction_router
    try:
        from capabilities.authz import _public_proof_url
    except ModuleNotFoundError:
        from ..capabilities.authz import _public_proof_url

    async def execute(hunt_id, idempotency_key, inputs):
        return await interaction_router.execute_hunt_capability(
            hunt_id, "authz.verify", interaction_router.HuntCapabilityRequest(
                idempotency_key=idempotency_key, input=dict(inputs),
            ),
        )
    return AuthorizationInvestigationService(interaction_router._pool(), execute, _public_proof_url)


Service = Annotated[AuthorizationInvestigationService, Depends(authorization_service)]


async def _call(awaitable):
    try:
        return await awaitable
    except AuthorizationWorkflowError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post("/hunts/{hunt_id}/authorization-investigations")
async def investigate_authorization(hunt_id: UUID, request: AuthorizationInvestigateRequest, service: Service):
    """Propose a same-Hunt captured GET comparison without sending target traffic."""
    return await _call(service.propose(hunt_id, **request.model_dump()))


@router.get("/hunts/{hunt_id}/authorization-investigations/{proposal_id}")
async def read_authorization_investigation(hunt_id: UUID, proposal_id: UUID, service: Service):
    """Resume from PostgreSQL and explain the canonical action evidence; never execute."""
    return await _call(service.read(hunt_id, proposal_id))


@router.post("/hunts/{hunt_id}/authorization-investigations/{proposal_id}/approve")
async def approve_authorization_investigation(hunt_id: UUID, proposal_id: UUID, request: AuthorizationApproveRequest, service: Service):
    """Run the frozen proposal through canonical capability approval and budget gates."""
    state = await _call(service.approve(hunt_id, proposal_id, **request.model_dump()))
    # A stable own-object crossing with an operator-reviewed denied-access expectation is useful
    # even though it is not deterministic authorization proof. Put that lead in Hunt's canonical
    # candidate backlog, explicitly unverified, instead of losing it inside this workflow response.
    return await _call(ensure_authorization_candidate(service, hunt_id, state))


@router.post("/hunts/{hunt_id}/authorization-investigations/{proposal_id}/skip")
async def skip_authorization_investigation(hunt_id: UUID, proposal_id: UUID, service: Service):
    """Record a deferral, not an executed/refuted experiment. Reconsideration stays possible."""
    return await _call(service.skip(hunt_id, proposal_id))


@router.get("/hunts/{hunt_id}/authorization-investigations/{proposal_id}/reproduction")
async def authorization_reproduction(hunt_id: UUID, proposal_id: UUID, service: Service):
    """Return capture references and action provenance, not a new replay."""
    state = await _call(service.read(hunt_id, proposal_id))
    return {key: state[key] for key in ("hunt_id", "proposal_id", "reproduction", "reproduction_is_plan", "attempts", "limitations")}
