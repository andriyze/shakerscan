"""Policy profile CRUD routes.

Extracted verbatim from the api.py monolith. Policy profiles are the deployment
gate shared by AI Gate, Model Intake, and DAST decisions. Mutations require a
server-derived Model Intake operator identity, validate that any required trust
anchors are active, and fail active Model Intake admissions closed when the
profile they were admitted under changes.

The database pool is supplied by the composition root through
``configure_policy_profile_router`` rather than imported from ``api.api``, so
this module depends only on shared helpers and the domain services it uses.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional
import uuid

import asyncpg
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

try:
    from model_intake_authority import _invalidate_model_intake_authority_change
    from operator_auth import _model_intake_authenticated_subject
    from serialization import _str_list, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..model_intake_authority import _invalidate_model_intake_authority_change
    from ..operator_auth import _model_intake_authenticated_subject
    from ..serialization import _str_list, row_to_dict


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None


def configure_policy_profile_router(pool_provider: Callable[[], Any]) -> None:
    """Bind the application database pool without importing the app module."""
    global _pool_provider
    _pool_provider = pool_provider


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool


class PolicyProfileRequest(BaseModel):
    name: str
    product_area: str = "ai_gate"
    environment: str = "production"
    minimum_block_severity: str = "high"
    expires_days: int = 30
    strict_model_intake: bool = False
    allow_active_exceptions: bool = True
    required_trust_anchor_ids: list[str] = Field(default_factory=list)
    owner: Optional[str] = None
    version: Optional[str] = None
    is_active: bool = True


POLICY_PRODUCT_AREAS = {"ai_gate", "model_intake", "dast"}
POLICY_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _validate_policy_profile_request(req: PolicyProfileRequest) -> None:
    if not req.name.strip():
        raise HTTPException(status_code=422, detail="name is required")
    if req.product_area not in POLICY_PRODUCT_AREAS:
        raise HTTPException(status_code=422, detail="product_area must be ai_gate, model_intake, or dast")
    if req.minimum_block_severity not in POLICY_SEVERITIES:
        raise HTTPException(status_code=422, detail="minimum_block_severity is invalid")
    if not req.environment.strip():
        raise HTTPException(status_code=422, detail="environment is required")
    if req.expires_days < 1 or req.expires_days > 3650:
        raise HTTPException(status_code=422, detail="expires_days must be between 1 and 3650")
    if req.strict_model_intake and req.product_area != "model_intake":
        raise HTTPException(
            status_code=422,
            detail="strict_model_intake is only valid for model_intake policy profiles",
        )
    if req.required_trust_anchor_ids and not (
        req.product_area == "model_intake" and req.strict_model_intake
    ):
        raise HTTPException(
            status_code=422,
            detail="required_trust_anchor_ids require a strict model_intake policy profile",
        )


async def _validate_policy_profile_required_anchor_ids(conn, req: PolicyProfileRequest) -> list[str]:
    try:
        required_anchor_ids = [str(uuid.UUID(item)) for item in _str_list(req.required_trust_anchor_ids)]
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="required_trust_anchor_ids must contain valid UUIDs")
    required_anchor_ids = list(dict.fromkeys(required_anchor_ids))
    if not required_anchor_ids:
        return []
    if req.product_area != "model_intake" or not req.strict_model_intake:
        return []
    rows = await conn.fetch(
        """
        SELECT id FROM model_intake_trust_anchors
        WHERE id = ANY($1::uuid[]) AND is_active = true
        """,
        [uuid.UUID(item) for item in required_anchor_ids],
    )
    found = {str(row["id"]) for row in rows}
    if found != set(required_anchor_ids):
        raise HTTPException(status_code=422, detail="required_trust_anchor_ids must reference active Model Intake trust anchors")
    return required_anchor_ids


@router.get("/policy-profiles")
async def list_policy_profiles():
    async with _pool().acquire() as conn:
        rows = await conn.fetch("SELECT * FROM policy_profiles ORDER BY created_at DESC")
    return {"policy_profiles": [row_to_dict(r) for r in rows]}


@router.post("/policy-profiles")
async def create_policy_profile(req: PolicyProfileRequest, http_request: Request):
    _model_intake_authenticated_subject(http_request)
    _validate_policy_profile_request(req)
    async with _pool().acquire() as conn:
        required_anchor_ids = await _validate_policy_profile_required_anchor_ids(conn, req)
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO policy_profiles
                    (name, product_area, environment, minimum_block_severity, expires_days,
                     strict_model_intake, allow_active_exceptions, required_trust_anchor_ids,
                     owner, version, is_active)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                RETURNING *
                """,
                req.name, req.product_area, req.environment.strip().lower(),
                req.minimum_block_severity, req.expires_days, req.strict_model_intake,
                req.allow_active_exceptions, json.dumps(required_anchor_ids),
                req.owner, req.version, req.is_active,
            )
        except asyncpg.UniqueViolationError:
            raise HTTPException(status_code=409, detail="Policy profile name already exists")
    return row_to_dict(row)


@router.patch("/policy-profiles/{profile_id}")
async def update_policy_profile(profile_id: str, req: PolicyProfileRequest, http_request: Request):
    actor = _model_intake_authenticated_subject(http_request)
    _validate_policy_profile_request(req)
    async with _pool().acquire() as conn, conn.transaction():
        previous = await conn.fetchrow(
            "SELECT * FROM policy_profiles WHERE id=$1 FOR UPDATE",
            uuid.UUID(profile_id),
        )
        if not previous:
            raise HTTPException(status_code=404, detail="Policy profile not found")
        required_anchor_ids = await _validate_policy_profile_required_anchor_ids(conn, req)
        row = await conn.fetchrow(
            """
            UPDATE policy_profiles SET
                name=$2, product_area=$3, environment=$4, minimum_block_severity=$5,
                expires_days=$6, strict_model_intake=$7, allow_active_exceptions=$8,
                required_trust_anchor_ids=$9, owner=$10, version=$11, is_active=$12, updated_at=NOW()
            WHERE id=$1 RETURNING *
            """,
            uuid.UUID(profile_id), req.name, req.product_area, req.environment.strip().lower(),
            req.minimum_block_severity, req.expires_days, req.strict_model_intake,
            req.allow_active_exceptions, json.dumps(required_anchor_ids),
            req.owner, req.version, req.is_active,
        )
        affected = previous["product_area"] == "model_intake" or row["product_area"] == "model_intake"
        invalidation = (
            await _invalidate_model_intake_authority_change(
                conn,
                actor=actor,
                trigger_type="policy_change",
                reason=f"Changed Model Intake policy profile {profile_id}",
                environments=[str(previous["environment"]), str(row["environment"])],
                policy_profiles=[str(previous["name"]), str(row["name"])],
            )
            if affected else {"admissions_invalidated": 0, "deployment_bindings_staled": 0}
        )
    return {**row_to_dict(row), "downstream_invalidation": invalidation}


@router.delete("/policy-profiles/{profile_id}")
async def delete_policy_profile(profile_id: str, http_request: Request):
    actor = _model_intake_authenticated_subject(http_request)
    async with _pool().acquire() as conn, conn.transaction():
        previous = await conn.fetchrow(
            "DELETE FROM policy_profiles WHERE id=$1 RETURNING *",
            uuid.UUID(profile_id),
        )
        if not previous:
            raise HTTPException(status_code=404, detail="Policy profile not found")
        invalidation = (
            await _invalidate_model_intake_authority_change(
                conn,
                actor=actor,
                trigger_type="policy_change",
                reason=f"Deleted Model Intake policy profile {profile_id}",
                environments=[str(previous["environment"])],
                policy_profiles=[str(previous["name"])],
            )
            if previous["product_area"] == "model_intake"
            else {"admissions_invalidated": 0, "deployment_bindings_staled": 0}
        )
    return {"deleted": True, "id": profile_id, "downstream_invalidation": invalidation}



__all__ = [
    "PolicyProfileRequest",
    "_validate_policy_profile_request",
    "_validate_policy_profile_required_anchor_ids",
    "configure_policy_profile_router",
    "create_policy_profile",
    "delete_policy_profile",
    "list_policy_profiles",
    "router",
    "update_policy_profile",
]
