"""Internal preview: reviewed metadata and redacted assurance; no scan dispatch."""

from datetime import datetime, timezone
import ipaddress
import os
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .evaluation import current_assurance, scan_authentication_summary
from .models import ProfileWrite, ValidationRecord, ValidationRequest, exact_origin
from .store import AssuranceStore, ProfileConflict, decode
from .jobs import ValidationJobs, validation_supported, validation_identity_contract
from .job_lifecycle import stop_request
try:
    from runtime.credentials import IMMEDIATE_HTTP_HEADER_KINDS
except ModuleNotFoundError:
    from api.runtime.credentials import IMMEDIATE_HTTP_HEADER_KINDS

router = APIRouter(tags=["authentication assurance"])
store = AssuranceStore()
PROCESS_GENERATION = uuid4()
_engine = {}


def configure_assurance_engine(*, approve, freeze, enqueue, build):
    _engine.update(approve=approve, freeze=freeze, enqueue=enqueue, build=build)


def enabled() -> bool:
    return os.environ.get("SHAKERSCAN_AUTHENTICATED_ASSURANCE", "").strip() == "1"


def require_preview(request: Request) -> str:
    if not enabled():
        raise HTTPException(404, "authenticated_assurance_disabled")
    # New management routes are local preview only until an authenticated gateway
    # integration has been verified. Browser headers cannot supply actor/role claims.
    try:
        bind = ipaddress.ip_address(os.environ.get("SHAKERSCAN_BIND_HOST", ""))
        peer = ipaddress.ip_address(request.client.host) if request.client else None
    except ValueError:
        raise HTTPException(403, "authenticated_assurance_local_preview_only") from None
    if not bind.is_loopback or not peer or not (peer.is_loopback or peer.is_private):
        raise HTTPException(403, "authenticated_assurance_local_preview_only")
    return "local-operator"


def pool(request: Request):
    value = getattr(request.app.state, "db_pool", None)
    if value is None:
        raise HTTPException(503, "assurance_database_unavailable")
    return value


def public_profile(profile: dict) -> dict:
    record = ValidationRecord.model_validate(profile["validation"]) if profile["validation"] else None
    try:
        destination_active = profile["target_active"] and exact_origin(profile["current_target_url"]) in profile["configuration"]["credential_destinations"]
    except ValueError:
        destination_active = False
    return {
        "profile_id": str(profile["profile_id"]), "revision": profile["revision"],
        "current_revision": profile["current_profile_revision"],
        "credential_version": profile["credential_version"],
        "credential_record_version": profile["credential_record_version"],
        "configuration": profile["configuration"],
        "configuration_digest": profile["configuration_digest"],
        "created_at": profile["created_at"], "created_by": profile["created_by"],
        "validation": profile["validation"],
        "assurance": {**current_assurance(
            record, revision=profile["current_profile_revision"], credential_version=profile["current_version"],
            credential_record_version=profile["current_record_version"],
            configuration_digest=profile["configuration_digest"],
            now=datetime.now(timezone.utc), process_generation=PROCESS_GENERATION,
            credential_active=profile["credential_active"],
            credential_expires_at=profile["credential_expires_at"],
            lifecycle_state=profile["current_lifecycle_state"],
            destination_active=destination_active,
        ), "last_validated_at": profile["last_successful_validation_at"]},
        "scan_selection_supported": False,
        "secret_values_visible": False,
    }


@router.get("/authenticated-scan-profiles/contract")
async def contract():
    can_validate = bool(_engine) and validation_supported()
    return {
        "schema_version": "authenticated-scan-profile/v1", "enabled": enabled(),
        "management": "local_preview" if enabled() else "disabled",
        "validation_execution": "queued_read_only" if can_validate else "unsupported", "scan_selection": "unsupported",
        "supported_validation_methods": sorted(IMMEDIATE_HTTP_HEADER_KINDS) if can_validate else [],
        "validation_identity_contract": validation_identity_contract(),
        "validation_history": True,
        "hunt_assurance": "unsupported", "interactive_sso": "unsupported",
        "reason_code": "not_validated" if can_validate else "validation_not_supported",
        "mutations_require_review": True, "grants_target_authorization": False,
        "secret_values_visible": False,
    }


@router.get("/authenticated-scan-profiles", dependencies=[Depends(require_preview)])
async def list_profiles(request: Request, target_id: UUID):
    async with pool(request).acquire() as conn:
        profiles = await store.list(conn, target_id)
    return {"profiles": [public_profile(profile) for profile in profiles]}


@router.get("/authenticated-scan-profiles/{profile_id}", dependencies=[Depends(require_preview)])
async def get_profile(request: Request, profile_id: UUID, revision: int | None = Query(default=None, ge=1)):
    async with pool(request).acquire() as conn:
        profile = await store.get(conn, profile_id, revision=revision)
    if not profile:
        raise HTTPException(404, "authenticated_profile_not_found")
    return public_profile(profile)


@router.get("/authenticated-scan-profiles/{profile_id}/history", dependencies=[Depends(require_preview)])
async def get_profile_history(request: Request, profile_id: UUID, limit: int = Query(default=20, ge=1, le=100), before: UUID | None = None):
    async with pool(request).acquire() as conn:
        if not await store.get(conn, profile_id):
            raise HTTPException(404, "authenticated_profile_not_found")
        try:
            history = await store.history(conn, profile_id, limit=limit, before=before)
        except ProfileConflict as exc:
            raise HTTPException(422, str(exc)) from None
    return {"profile_id": str(profile_id), **history}


@router.post("/authenticated-scan-profiles")
async def write_profile(request: Request, body: ProfileWrite, actor: str = Depends(require_preview)):
    try:
        async with pool(request).acquire() as conn, conn.transaction():
            result = await store.write(conn, body, actor=actor)
    except ProfileConflict as exc:
        raise HTTPException(409, str(exc)) from None
    return public_profile(result)


@router.post("/authenticated-scan-profiles/{profile_id}/validate", status_code=202)
async def validate_profile(request: Request, profile_id: UUID, body: ValidationRequest,
                           actor: str = Depends(require_preview)):
    if not _engine:
        raise HTTPException(503, "validation_not_supported")
    try:
        async with pool(request).acquire() as conn, conn.transaction():
            payload = await ValidationJobs().prepare(conn, profile_id=profile_id, request=body,
                actor=actor, generation=PROCESS_GENERATION, expected_build_fingerprint=_engine["build"](),
                approve=_engine["approve"], freeze=_engine["freeze"])
    except ProfileConflict as exc:
        raise HTTPException(429 if str(exc) == "validation_rate_limited" else 409, str(exc)) from None
    job_id = UUID(payload["job_id"])
    try:
        _engine["enqueue"](payload)
    except Exception:
        async with pool(request).acquire() as conn, conn.transaction():
            await stop_request(conn, job_id, reason="worker_unavailable")
        raise HTTPException(503, "worker_unavailable") from None
    return {"request_id": str(job_id), "status": "queued",
            "status_url": f"/authenticated-scan-profiles/validations/{job_id}",
            "evidence_url": "/credentials"}


@router.get("/authenticated-scan-profiles/validations/{request_id}", dependencies=[Depends(require_preview)])
async def get_validation(request: Request, request_id: UUID):
    async with pool(request).acquire() as conn:
        result = await ValidationJobs().read(conn, request_id)
    if not result:
        raise HTTPException(404, "validation_request_not_found")
    return result


@router.post("/authenticated-scan-profiles/validations/{request_id}/cancel", dependencies=[Depends(require_preview)])
async def cancel_validation(request: Request, request_id: UUID):
    async with pool(request).acquire() as conn, conn.transaction():
        await stop_request(conn, request_id)
        result = await ValidationJobs().read(conn, request_id)
    if not result:
        raise HTTPException(404, "validation_request_not_found")
    return result


@router.get("/scans/{scan_id}/authentication-assurance")
async def get_scan_assurance(request: Request, scan_id: UUID):
    # Same read boundary as the existing Scan detail API. This remains readable
    # when management is disabled; historical uncertainty must not disappear.
    async with pool(request).acquire() as conn:
        row = await conn.fetchrow("SELECT options FROM scans WHERE id=$1", scan_id)
        interrupted = await conn.fetchval("""SELECT COUNT(*) FROM scan_capability_actions WHERE scan_id=$1 AND
            (reason_code='authentication_uncertain' OR receipt_json->'redacted_execution'->'identity_interruption'->>'reason_code'='authentication_uncertain')""", scan_id) if row else 0
    if not row:
        raise HTTPException(404, "scan_not_found")
    return {**scan_authentication_summary(decode(row["options"] or {}), interrupted_action_count=interrupted),
            "scan_id": str(scan_id), "evidence_url": f"/scans/{scan_id}"}
