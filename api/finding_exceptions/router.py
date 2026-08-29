"""Finding exception (waiver) routes.

Extracted verbatim from the api.py monolith. Owns the exception queue —
creating, updating, and deleting scoped waivers, and the lifecycle sweep that
expires them — so a waiver's owner, approver, scope, and expiry stay together
with the code that enforces them.

The database pool is supplied by the composition root through
``configure_finding_exception_router``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Callable, Optional
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from api_utils import _optional_uuid, _parse_iso_datetime, _uuid_or_400, utc_now_iso
    from serialization import _decode_json_value, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..api_utils import _optional_uuid, _parse_iso_datetime, _uuid_or_400, utc_now_iso
    from ..serialization import _decode_json_value, row_to_dict


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_approval_validator: Callable[..., Any] | None = None
_command_recorder: Callable[..., Any] | None = None


def configure_finding_exception_router(
    pool_provider: Callable[[], Any],
    *,
    approval_validator: Callable[..., Any],
    command_recorder: Callable[..., Any],
) -> None:
    """Bind the pool and the collaborators this domain needs.

    The approval gate and the command-result ledger are still hubs inside
    api.py, so the composition root injects them and the dependency direction
    stays app -> router.
    """
    global _pool_provider, _approval_validator, _command_recorder
    _pool_provider = pool_provider
    _approval_validator = approval_validator
    _command_recorder = command_recorder


async def _validate_approval_receipt_for_action(*args: Any, **kwargs: Any) -> Any:
    if _approval_validator is None:
        raise HTTPException(status_code=503, detail="approval validation is not ready")
    return await _approval_validator(*args, **kwargs)


async def _record_command_result(*args: Any, **kwargs: Any) -> Any:
    if _command_recorder is None:
        raise HTTPException(status_code=503, detail="command ledger is not ready")
    return await _command_recorder(*args, **kwargs)


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool

class FindingExceptionRequest(BaseModel):
    finding_id: Optional[str] = None
    fingerprint: Optional[str] = None
    policy_id: Optional[str] = None       # scopes the waiver to one policy profile (enforced)
    target_id: Optional[str] = None       # scopes the waiver to one target (enforced in loader SQL)
    scope: Optional[str] = None           # free-text descriptor; not an enforcement gate
    owner: Optional[str] = None
    approver: Optional[str] = None
    reason: Optional[str] = None
    compensating_controls: Optional[str] = None
    status: str = "active"
    expires_at: Optional[str] = None


class FindingExceptionLifecycleSweepRequest(BaseModel):
    dry_run: bool = True
    target_id: Optional[str] = None
    limit: int = Field(default=200, ge=1, le=500)
    approval_receipt_id: Optional[str] = None


EFFECTIVE_EXCEPTION_STATUSES = {"active", "approved", "accepted_risk"}


def _uuid_or_422(value: str, field_name: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be a valid UUID") from exc


def _validate_finding_exception_accountability(req: FindingExceptionRequest) -> datetime | None:
    if req.status not in EFFECTIVE_EXCEPTION_STATUSES:
        return _parse_iso_datetime(req.expires_at) if req.expires_at else None
    missing = [
        label for label, value in (
            ("policy_id", req.policy_id),
            ("target_id", req.target_id),
            ("owner", req.owner),
            ("approver", req.approver),
            ("reason", req.reason),
            ("compensating_controls", req.compensating_controls),
            ("expires_at", req.expires_at),
        ) if not str(value or "").strip()
    ]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"effective exceptions require: {', '.join(missing)}",
        )
    _uuid_or_422(str(req.policy_id), "policy_id")
    _uuid_or_422(str(req.target_id), "target_id")
    expires_at = _parse_iso_datetime(req.expires_at)
    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=422, detail="expires_at must be in the future")
    return expires_at


async def _require_active_policy_profile(conn: Any, policy_id: str | None) -> None:
    if not policy_id:
        return
    row = await conn.fetchrow(
        "SELECT id FROM policy_profiles WHERE id=$1 AND is_active=true",
        _uuid_or_422(policy_id, "policy_id"),
    )
    if not row:
        raise HTTPException(status_code=422, detail="policy_id must reference an active policy profile")


@router.get("/finding-exceptions")
async def list_finding_exceptions(
    target_id: Optional[str] = None,
    status: Optional[str] = None,
    queue_filter: Optional[str] = None,
    expiring_within_days: int = Query(7, ge=1, le=365),
    limit: int = Query(200, ge=1, le=500),
):
    clauses, params = [], []
    if target_id:
        params.append(_uuid_or_422(target_id, "target_id"))
        clauses.append(f"target_id = ${len(params)}")
    if status:
        params.append(status)
        clauses.append(f"status = ${len(params)}")
    qf = str(queue_filter or "").strip().lower()
    if qf in {"expired", "expired_or_status"}:
        clauses.append("status <> 'revoked'")
        clauses.append("(status = 'expired' OR (expires_at IS NOT NULL AND expires_at < NOW()))")
    elif qf in {"expiring", "expiring_soon"}:
        params.append(int(expiring_within_days))
        clauses.append(
            f"expires_at IS NOT NULL AND expires_at >= NOW() "
            f"AND expires_at <= NOW() + (${len(params)}::int * INTERVAL '1 day')"
        )
        clauses.append("status IN ('active', 'approved', 'accepted_risk')")
    elif qf in {"missing_owner", "missing_approver", "missing_controls", "policy_scoped", "target_scoped"}:
        clauses.append("status IN ('active', 'approved', 'accepted_risk')")
        if qf == "missing_owner":
            clauses.append("(owner IS NULL OR btrim(owner) = '')")
        elif qf == "missing_approver":
            clauses.append("(approver IS NULL OR btrim(approver) = '')")
        elif qf == "missing_controls":
            clauses.append("(compensating_controls IS NULL OR btrim(compensating_controls) = '')")
        elif qf == "policy_scoped":
            clauses.append("policy_id IS NOT NULL")
        elif qf == "target_scoped":
            clauses.append("target_id IS NOT NULL")
    elif qf:
        raise HTTPException(
            status_code=422,
            detail="queue_filter must be one of expired, expiring, missing_owner, missing_approver, missing_controls, policy_scoped, target_scoped",
        )
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    async with _pool().acquire() as conn:
        params.append(limit)
        rows = await conn.fetch(
            f"SELECT * FROM finding_exceptions{where} ORDER BY created_at DESC LIMIT ${len(params)}",
            *params,
        )
    return {"finding_exceptions": [row_to_dict(r) for r in rows]}


@router.post("/finding-exceptions/lifecycle/sweep")
async def finding_exception_lifecycle_sweep(req: FindingExceptionLifecycleSweepRequest):
    return await _finding_exception_lifecycle_sweep(req, pool=_pool())


async def _finding_exception_lifecycle_sweep(
    req: FindingExceptionLifecycleSweepRequest,
    *,
    pool: asyncpg.Pool,
) -> dict[str, Any]:
    """Preview or expire elapsed exceptions without renewing or deleting them."""
    try:
        target_uuid = uuid.UUID(req.target_id) if req.target_id else None
    except ValueError:
        raise HTTPException(status_code=422, detail="target_id must be a UUID")

    async with pool.acquire() as conn:
        if not req.dry_run:
            await _validate_approval_receipt_for_action(
                conn,
                req.approval_receipt_id,
                target_id=target_uuid,
                action_name="finding_exception.lifecycle_sweep",
                command="finding_exception.lifecycle_sweep",
                risk_tier="active",
                always_require_receipt=True,
            )
        candidates = await conn.fetch(
            """
            SELECT *
            FROM finding_exceptions
            WHERE status IN ('active', 'approved', 'accepted_risk')
              AND expires_at IS NOT NULL
              AND expires_at < NOW()
              AND ($1::uuid IS NULL OR target_id = $1)
            ORDER BY expires_at ASC, created_at ASC
            LIMIT $2
            """,
            target_uuid,
            req.limit,
        )
        candidate_ids = [str(row["id"]) for row in candidates]
        expired_rows: list[Any] = []
        command_result: dict[str, Any] | None = None
        if candidate_ids and not req.dry_run:
            expired_rows = await conn.fetch(
                """
                UPDATE finding_exceptions
                SET status = 'expired',
                    updated_at = NOW(),
                    edit_history = edit_history || jsonb_build_array(
                        jsonb_build_object(
                            'status', status,
                            'expires_at', expires_at,
                            'replaced_at', NOW(),
                            'transition', 'lifecycle_sweep'
                        )
                    )
                WHERE id = ANY($1::uuid[])
                  AND status IN ('active', 'approved', 'accepted_risk')
                  AND expires_at IS NOT NULL
                  AND expires_at < NOW()
                RETURNING id
                """,
                [uuid.UUID(item) for item in candidate_ids],
            )
        if not req.dry_run:
            expired_ids = [str(row["id"]) for row in expired_rows]
            command_result = await _record_command_result(
                conn,
                command="finding_exception.lifecycle_sweep",
                status="completed",
                risk_tier="active",
                approval_receipt_id=req.approval_receipt_id,
                operator_message=f"Expired {len(expired_ids)} elapsed finding exception(s)",
                next_action="/findings",
                result_json={
                    "target_id": str(target_uuid) if target_uuid else None,
                    "candidate_count": len(candidate_ids),
                    "expired_count": len(expired_ids),
                    "expired_exception_ids": expired_ids,
                },
            )
    response = {
        "dry_run": req.dry_run,
        "target_id": str(target_uuid) if target_uuid else None,
        "candidate_count": len(candidate_ids),
        "expired_count": len(expired_rows),
        "candidate_exception_ids": candidate_ids,
        "execution_enabled": not req.dry_run,
    }
    if command_result:
        response["operation_id"] = command_result["id"]
    return response


@router.post("/finding-exceptions")
async def create_finding_exception(req: FindingExceptionRequest):
    if not (req.finding_id or req.fingerprint):
        raise HTTPException(status_code=422, detail="finding_id or fingerprint is required")
    expires_at = _validate_finding_exception_accountability(req)
    async with _pool().acquire() as conn:
        await _require_active_policy_profile(conn, req.policy_id)
        row = await conn.fetchrow(
            """
            INSERT INTO finding_exceptions
                (finding_id, fingerprint, policy_id, target_id, scope, owner, approver,
                 reason, compensating_controls, status, expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            RETURNING *
            """,
            req.finding_id, req.fingerprint,
            _uuid_or_422(req.policy_id, "policy_id") if req.policy_id else None,
            _uuid_or_422(req.target_id, "target_id") if req.target_id else None,
            req.scope, req.owner, req.approver, req.reason, req.compensating_controls,
            req.status, expires_at,
        )
    return row_to_dict(row)


@router.patch("/finding-exceptions/{exception_id}")
async def update_finding_exception(exception_id: str, req: FindingExceptionRequest):
    exception_uuid = _uuid_or_422(exception_id, "exception_id")
    async with _pool().acquire() as conn:
        current = await conn.fetchrow("SELECT * FROM finding_exceptions WHERE id=$1", exception_uuid)
        if not current:
            raise HTTPException(status_code=404, detail="Finding exception not found")
        supplied = req.model_dump(exclude_unset=True)
        merged = {
            field: supplied.get(field, current.get(field))
            for field in FindingExceptionRequest.model_fields
        }
        for uuid_field in ("policy_id", "target_id"):
            if merged.get(uuid_field) is not None:
                merged[uuid_field] = str(merged[uuid_field])
        merged_req = FindingExceptionRequest(**merged)
        expires_at = _validate_finding_exception_accountability(merged_req)
        if merged_req.status in EFFECTIVE_EXCEPTION_STATUSES:
            await _require_active_policy_profile(conn, merged_req.policy_id)
        prior_snapshot = {
            "policy_id": str(current["policy_id"]) if current["policy_id"] else None,
            "owner": current["owner"],
            "approver": current["approver"],
            "reason": current["reason"],
            "compensating_controls": current["compensating_controls"],
            "status": current["status"],
            "expires_at": current["expires_at"].isoformat() if current["expires_at"] else None,
            "replaced_at": utc_now_iso(),
        }
        row = await conn.fetchrow(
            """
            UPDATE finding_exceptions SET
                policy_id=$2, target_id=$3, scope=$4, owner=$5, approver=$6, reason=$7,
                compensating_controls=$8, status=$9, expires_at=$10, updated_at=NOW(),
                edit_history = edit_history || $11::jsonb
            WHERE id=$1 RETURNING *
            """,
            exception_uuid,
            _uuid_or_422(merged_req.policy_id, "policy_id") if merged_req.policy_id else None,
            _uuid_or_422(merged_req.target_id, "target_id") if merged_req.target_id else None,
            merged_req.scope, merged_req.owner, merged_req.approver, merged_req.reason,
            merged_req.compensating_controls, merged_req.status, expires_at,
            json.dumps([prior_snapshot], default=str),
        )
        if not row:
            raise HTTPException(status_code=404, detail="Finding exception not found")
    return row_to_dict(row)


@router.delete("/finding-exceptions/{exception_id}")
async def delete_finding_exception(exception_id: str):
    async with _pool().acquire() as conn:
        result = await conn.execute(
            "DELETE FROM finding_exceptions WHERE id=$1",
            _uuid_or_422(exception_id, "exception_id"),
        )
    if result.endswith("0"):
        raise HTTPException(status_code=404, detail="Finding exception not found")
    return {"deleted": True, "id": exception_id}
