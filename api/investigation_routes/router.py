"""Investigation routes.

Extracted verbatim from the api.py monolith. Two read-only views over the
investigation candidate backlog that the Leads pages render. Candidates are
evidence-backed leads, never verified findings: only a deterministic proof
contract promotes one.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Optional

from fastapi import APIRouter, HTTPException, Query

try:
    from action_scope import _decode_json_value
    from api_utils import _uuid_or_400
    from serialization import row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..action_scope import _decode_json_value
    from ..api_utils import _uuid_or_400
    from ..serialization import row_to_dict

try:
    import investigation_candidates
except ModuleNotFoundError:  # package import in host-side tests
    from .. import investigation_candidates


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


def configure_investigation_router(
    pool_provider: Callable[[], Any], **collaborators: Callable[..., Any]
) -> None:
    """Bind the pool and the collaborators this domain needs."""
    global _pool_provider
    _pool_provider = pool_provider
    _deps.update(collaborators)


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool


def _dep(name: str) -> Callable[..., Any]:
    call = _deps.get(name)
    if call is None:
        raise HTTPException(status_code=503, detail=f"{name} is not ready")
    return call


def _get(name: str) -> Any:
    """Resolve an injected collaborator that still lives in the composition root."""
    return _dep(name)()



__all__ = ["configure_investigation_router", "router"]
@router.get("/investigation/candidates")
async def list_investigation_candidates(
    plane: str | None = Query(None),
    target_id: str | None = Query(None),
    device_target_id: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List non-authoritative hunt candidates and their verifier lifecycle."""
    normalized_plane = str(plane or "").strip().lower() or None
    normalized_status = str(status or "").strip().lower() or None
    if normalized_plane not in (None, *sorted(investigation_candidates.PLANES)):
        raise HTTPException(status_code=422, detail="plane must be web or device")
    if normalized_status not in (None, *sorted(investigation_candidates.STATUSES)):
        raise HTTPException(status_code=422, detail="unsupported candidate status")
    if target_id and device_target_id:
        raise HTTPException(status_code=422, detail="web and device candidate filters are mutually exclusive")
    try:
        target_uuid = uuid.UUID(target_id) if target_id else None
        device_uuid = uuid.UUID(device_target_id) if device_target_id else None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="candidate target filter must be a UUID") from exc
    if normalized_plane == "web" and device_uuid:
        raise HTTPException(status_code=422, detail="web candidates cannot use device_target_id")
    if normalized_plane == "device" and target_uuid:
        raise HTTPException(status_code=422, detail="device candidates cannot use target_id")
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT c.*, COUNT(*) OVER() AS total_count,
                      (SELECT COUNT(*) FROM investigation_candidate_observations o
                       WHERE o.candidate_id=c.id) AS observation_count
               FROM investigation_candidates c
               WHERE ($1::text IS NULL OR c.plane=$1)
                 AND ($2::uuid IS NULL OR c.target_id=$2)
                 AND ($3::uuid IS NULL OR c.device_target_id=$3)
                 AND ($4::text IS NULL OR c.status=$4)
               ORDER BY c.last_seen_at DESC, c.id DESC
               LIMIT $5 OFFSET $6""",
            normalized_plane, target_uuid, device_uuid, normalized_status, limit, offset,
        )
    total = int(rows[0]["total_count"] or 0) if rows else 0
    candidates = []
    for row in rows:
        payload = _public_investigation_candidate(row)
        payload.pop("total_count", None)
        candidates.append(payload)
    return {"candidates": candidates, "total": total, "limit": limit, "offset": offset}


@router.get("/investigation/candidates/{candidate_id}")
async def get_investigation_candidate(candidate_id: str):
    """Inspect one candidate with its deterministic verification and evidence records."""
    candidate_uuid = _uuid_or_400(candidate_id, "candidate id")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM investigation_candidates WHERE id=$1", candidate_uuid)
        if not row:
            raise HTTPException(status_code=404, detail="Investigation candidate not found")
        verifications = await conn.fetch(
            """SELECT id, finding_id, scan_id, status, result_status, verdict, verdict_reason,
                      finding_type, confidence, verification_mode, contract_id, contract_version,
                      proof_basis, proof, created_at, started_at, completed_at
               FROM finding_verifications WHERE candidate_id=$1
               ORDER BY created_at DESC LIMIT 100""",
            candidate_uuid,
        )
        evidence = await conn.fetch(
            """SELECT id, finding_id, scan_id, proof_state, evidence_strength, contract_id,
                      contract_version, proof_basis, proof_observation, hash, created_at
               FROM evidence_instances WHERE candidate_id=$1
               ORDER BY created_at DESC LIMIT 100""",
            candidate_uuid,
        )
        observations = await conn.fetch(
            """SELECT id, research_episode_id, agent_hunt_run_id, device_agent_run_id,
                      source_kind, title, claim, claimed_severity, evidence_refs,
                      verifier_contract_id, observation_context, created_by, observed_at
               FROM investigation_candidate_observations
               WHERE candidate_id=$1 ORDER BY observed_at DESC, id DESC LIMIT 250""",
            candidate_uuid,
        )
    verification_payloads = []
    for item in verifications:
        payload = row_to_dict(item)
        payload["proof"] = _decode_json_value(payload.get("proof")) or {}
        verification_payloads.append(payload)
    evidence_payloads = []
    for item in evidence:
        payload = row_to_dict(item)
        payload["proof_observation"] = _decode_json_value(payload.get("proof_observation")) or {}
        evidence_payloads.append(payload)
    observation_payloads = []
    for item in observations:
        payload = row_to_dict(item)
        payload["evidence_refs"] = _decode_json_value(payload.get("evidence_refs")) or []
        payload["observation_context"] = _decode_json_value(payload.get("observation_context")) or {}
        observation_payloads.append(payload)
    return {
        "candidate": _public_investigation_candidate(row),
        "observations": observation_payloads,
        "verifications": verification_payloads,
        "evidence": evidence_payloads,
    }
def _public_investigation_candidate(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key, default in (
        ("canonical_locus", {}),
        ("evidence_refs", []),
        ("verification_context", {}),
    ):
        payload[key] = _decode_json_value(payload.get(key)) or default
    payload["authoritative"] = False
    payload["promotion_ready"] = payload.get("status") == "verified"
    return payload
