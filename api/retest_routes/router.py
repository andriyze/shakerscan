"""Retest routes.

Extracted verbatim from the api.py monolith. Read-only history of deterministic
and AI-driven verification runs: the runs recorded for one finding, and one run
with its proof, artifacts, and replay commands.

Reads only. Queueing a retest stays on the findings surface, because that is
where the approval and severity gating lives.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Optional
from urllib.parse import urljoin

from fastapi import APIRouter, HTTPException, Query

try:
    from serialization import row_to_dict
    from ai_targets import router as _ai_targets
except ModuleNotFoundError:  # package import in host-side tests
    from ..serialization import row_to_dict
    from ..ai_targets import router as _ai_targets

router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


def configure_retest_router(
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



__all__ = ["configure_retest_router", "router"]


def _tested_endpoint(value: Any, base_url: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if isinstance(base_url, str) and base_url.strip():
        return urljoin(base_url.strip().rstrip("/") + "/", candidate)
    return candidate


def _tested_scope(result: dict[str, Any]) -> tuple[str | None, list[str]]:
    """Derive replay scope only from durable records of requests that executed."""
    base_url = result.get("target_url")
    artifacts = result.get("artifacts") if isinstance(result.get("artifacts"), dict) else {}
    raw_candidates: list[Any] = [
        artifacts.get("attempted_url"),
    ]
    step_results = artifacts.get("ai_step_results")
    if isinstance(step_results, list):
        raw_candidates.extend(
            row.get("step", {}).get("url")
            for row in step_results
            if isinstance(row, dict) and isinstance(row.get("step"), dict)
        )

    endpoints: list[str] = []
    for value in raw_candidates:
        endpoint = _tested_endpoint(value, base_url)
        if endpoint and endpoint not in endpoints:
            endpoints.append(endpoint)
    return (endpoints[0] if endpoints else None, endpoints)


def public_retest_row(row: Any) -> dict[str, Any]:
    """Return one replay with typed proof and an explicit authority boundary.

    ``verdict`` can contain an AI assessment such as ``likely_vulnerable`` even
    when the deterministic replay did not satisfy its proof contract. Expose
    those as separate facts so clients never present model prose as execution
    proof.
    """
    result = row_to_dict(row)
    for field in ("proof", "artifacts", "auth_context", "ai_plan", "replay_commands"):
        value = result.get(field)
        if isinstance(value, str):
            try:
                result[field] = json.loads(value)
            except (TypeError, ValueError):
                pass
    proof = result.get("proof") if isinstance(result.get("proof"), dict) else {}
    proof_proven = proof.get("proven") is True
    mode = str(result.get("verification_mode") or "").lower()
    result["deterministic_proof_state"] = "proven" if proof_proven else "not_proven"
    result["verdict_basis"] = (
        "deterministic_proof"
        if proof_proven
        else "ai_assessment"
        if mode == "ai_driven" and result.get("verdict")
        else "execution_result"
    )
    primary_endpoint, tested_endpoints = _tested_scope(result)
    result["primary_tested_endpoint"] = primary_endpoint
    result["tested_endpoints"] = tested_endpoints
    result["tested_scope"] = (
        "multiple_endpoints" if len(tested_endpoints) > 1
        else "single_endpoint" if tested_endpoints
        else None
    )
    return result


@router.get("/retests/finding/{finding_id:path}")
async def list_finding_retests(finding_id: str, limit: int = Query(20, ge=1, le=200)):
    """List retest history for a finding."""
    async with _pool().acquire() as conn:
        finding = await _ai_targets.get_finding_record(conn, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        rows = await conn.fetch("""
            SELECT *
            FROM finding_verifications
            WHERE finding_id = $1
            ORDER BY created_at DESC
            LIMIT $2
        """, finding["id"], limit)

    return {
        "finding_id": str(finding["id"]),
        "retests": [public_retest_row(r) for r in rows],
        "count": len(rows),
    }


@router.get("/retests/{retest_id}")
async def get_retest(retest_id: str):
    """Get a single retest record by ID."""
    async with _pool().acquire() as conn:
        try:
            retest_uuid = uuid.UUID(retest_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid retest ID")

        row = await conn.fetchrow("""
            SELECT fv.*, f.title, f.severity, f.fingerprint
            FROM finding_verifications fv
            JOIN findings f ON fv.finding_id = f.id
            WHERE fv.id = $1
        """, retest_uuid)

        if not row:
            raise HTTPException(status_code=404, detail="Retest not found")

    return public_retest_row(row)
