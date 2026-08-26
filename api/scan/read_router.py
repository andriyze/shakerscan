"""Public, content-safe read API for canonical Scan execution state."""

from __future__ import annotations

import json
from typing import Any, Callable, Literal, Mapping, Sequence
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .action_store import PostgresScanActionStore
from .continuation import ScanPlanRevision
from .contracts import (
    SCAN_MINIMUM_FAMILY_QUOTAS,
    public_scan_contract,
    resolve_scan_contract,
)
from .explanation import (
    action_list_response,
    build_scan_execution_explanation,
    capability_list_response,
    coverage_response,
)
from .parity import build_scan_semantic_parity_artifact


router = APIRouter()


class ScanFamilyPreviewRequest(BaseModel):
    """Target-independent family and quota resolution used by every Scan client."""

    model_config = ConfigDict(extra="forbid")

    preset: Literal["passive", "standard_active", "custom"] = "passive"
    budget_profile: Literal["fast", "balanced", "thorough"] = "balanced"
    include_families: list[str] = Field(default_factory=list, max_length=100)
    exclude_families: list[str] = Field(default_factory=list, max_length=100)
    active_testing: bool = False
    allow_state_changing_http: bool = False
    network_discovery: bool = False
    subdomain_discovery: bool = False
    execution_topology: Literal["single_worker", "parallel"] = "single_worker"

PUBLIC_SCAN_ACTIONS_SQL = """
    SELECT a.action_id, a.stage, a.ordinal, a.capability_name, a.adapter_name,
           a.adapter_version, a.output_schema, a.action_digest, a.requested_budget,
           a.placement_json, a.dependencies_json, a.required, a.supporting, a.status,
           a.reason_code, a.reservation_id, a.receipt_id, a.receipt_hash,
           a.observation_manifest_id, a.result_digest, a.result_json, a.receipt_json,
           a.backend_name, a.worker_id, a.attempt, a.started_at, a.finished_at,
           r.status AS reservation_status,
           r.hold_applied AS reservation_hold_applied,
           r.requested_json AS reservation_requested,
           r.actual_json AS reservation_actual,
           r.execution_uncertain
      FROM scan_capability_actions a
      LEFT JOIN budget_reservations r ON r.id=a.reservation_id
     WHERE a.scan_id=$1
     ORDER BY a.ordinal
"""

_pool_provider: Callable[[], Any] | None = None


def configure_scan_read_router(pool_provider: Callable[[], Any]) -> None:
    """Bind runtime infrastructure without coupling this router to ``api.py``."""
    global _pool_provider
    _pool_provider = pool_provider


def _pool() -> Any:
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="Database is not ready")
    return pool


def _decode_json_value(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return value
    return value


def _json_object(value: Any) -> dict[str, Any]:
    decoded = _decode_json_value(value)
    return dict(decoded) if isinstance(decoded, Mapping) else {}


def public_scan_execution_explanation(
    scan: Mapping[str, Any],
    action_rows: Sequence[Mapping[str, Any]],
    plan_revision: ScanPlanRevision | None = None,
) -> dict[str, Any]:
    """Build the allowlisted public projection shared by detail and read APIs."""
    report = _decode_json_value(scan.get("result"))
    return build_scan_execution_explanation(
        scan_id=str(scan.get("id") or ""),
        scan_status=str(scan.get("status") or "unknown"),
        plan_payload=_json_object(scan.get("scan_action_plan_json")),
        action_rows=tuple(dict(row) for row in action_rows),
        report=report if isinstance(report, Mapping) else {},
        plan_revision=(
            plan_revision.canonical_dict() if plan_revision is not None else None
        ),
        plan_budget_limits=_json_object(scan.get("budget_json")),
    )


async def load_public_scan_execution_explanation(
    conn: Any,
    scan_id: str,
) -> dict[str, Any]:
    try:
        parsed_scan_id = uuid.UUID(str(scan_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc
    scan = await conn.fetchrow(
        """SELECT id, status, result, budget_json, scan_action_plan_json,
                  scan_action_plan_digest, scan_action_plan_schema
             FROM scans WHERE id=$1""",
        parsed_scan_id,
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    action_rows = await conn.fetch(PUBLIC_SCAN_ACTIONS_SQL, parsed_scan_id)
    try:
        plan_revision = await PostgresScanActionStore().load_plan_revision(
            conn, scan_id=str(parsed_scan_id),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=409,
            detail=f"Scan plan revision is invalid: {exc}",
        ) from exc
    return public_scan_execution_explanation(scan, action_rows, plan_revision)


@router.get("/scan/contracts")
async def get_scan_public_contract():
    """Expose the canonical Scan vocabulary consumed by UI and CLI clients."""
    return public_scan_contract()


@router.post("/scan/contracts/preview")
async def preview_scan_contract(request: ScanFamilyPreviewRequest):
    """Resolve the exact immutable family set before a Scan is submitted."""
    try:
        contract = resolve_scan_contract(
            budget_profile=request.budget_profile,
            policy={
                "preset": request.preset,
                "active_testing": request.active_testing,
                "allow_state_changing_http": request.allow_state_changing_http,
                "network_discovery": request.network_discovery,
                "subdomain_discovery": request.subdomain_discovery,
                "include_families": request.include_families,
                "exclude_families": request.exclude_families,
            },
            # Preview cannot validate a target-bound receipt. Preserve permission
            # resolution without granting executable receipt authority.
            approval_receipt_id=(
                "preview-only" if request.allow_state_changing_http or request.network_discovery else None
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    resolved = list(contract.execution_plan.resolved_families)
    prerequisites = ["http.request"]
    if "recon" in resolved:
        prerequisites.extend(["web.probe", "web.crawl"])
    return {
        "preset": contract.execution_plan.family_preset,
        "requested_families": list(contract.execution_plan.requested_families),
        "resolved_families": resolved,
        "derived_prerequisites": list(dict.fromkeys(prerequisites)),
        "active_permissions": {
            "active_testing": contract.policy.active_testing,
            "state_changing_http": contract.policy.allow_state_changing_http,
            "network_discovery": contract.policy.network_discovery,
        },
        "minimum_family_quotas": {
            family: SCAN_MINIMUM_FAMILY_QUOTAS[family]
            for family in resolved if family in SCAN_MINIMUM_FAMILY_QUOTAS
        },
        "execution_topology": request.execution_topology,
        "ai_used": False,
    }


@router.get("/scans/{scan_id}/actions")
async def get_scan_actions(scan_id: str):
    """Explain the immutable stage/action timeline without private inputs."""
    async with _pool().acquire() as conn:
        explanation = await load_public_scan_execution_explanation(conn, scan_id)
    return action_list_response(explanation)


@router.get("/scans/{scan_id}/capabilities")
async def get_scan_capabilities(scan_id: str):
    """Summarize planned and executed capability coverage for one Scan."""
    async with _pool().acquire() as conn:
        explanation = await load_public_scan_execution_explanation(conn, scan_id)
    return capability_list_response(explanation)


@router.get("/scans/{scan_id}/coverage")
async def get_scan_coverage(scan_id: str):
    """Explain coverage gaps, grade reliability, and transport parity."""
    async with _pool().acquire() as conn:
        explanation = await load_public_scan_execution_explanation(conn, scan_id)
    return coverage_response(explanation)


@router.get("/scans/{scan_id}/parity-artifact")
async def get_scan_parity_artifact(scan_id: str):
    """Return a content-free semantic artifact for placement certification."""
    try:
        parsed_scan_id = uuid.UUID(str(scan_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc
    async with _pool().acquire() as conn:
        explanation = await load_public_scan_execution_explanation(conn, scan_id)
        findings = await conn.fetch(
            """
            SELECT fingerprint, tool, url, title
              FROM findings
             WHERE scan_id=$1
             ORDER BY fingerprint, id
            """,
            parsed_scan_id,
        )
    return build_scan_semantic_parity_artifact(
        explanation,
        tuple(dict(row) for row in findings),
    )


__all__ = [
    "PUBLIC_SCAN_ACTIONS_SQL",
    "configure_scan_read_router",
    "get_scan_actions",
    "get_scan_capabilities",
    "get_scan_coverage",
    "get_scan_parity_artifact",
    "get_scan_public_contract",
    "preview_scan_contract",
    "load_public_scan_execution_explanation",
    "public_scan_execution_explanation",
    "router",
]
