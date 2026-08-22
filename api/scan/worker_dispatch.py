"""Canonical Scan V2 dispatch adapter for the current worker process.

This module is deliberately small and side-effect free. It converts a validated
``WorkerScanAdmission`` into the bounded options understood by the existing
scanner subprocess while preserving the canonical plan as the only authority.
"""

from __future__ import annotations

import math
from typing import Any, Mapping

from .jobs import (
    ScanShardAuthority,
)
from .worker_contract import WorkerScanAdmission, resolve_worker_scan_admission


NON_DAST_RUN_KINDS = frozenset({
    "ai_api", "ai_rag", "ai_trace", "ai_mcp", "ai_widget", "model_intake",
    "device_posture", "device_probe", "device_web_dast", "asm_recon", "asm_batch",
    "asm_dynamic_batch",
})


def is_deterministic_dast(options: Mapping[str, Any] | None) -> bool:
    if not isinstance(options, Mapping):
        return False
    return str(options.get("run_kind") or "web_dast").strip().lower() not in NON_DAST_RUN_KINDS


def prepare_worker_dispatch(
    options: Mapping[str, Any],
) -> tuple[dict[str, Any], WorkerScanAdmission]:
    """Validate admission and derive bounded scanner-process options.

    Legacy calls remain readable during migration. A call containing any V2 marker
    is fail-closed and cannot silently downgrade to legacy execution.
    """
    admission = resolve_worker_scan_admission(options)
    if not admission.canonical or admission.plan is None:
        return dict(options), admission

    normalized = admission.normalize_options(options)
    policy, parent_budget = admission.plan.policy, admission.plan.budget
    budget = parent_budget
    shard_authority = None
    raw_shard_authority = options.get("canonical_shard_authority")
    if raw_shard_authority is not None:
        shard_authority = ScanShardAuthority.from_payload(raw_shard_authority)
        shard_authority.validate_against_plan(admission.plan)
        budget = shard_authority.sub_budget

    # Never merge caller-supplied legacy tuning into a canonical plan. Every surviving scanner
    # ceiling is derived from the immutable ScanBudget so stale UI fields cannot expand authority.
    custom_budget = {
        "max_duration_minutes": max(1, math.ceil(budget.max_duration_seconds / 60)),
        "request_max": budget.max_http_requests,
        "max_urls": budget.max_endpoints,
        "browser_max_pages": min(budget.max_browser_actions, budget.max_endpoints),
        "api_probe_limit": budget.max_endpoints,
        "phase4_max_seconds": budget.max_tool_wall_seconds,
        "nuclei_max_targets": budget.max_endpoints,
        "active_worklist_max": budget.max_endpoints,
    }
    if policy.active_testing:
        custom_budget.update({
            "active_max_seconds": budget.max_tool_wall_seconds,
            "active_max_endpoints": budget.max_endpoints,
        })

    normalized.update({
        "custom_budget": custom_budget,
        "max_workers": budget.max_workers,
        "allow_state_changing_http": policy.allow_state_changing_http,
        "include_families": list(policy.include_families),
        "exclude_families": list(policy.exclude_families),
        "scan_generation": admission.plan.generation,
        "scan_engine": admission.plan.engine,
        "_v2_worker_authority": {
            "schema_version": admission.plan.schema_version,
            "plan_digest": admission.plan.digest,
            "engine": admission.plan.engine,
            "generation": admission.plan.generation,
            "allow_state_changing_http": policy.allow_state_changing_http,
            "max_workers": budget.max_workers,
            "backing_scan_type": admission.backing_scan_type,
            "temporary_backing_adapter": True,
        },
    })
    if shard_authority is not None:
        normalized["_v2_worker_authority"].update({
            "parent_scan_id": shard_authority.parent_scan_id,
            "parent_plan_digest": shard_authority.parent_execution_plan_digest,
            "shard_options_digest": shard_authority.options_digest,
            "shard_label": shard_authority.shard_label,
            "shard_index": shard_authority.shard_index,
            "shard_count": shard_authority.shard_count,
            "parallel_discovery": shard_authority.parallel_discovery,
        })
    if "parallel_worker_count" in normalized:
        try:
            normalized["parallel_worker_count"] = min(
                max(1, int(normalized["parallel_worker_count"])),
                budget.max_workers,
            )
        except (TypeError, ValueError):
            normalized["parallel_worker_count"] = budget.max_workers
    return normalized, admission


def execution_result_metadata(admission: WorkerScanAdmission) -> dict[str, Any] | None:
    if not admission.canonical or admission.plan is None:
        return None
    return {
        **admission.plan.canonical_dict(),
        "plan_digest": admission.plan.digest,
        "compatibility": {
            "backing_scan_type": admission.backing_scan_type,
            "temporary": True,
        },
    }
