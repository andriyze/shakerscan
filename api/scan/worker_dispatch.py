"""Canonical Scan V2 dispatch adapter for the current worker process.

This module is deliberately small and side-effect free. It converts a validated
``WorkerScanAdmission`` into the bounded options understood by the existing
scanner subprocess while preserving the canonical plan as the only authority.
"""

from __future__ import annotations

import math
from typing import Any, Mapping

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
    policy, budget = admission.plan.policy, admission.plan.budget
    custom_budget = dict(normalized.get("custom_budget") or {})
    custom_budget.update({
        "max_duration_minutes": max(1, math.ceil(budget.max_duration_seconds / 60)),
        "request_max": budget.max_http_requests,
        "max_urls": budget.max_endpoints,
    })
    normalized.update({
        "custom_budget": custom_budget,
        "include_families": list(policy.include_families),
        "exclude_families": list(policy.exclude_families),
        "scan_generation": admission.plan.generation,
        "scan_engine": admission.plan.engine,
        "_v2_worker_authority": {
            "schema_version": admission.plan.schema_version,
            "plan_digest": admission.plan.digest,
            "engine": admission.plan.engine,
            "generation": admission.plan.generation,
            "backing_scan_type": admission.backing_scan_type,
            "temporary_backing_adapter": True,
        },
    })
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
