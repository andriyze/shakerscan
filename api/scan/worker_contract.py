"""Worker admission for canonical Scan V2 jobs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .execution import ScanExecutionPlan
from .worker_validation import (
    V2_KEYS,
    WorkerScanContractError,
    validate_execution_plan,
)


@dataclass(frozen=True)
class WorkerScanAdmission:
    plan: ScanExecutionPlan

    @property
    def canonical(self) -> bool:
        return True

    def canonical_overrides(self) -> dict[str, Any]:
        return {
            "active": self.plan.policy.active_testing,
            "network_discovery": self.plan.policy.network_discovery,
            "subfinder": self.plan.policy.subdomain_discovery,
            "budget_profile": self.plan.budget_profile,
        }

    def normalize_options(self, options: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(options)
        result.update(self.canonical_overrides())
        return result


def resolve_worker_scan_admission(options: Mapping[str, Any]) -> WorkerScanAdmission:
    """Validate complete V2 authority without any legacy downgrade."""
    if not isinstance(options, Mapping):
        raise WorkerScanContractError("scan options must be an object")
    if not V2_KEYS & set(options):
        raise WorkerScanContractError(
            "digest-less deterministic Scan execution has been removed"
        )

    plan = validate_execution_plan(options)
    forbidden = sorted(
        {"scan_type", "legacy_scan_type", "quick", "thorough"}.intersection(options)
    )
    if forbidden:
        raise WorkerScanContractError(
            "legacy Scan authority is forbidden in canonical worker jobs: "
            + ", ".join(forbidden)
        )
    for key, expected in (
        ("active", plan.policy.active_testing),
        ("network_discovery", plan.policy.network_discovery),
        ("subfinder", plan.policy.subdomain_discovery),
    ):
        if key in options and options[key] is not None:
            if not isinstance(options[key], bool) or options[key] is not expected:
                raise WorkerScanContractError(f"{key} conflicts with canonical Scan policy")
    if plan.policy.active_testing and bool(options.get("public")):
        raise WorkerScanContractError("public execution is incompatible with active_testing")
    return WorkerScanAdmission(plan=plan)
