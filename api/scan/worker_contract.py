"""Worker admission for canonical Scan V2 jobs and isolated legacy jobs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .execution import ScanExecutionPlan
from .legacy import LEGACY_SCAN_MAPPING, translate_legacy_scan_type
from .worker_validation import (
    V2_KEYS,
    WorkerScanContractError,
    validate_execution_plan,
)


@dataclass(frozen=True)
class WorkerScanAdmission:
    canonical: bool
    backing_scan_type: str
    plan: ScanExecutionPlan | None = None
    legacy_source: str | None = None

    def canonical_overrides(self) -> dict[str, Any]:
        if not self.canonical or self.plan is None:
            return {}
        return {
            "scan_type": self.backing_scan_type,
            "active": self.plan.policy.active_testing,
            "network_discovery": self.plan.policy.network_discovery,
            "subfinder": self.plan.policy.subdomain_discovery,
            "budget_profile": self.plan.budget_profile,
            "quick": False,
            "thorough": False,
        }

    def normalize_options(self, options: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(options)
        result.update(self.canonical_overrides())
        return result


def _legacy(options: Mapping[str, Any]) -> WorkerScanAdmission:
    scan_type = str(options.get("scan_type") or "standard").strip().lower()
    if scan_type not in LEGACY_SCAN_MAPPING:
        allowed = ", ".join(sorted(LEGACY_SCAN_MAPPING))
        raise WorkerScanContractError(
            f"scan_type must be one of: {allowed}"
        )
    return WorkerScanAdmission(False, scan_type, legacy_source=scan_type)


def resolve_worker_scan_admission(options: Mapping[str, Any]) -> WorkerScanAdmission:
    """Validate V2 authority before deriving any legacy CLI flags.

    The presence of any V2 marker makes the complete contract mandatory. Missing V2
    fields never downgrade into legacy execution.
    """
    if not isinstance(options, Mapping):
        raise WorkerScanContractError("scan options must be an object")
    if not V2_KEYS & set(options):
        return _legacy(options)

    plan = validate_execution_plan(options)
    backing = "full" if plan.policy.active_testing else "deep"
    submitted = str(options.get("scan_type") or "").strip().lower()
    if submitted and submitted != backing:
        raise WorkerScanContractError(
            "caller-controlled scan_type conflicts with canonical Scan policy"
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
    if bool(options.get("quick")) or bool(options.get("thorough")):
        raise WorkerScanContractError(
            "legacy quick/thorough flags are invalid for canonical Scan"
        )

    source = options.get("legacy_scan_type")
    if source is not None:
        translation = translate_legacy_scan_type(str(source))
        if translation is None:
            raise WorkerScanContractError("legacy_scan_type metadata is invalid")
        if (
            translation.active_testing != plan.policy.active_testing
            or translation.budget_profile != plan.budget_profile
        ):
            raise WorkerScanContractError(
                "legacy_scan_type metadata conflicts with canonical Scan policy"
            )
        source = translation.legacy_scan_type
    return WorkerScanAdmission(True, backing, plan, source)
