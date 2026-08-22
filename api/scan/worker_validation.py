"""Strict reconstruction of persisted Scan V2 execution plans."""

from __future__ import annotations

from dataclasses import fields
import re
from typing import Any, Mapping

try:
    from check_registry import normalize_scan_policy_families
except ModuleNotFoundError:
    from ..check_registry import normalize_scan_policy_families

try:
    from runtime.models import ScanBudget, ScanPolicy
except ModuleNotFoundError:
    from ..runtime.models import ScanBudget, ScanPolicy

from .execution import (
    SCAN_ENGINE,
    SCAN_EXECUTION_SCHEMA,
    SCAN_GENERATION,
    ScanExecutionPlan,
)


V2_KEYS = frozenset({
    "scan_generation", "scan_engine", "scan_execution_plan_schema",
    "scan_execution_plan_digest", "scan_execution_plan", "scan_policy",
    "resolved_scan_budget", "scan_compatibility",
})
REQUIRED_V2_KEYS = V2_KEYS | {"budget_profile"}
PLAN_KEYS = frozenset({
    "schema_version", "generation", "engine", "budget_profile", "policy", "budget"
})
POLICY_KEYS = frozenset(field.name for field in fields(ScanPolicy))
BUDGET_KEYS = frozenset(field.name for field in fields(ScanBudget))
BUDGET_CEILINGS: Mapping[str, int] = {
    "max_duration_seconds": 172_800,
    "max_http_requests": 1_000_000,
    "max_endpoints": 100_000,
    "max_browser_actions": 20_000,
    "max_tcp_ports": 262_140,
    "max_tool_wall_seconds": 86_400,
    "max_workers": 128,
}
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
FAMILY_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,79}$")
RECEIPT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


class WorkerScanContractError(ValueError):
    """Queued Scan options do not match the persisted execution authority."""


def object_value(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise WorkerScanContractError(f"{name} must be an object")
    return dict(value)


def exact_keys(value: Mapping[str, Any], expected: frozenset[str], name: str) -> None:
    missing, unknown = sorted(expected - set(value)), sorted(set(value) - expected)
    if missing or unknown:
        parts = []
        if missing:
            parts.append(f"missing {', '.join(missing)}")
        if unknown:
            parts.append(f"unknown {', '.join(unknown)}")
        raise WorkerScanContractError(f"{name} fields are invalid: {'; '.join(parts)}")


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise WorkerScanContractError(f"{name} must be a boolean")
    return value


def _receipt(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value != value.strip() or not RECEIPT_RE.fullmatch(value):
        raise WorkerScanContractError(f"{name} is invalid")
    return value


def _families(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > 100:
        raise WorkerScanContractError(f"{name} must be an array of at most 100 items")
    result: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise WorkerScanContractError(f"{name} entries must be strings")
        item = raw.strip().lower()
        if item != raw or not FAMILY_RE.fullmatch(item):
            raise WorkerScanContractError(f"{name} contains an invalid family identifier")
        if item in result:
            raise WorkerScanContractError(f"{name} contains duplicate family identifiers")
        result.append(item)
    try:
        return normalize_scan_policy_families(
            result,
            field=name,
            require_canonical=True,
        )
    except ValueError as exc:
        raise WorkerScanContractError(str(exc)) from exc


def _policy(value: Any) -> ScanPolicy:
    raw = object_value(value, "scan execution policy")
    exact_keys(raw, POLICY_KEYS, "scan execution policy")
    policy = ScanPolicy(
        active_testing=_bool(raw["active_testing"], "active_testing"),
        allow_state_changing_http=_bool(
            raw["allow_state_changing_http"], "allow_state_changing_http"
        ),
        network_discovery=_bool(raw["network_discovery"], "network_discovery"),
        subdomain_discovery=_bool(raw["subdomain_discovery"], "subdomain_discovery"),
        include_families=_families(raw["include_families"], "include_families"),
        exclude_families=_families(raw["exclude_families"], "exclude_families"),
        scope_receipt_id=_receipt(raw["scope_receipt_id"], "scope_receipt_id"),
        approval_receipt_id=_receipt(raw["approval_receipt_id"], "approval_receipt_id"),
    )
    if set(policy.include_families) & set(policy.exclude_families):
        raise WorkerScanContractError("include_families and exclude_families must not overlap")
    if policy.allow_state_changing_http and not policy.active_testing:
        raise WorkerScanContractError("state-changing HTTP requires active_testing")
    if policy.allow_state_changing_http and not policy.approval_receipt_id:
        raise WorkerScanContractError("state-changing HTTP requires an approval receipt")
    if policy.network_discovery and not policy.active_testing:
        raise WorkerScanContractError("network_discovery requires active_testing")
    if policy.network_discovery and not policy.approval_receipt_id:
        raise WorkerScanContractError("network_discovery requires an approval receipt")
    return policy


def _budget(value: Any) -> ScanBudget:
    raw = object_value(value, "scan execution budget")
    exact_keys(raw, BUDGET_KEYS, "scan execution budget")
    normalized: dict[str, int] = {}
    for name in BUDGET_KEYS:
        amount = raw[name]
        if isinstance(amount, bool) or not isinstance(amount, int):
            raise WorkerScanContractError(f"{name} must be a positive integer")
        if not 1 <= amount <= BUDGET_CEILINGS[name]:
            raise WorkerScanContractError(
                f"{name} must be between 1 and {BUDGET_CEILINGS[name]}"
            )
        normalized[name] = amount
    return ScanBudget(**normalized)


def _profile(value: Any) -> str:
    if not isinstance(value, str):
        raise WorkerScanContractError("budget_profile must be a string")
    result = value.strip().lower()
    if value != result or result not in {"fast", "balanced", "thorough"}:
        raise WorkerScanContractError("budget_profile must be fast, balanced, or thorough")
    return result


def validate_execution_plan(options: Mapping[str, Any]) -> ScanExecutionPlan:
    """Reconstruct the plan and verify digest plus flattened snapshots."""
    missing = sorted(REQUIRED_V2_KEYS - set(options))
    if missing:
        raise WorkerScanContractError(
            f"canonical scan metadata is incomplete: missing {', '.join(missing)}"
        )
    if options["scan_generation"] != SCAN_GENERATION:
        raise WorkerScanContractError(f"scan_generation must be {SCAN_GENERATION}")
    if options["scan_engine"] != SCAN_ENGINE:
        raise WorkerScanContractError(f"scan_engine must be {SCAN_ENGINE}")
    if options["scan_execution_plan_schema"] != SCAN_EXECUTION_SCHEMA:
        raise WorkerScanContractError(
            f"scan_execution_plan_schema must be {SCAN_EXECUTION_SCHEMA}"
        )

    raw = object_value(options["scan_execution_plan"], "scan_execution_plan")
    exact_keys(raw, PLAN_KEYS, "scan_execution_plan")
    if raw["schema_version"] != SCAN_EXECUTION_SCHEMA:
        raise WorkerScanContractError("scan execution plan schema is invalid")
    if raw["generation"] != SCAN_GENERATION:
        raise WorkerScanContractError("scan execution plan generation is invalid")
    if raw["engine"] != SCAN_ENGINE:
        raise WorkerScanContractError("scan execution plan engine is invalid")
    plan = ScanExecutionPlan(
        policy=_policy(raw["policy"]),
        budget_profile=_profile(raw["budget_profile"]),
        budget=_budget(raw["budget"]),
    )
    canonical = plan.canonical_dict()
    if raw != canonical:
        raise WorkerScanContractError("scan execution plan is not canonical")
    digest = options["scan_execution_plan_digest"]
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise WorkerScanContractError("scan_execution_plan_digest is invalid")
    if digest != plan.digest:
        raise WorkerScanContractError("scan execution plan digest mismatch")
    if options["budget_profile"] != plan.budget_profile:
        raise WorkerScanContractError("flattened budget_profile does not match the plan")
    if options["scan_policy"] != canonical["policy"]:
        raise WorkerScanContractError("flattened scan_policy does not match the plan")
    if options["resolved_scan_budget"] != canonical["budget"]:
        raise WorkerScanContractError("flattened resolved_scan_budget does not match the plan")
    return plan
