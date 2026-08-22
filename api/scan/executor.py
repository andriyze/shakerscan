"""Native fixed-stage execution contract for deterministic Scan V2.

The current scanner subprocess remains an adapter while detector code is migrated,
but canonical workers select behavior only from the immutable Scan plan and this
fixed phase graph. Compatibility presets never cross this boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from typing import Any, Mapping

from .execution import ScanExecutionPlan
from .jobs import (
    ScanShardAuthority,
    ScanShardBudget,
    target_binding_from_payload,
)
from .worker_validation import (
    FAMILY_RE,
    WorkerScanContractError,
    validate_execution_plan,
)

try:
    from runtime.models import ScanBudget, TargetBinding
except ModuleNotFoundError:
    from ..runtime.models import ScanBudget, TargetBinding


NATIVE_SCAN_EXECUTION_SCHEMA = "native-scan-execution/v3"
NATIVE_SCAN_STAGES = (
    "bind_target",
    "resolve_inputs",
    "discover_surface",
    "discover_network",
    "deterministic_baseline",
    "deterministic_active",
    "verify_candidates",
    "finalize_evidence",
)
_INTERNAL_FAMILY_KEYS = (
    "asm_check_family", "check_family", "coverage_attempt_family",
)
_LEGACY_BEHAVIOR_KEYS = frozenset({
    "scan_type", "legacy_scan_type", "quick", "thorough", "complete",
    "complete_tier", "smart_mode", "aggressive", "exploit_depth",
    "no_early_stop", "thorough_params", "nuclei", "xss", "sqli",
    "vuln_auth", "vuln_injection", "vuln_web", "exposure_client",
    "exposure_infra", "threat_intel", "deep_domxss", "oob_callback_url",
    "smart_bola_max_endpoints", "dom_xss_max_files", "sqli_extract_max",
    "oob_max_findings", "oob_max_payloads",
})
SCAN_RUNTIME_BUDGET_DIMENSIONS = (
    "http_requests",
    "state_changing_requests",
    "browser_actions",
    "tcp_ports_attempted",
    "hosts_attempted",
    "tool_wall_seconds",
)


class NativeScanExecutionError(ValueError):
    """A canonical Scan cannot be represented by the native fixed-stage graph."""


def _digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _focused_family(
    plan: ScanExecutionPlan, options: Mapping[str, Any],
) -> str | None:
    selected: list[str] = []
    for key in _INTERNAL_FAMILY_KEYS:
        raw = options.get(key)
        if raw in (None, ""):
            continue
        if not isinstance(raw, str):
            raise NativeScanExecutionError(
                f"canonical internal family assignment {key} must be a string"
            )
        family = raw.strip().lower()
        if family != raw or not FAMILY_RE.fullmatch(family):
            raise NativeScanExecutionError(
                f"canonical internal family assignment {key} is invalid"
            )
        selected.append(family)
    if len(set(selected)) > 1:
        raise NativeScanExecutionError(
            "canonical shard contains conflicting internal family assignments"
        )
    family = selected[0] if selected else None
    if not family or family == "all":
        return None
    include = set(plan.policy.include_families)
    exclude = set(plan.policy.exclude_families)
    if family in exclude or (include and family not in include):
        raise NativeScanExecutionError(
            f"internal family assignment {family!r} exceeds canonical Scan policy"
        )
    return family


def _bool_option(options: Mapping[str, Any], key: str) -> bool:
    value = options.get(key)
    if value is None:
        return False
    if not isinstance(value, bool):
        raise NativeScanExecutionError(f"canonical adapter option {key} must be a boolean")
    return value


def _budget_payload(budget: ScanBudget | ScanShardBudget) -> dict[str, int]:
    if isinstance(budget, ScanShardBudget):
        return budget.payload()
    return {
        "max_duration_seconds": budget.max_duration_seconds,
        "max_http_requests": budget.max_http_requests,
        "max_endpoints": budget.max_endpoints,
        "max_browser_actions": budget.max_browser_actions,
        "max_tcp_ports": budget.max_tcp_ports,
        "max_tool_wall_seconds": budget.max_tool_wall_seconds,
        "max_workers": budget.max_workers,
    }


def _runtime_budget_limits(
    plan: ScanExecutionPlan,
    budget: ScanBudget | ScanShardBudget,
    target: TargetBinding,
) -> dict[str, int]:
    values = _budget_payload(budget)
    state_changing = (
        values["max_http_requests"]
        if plan.policy.active_testing and plan.policy.allow_state_changing_http
        else 0
    )
    return {
        "http_requests": values["max_http_requests"],
        "state_changing_requests": state_changing,
        "browser_actions": values["max_browser_actions"],
        # Canonical port discovery is separately reserved. The native baseline
        # may use one additional TCP port for its frozen-address TLS handshake.
        "tcp_ports_attempted": min(
            values["max_tcp_ports"],
            1 if any(
                str(origin).lower().startswith("https://")
                for origin in target.allowed_origins
            ) else 0,
        ),
        "hosts_attempted": values["max_endpoints"],
        "tool_wall_seconds": values["max_tool_wall_seconds"],
    }


def _normalize_runtime_budget(
    value: Mapping[str, Any],
    *,
    limits: Mapping[str, int],
) -> dict[str, int]:
    if set(value) != set(SCAN_RUNTIME_BUDGET_DIMENSIONS):
        raise NativeScanExecutionError(
            "native Scan runtime budget dimensions are invalid"
        )
    normalized: dict[str, int] = {}
    for name in SCAN_RUNTIME_BUDGET_DIMENSIONS:
        raw = value.get(name)
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise NativeScanExecutionError(
                f"native Scan runtime budget {name} must be an integer"
            )
        amount = raw
        if amount < 0 or amount > int(limits[name]):
            raise NativeScanExecutionError(
                f"native Scan runtime budget {name} exceeds its authority"
            )
        normalized[name] = amount
    if normalized["state_changing_requests"] > normalized["http_requests"]:
        raise NativeScanExecutionError(
            "state-changing runtime budget exceeds HTTP runtime budget"
        )
    return normalized


def _scanner_budget_options(
    budget: ScanBudget | ScanShardBudget,
    *, active_testing: bool,
) -> dict[str, int]:
    values = _budget_payload(budget)
    result = {
        "max_duration_minutes": max(1, (values["max_duration_seconds"] + 59) // 60),
        "request_max": values["max_http_requests"],
        "max_urls": values["max_endpoints"],
        "browser_max_pages": min(
            values["max_browser_actions"], values["max_endpoints"],
        ),
        "api_probe_limit": values["max_endpoints"],
        "phase4_max_seconds": values["max_tool_wall_seconds"],
        "nuclei_max_targets": values["max_endpoints"],
        "active_worklist_max": values["max_endpoints"],
    }
    if active_testing:
        result.update({
            "active_max_seconds": values["max_tool_wall_seconds"],
            "active_max_endpoints": values["max_endpoints"],
        })
    return result


@dataclass(frozen=True)
class NativeScanExecution:
    execution_plan: ScanExecutionPlan
    target_binding: TargetBinding
    execution_budget: ScanBudget | ScanShardBudget
    shard_authority: ScanShardAuthority | None = None
    focused_family: str | None = None
    skip_global_checks: bool = False
    focused_endpoints_only: bool = False
    zero_rediscovery: bool = False
    discovery_manifest_only: bool = False
    runtime_budget: Mapping[str, int] | None = None

    def __post_init__(self) -> None:
        limits = _runtime_budget_limits(
            self.execution_plan, self.execution_budget, self.target_binding,
        )
        normalized = _normalize_runtime_budget(
            limits if self.runtime_budget is None else self.runtime_budget,
            limits=limits,
        )
        object.__setattr__(self, "runtime_budget", normalized)

    def with_runtime_budget(
        self, runtime_budget: Mapping[str, Any],
    ) -> "NativeScanExecution":
        return replace(self, runtime_budget=dict(runtime_budget))

    def stage_rows(self) -> tuple[dict[str, Any], ...]:
        policy = self.execution_plan.policy
        rows: list[dict[str, Any]] = []
        for name in NATIVE_SCAN_STAGES:
            enabled = True
            reason = "required"
            if name == "discover_surface" and self.zero_rediscovery:
                enabled, reason = False, "assigned_endpoint_scope"
            elif name == "discover_network":
                placed_discovery = bool(
                    self.shard_authority is not None
                    and self.shard_authority.parallel_discovery
                )
                enabled = bool(
                    policy.network_discovery
                    and (not self.skip_global_checks or placed_discovery)
                    and (not self.discovery_manifest_only or placed_discovery)
                )
                if enabled:
                    reason = "worker_capability_stage"
                elif self.discovery_manifest_only:
                    reason = "discovery_manifest_only"
                elif self.skip_global_checks:
                    reason = "global_checks_skipped"
                else:
                    reason = "policy_disabled"
            elif name == "deterministic_baseline" and self.discovery_manifest_only:
                enabled, reason = False, "discovery_manifest_only"
            elif name == "deterministic_active":
                enabled = bool(policy.active_testing and not self.discovery_manifest_only)
                reason = "policy_enabled" if enabled else "policy_disabled"
            rows.append({"name": name, "enabled": enabled, "reason": reason})
        return tuple(rows)

    def payload(self) -> dict[str, Any]:
        core = {
            "schema_version": NATIVE_SCAN_EXECUTION_SCHEMA,
            "execution_plan": self.execution_plan.canonical_dict(),
            "execution_plan_digest": self.execution_plan.digest,
            "target_binding": self.target_binding.canonical_dict(),
            "target_binding_digest": self.target_binding.digest,
            "execution_budget": _budget_payload(self.execution_budget),
            "runtime_budget": dict(self.runtime_budget or {}),
            "shard_authority": (
                self.shard_authority.payload() if self.shard_authority is not None else None
            ),
            "stages": list(self.stage_rows()),
            "focused_family": self.focused_family,
            "adapter_scope": {
                "skip_global_checks": self.skip_global_checks,
                "focused_endpoints_only": self.focused_endpoints_only,
                "zero_rediscovery": self.zero_rediscovery,
                "discovery_manifest_only": self.discovery_manifest_only,
            },
        }
        return {**core, "execution_digest": _digest(core)}

    def normalize_options(self, options: Mapping[str, Any]) -> dict[str, Any]:
        normalized = {
            str(key): value
            for key, value in options.items()
            if str(key) not in _LEGACY_BEHAVIOR_KEYS
        }
        policy = self.execution_plan.policy
        normalized.update({
            "active": policy.active_testing,
            # Network policy is executed by worker-owned registry capabilities.
            # The scanner subprocess must not repeat unreserved port traffic.
            "network_discovery": False,
            "subfinder": False,
            "request_budget_mode": "enforce",
            "native_scan_execution": self.payload(),
            "custom_budget": _scanner_budget_options(
                self.execution_budget,
                active_testing=policy.active_testing,
            ),
        })
        runtime = dict(self.runtime_budget or {})
        normalized["custom_budget"].update({
            "request_max": runtime["http_requests"],
            "max_urls": runtime["hosts_attempted"],
            "browser_max_pages": min(
                runtime["browser_actions"], runtime["hosts_attempted"],
            ),
            "api_probe_limit": runtime["hosts_attempted"],
            "phase4_max_seconds": runtime["tool_wall_seconds"],
            "nuclei_max_targets": runtime["hosts_attempted"],
            "active_worklist_max": runtime["hosts_attempted"],
        })
        if policy.active_testing:
            normalized["custom_budget"].update({
                "active_max_seconds": runtime["tool_wall_seconds"],
                "active_max_endpoints": runtime["hosts_attempted"],
            })
        normalized["request_budget_reserved"] = runtime["http_requests"]
        for key in _INTERNAL_FAMILY_KEYS:
            normalized.pop(key, None)
        if self.focused_family:
            normalized["asm_check_family"] = self.focused_family
        return normalized


def build_native_scan_execution(
    plan: ScanExecutionPlan,
    options: Mapping[str, Any],
    *,
    target_binding: TargetBinding | Mapping[str, Any] | None = None,
) -> NativeScanExecution:
    if not isinstance(options, Mapping):
        raise NativeScanExecutionError("canonical Scan options must be an object")
    raw_target_binding = (
        target_binding
        if target_binding is not None
        else options.get("_canonical_target_binding")
    )
    try:
        if isinstance(raw_target_binding, Mapping):
            binding = target_binding_from_payload(raw_target_binding)
        elif callable(getattr(raw_target_binding, "canonical_dict", None)):
            binding = target_binding_from_payload(raw_target_binding.canonical_dict())
        else:
            binding = target_binding_from_payload(raw_target_binding)
    except (TypeError, ValueError) as exc:
        raise NativeScanExecutionError(
            f"canonical target binding is invalid: {exc}"
        ) from exc
    if not binding.allowed_origins or not binding.allowed_addresses:
        raise NativeScanExecutionError(
            "canonical target binding requires frozen origins and addresses"
        )
    if binding.scope_receipt_id != plan.policy.scope_receipt_id:
        raise NativeScanExecutionError(
            "canonical target binding scope receipt does not match the Scan plan"
        )
    shard_authority = None
    if options.get("canonical_shard_authority") is not None:
        try:
            shard_authority = ScanShardAuthority.from_payload(
                options["canonical_shard_authority"]
            )
            shard_authority.validate_against_plan(plan)
        except (TypeError, ValueError) as exc:
            raise NativeScanExecutionError(
                f"canonical shard authority is invalid: {exc}"
            ) from exc
    skip_global_checks = _bool_option(options, "skip_global_checks")
    focused_endpoints_only = _bool_option(options, "focused_endpoints_only")
    zero_rediscovery = _bool_option(options, "zero_rediscovery")
    parallel_discovery = _bool_option(options, "parallel_discovery")
    discovery_manifest_only = _bool_option(options, "discovery_manifest_only")
    discovery_only = bool(parallel_discovery or discovery_manifest_only)
    if shard_authority is not None and shard_authority.parallel_discovery != discovery_only:
        raise NativeScanExecutionError(
            "canonical shard discovery scope conflicts with shard authority"
        )
    execution_budget = (
        shard_authority.sub_budget if shard_authority is not None else plan.budget
    )
    return NativeScanExecution(
        execution_plan=plan,
        target_binding=binding,
        execution_budget=execution_budget,
        shard_authority=shard_authority,
        focused_family=_focused_family(plan, options),
        skip_global_checks=skip_global_checks,
        focused_endpoints_only=focused_endpoints_only,
        zero_rediscovery=zero_rediscovery,
        discovery_manifest_only=discovery_only,
    )


def validate_native_scan_execution_payload(value: Any) -> dict[str, Any]:
    """Validate the secret-free worker-to-scanner execution envelope."""
    if not isinstance(value, Mapping):
        raise NativeScanExecutionError("native Scan execution must be an object")
    raw = dict(value)
    expected = {
        "schema_version", "execution_plan", "execution_plan_digest", "stages",
        "target_binding", "target_binding_digest", "execution_budget",
        "runtime_budget",
        "shard_authority", "focused_family", "adapter_scope", "execution_digest",
    }
    if set(raw) != expected:
        raise NativeScanExecutionError("native Scan execution fields are invalid")
    if raw["schema_version"] != NATIVE_SCAN_EXECUTION_SCHEMA:
        raise NativeScanExecutionError("native Scan execution schema is invalid")
    core = {key: raw[key] for key in expected if key != "execution_digest"}
    if raw["execution_digest"] != _digest(core):
        raise NativeScanExecutionError("native Scan execution digest mismatch")
    plan = raw.get("execution_plan")
    if not isinstance(plan, Mapping):
        raise NativeScanExecutionError("native Scan execution plan is invalid")
    if set(plan) != {
        "schema_version", "generation", "engine", "budget_profile", "policy", "budget",
    }:
        raise NativeScanExecutionError("native Scan execution-plan fields are invalid")
    if (
        plan.get("schema_version") != "scan-execution-plan/v1"
        or plan.get("generation") != "v2"
        or plan.get("engine") != "scan"
    ):
        raise NativeScanExecutionError("native Scan requires the V2 Scan engine")
    try:
        reconstructed_plan = validate_execution_plan({
            "scan_generation": plan.get("generation"),
            "scan_engine": plan.get("engine"),
            "scan_execution_plan_schema": plan.get("schema_version"),
            "scan_execution_plan_digest": raw.get("execution_plan_digest"),
            "scan_execution_plan": dict(plan),
            "scan_policy": plan.get("policy"),
            "resolved_scan_budget": plan.get("budget"),
            "budget_profile": plan.get("budget_profile"),
            "scan_compatibility": {},
        })
    except (TypeError, ValueError, WorkerScanContractError) as exc:
        raise NativeScanExecutionError(f"native Scan plan is invalid: {exc}") from exc
    try:
        reconstructed_binding = target_binding_from_payload(raw.get("target_binding"))
    except (TypeError, ValueError) as exc:
        raise NativeScanExecutionError(
            f"native Scan target binding is invalid: {exc}"
        ) from exc
    if raw.get("target_binding_digest") != reconstructed_binding.digest:
        raise NativeScanExecutionError("native Scan target-binding digest mismatch")
    raw_shard = raw.get("shard_authority")
    expected_options: dict[str, Any] = {}
    expected_options["_canonical_target_binding"] = reconstructed_binding.canonical_dict()
    if raw_shard is not None:
        expected_options["canonical_shard_authority"] = raw_shard
    execution_budget = raw.get("execution_budget")
    if not isinstance(execution_budget, Mapping):
        raise NativeScanExecutionError("native Scan execution budget is invalid")
    try:
        expected_budget = (
            ScanShardAuthority.from_payload(raw_shard).sub_budget.payload()
            if raw_shard is not None
            else _budget_payload(reconstructed_plan.budget)
        )
    except (TypeError, ValueError) as exc:
        raise NativeScanExecutionError(f"native Scan shard authority is invalid: {exc}") from exc
    if dict(execution_budget) != expected_budget:
        raise NativeScanExecutionError(
            "native Scan execution budget does not match its authority"
        )
    runtime_budget = raw.get("runtime_budget")
    if not isinstance(runtime_budget, Mapping):
        raise NativeScanExecutionError("native Scan runtime budget is invalid")
    scope = raw.get("adapter_scope")
    if not isinstance(scope, Mapping) or set(scope) != {
        "skip_global_checks", "focused_endpoints_only", "zero_rediscovery",
        "discovery_manifest_only",
    } or any(not isinstance(item, bool) for item in scope.values()):
        raise NativeScanExecutionError("native Scan adapter scope is invalid")
    expected_options.update(dict(scope))
    if scope["discovery_manifest_only"]:
        expected_options["discovery_manifest_only"] = True
    focused_family = str(raw.get("focused_family") or "").strip().lower() or None
    if focused_family:
        expected_options["asm_check_family"] = focused_family
    expected_execution = build_native_scan_execution(
        reconstructed_plan, expected_options,
    ).with_runtime_budget(runtime_budget)
    if raw != expected_execution.payload():
        raise NativeScanExecutionError(
            "native Scan execution decisions do not match the canonical plan"
        )
    return raw
