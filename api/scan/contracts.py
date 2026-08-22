"""Canonical Scan V2 request resolution and legacy compatibility mapping."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, Mapping

try:
    from check_registry import normalize_scan_policy_families
except ModuleNotFoundError:
    from ..check_registry import normalize_scan_policy_families

try:
    from runtime.models import ScanBudget, ScanPolicy
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.models import ScanBudget, ScanPolicy

from .execution import ScanExecutionPlan
from .legacy import (
    LEGACY_SCAN_MAPPING,
    compatibility_executor_alias,
    translate_legacy_scan_type,
)


BUDGET_PROFILES: Mapping[str, ScanBudget] = {
    "fast": ScanBudget(300, 1_000, 500, 50, 1_000, 180, 2),
    "balanced": ScanBudget(1_200, 5_000, 2_000, 200, 5_000, 900, 4),
    "thorough": ScanBudget(3_600, 20_000, 10_000, 1_000, 20_000, 2_700, 8),
}

_BUDGET_CEILINGS = {
    "max_duration_seconds": 172_800,
    "max_http_requests": 1_000_000,
    "max_endpoints": 100_000,
    "max_browser_actions": 20_000,
    "max_tcp_ports": 262_140,
    "max_tool_wall_seconds": 86_400,
    "max_workers": 128,
}

SCAN_AUTHENTICATION_KEYS = frozenset({
    "auth_cookies", "auth_header", "auth_headers_json", "auth_scenario_json",
    "login_url", "login_username", "login_password", "login_extra_fields", "auto_auth",
    "oauth_client_id", "oauth_client_secret", "oauth_token_url", "oauth_scope",
    "oauth_username", "oauth_password", "user2_cookies", "user2_header",
    "user2_login_username", "user2_login_password",
})


def normalize_scan_authentication(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize the bounded V2 authentication contract without logging secret values."""
    authentication = dict(value or {})
    unknown = set(authentication) - set(SCAN_AUTHENTICATION_KEYS)
    if unknown:
        raise ValueError(f"unsupported authentication fields: {', '.join(sorted(unknown))}")
    normalized: dict[str, Any] = {}
    for key, item in authentication.items():
        if item in (None, "", [], {}):
            continue
        if key == "auto_auth":
            if not isinstance(item, bool):
                raise ValueError("auto_auth must be a boolean")
            normalized[key] = item
            continue
        if not isinstance(item, str) or len(item) > 131_072:
            raise ValueError(f"{key} must be a string of at most 131072 characters")
        normalized[key] = item
    return normalized


@dataclass(frozen=True)
class ResolvedScanContract:
    generation: str
    policy: ScanPolicy
    budget_profile: str
    budget: ScanBudget
    execution_plan: ScanExecutionPlan
    legacy_executor_alias: str
    legacy_scan_type: str | None = None
    deprecations: tuple[Mapping[str, Any], ...] = ()

    @property
    def execution_scan_type(self) -> str:
        """Deprecated compatibility property for the current monolithic worker.

        Canonical consumers must use ``execution_plan``. This property can be removed
        once worker/scanner dispatch no longer accepts six legacy mode names.
        """
        return self.legacy_executor_alias

    def option_metadata(self) -> dict[str, Any]:
        metadata = self.execution_plan.option_metadata()
        metadata.update({
            "legacy_scan_type": self.legacy_scan_type,
            "deprecations": [dict(item) for item in self.deprecations],
            "scan_compatibility": {
                "legacy_executor_alias": self.legacy_executor_alias,
                "temporary": True,
            },
        })
        return metadata


def bind_scan_scope_receipt(
    contract: ResolvedScanContract, scope_receipt_id: str | None,
) -> ResolvedScanContract:
    """Bind a validated scope receipt into every canonical Scan snapshot.

    Target-bound approval is validated only after the target row exists. Rebuild
    the immutable plan at that boundary instead of mutating the flattened policy
    and leaving the execution-plan digest stale.
    """
    scope_id = str(scope_receipt_id or "").strip() or None
    if contract.policy.scope_receipt_id == scope_id:
        return contract
    if contract.policy.scope_receipt_id and scope_id != contract.policy.scope_receipt_id:
        raise ValueError("validated scope receipt conflicts with the Scan contract")
    policy = replace(contract.policy, scope_receipt_id=scope_id)
    plan = ScanExecutionPlan(
        policy=policy,
        budget_profile=contract.budget_profile,
        budget=contract.budget,
    )
    return replace(contract, policy=policy, execution_plan=plan)


def _resolve_budget(profile: str, advanced: Mapping[str, Any] | None) -> ScanBudget:
    try:
        base = asdict(BUDGET_PROFILES[profile])
    except KeyError as exc:
        raise ValueError("budget_profile must be fast, balanced, or thorough") from exc
    advanced = advanced if isinstance(advanced, Mapping) else {}
    unknown = set(advanced) - set(_BUDGET_CEILINGS) - {
        "include_families", "exclude_families", "force_single_worker"
    }
    if unknown:
        raise ValueError(f"unsupported advanced scan limits: {', '.join(sorted(unknown))}")
    for key, ceiling in _BUDGET_CEILINGS.items():
        if key not in advanced or advanced[key] is None:
            continue
        value = advanced[key]
        if isinstance(value, bool):
            raise ValueError(f"{key} must be a positive integer")
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be a positive integer") from exc
        if not 1 <= value <= ceiling:
            raise ValueError(f"{key} must be between 1 and {ceiling}")
        base[key] = value
    if advanced.get("force_single_worker"):
        base["max_workers"] = 1
    return ScanBudget(**base)


def resolve_scan_contract(
    *,
    budget_profile: str | None = None,
    policy: Mapping[str, Any] | None = None,
    advanced: Mapping[str, Any] | None = None,
    approval_receipt_id: str | None = None,
    legacy_scan_type: str | None = None,
) -> ResolvedScanContract:
    """Resolve one immutable V2 Scan plan plus a temporary old-worker adapter.

    Legacy ``scan_type`` is translated exactly once at this boundary. The canonical
    execution plan always has engine identity ``scan``; it never becomes Hunt and it
    never embeds ``quick``, ``deep``, ``full``, ``aggressive``, or ``smart``.
    """
    translation = translate_legacy_scan_type(legacy_scan_type)
    compatibility_advanced: dict[str, Any] = {}
    deprecation_items: list[Mapping[str, Any]] = []
    if translation is not None:
        profile = translation.budget_profile
        active_testing = translation.active_testing
        compatibility_advanced.update(translation.advanced)
        deprecation_items.append(translation.deprecation())
    else:
        requested_profile = str(budget_profile or "balanced").strip().lower()
        if requested_profile == "exhaustive":
            profile = "thorough"
            deprecation_items.append({
                "field": "budget_profile", "value": "exhaustive",
                "replacement": "thorough",
            })
        else:
            profile = requested_profile
        active_testing = bool((policy or {}).get("active_testing", False))

    policy_data = policy if isinstance(policy, Mapping) else {}
    allowed_policy_keys = {
        "active_testing", "allow_state_changing_http", "network_discovery",
        "subdomain_discovery", "include_families", "exclude_families",
    }
    unknown_policy = set(policy_data) - allowed_policy_keys
    if unknown_policy:
        raise ValueError(f"unsupported scan policy fields: {', '.join(sorted(unknown_policy))}")
    active_testing = bool(
        active_testing if translation is not None else policy_data.get("active_testing", False)
    )
    include = normalize_scan_policy_families(
        policy_data.get("include_families")
        or (advanced or {}).get("include_families")
        or [],
        field="include_families",
    )
    exclude = normalize_scan_policy_families(
        policy_data.get("exclude_families")
        or (advanced or {}).get("exclude_families")
        or [],
        field="exclude_families",
    )
    if set(include) & set(exclude):
        raise ValueError("include_families and exclude_families must not overlap")
    resolved_policy = ScanPolicy(
        active_testing=active_testing,
        allow_state_changing_http=bool(policy_data.get("allow_state_changing_http", False)),
        network_discovery=bool(policy_data.get("network_discovery", False)),
        subdomain_discovery=bool(policy_data.get("subdomain_discovery", False)),
        include_families=include,
        exclude_families=exclude,
        approval_receipt_id=str(approval_receipt_id or "").strip() or None,
    )
    if resolved_policy.allow_state_changing_http and not resolved_policy.active_testing:
        raise ValueError("state-changing HTTP requires active_testing")
    if resolved_policy.network_discovery and not resolved_policy.active_testing:
        raise ValueError("network_discovery requires active_testing")
    if resolved_policy.network_discovery and not resolved_policy.approval_receipt_id:
        raise ValueError("network_discovery requires a target-bound approval receipt")
    merged_advanced = {**compatibility_advanced, **dict(advanced or {})}
    budget = _resolve_budget(profile, merged_advanced)
    execution_plan = ScanExecutionPlan(
        policy=resolved_policy,
        budget_profile=profile,
        budget=budget,
    )
    return ResolvedScanContract(
        generation="v2",
        policy=resolved_policy,
        budget_profile=profile,
        budget=budget,
        execution_plan=execution_plan,
        legacy_executor_alias=compatibility_executor_alias(
            policy=resolved_policy, translation=translation
        ),
        legacy_scan_type=(translation.legacy_scan_type if translation is not None else None),
        deprecations=tuple(deprecation_items),
    )
