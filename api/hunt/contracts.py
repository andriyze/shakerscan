"""Pure capability resolution for the canonical Hunt V2 authority contract.

The external coding agent owns technique sequencing. ``HuntStartContract`` is the only policy
and budget model; this module projects that authority onto the canonical capability registry.
"""

from __future__ import annotations

from typing import Any

try:
    from runtime.capability_registry import CAPABILITY_REGISTRY, CapabilitySpec
except ModuleNotFoundError:
    from ..runtime.capability_registry import CAPABILITY_REGISTRY, CapabilitySpec

from .start_contract import HuntStartContract, HuntStartContractError


_APPROVAL_POLICIES = frozenset({
    "active_testing",
    "credential_use",
    "network_discovery",
    "oob_interactions",
    "state_changing_http",
})


def capability_is_allowed(
    spec: CapabilitySpec,
    contract: HuntStartContract,
    *,
    credentials_available: bool,
) -> bool:
    """Return whether one registry capability fits the exact authority envelope."""
    if not spec.planner_visible or spec.hunt_executor is None:
        return False
    if contract.target_kind not in spec.target_kinds:
        return False
    policy = contract.policy
    if spec.risk_tier == "active" and not policy.active_testing:
        return False
    if spec.risk_tier == "credential" and not credentials_available:
        return False
    if spec.risk_tier == "mutation" and not policy.allow_state_changing_http:
        return False
    required = spec.required_approval
    if required is not None and required not in _APPROVAL_POLICIES:
        return False
    if required == "active_testing" and not policy.active_testing:
        return False
    if required == "credential_use" and not credentials_available:
        return False
    if required == "network_discovery" and not policy.network_discovery:
        return False
    if required == "oob_interactions" and not policy.allow_oob_interactions:
        return False
    if required == "state_changing_http" and not policy.allow_state_changing_http:
        return False

    ledger_limits = contract.resolved_budget_object.ledger_limits()
    if int(ledger_limits["active_actions"]) == 0 and (
        spec.risk_tier in {"active", "credential", "mutation"}
        or required in {
            "active_testing", "credential_use", "network_discovery",
            "oob_interactions", "state_changing_http",
        }
    ):
        return False
    if any(
        int(amount) > 0 and int(ledger_limits.get(dimension, 0)) == 0
        for dimension, amount in spec.budget_cost.items()
    ):
        return False
    return True


def allowed_capability_names(
    contract: HuntStartContract,
    *,
    credentials_available: bool,
) -> tuple[str, ...]:
    available = {
        spec.name: spec
        for spec in CAPABILITY_REGISTRY.list(
            target_kind=contract.target_kind,
            include_active=True,
        )
        if capability_is_allowed(
            spec,
            contract,
            credentials_available=credentials_available,
        )
    }
    if not contract.capabilities:
        return tuple(available)
    result: list[str] = []
    for name in contract.capabilities:
        try:
            CAPABILITY_REGISTRY.require(name)
        except KeyError as exc:
            raise HuntStartContractError(str(exc)) from exc
        if name not in available:
            raise HuntStartContractError(
                f"capability {name} is outside this target, budget, or Hunt policy"
            )
        if name not in result:
            result.append(name)
    return tuple(result)


def capability_manifest(
    contract: HuntStartContract,
    *,
    credentials_available: bool,
) -> list[dict[str, Any]]:
    allowed = set(allowed_capability_names(
        contract,
        credentials_available=credentials_available,
    ))
    return [
        spec.planner_contract()
        for spec in CAPABILITY_REGISTRY.list(
            target_kind=contract.target_kind,
            include_active=True,
        )
        if spec.name in allowed
    ]
