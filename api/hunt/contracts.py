"""Pure Hunt V2 policy, budget, and capability resolution.

The external coding agent owns technique sequencing. This module only computes server authority;
it contains no planner or model reasoning loop.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

try:
    from runtime.capability_registry import CAPABILITY_REGISTRY, CapabilitySpec
except ModuleNotFoundError:
    from ..runtime.capability_registry import CAPABILITY_REGISTRY, CapabilitySpec


@dataclass(frozen=True)
class HuntBudget:
    max_duration_seconds: int
    max_capability_calls: int
    max_http_requests: int
    max_active_actions: int
    max_candidates: int
    max_verifications: int
    max_tcp_ports: int
    max_browser_actions: int
    max_state_changing_requests: int
    max_device_fragility_points: int
    max_hosts: int
    max_udp_ports: int
    max_oob_interactions: int

    def ledger_limits(self) -> dict[str, int]:
        return {
            "agent_actions": self.max_capability_calls,
            "active_actions": self.max_active_actions,
            "http_requests": self.max_http_requests,
            "tcp_ports_attempted": self.max_tcp_ports,
            "browser_actions": self.max_browser_actions,
            "state_changing_requests": self.max_state_changing_requests,
            "tool_wall_seconds": self.max_duration_seconds,
            "device_fragility_points": self.max_device_fragility_points,
            "hosts_attempted": self.max_hosts,
            "udp_ports_attempted": self.max_udp_ports,
            "oob_interactions": self.max_oob_interactions,
        }


HUNT_BUDGET_PROFILES: Mapping[str, HuntBudget] = {
    "fast": HuntBudget(900, 20, 500, 4, 20, 4, 100, 20, 4, 20, 50, 100, 10),
    "balanced": HuntBudget(3_600, 80, 5_000, 20, 100, 20, 1_200, 200, 20, 100, 500, 1_000, 50),
    "thorough": HuntBudget(14_400, 300, 20_000, 80, 500, 100, 10_000, 1_000, 80, 500, 5_000, 5_000, 200),
}


@dataclass(frozen=True)
class HuntPolicy:
    target_kind: str
    active_testing: bool
    credential_access: bool
    mutation_allowed: bool
    approval_receipt_id: str | None
    device_fragility_profile: str | None
    budget_profile: str
    budget: HuntBudget

    def public(self) -> dict[str, Any]:
        result = asdict(self)
        result["budget"] = asdict(self.budget)
        return result


def resolve_hunt_policy(
    *,
    target_kind: str,
    budget_profile: str | None,
    approval_receipt_id: str | None,
    approval_validated: bool,
    credentials_available: bool = False,
    device_fragility_profile: str | None = None,
) -> HuntPolicy:
    kind = str(target_kind or "").strip().lower()
    if kind not in {"web", "api", "device", "network"}:
        raise ValueError("unsupported Hunt target kind")
    profile = str(budget_profile or "balanced").strip().lower()
    try:
        budget = HUNT_BUDGET_PROFILES[profile]
    except KeyError as exc:
        raise ValueError("budget_profile must be fast, balanced, or thorough") from exc
    receipt = str(approval_receipt_id or "").strip() or None
    active = bool(receipt and approval_validated)
    return HuntPolicy(
        target_kind=kind,
        active_testing=active,
        credential_access=bool(active and credentials_available),
        mutation_allowed=False,
        approval_receipt_id=receipt,
        device_fragility_profile=(str(device_fragility_profile).strip() or None)
        if kind == "device" and device_fragility_profile else None,
        budget_profile=profile,
        budget=budget,
    )


def _capability_public(spec: CapabilitySpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "description": spec.description,
        "risk_tier": spec.risk_tier,
        "input_schema": dict(spec.input_schema),
        "output_schema": spec.output_schema,
        "budget_cost": dict(spec.budget_cost),
        "required_approval": spec.required_approval,
        "evidence_contract": list(spec.evidence_contract),
    }


def capability_manifest(policy: HuntPolicy) -> list[dict[str, Any]]:
    return [
        _capability_public(spec)
        for spec in CAPABILITY_REGISTRY.list(
            target_kind=policy.target_kind,
            include_active=policy.active_testing,
        )
    ]
