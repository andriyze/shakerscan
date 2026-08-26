"""Deterministic whole-plan budget admission for canonical Scan actions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Mapping, Protocol

try:
    from runtime.models import ScanBudget
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.models import ScanBudget

from .action_plan import ScanAction, ScanActionPlan
from .external_process import fit_reservation_scaled_profile


MANDATORY_ACTION_IDS = frozenset({
    "baseline.http",
    "baseline.tls",
    "discover.web_probe",
    "finalize.report",
})

TARGET_TRAFFIC_DIMENSIONS = frozenset({
    "http_requests",
    "state_changing_requests",
    "browser_actions",
    "tcp_ports_attempted",
    "hosts_attempted",
})


class ScanBudgetAllocationError(ValueError):
    """A required action graph cannot fit inside its immutable Scan budget."""

    def __init__(self, action_id: str, shortages: Mapping[str, int]) -> None:
        self.action_id = action_id
        self.shortages = dict(sorted(shortages.items()))
        super().__init__(
            f"required Scan action {action_id} exceeds the plan budget: {self.shortages}"
        )


@dataclass(frozen=True)
class ScanBudgetAllocation:
    plan: ScanActionPlan
    limits: Mapping[str, int]
    allocated: Mapping[str, int]
    residual_scan_execute_budget: Mapping[str, int]
    skipped_action_ids: tuple[str, ...]

    @property
    def unallocated_budget(self) -> Mapping[str, int]:
        """Authority not assigned to any action in this immutable plan."""
        return self.residual_scan_execute_budget


class ScanBudgetLimits(Protocol):
    def ledger_limits(self) -> Mapping[str, int]: ...


def _phase(action: ScanAction) -> int:
    if action.action_id in MANDATORY_ACTION_IDS:
        return 0
    if action.required:
        return 1
    if action.supporting:
        return 2
    return 3


def allocate_scan_action_plan(
    plan: ScanActionPlan,
    budget: ScanBudget | ScanBudgetLimits,
    *,
    assign_residual_to_finalizer: bool = False,
    require_finalizer: bool = True,
    reserved_budget: Mapping[str, int] | None = None,
) -> ScanBudgetAllocation:
    """Admit the complete worst-case graph before any action may execute.

    Registry maximums are retained unless a capability declares reviewed process
    tiers. A selected smaller tier is frozen into the returned action digest before
    traffic. Required work fails admission when no tier fits; optional work remains
    in the immutable plan with a stable skip reason. Residual authority remains
    visibly unallocated; explicit continuation holds stay in that residual authority.
    The pure finalizer never receives target-traffic authority.
    """
    limits = budget.ledger_limits()
    reserved = {
        str(name): int(amount)
        for name, amount in dict(reserved_budget or {}).items()
    }
    undeclared_reserved = set(reserved) - set(limits)
    invalid_reserved = {
        name: amount for name, amount in reserved.items()
        if amount < 0 or amount > limits.get(name, 0)
    }
    if undeclared_reserved or invalid_reserved:
        raise ScanBudgetAllocationError(
            "reserved_budget",
            {
                **{f"undeclared:{name}": reserved[name]
                   for name in sorted(undeclared_reserved)},
                **{f"invalid:{name}": amount
                   for name, amount in sorted(invalid_reserved.items())},
            },
        )
    allocated = {name: 0 for name in limits}
    admitted: dict[str, ScanAction] = {}
    def shortages(action: ScanAction) -> dict[str, int]:
        undeclared = set(action.requested_budget) - set(limits)
        if undeclared:
            raise ScanBudgetAllocationError(
                action.action_id,
                {f"undeclared:{name}": action.requested_budget[name]
                 for name in sorted(undeclared)},
            )
        return {
            name: allocated[name] + reserved.get(name, 0) + amount - limits[name]
            for name, amount in action.requested_budget.items()
            if allocated[name] + reserved.get(name, 0) + amount > limits[name]
        }

    for action in sorted(plan.actions, key=lambda item: (_phase(item), item.action_id)):
        failed_dependencies = tuple(
            dependency
            for dependency in action.dependencies
            if dependency in admitted
            and admitted[dependency].admission_status == "skipped"
        )
        # Finalization consumes all terminal action states, including skips.
        if failed_dependencies and action.action_id != "finalize.report":
            if action.required or action.action_id in MANDATORY_ACTION_IDS:
                raise ScanBudgetAllocationError(
                    action.action_id, {"dependency_failed": len(failed_dependencies)},
                )
            admitted[action.action_id] = replace(
                action,
                requested_budget={},
                admission_status="skipped",
                reason_code="dependency_failed",
                action_digest=None,
            )
            continue

        missing = shortages(action)
        if missing:
            scaled = fit_reservation_scaled_profile(
                action.capability_name,
                requested=action.requested_budget,
                available={
                    name: max(
                        0,
                        limits[name] - allocated[name] - reserved.get(name, 0),
                    )
                    for name in limits
                },
            )
            if scaled is not None:
                action = replace(
                    action, requested_budget=scaled, action_digest=None,
                )
                missing = shortages(action)
        if missing:
            if action.required or action.action_id in MANDATORY_ACTION_IDS:
                raise ScanBudgetAllocationError(action.action_id, missing)
            admitted[action.action_id] = replace(
                action,
                requested_budget={},
                admission_status="skipped",
                reason_code="insufficient_plan_budget",
                action_digest=None,
            )
            continue

        admitted[action.action_id] = action
        for name, amount in action.requested_budget.items():
            allocated[name] += amount

    finalizer = admitted.get("finalize.report")
    if require_finalizer and (
        finalizer is None or finalizer.admission_status != "planned"
    ):
        raise ScanBudgetAllocationError("finalize.report", {"action": 1})
    if not require_finalizer and finalizer is not None:
        raise ScanBudgetAllocationError(
            "finalize.report", {"unexpected_action": 1},
        )
    if finalizer is not None and finalizer.capability_name == "scan.finalize":
        forbidden = {
            name: int(finalizer.requested_budget.get(name, 0))
            for name in TARGET_TRAFFIC_DIMENSIONS
            if int(finalizer.requested_budget.get(name, 0)) > 0
        }
        if forbidden:
            raise ScanBudgetAllocationError(finalizer.action_id, forbidden)

    residual = {name: limits[name] - allocated[name] for name in limits}
    if assign_residual_to_finalizer:
        if finalizer is None:
            raise ScanBudgetAllocationError("finalize.report", {"action": 1})
        if finalizer.capability_name != "scan.execute":
            raise ScanBudgetAllocationError(
                "finalize.report", {"legacy_residual_assignment": 1},
            )
        final_budget = dict(finalizer.requested_budget)
        for name, amount in residual.items():
            if amount:
                final_budget[name] = final_budget.get(name, 0) + amount
                allocated[name] += amount
        admitted[finalizer.action_id] = replace(
            finalizer, requested_budget=final_budget, action_digest=None,
        )

    allocated_plan = ScanActionPlan(
        scan_id=plan.scan_id,
        execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=plan.target_binding_digest,
        actions=tuple(admitted[action.action_id] for action in plan.actions),
    )
    for name, amount in allocated.items():
        if amount > limits[name]:
            raise AssertionError(f"allocated {name} exceeds its immutable Scan limit")

    return ScanBudgetAllocation(
        plan=allocated_plan,
        limits=MappingProxyType(dict(limits)),
        allocated=MappingProxyType(dict(allocated)),
        residual_scan_execute_budget=MappingProxyType(dict(residual)),
        skipped_action_ids=tuple(
            action.action_id
            for action in allocated_plan.actions
            if action.admission_status == "skipped"
        ),
    )
