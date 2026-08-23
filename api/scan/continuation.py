"""Content-addressed two-phase Scan planning after bounded discovery."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping
import uuid

try:
    from runtime.budgets import BUDGET_DIMENSIONS
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.budgets import BUDGET_DIMENSIONS

from .action_plan import ScanAction, ScanActionPlan, ScanActionPlanError


SCAN_CONTINUATION_ALLOCATION_SCHEMA = "scan-continuation-allocation/v1"
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_ACTIONS = 512


class ScanContinuationError(ValueError):
    """A continuation differs from its frozen parent or budget authority."""


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _hex(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _HEX_64_RE.fullmatch(normalized):
        raise ScanContinuationError(f"{name} must be a SHA-256 digest")
    return normalized


def _budget(value: Mapping[str, Any]) -> Mapping[str, int]:
    normalized: dict[str, int] = {}
    for raw_name, raw_amount in dict(value or {}).items():
        name = str(raw_name or "").strip()
        if name not in BUDGET_DIMENSIONS:
            raise ScanContinuationError(
                f"unknown continuation budget dimension: {name}"
            )
        if isinstance(raw_amount, bool) or not isinstance(raw_amount, int):
            raise ScanContinuationError(
                f"continuation budget {name} must be an integer"
            )
        if raw_amount < 0:
            raise ScanContinuationError(
                f"continuation budget {name} must be non-negative"
            )
        normalized[name] = raw_amount
    if not normalized:
        raise ScanContinuationError("continuation budget ceiling is empty")
    return MappingProxyType({name: normalized[name] for name in sorted(normalized)})


@dataclass(frozen=True)
class ContinuationBudgetCeiling:
    """Allocator-compatible view of one already-frozen residual ceiling."""

    limits: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "limits", _budget(self.limits))

    def ledger_limits(self) -> Mapping[str, int]:
        return self.limits


@dataclass(frozen=True)
class ScanContinuationAllocation:
    scan_id: str
    parent_plan_digest: str
    execution_plan_digest: str
    target_binding_digest: str
    parent_action_ids: tuple[str, ...]
    budget_ceiling: Mapping[str, int]
    max_endpoint_entries: int
    max_candidate_entries: int
    required_capabilities: tuple[str, ...] = ()
    schema_version: str = SCAN_CONTINUATION_ALLOCATION_SCHEMA
    allocation_digest: str | None = field(default=None, compare=True)

    def __post_init__(self) -> None:
        if self.schema_version != SCAN_CONTINUATION_ALLOCATION_SCHEMA:
            raise ScanContinuationError("unsupported Scan continuation allocation")
        try:
            scan_id = str(uuid.UUID(str(self.scan_id)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ScanContinuationError("continuation scan_id must be a UUID") from exc
        action_ids = tuple(str(item or "").strip() for item in self.parent_action_ids)
        if (
            not action_ids
            or any(not item for item in action_ids)
            or len(action_ids) > _MAX_ACTIONS
            or len(set(action_ids)) != len(action_ids)
        ):
            raise ScanContinuationError("continuation parent actions are invalid")
        capabilities = tuple(sorted({
            str(item or "").strip() for item in self.required_capabilities
            if str(item or "").strip()
        }))
        if len(capabilities) > 32:
            raise ScanContinuationError("too many required continuation capabilities")
        for name, value, maximum in (
            ("max_endpoint_entries", self.max_endpoint_entries, 100_000),
            ("max_candidate_entries", self.max_candidate_entries, 20_000),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ScanContinuationError(f"{name} is outside its bound")
        object.__setattr__(self, "scan_id", scan_id)
        object.__setattr__(self, "parent_plan_digest", _hex(
            self.parent_plan_digest, name="parent_plan_digest",
        ))
        object.__setattr__(self, "execution_plan_digest", _hex(
            self.execution_plan_digest, name="execution_plan_digest",
        ))
        object.__setattr__(self, "target_binding_digest", _hex(
            self.target_binding_digest, name="target_binding_digest",
        ))
        object.__setattr__(self, "parent_action_ids", action_ids)
        object.__setattr__(self, "budget_ceiling", _budget(self.budget_ceiling))
        object.__setattr__(self, "required_capabilities", capabilities)
        expected = _digest(self.digest_material())
        if self.allocation_digest is not None and _hex(
            self.allocation_digest, name="allocation_digest",
        ) != expected:
            raise ScanContinuationError(
                "allocation_digest does not match continuation authority"
            )
        object.__setattr__(self, "allocation_digest", expected)

    def digest_material(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "parent_plan_digest": self.parent_plan_digest,
            "execution_plan_digest": self.execution_plan_digest,
            "target_binding_digest": self.target_binding_digest,
            "parent_action_ids": list(self.parent_action_ids),
            "budget_ceiling": dict(self.budget_ceiling),
            "max_endpoint_entries": self.max_endpoint_entries,
            "max_candidate_entries": self.max_candidate_entries,
            "required_capabilities": list(self.required_capabilities),
        }

    def canonical_dict(self) -> dict[str, Any]:
        return {**self.digest_material(), "allocation_digest": self.allocation_digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScanContinuationAllocation":
        expected = {
            "schema_version", "scan_id", "parent_plan_digest",
            "execution_plan_digest", "target_binding_digest", "parent_action_ids",
            "budget_ceiling", "max_endpoint_entries", "max_candidate_entries",
            "required_capabilities", "allocation_digest",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ScanContinuationError("continuation allocation fields are invalid")
        return cls(**dict(value))


def merge_scan_action_continuation(
    *,
    parent_plan: ScanActionPlan,
    continuation_plan: ScanActionPlan,
    allocation: ScanContinuationAllocation,
) -> ScanActionPlan:
    """Append a digest-bound continuation without changing executed actions."""
    if (
        parent_plan.scan_id != allocation.scan_id
        or parent_plan.plan_digest != allocation.parent_plan_digest
        or parent_plan.execution_plan_digest != allocation.execution_plan_digest
        or parent_plan.target_binding_digest != allocation.target_binding_digest
        or tuple(action.action_id for action in parent_plan.actions)
        != allocation.parent_action_ids
    ):
        raise ScanContinuationError(
            "continuation allocation differs from its immutable parent plan"
        )
    if (
        continuation_plan.scan_id != parent_plan.scan_id
        or continuation_plan.execution_plan_digest != parent_plan.execution_plan_digest
        or continuation_plan.target_binding_digest != parent_plan.target_binding_digest
    ):
        raise ScanContinuationError(
            "continuation plan differs from parent Scan authority"
        )
    finalizers = [
        action for action in continuation_plan.actions
        if action.action_id == "finalize.report"
    ]
    if len(finalizers) != 1:
        raise ScanContinuationError(
            "continuation plan must contain exactly one finalizer"
        )

    parent_ids = set(allocation.parent_action_ids)
    appended: list[ScanAction] = []
    for action in continuation_plan.actions:
        if action.action_id == "finalize.report":
            continue
        if action.action_id in parent_ids:
            if action.action_id.startswith("inputs.auth_"):
                continue
            raise ScanContinuationError(
                f"continuation action duplicates parent authority: {action.action_id}"
            )
        appended.append(action)

    consumed = {name: 0 for name in allocation.budget_ceiling}
    for action in (*appended, finalizers[0]):
        for name, amount in action.requested_budget.items():
            if name not in consumed:
                raise ScanContinuationError(
                    f"continuation action uses undeclared budget: {name}"
                )
            consumed[name] += amount
    shortages = {
        name: consumed[name] - allocation.budget_ceiling[name]
        for name in consumed
        if consumed[name] > allocation.budget_ceiling[name]
    }
    if shortages:
        raise ScanContinuationError(
            f"continuation exceeds its upfront allocation: {shortages}"
        )

    actions: list[ScanAction] = list(parent_plan.actions)
    for action in appended:
        actions.append(replace(
            action, ordinal=len(actions), action_digest=None,
        ))
    finalizer = replace(
        finalizers[0],
        ordinal=len(actions),
        dependencies=tuple(action.action_id for action in actions),
        action_digest=None,
    )
    actions.append(finalizer)
    if len(actions) > _MAX_ACTIONS:
        raise ScanContinuationError("continued Scan plan exceeds its action bound")
    try:
        return ScanActionPlan(
            scan_id=parent_plan.scan_id,
            execution_plan_digest=parent_plan.execution_plan_digest,
            target_binding_digest=parent_plan.target_binding_digest,
            actions=tuple(actions),
        )
    except ScanActionPlanError as exc:
        raise ScanContinuationError(str(exc)) from exc


__all__ = [
    "ContinuationBudgetCeiling",
    "SCAN_CONTINUATION_ALLOCATION_SCHEMA",
    "ScanContinuationAllocation",
    "ScanContinuationError",
    "merge_scan_action_continuation",
]
