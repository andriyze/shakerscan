"""Content-addressed compiler for canonical parallel Scan action partitions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

try:
    from runtime.models import ScanBudget, TargetBinding
except ModuleNotFoundError:
    from ..runtime.models import ScanBudget, TargetBinding

from .action_plan import ScanActionPlan
from .execution import ScanExecutionPlan
from .jobs import ScanShardBudget


PARALLEL_ACTION_PARTITION_SCHEMA = "parallel-action-partition/v1"
PARALLEL_ACTION_PARTITION_RECORD_SCHEMA = "parallel-action-partition-record/v1"
_VALID_STRATEGIES = frozenset({
    "auto", "scope", "family", "coverage", "coverage_family", "auth_split",
})
_LEDGER_TO_BUDGET = {
    "http_requests": "max_http_requests",
    "state_changing_requests": "max_state_changing_requests",
    "browser_actions": "max_browser_actions",
    "tcp_ports_attempted": "max_tcp_ports",
    "hosts_attempted": "max_hosts",
    "tool_wall_seconds": "max_tool_wall_seconds",
}


class ParallelActionPlanError(ValueError):
    """A parent plan cannot be partitioned without widening its authority."""


def _digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _weighted_shares(
    total: int,
    weights: Sequence[int],
    *,
    minimum: int,
) -> tuple[int, ...]:
    count = len(weights)
    if count < 1:
        return ()
    if total < minimum * count:
        raise ParallelActionPlanError(
            f"parallel budget {total} cannot fund {count} child minimums of {minimum}"
        )
    remaining = total - (minimum * count)
    normalized = [max(1, int(item)) for item in weights]
    denominator = sum(normalized)
    result: list[int] = []
    assigned_weight = 0
    for weight in normalized:
        start = (remaining * assigned_weight) // denominator
        assigned_weight += weight
        end = (remaining * assigned_weight) // denominator
        result.append(minimum + end - start)
    return tuple(result)


def _entry_weight(options: Mapping[str, Any]) -> int:
    endpoints = options.get("custom_endpoints")
    if isinstance(endpoints, (list, tuple)):
        return max(1, len(endpoints))
    return 1


def _work_partition_digest(options: Mapping[str, Any]) -> str:
    endpoints = options.get("custom_endpoints")
    endpoint_hashes = [
        hashlib.sha256(str(item).encode("utf-8")).hexdigest()
        for item in endpoints or ()
        if isinstance(item, str) and item.strip()
    ] if isinstance(endpoints, (list, tuple)) else []
    request_refs = options.get("request_manifest_refs")
    request_digests = sorted(
        str(key).lower()
        for key in request_refs
        if isinstance(key, str)
    ) if isinstance(request_refs, Mapping) else []
    return _digest({
        "endpoint_hashes": endpoint_hashes,
        "request_selection_digests": request_digests,
        "auth_state": str(options.get("auth_state") or "anonymous"),
        "family": str(
            options.get("coverage_attempt_family")
            or options.get("asm_check_family")
            or options.get("check_family")
            or "all"
        ).lower(),
    })


@dataclass(frozen=True)
class ParallelChildPartition:
    scan_id: str
    index: int
    label: str
    role: str
    budget: ScanShardBudget
    work_partition_digest: str

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "index": self.index,
            "label": self.label,
            "role": self.role,
            "budget": self.budget.payload(),
            "work_partition_digest": self.work_partition_digest,
        }


@dataclass(frozen=True)
class ParallelActionPartition:
    parent_scan_id: str
    parent_execution_plan_digest: str
    parent_action_plan_digest: str
    target_binding_digest: str
    strategy: str
    available_worker_count: int
    children: tuple[ParallelChildPartition, ...]
    parent_owned_action_ids: tuple[str, ...]
    globally_assigned_action_ids: tuple[str, ...]
    schema_version: str = PARALLEL_ACTION_PARTITION_SCHEMA

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "parent_scan_id": self.parent_scan_id,
            "parent_execution_plan_digest": self.parent_execution_plan_digest,
            "parent_action_plan_digest": self.parent_action_plan_digest,
            "target_binding_digest": self.target_binding_digest,
            "strategy": self.strategy,
            "available_worker_count": self.available_worker_count,
            "children": [item.canonical_dict() for item in self.children],
            "parent_owned_action_ids": list(self.parent_owned_action_ids),
            "globally_assigned_action_ids": list(self.globally_assigned_action_ids),
        }

    @property
    def partition_digest(self) -> str:
        return _digest(self.canonical_dict())

    def record(self, child_action_plans: Mapping[str, ScanActionPlan]) -> dict[str, Any]:
        expected = {child.scan_id for child in self.children}
        if set(child_action_plans) != expected:
            raise ParallelActionPlanError(
                "child action plans do not exactly cover the parallel partition"
            )
        child_records = []
        for child in self.children:
            plan = child_action_plans[child.scan_id]
            if plan.scan_id != child.scan_id:
                raise ParallelActionPlanError(
                    "child action plan owner differs from its partition"
                )
            child_records.append({
                "scan_id": child.scan_id,
                "index": child.index,
                "role": child.role,
                "action_plan_digest": plan.plan_digest,
                "action_ids": [action.action_id for action in plan.actions],
            })
        payload = {
            "schema_version": PARALLEL_ACTION_PARTITION_RECORD_SCHEMA,
            "partition_digest": self.partition_digest,
            "parent_scan_id": self.parent_scan_id,
            "parent_action_plan_digest": self.parent_action_plan_digest,
            "children": child_records,
        }
        return {**payload, "record_digest": _digest(payload)}


class ParallelActionPlanCompiler:
    """Compile immutable child roles and budgets from canonical parent authority."""

    @staticmethod
    def resolve_strategy(
        execution_plan: ScanExecutionPlan,
        *,
        requested: str | None,
        known_endpoint_count: int,
    ) -> str:
        strategy = str(requested or "auto").strip().lower()
        if strategy not in _VALID_STRATEGIES:
            strategy = "auto"
        if strategy != "auto":
            return strategy
        if known_endpoint_count >= 2:
            return "scope"
        return "coverage" if execution_plan.policy.active_testing else "family"

    def compile(
        self,
        *,
        parent_execution_plan: ScanExecutionPlan,
        parent_action_plan: ScanActionPlan,
        target_binding: TargetBinding,
        child_specs: Sequence[Mapping[str, Any]],
        consumed_budget: Mapping[str, Any] | None = None,
        strategy: str,
        available_worker_count: int = 0,
    ) -> ParallelActionPartition:
        if (
            parent_action_plan.scan_id == ""
            or parent_action_plan.execution_plan_digest != parent_execution_plan.digest
            or parent_action_plan.target_binding_digest != target_binding.digest
        ):
            raise ParallelActionPlanError(
                "parallel parent action authority does not match execution authority"
            )
        if len(child_specs) < 2:
            raise ParallelActionPlanError("parallel partition requires at least two children")
        indices = [int(item.get("index", -1)) for item in child_specs]
        if indices != list(range(len(child_specs))):
            raise ParallelActionPlanError("parallel child indices must be contiguous")
        scan_ids = [str(item.get("scan_id") or "") for item in child_specs]
        if any(not item for item in scan_ids) or len(set(scan_ids)) != len(scan_ids):
            raise ParallelActionPlanError("parallel child Scan identities must be unique")

        backbone = [
            index for index, item in enumerate(child_specs)
            if bool((item.get("options") or {}).get("parallel_backbone"))
        ]
        if len(backbone) > 1:
            raise ParallelActionPlanError("parallel partition has multiple global backbones")
        global_index = backbone[0] if backbone else 0
        base_weights = [
            _entry_weight(item.get("options") or {}) for item in child_specs
        ]
        weights = list(base_weights)
        weights[global_index] += max(1, sum(base_weights) - base_weights[global_index])

        parent_budget: ScanBudget = parent_execution_plan.budget
        consumed = dict(consumed_budget or {})
        remaining = {
            ledger_name: max(0, int(limit) - max(0, int(consumed.get(ledger_name) or 0)))
            for ledger_name, limit in parent_budget.ledger_limits().items()
        }
        http = _weighted_shares(remaining["http_requests"], weights, minimum=1)
        endpoints = _weighted_shares(parent_budget.max_endpoints, weights, minimum=1)
        hosts = _weighted_shares(remaining["hosts_attempted"], weights, minimum=1)
        mutation = _weighted_shares(
            remaining["state_changing_requests"], weights, minimum=0,
        )
        tool = _weighted_shares(
            remaining["tool_wall_seconds"], weights, minimum=0,
        )
        browser = [0] * len(child_specs)
        browser[global_index] = remaining["browser_actions"]
        tcp = [0] * len(child_specs)
        tcp[global_index] = remaining["tcp_ports_attempted"]

        children: list[ParallelChildPartition] = []
        for index, item in enumerate(child_specs):
            budget = ScanShardBudget(
                max_duration_seconds=parent_budget.max_duration_seconds,
                max_http_requests=http[index],
                max_endpoints=endpoints[index],
                max_browser_actions=browser[index],
                max_tcp_ports=tcp[index],
                max_tool_wall_seconds=tool[index],
                max_workers=1,
                max_state_changing_requests=min(mutation[index], http[index]),
                max_hosts=min(hosts[index], endpoints[index]),
            )
            children.append(ParallelChildPartition(
                scan_id=str(item["scan_id"]),
                index=index,
                label=str(item.get("label") or f"shard[{index}]"),
                role="global" if index == global_index else "endpoint",
                budget=budget,
                work_partition_digest=_work_partition_digest(
                    item.get("options") or {},
                ),
            ))

        for ledger_name, budget_name in _LEDGER_TO_BUDGET.items():
            allocated = sum(getattr(child.budget, budget_name) for child in children)
            if allocated > remaining[ledger_name]:
                raise ParallelActionPlanError(
                    f"parallel child {ledger_name} authority exceeds parent remainder"
                )
        parent_owned = tuple(
            action.action_id for action in parent_action_plan.actions
            if action.action_id == "finalize.report"
        )
        global_actions = tuple(
            action.action_id for action in parent_action_plan.actions
            if action.action_id not in parent_owned
        )
        return ParallelActionPartition(
            parent_scan_id=parent_action_plan.scan_id,
            parent_execution_plan_digest=parent_execution_plan.digest,
            parent_action_plan_digest=str(parent_action_plan.plan_digest),
            target_binding_digest=target_binding.digest,
            strategy=strategy,
            available_worker_count=max(0, int(available_worker_count or 0)),
            children=tuple(children),
            parent_owned_action_ids=parent_owned,
            globally_assigned_action_ids=global_actions,
        )


def validate_parallel_partition_record(
    record: Mapping[str, Any],
    *,
    parent_scan_id: str,
    child_plan_digests: Mapping[str, str],
) -> None:
    raw = dict(record)
    supplied_record_digest = str(raw.pop("record_digest", ""))
    if (
        raw.get("schema_version") != PARALLEL_ACTION_PARTITION_RECORD_SCHEMA
        or raw.get("parent_scan_id") != parent_scan_id
        or supplied_record_digest != _digest(raw)
    ):
        raise ParallelActionPlanError("parallel action partition record is invalid")
    children = raw.get("children")
    if not isinstance(children, list):
        raise ParallelActionPlanError("parallel action partition children are invalid")
    expected = {
        str(item.get("scan_id") or ""): str(item.get("action_plan_digest") or "")
        for item in children if isinstance(item, Mapping)
    }
    if expected != dict(child_plan_digests):
        raise ParallelActionPlanError(
            "persisted child action plans differ from the parent partition"
        )
