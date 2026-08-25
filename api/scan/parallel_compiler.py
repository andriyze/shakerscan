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
from .continuation import ScanContinuationAllocation
from .execution import ScanExecutionPlan
from .jobs import ScanShardBudget


PARALLEL_ACTION_PARTITION_SCHEMA = "parallel-action-partition/v2"
PARALLEL_ACTION_PARTITION_RECORD_SCHEMA = "parallel-action-partition-record/v2"
_LEGACY_PARALLEL_ACTION_PARTITION_RECORD_SCHEMA = (
    "parallel-action-partition-record/v1"
)
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
            or "all"
        ).lower(),
    })


def _work_item_id(kind: str, value: Any) -> str:
    return _digest({"kind": kind, "value": value})


def build_parallel_work_assignment(
    *,
    endpoints: Sequence[Any] = (),
    request_entries: Sequence[Mapping[str, Any]] = (),
    work_manifest_refs: Sequence[Mapping[str, Any]] = (),
    allowed_family_scope: Sequence[str] = (),
    work_scope: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a content-free exact work binding for one parallel child."""
    attempt_scope = {
        str(key).strip(): str(value).strip().lower()
        for key, value in dict(work_scope or {}).items()
        if str(key).strip() and str(value).strip()
    }

    def scoped(value: Any) -> Any:
        if not attempt_scope:
            return value
        return {"attempt_scope": attempt_scope, "value": value}

    endpoint_work_ids = sorted({
        _work_item_id("endpoint", scoped(str(item).strip()))
        for item in endpoints
        if str(item).strip()
    })
    request_work_ids = sorted({
        _work_item_id("request", scoped({
            key: nested
            for key, nested in dict(item).items()
            if key != "selected_shard"
        }))
        for item in request_entries
        if isinstance(item, Mapping)
    })
    refs = [dict(item) for item in work_manifest_refs if isinstance(item, Mapping)]
    refs.sort(key=lambda item: json.dumps(
        item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ))
    families = sorted({
        str(item).strip().lower()
        for item in allowed_family_scope
        if str(item).strip()
    })
    material = {
        "endpoint_work_ids": endpoint_work_ids,
        "request_work_ids": request_work_ids,
        "work_manifest_refs": refs,
        "allowed_family_scope": families,
    }
    return {**material, "work_partition_digest": _digest(material)}


def _canonical_work_assignment(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ParallelActionPlanError("parallel child work assignment is invalid")
    endpoint_ids = value.get("endpoint_work_ids")
    request_ids = value.get("request_work_ids")
    refs = value.get("work_manifest_refs")
    families = value.get("allowed_family_scope")
    if not all(isinstance(item, list) for item in (
        endpoint_ids, request_ids, refs, families,
    )):
        raise ParallelActionPlanError("parallel child work assignment fields are invalid")
    if (
        len(endpoint_ids) != len(set(endpoint_ids))
        or len(request_ids) != len(set(request_ids))
        or any(
            not isinstance(item, str)
            or len(item) != 64
            or any(char not in "0123456789abcdef" for char in item)
            for item in (*endpoint_ids, *request_ids)
        )
        or any(not isinstance(item, Mapping) for item in refs)
        or any(not isinstance(item, str) or not item for item in families)
    ):
        raise ParallelActionPlanError("parallel child work assignment content is invalid")
    material = {
        "endpoint_work_ids": sorted(endpoint_ids),
        "request_work_ids": sorted(request_ids),
        "work_manifest_refs": sorted(
            (dict(item) for item in refs),
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            ),
        ),
        "allowed_family_scope": sorted(set(families)),
    }
    if str(value.get("work_partition_digest") or "") != _digest(material):
        raise ParallelActionPlanError("parallel child work partition digest is invalid")
    return {**material, "work_partition_digest": _digest(material)}


def merge_parallel_work_assignments(
    assignments: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Freeze the exact union of already-scoped child work assignments."""
    canonical = tuple(_canonical_work_assignment(item) for item in assignments)
    refs_by_value: dict[str, dict[str, Any]] = {}
    for assignment in canonical:
        for reference in assignment["work_manifest_refs"]:
            encoded = json.dumps(
                reference, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            )
            refs_by_value[encoded] = dict(reference)
    material = {
        "endpoint_work_ids": sorted({
            work_id
            for assignment in canonical
            for work_id in assignment["endpoint_work_ids"]
        }),
        "request_work_ids": sorted({
            work_id
            for assignment in canonical
            for work_id in assignment["request_work_ids"]
        }),
        "work_manifest_refs": [
            refs_by_value[key] for key in sorted(refs_by_value)
        ],
        "allowed_family_scope": sorted({
            family
            for assignment in canonical
            for family in assignment["allowed_family_scope"]
        }),
    }
    return {**material, "work_partition_digest": _digest(material)}


def _projection_id(action_id: str) -> str:
    head, dot, tail = action_id.rpartition(".")
    return head if dot and len(tail) == 5 and tail.isdigit() else action_id


def _capability_family(capability_name: str) -> str:
    if capability_name.startswith("xss."):
        return "xss"
    if capability_name.startswith("sqli."):
        return "sqli"
    if capability_name.startswith("templates."):
        return "nuclei"
    if capability_name.startswith("authz."):
        return "bola"
    if capability_name.startswith(("web.", "http.", "dns.", "tls.", "ports.", "service.", "subdomains.")):
        return "recon"
    if capability_name.startswith(("auth.", "collections.")):
        return "inputs"
    if capability_name == "scan.finalize":
        return "finalizer"
    return capability_name.split(".", 1)[0]


def parallel_capability_family_scope(
    capability_names: Sequence[str],
) -> tuple[str, ...]:
    return tuple(sorted({_capability_family(item) for item in capability_names}))


def _is_global_action(action_id: str) -> bool:
    return action_id.startswith(("baseline.", "discover."))


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
    assigned_parent_action_ids: tuple[str, ...]
    required_parent_action_ids: tuple[str, ...]
    allowed_parent_capabilities: tuple[str, ...]
    continuation_allocation_digest: str | None
    allowed_continuation_capabilities: tuple[str, ...]
    required_continuation_capabilities: tuple[str, ...]
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
            "assigned_parent_action_ids": list(self.assigned_parent_action_ids),
            "required_parent_action_ids": list(self.required_parent_action_ids),
            "allowed_parent_capabilities": list(self.allowed_parent_capabilities),
            "continuation_allocation_digest": self.continuation_allocation_digest,
            "allowed_continuation_capabilities": list(
                self.allowed_continuation_capabilities
            ),
            "required_continuation_capabilities": list(
                self.required_continuation_capabilities
            ),
        }

    @property
    def partition_digest(self) -> str:
        return _digest(self.canonical_dict())

    def record(
        self,
        child_action_plans: Mapping[str, ScanActionPlan],
        *,
        child_work_assignments: Mapping[str, Mapping[str, Any]] | None = None,
        parent_work_assignment: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        expected = {child.scan_id for child in self.children}
        if set(child_action_plans) != expected:
            raise ParallelActionPlanError(
                "child action plans do not exactly cover the parallel partition"
            )
        supplied_assignments = dict(child_work_assignments or {})
        if supplied_assignments and set(supplied_assignments) != expected:
            raise ParallelActionPlanError(
                "child work assignments do not exactly cover the parallel partition"
            )
        # Parent plans are not children. Use the immutable parent plan authority
        # captured by compile() below rather than accepting caller-supplied data.
        parent_projection_ids = set(self.assigned_parent_action_ids)
        required_parent_ids = set(self.required_parent_action_ids)
        parent_capabilities = set(self.allowed_parent_capabilities)
        continuation_capabilities = set(
            self.allowed_continuation_capabilities
        )
        required_continuation = set(
            self.required_continuation_capabilities
        )
        global_action_ids = set(self.globally_assigned_action_ids)
        parent_owned_ids = set(self.parent_owned_action_ids)
        child_records = []
        endpoint_owners: dict[str, str] = {}
        request_owners: dict[str, str] = {}
        assigned_projection_ids: set[str] = set()
        assigned_continuation_capabilities: set[str] = set()
        global_occurrences: dict[str, int] = {
            action_id: 0 for action_id in global_action_ids
        }
        for child in self.children:
            plan = child_action_plans[child.scan_id]
            if plan.scan_id != child.scan_id:
                raise ParallelActionPlanError(
                    "child action plan owner differs from its partition"
                )
            if any(action.action_id in parent_owned_ids for action in plan.actions):
                raise ParallelActionPlanError(
                    "parent-owned finalization cannot execute on a parallel child"
                )
            action_projection_ids = {
                _projection_id(action.action_id) for action in plan.actions
            }
            unauthorized_projection = {
                _projection_id(action.action_id)
                for action in plan.actions
                if (
                    _projection_id(action.action_id) not in parent_projection_ids
                    and action.capability_name not in continuation_capabilities
                )
            }
            if unauthorized_projection:
                raise ParallelActionPlanError(
                    "parallel child introduced an action outside parent authority"
                )
            if any(
                action.capability_name not in parent_capabilities
                and action.capability_name not in continuation_capabilities
                for action in plan.actions
            ):
                raise ParallelActionPlanError(
                    "parallel child introduced an unauthorized capability family"
                )
            child_global = {
                action.action_id for action in plan.actions
                if action.action_id in global_action_ids
            }
            if child.role == "global":
                if child_global != global_action_ids:
                    raise ParallelActionPlanError(
                        "global child does not exactly own the global action set"
                    )
            elif child_global:
                raise ParallelActionPlanError(
                    "endpoint child duplicates a global action"
                )
            for action_id in child_global:
                global_occurrences[action_id] += 1
            assigned_projection_ids.update(action_projection_ids)
            assigned_continuation_capabilities.update(
                action.capability_name
                for action in plan.actions
                if action.capability_name in continuation_capabilities
            )

            if supplied_assignments:
                assignment = _canonical_work_assignment(
                    supplied_assignments[child.scan_id]
                )
            else:
                assignment = build_parallel_work_assignment()
            for kind, owners, ids in (
                ("endpoint", endpoint_owners, assignment["endpoint_work_ids"]),
                ("request", request_owners, assignment["request_work_ids"]),
            ):
                for work_id in ids:
                    previous = owners.setdefault(work_id, child.scan_id)
                    if previous != child.scan_id:
                        raise ParallelActionPlanError(
                            f"duplicate {kind} work across parallel children"
                        )
            actual_families = sorted({
                _capability_family(action.capability_name)
                for action in plan.actions
            })
            declared_families = set(assignment["allowed_family_scope"])
            if declared_families and not set(actual_families) <= declared_families:
                raise ParallelActionPlanError(
                    "parallel child action family exceeds its allowed family scope"
                )
            effective_families = (
                assignment["allowed_family_scope"] or actual_families
            )
            assignment_material = {
                "endpoint_work_ids": assignment["endpoint_work_ids"],
                "request_work_ids": assignment["request_work_ids"],
                "work_manifest_refs": assignment["work_manifest_refs"],
                "allowed_family_scope": effective_families,
            }
            effective_work_digest = _digest(assignment_material)
            aggregate_input_digest = _digest({
                "work_partition_digest": effective_work_digest,
                "action_input_binding_digests": [
                    action.input_binding_digest for action in plan.actions
                ],
            })
            child_records.append({
                "scan_id": child.scan_id,
                "index": child.index,
                "role": child.role,
                "action_plan_digest": plan.plan_digest,
                "expected_action_ids": [
                    action.action_id for action in plan.actions
                ],
                "expected_global_action_ids": sorted(child_global),
                "work_manifest_refs": assignment["work_manifest_refs"],
                "work_partition_digest": effective_work_digest,
                "endpoint_work_ids": assignment["endpoint_work_ids"],
                "request_work_ids": assignment["request_work_ids"],
                "allowed_family_scope": effective_families,
                "input_binding_digest": aggregate_input_digest,
            })
        if any(count != 1 for count in global_occurrences.values()):
            raise ParallelActionPlanError(
                "global actions must occur exactly once across parallel children"
            )
        if not required_parent_ids <= assigned_projection_ids:
            raise ParallelActionPlanError(
                "parallel children left required parent work unassigned"
            )
        if not required_continuation <= assigned_continuation_capabilities:
            raise ParallelActionPlanError(
                "parallel children left required continuation work unassigned"
            )
        observed_parent_work = build_parallel_work_assignment(
            endpoints=(),
            request_entries=(),
        )
        observed_parent_work.update({
            "endpoint_work_ids": sorted(endpoint_owners),
            "request_work_ids": sorted(request_owners),
        })
        observed_material = {
            key: observed_parent_work[key]
            for key in (
                "endpoint_work_ids", "request_work_ids",
                "work_manifest_refs", "allowed_family_scope",
            )
        }
        observed_parent_work["work_partition_digest"] = _digest(observed_material)
        if parent_work_assignment is not None:
            expected_parent_work = _canonical_work_assignment(
                parent_work_assignment
            )
            if (
                expected_parent_work["endpoint_work_ids"]
                != observed_parent_work["endpoint_work_ids"]
                or expected_parent_work["request_work_ids"]
                != observed_parent_work["request_work_ids"]
            ):
                raise ParallelActionPlanError(
                    "parallel child work union differs from parent-assigned work"
                )
        else:
            expected_parent_work = observed_parent_work
        payload = {
            "schema_version": PARALLEL_ACTION_PARTITION_RECORD_SCHEMA,
            "partition_digest": self.partition_digest,
            "parent_scan_id": self.parent_scan_id,
            "parent_action_plan_digest": self.parent_action_plan_digest,
            "parent_owned_action_ids": list(self.parent_owned_action_ids),
            "allowed_parent_action_ids": list(self.assigned_parent_action_ids),
            "allowed_parent_capabilities": list(self.allowed_parent_capabilities),
            "required_parent_action_ids": list(self.required_parent_action_ids),
            "continuation_allocation_digest": self.continuation_allocation_digest,
            "allowed_continuation_capabilities": list(
                self.allowed_continuation_capabilities
            ),
            "required_continuation_capabilities": list(
                self.required_continuation_capabilities
            ),
            "expected_global_action_ids": list(self.globally_assigned_action_ids),
            "parent_endpoint_work_ids": expected_parent_work["endpoint_work_ids"],
            "parent_request_work_ids": expected_parent_work["request_work_ids"],
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
        continuation_allocation: ScanContinuationAllocation | None = None,
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
        if continuation_allocation is not None and (
            continuation_allocation.scan_id != parent_action_plan.scan_id
            or continuation_allocation.parent_plan_digest
            != parent_action_plan.plan_digest
            or continuation_allocation.execution_plan_digest
            != parent_execution_plan.digest
            or continuation_allocation.target_binding_digest
            != target_binding.digest
            or continuation_allocation.parent_action_ids
            != tuple(action.action_id for action in parent_action_plan.actions)
        ):
            raise ParallelActionPlanError(
                "parallel continuation allocation differs from parent authority"
            )

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
            if _is_global_action(action.action_id)
        )
        assigned_parent = tuple(dict.fromkeys(
            _projection_id(action.action_id)
            for action in parent_action_plan.actions
            if action.action_id not in parent_owned
        ))
        required_parent = tuple(dict.fromkeys(
            _projection_id(action.action_id)
            for action in parent_action_plan.actions
            if action.required and action.action_id not in parent_owned
        ))
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
            assigned_parent_action_ids=assigned_parent,
            required_parent_action_ids=required_parent,
            allowed_parent_capabilities=tuple(sorted({
                action.capability_name for action in parent_action_plan.actions
                if action.action_id not in parent_owned
            })),
            continuation_allocation_digest=(
                continuation_allocation.allocation_digest
                if continuation_allocation is not None else None
            ),
            allowed_continuation_capabilities=(
                continuation_allocation.allowed_capabilities
                if continuation_allocation is not None else ()
            ),
            required_continuation_capabilities=(
                continuation_allocation.required_capabilities
                if continuation_allocation is not None else ()
            ),
        )


def validate_parallel_partition_record(
    record: Mapping[str, Any],
    *,
    parent_scan_id: str,
    child_plan_digests: Mapping[str, str],
    child_action_plans: Mapping[str, ScanActionPlan | Mapping[str, Any]] | None = None,
) -> None:
    raw = dict(record)
    supplied_record_digest = str(raw.pop("record_digest", ""))
    if (
        raw.get("schema_version") not in {
            PARALLEL_ACTION_PARTITION_RECORD_SCHEMA,
            _LEGACY_PARALLEL_ACTION_PARTITION_RECORD_SCHEMA,
        }
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
    semantic_authority_v2 = (
        raw.get("schema_version") == PARALLEL_ACTION_PARTITION_RECORD_SCHEMA
    )
    parent_owned = set(raw.get("parent_owned_action_ids") or ())
    allowed_parent_actions = set(raw.get("allowed_parent_action_ids") or ())
    allowed_parent_capabilities = set(
        raw.get("allowed_parent_capabilities") or ()
    )
    required_parent = set(raw.get("required_parent_action_ids") or ())
    allowed_continuation = set(
        raw.get("allowed_continuation_capabilities") or ()
    )
    required_continuation = set(
        raw.get("required_continuation_capabilities") or ()
    )
    expected_global = set(raw.get("expected_global_action_ids") or ())
    parent_endpoints = list(raw.get("parent_endpoint_work_ids") or ())
    parent_requests = list(raw.get("parent_request_work_ids") or ())
    authority_lists = (
        raw.get("allowed_parent_action_ids"),
        raw.get("allowed_parent_capabilities"),
        raw.get("allowed_continuation_capabilities"),
        raw.get("required_continuation_capabilities"),
    ) if semantic_authority_v2 else ()
    if any(
        not isinstance(value, list)
        for value in (
            raw.get("parent_owned_action_ids"),
            raw.get("required_parent_action_ids"),
            raw.get("expected_global_action_ids"),
            raw.get("parent_endpoint_work_ids"),
            raw.get("parent_request_work_ids"),
            *authority_lists,
        )
    ):
        raise ParallelActionPlanError("parallel action partition authority is invalid")
    global_occurrences = {action_id: 0 for action_id in expected_global}
    observed_endpoints: list[str] = []
    observed_requests: list[str] = []
    observed_projection_ids: set[str] = set()
    observed_continuation_capabilities: set[str] = set()
    plans = dict(child_action_plans or {})
    if plans and set(plans) != set(expected):
        raise ParallelActionPlanError(
            "persisted child action plan bodies do not cover the partition"
        )
    for item in children:
        if not isinstance(item, Mapping):
            raise ParallelActionPlanError("parallel action partition child is invalid")
        scan_id = str(item.get("scan_id") or "")
        role = str(item.get("role") or "")
        action_ids = item.get("expected_action_ids")
        child_global = item.get("expected_global_action_ids")
        endpoint_ids = item.get("endpoint_work_ids")
        request_ids = item.get("request_work_ids")
        refs = item.get("work_manifest_refs")
        families = item.get("allowed_family_scope")
        if not all(isinstance(value, list) for value in (
            action_ids, child_global, endpoint_ids, request_ids, refs, families,
        )):
            raise ParallelActionPlanError("parallel action partition child fields are invalid")
        if parent_owned.intersection(action_ids):
            raise ParallelActionPlanError(
                "parent-owned action appears in a child action plan"
            )
        if role == "global":
            if set(child_global) != expected_global:
                raise ParallelActionPlanError(
                    "global child action ownership differs from the partition"
                )
        elif child_global:
            raise ParallelActionPlanError("endpoint child duplicates a global action")
        for action_id in child_global:
            if action_id not in global_occurrences:
                raise ParallelActionPlanError(
                    "child introduced an unassigned global action"
                )
            global_occurrences[action_id] += 1
        observed_projection_ids.update(_projection_id(item) for item in action_ids)
        assignment = _canonical_work_assignment({
            "endpoint_work_ids": endpoint_ids,
            "request_work_ids": request_ids,
            "work_manifest_refs": refs,
            "allowed_family_scope": families,
            "work_partition_digest": item.get("work_partition_digest"),
        })
        observed_endpoints.extend(assignment["endpoint_work_ids"])
        observed_requests.extend(assignment["request_work_ids"])
        if plans:
            plan_value = plans[scan_id]
            try:
                plan = (
                    plan_value
                    if isinstance(plan_value, ScanActionPlan)
                    else ScanActionPlan.from_dict(plan_value)
                )
            except (TypeError, ValueError) as exc:
                raise ParallelActionPlanError(
                    "persisted child action plan body is invalid"
                ) from exc
            if (
                plan.scan_id != scan_id
                or plan.plan_digest != item.get("action_plan_digest")
                or [action.action_id for action in plan.actions] != action_ids
                or not set({
                    _capability_family(action.capability_name)
                    for action in plan.actions
                }) <= set(families)
                or _digest({
                    "work_partition_digest": assignment["work_partition_digest"],
                    "action_input_binding_digests": [
                        action.input_binding_digest for action in plan.actions
                    ],
                }) != item.get("input_binding_digest")
            ):
                raise ParallelActionPlanError(
                    "persisted child action authority differs from the semantic partition"
                )
            for action in plan.actions:
                projection = _projection_id(action.action_id)
                capability = action.capability_name
                if semantic_authority_v2 and (
                    projection not in allowed_parent_actions
                    and capability not in allowed_continuation
                ):
                    raise ParallelActionPlanError(
                        "persisted child action exceeds parent authority"
                    )
                if semantic_authority_v2 and (
                    capability not in allowed_parent_capabilities
                    and capability not in allowed_continuation
                ):
                    raise ParallelActionPlanError(
                        "persisted child capability exceeds parent authority"
                    )
                if capability in allowed_continuation:
                    observed_continuation_capabilities.add(capability)
    if any(count != 1 for count in global_occurrences.values()):
        raise ParallelActionPlanError(
            "global actions do not occur exactly once in the partition"
        )
    if len(observed_endpoints) != len(set(observed_endpoints)):
        raise ParallelActionPlanError("parallel endpoint work is duplicated")
    if len(observed_requests) != len(set(observed_requests)):
        raise ParallelActionPlanError("parallel request work is duplicated")
    if sorted(observed_endpoints) != sorted(parent_endpoints):
        raise ParallelActionPlanError("parallel endpoint work is incomplete")
    if sorted(observed_requests) != sorted(parent_requests):
        raise ParallelActionPlanError("parallel request work is incomplete")
    if not required_parent <= observed_projection_ids:
        raise ParallelActionPlanError("required parent action work is unassigned")
    if (
        semantic_authority_v2
        and plans
        and not required_continuation <= observed_continuation_capabilities
    ):
        raise ParallelActionPlanError(
            "required continuation capability work is unassigned"
        )
