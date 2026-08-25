from dataclasses import replace

import pytest

from api.runtime.models import TargetBinding
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.contracts import resolve_scan_contract
from api.scan.jobs import derive_scan_shard_budget
from api.scan.parallel_compiler import (
    ParallelActionPlanCompiler,
    ParallelActionPlanError,
    validate_parallel_partition_record,
)


PARENT_ID = "10000000-0000-4000-8000-000000000001"
CHILD_IDS = (
    "20000000-0000-4000-8000-000000000001",
    "20000000-0000-4000-8000-000000000002",
    "20000000-0000-4000-8000-000000000003",
)


def _target():
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="example.test",
        allowed_origins=("https://example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )


def _authority():
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": True,
            "exclude_families": ["nuclei", "xss", "sqli", "bola"],
        },
    )
    raw = ScanActionPlanCompiler().compile(
        scan_id=PARENT_ID,
        execution_plan=contract.execution_plan,
        target_binding=_target(),
    )
    parent = allocate_scan_action_plan(raw, contract.budget).plan
    return contract.execution_plan, parent


def _children(*, reordered=False):
    result = []
    for index, child_id in enumerate(CHILD_IDS):
        options = {
            "custom_endpoints": [f"GET /v1/items/{index}?secret=redacted-at-source"],
            "auth_state": "anonymous",
        }
        if index == 0:
            options["parallel_backbone"] = True
        item = {
            "scan_id": child_id,
            "index": index,
            "label": "global-backbone" if index == 0 else f"scope[{index}]",
            "options": options,
        }
        if reordered:
            item = {key: item[key] for key in reversed(tuple(item))}
            item["options"] = {
                key: options[key] for key in reversed(tuple(options))
            }
        result.append(item)
    return tuple(result)


def test_canonical_parallel_partition_is_deterministic_and_budget_bounded():
    execution, parent = _authority()
    compiler = ParallelActionPlanCompiler()
    first = compiler.compile(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=_children(),
        strategy="scope",
        available_worker_count=3,
    )
    second = compiler.compile(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=_children(reordered=True),
        strategy="scope",
        available_worker_count=3,
    )

    assert first.partition_digest == second.partition_digest
    assert [child.role for child in first.children] == [
        "global", "endpoint", "endpoint",
    ]
    assert sum(child.budget.max_http_requests for child in first.children) == (
        execution.budget.max_http_requests
    )
    assert sum(child.budget.max_tool_wall_seconds for child in first.children) == (
        execution.budget.max_tool_wall_seconds
    )
    assert sum(child.budget.max_browser_actions for child in first.children) == (
        execution.budget.max_browser_actions
    )
    assert first.children[1].budget.max_browser_actions == 0
    assert first.children[2].budget.max_tcp_ports == 0
    assert first.parent_owned_action_ids == ("finalize.report",)
    assert "finalize.report" not in first.globally_assigned_action_ids
    assert "secret=redacted-at-source" not in str(first.canonical_dict())


def test_parallel_partition_uses_remaining_parent_ledger_and_exact_child_budget():
    execution, parent = _authority()
    partition = ParallelActionPlanCompiler().compile(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=_children(),
        consumed_budget={
            "http_requests": 17,
            "tool_wall_seconds": 11,
            "hosts_attempted": 2,
        },
        strategy="scope",
    )
    assert sum(child.budget.max_http_requests for child in partition.children) == (
        execution.budget.max_http_requests - 17
    )
    assert sum(child.budget.max_tool_wall_seconds for child in partition.children) == (
        execution.budget.max_tool_wall_seconds - 11
    )
    exact = partition.children[1].budget
    derived = derive_scan_shard_budget(
        {"parallel_budget_partition": exact.payload()}, execution.budget,
    )
    assert derived == exact


def test_parallel_partition_record_rejects_unplanned_child_plan():
    execution, parent = _authority()
    partition = ParallelActionPlanCompiler().compile(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=_children(),
        strategy="scope",
    )
    plans = {
        child.scan_id: replace(parent, scan_id=child.scan_id, plan_digest=None)
        for child in partition.children
    }
    record = partition.record(plans)
    digests = {scan_id: str(plan.plan_digest) for scan_id, plan in plans.items()}
    validate_parallel_partition_record(
        record,
        parent_scan_id=PARENT_ID,
        child_plan_digests=digests,
    )
    with pytest.raises(ParallelActionPlanError, match="differ"):
        validate_parallel_partition_record(
            record,
            parent_scan_id=PARENT_ID,
            child_plan_digests={**digests, CHILD_IDS[2]: "f" * 64},
        )


def test_canonical_strategy_uses_policy_and_known_work_not_scan_mode():
    active, _parent = _authority()
    passive = resolve_scan_contract(budget_profile="balanced").execution_plan

    assert ParallelActionPlanCompiler.resolve_strategy(
        active, requested="auto", known_endpoint_count=0,
    ) == "coverage"
    assert ParallelActionPlanCompiler.resolve_strategy(
        passive, requested="auto", known_endpoint_count=3,
    ) == "scope"
    assert ParallelActionPlanCompiler.resolve_strategy(
        passive, requested="auto", known_endpoint_count=0,
    ) == "family"


def test_parallel_partition_rejects_more_children_than_parent_minimum_budget():
    execution, parent = _authority()
    with pytest.raises(ParallelActionPlanError, match="cannot fund"):
        ParallelActionPlanCompiler().compile(
            parent_execution_plan=execution,
            parent_action_plan=parent,
            target_binding=_target(),
            child_specs=_children(),
            consumed_budget={
                "http_requests": execution.budget.max_http_requests - 2,
            },
            strategy="scope",
        )
