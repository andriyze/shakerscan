from dataclasses import replace
import hashlib
import json

import pytest

from api.runtime.models import TargetBinding
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.contracts import resolve_scan_contract
from api.scan.continuation import ScanContinuationAllocation
from api.scan.jobs import derive_scan_shard_budget
from api.scan.parallel_compiler import (
    ParallelActionPlanCompiler,
    ParallelActionPlanError,
    build_parallel_work_assignment,
    merge_parallel_work_assignments,
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
        options = {"auth_state": "anonymous"}
        if index == 0:
            options["parallel_backbone"] = True
        else:
            options["custom_endpoints"] = [
                f"GET /v1/items/{index}?secret=redacted-at-source"
            ]
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


def _projected_plans(partition, parent):
    result = {}
    global_ids = set(partition.globally_assigned_action_ids)
    for child in partition.children:
        selected = [
            action for action in parent.actions
            if action.action_id != "finalize.report"
            and ((action.action_id in global_ids) == (child.role == "global"))
        ]
        selected_ids = {action.action_id for action in selected}
        actions = tuple(
            replace(
                action,
                ordinal=index,
                dependencies=tuple(
                    dependency for dependency in action.dependencies
                    if dependency in selected_ids
                ),
                action_digest=None,
            )
            for index, action in enumerate(selected)
        )
        result[child.scan_id] = replace(
            parent, scan_id=child.scan_id, actions=actions, plan_digest=None,
        )
    return result


def _assignments(children):
    return {
        child["scan_id"]: build_parallel_work_assignment(
            endpoints=child["options"].get("custom_endpoints") or (),
        )
        for child in children
    }


def _parent_assignment(assignments):
    endpoint_ids = sorted({
        item
        for assignment in assignments.values()
        for item in assignment["endpoint_work_ids"]
    })
    material = {
        "endpoint_work_ids": endpoint_ids,
        "request_work_ids": [],
        "work_manifest_refs": [],
        "allowed_family_scope": [],
    }
    return {
        **material,
        "work_partition_digest": hashlib.sha256(json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode()).hexdigest(),
    }


def test_family_attempt_scope_distinguishes_intentional_endpoint_rechecks():
    endpoint = "GET /v1/items/1?secret=redacted-at-source"
    sqli = build_parallel_work_assignment(
        endpoints=(endpoint,),
        work_scope={"auth_state": "anonymous", "family": "sqli"},
    )
    same_sqli = build_parallel_work_assignment(
        endpoints=(endpoint,),
        work_scope={"family": "SQLI", "auth_state": "ANONYMOUS"},
    )
    xss = build_parallel_work_assignment(
        endpoints=(endpoint,),
        work_scope={"auth_state": "anonymous", "family": "xss"},
    )

    assert sqli == same_sqli
    assert sqli["endpoint_work_ids"] != xss["endpoint_work_ids"]
    merged = merge_parallel_work_assignments((sqli, xss))
    assert merged["endpoint_work_ids"] == sorted({
        *sqli["endpoint_work_ids"], *xss["endpoint_work_ids"],
    })
    assert endpoint not in json.dumps(merged)


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
    children = _children()
    plans = _projected_plans(partition, parent)
    assignments = _assignments(children)
    record = partition.record(
        plans,
        child_work_assignments=assignments,
        parent_work_assignment=_parent_assignment(assignments),
    )
    digests = {scan_id: str(plan.plan_digest) for scan_id, plan in plans.items()}
    validate_parallel_partition_record(
        record,
        parent_scan_id=PARENT_ID,
        child_plan_digests=digests,
        child_action_plans=plans,
    )
    with pytest.raises(ParallelActionPlanError, match="differ"):
        validate_parallel_partition_record(
            record,
            parent_scan_id=PARENT_ID,
            child_plan_digests={**digests, CHILD_IDS[2]: "f" * 64},
        )


def test_parallel_partition_validator_preserves_v1_upgrade_records():
    execution, parent = _authority()
    partition = ParallelActionPlanCompiler().compile(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=_children(),
        strategy="scope",
    )
    plans = _projected_plans(partition, parent)
    assignments = _assignments(_children())
    current = partition.record(
        plans,
        child_work_assignments=assignments,
        parent_work_assignment=_parent_assignment(assignments),
    )
    legacy = {
        key: value for key, value in current.items()
        if key not in {
            "record_digest", "allowed_parent_action_ids",
            "allowed_parent_capabilities", "continuation_allocation_digest",
            "allowed_continuation_capabilities",
            "required_continuation_capabilities",
        }
    }
    legacy["schema_version"] = "parallel-action-partition-record/v1"
    legacy["record_digest"] = hashlib.sha256(json.dumps(
        legacy, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()

    validate_parallel_partition_record(
        legacy,
        parent_scan_id=PARENT_ID,
        child_plan_digests={
            scan_id: str(plan.plan_digest) for scan_id, plan in plans.items()
        },
        child_action_plans=plans,
    )


def test_parallel_partition_accepts_only_preallocated_continuation_actions():
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": True,
            "include_families": ["xss"],
            "exclude_families": ["nuclei", "sqli", "bola"],
        },
        approval_receipt_id="approval-1",
    )
    admitted = allocate_scan_action_plan(
        ScanActionPlanCompiler().compile(
            scan_id=PARENT_ID,
            execution_plan=contract.execution_plan,
            target_binding=_target(),
            defer_manifest_actions=True,
            include_finalizer=False,
        ),
        contract.budget,
        assign_residual_to_finalizer=False,
        require_finalizer=False,
    )
    parent = admitted.plan
    continuation = ScanContinuationAllocation(
        scan_id=PARENT_ID,
        parent_plan_digest=parent.plan_digest,
        execution_plan_digest=parent.execution_plan_digest,
        target_binding_digest=parent.target_binding_digest,
        parent_action_ids=tuple(action.action_id for action in parent.actions),
        budget_ceiling=admitted.residual_scan_execute_budget,
        max_endpoint_entries=contract.budget.max_endpoints,
        max_candidate_entries=contract.budget.max_http_requests,
        required_capabilities=("xss.verify",),
        allowed_capabilities=("xss.verify",),
    )
    children = _children()
    partition = ParallelActionPlanCompiler().compile(
        parent_execution_plan=contract.execution_plan,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=children,
        continuation_allocation=continuation,
        strategy="scope",
    )
    plans = _projected_plans(partition, parent)
    endpoint_id = CHILD_IDS[1]
    seed = parent.actions[0]
    continuation_action = replace(
        seed,
        action_id="verify.xss",
        capability_name="xss.verify",
        ordinal=len(plans[endpoint_id].actions),
        dependencies=(),
        required=True,
        action_digest=None,
    )
    plans[endpoint_id] = replace(
        plans[endpoint_id],
        actions=(*plans[endpoint_id].actions, continuation_action),
        plan_digest=None,
    )
    assignments = _assignments(children)

    record = partition.record(
        plans,
        child_work_assignments=assignments,
        parent_work_assignment=_parent_assignment(assignments),
    )
    validate_parallel_partition_record(
        record,
        parent_scan_id=PARENT_ID,
        child_plan_digests={
            scan_id: str(plan.plan_digest) for scan_id, plan in plans.items()
        },
        child_action_plans=plans,
    )
    assert record["continuation_allocation_digest"] == (
        continuation.allocation_digest
    )

    rogue = replace(
        continuation_action,
        capability_name="rogue.execute",
        action_digest=None,
    )
    rogue_plans = {
        **plans,
        endpoint_id: replace(
            plans[endpoint_id],
            actions=(*plans[endpoint_id].actions[:-1], rogue),
            plan_digest=None,
        ),
    }
    with pytest.raises(ParallelActionPlanError, match="outside parent authority"):
        partition.record(rogue_plans)


def test_parallel_partition_rejects_a_cloned_full_parent_plan_on_every_child():
    execution, parent = _authority()
    partition = ParallelActionPlanCompiler().compile(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=_children(),
        strategy="scope",
    )
    clones = {
        child.scan_id: replace(parent, scan_id=child.scan_id, plan_digest=None)
        for child in partition.children
    }
    with pytest.raises(ParallelActionPlanError, match="parent-owned finalization"):
        partition.record(clones)


def test_parallel_partition_rejects_missing_and_duplicate_endpoint_work():
    execution, parent = _authority()
    children = _children()
    partition = ParallelActionPlanCompiler().compile(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=children,
        strategy="scope",
    )
    plans = _projected_plans(partition, parent)
    assignments = _assignments(children)
    missing_parent = build_parallel_work_assignment(
        endpoints=("GET /v1/items/1", "GET /v1/items/2", "GET /missing"),
    )
    with pytest.raises(ParallelActionPlanError, match="union differs"):
        partition.record(
            plans,
            child_work_assignments=assignments,
            parent_work_assignment=missing_parent,
        )

    duplicated = dict(assignments)
    duplicated[CHILD_IDS[2]] = duplicated[CHILD_IDS[1]]
    with pytest.raises(ParallelActionPlanError, match="duplicate endpoint"):
        partition.record(plans, child_work_assignments=duplicated)


def test_parallel_partition_rejects_duplicate_global_and_extra_capability_family():
    execution, parent = _authority()
    partition = ParallelActionPlanCompiler().compile(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=_children(),
        strategy="scope",
    )
    plans = _projected_plans(partition, parent)
    endpoint_id = CHILD_IDS[1]
    duplicate = parent.actions[0]
    endpoint_actions = (replace(
        duplicate, ordinal=0, dependencies=(), action_digest=None,
    ),)
    duplicate_plans = {
        **plans,
        endpoint_id: replace(
            plans[endpoint_id], actions=endpoint_actions, plan_digest=None,
        ),
    }
    with pytest.raises(ParallelActionPlanError, match="duplicates a global"):
        partition.record(duplicate_plans)

    global_id = CHILD_IDS[0]
    first = plans[global_id].actions[0]
    rogue = replace(first, capability_name="rogue.execute", action_digest=None)
    rogue_plan = replace(
        plans[global_id],
        actions=(rogue, *plans[global_id].actions[1:]),
        plan_digest=None,
    )
    with pytest.raises(ParallelActionPlanError, match="capability family"):
        partition.record({**plans, global_id: rogue_plan})


def test_parallel_partition_rejects_wrong_work_digest_and_unassigned_required_action():
    execution, parent = _authority()
    children = _children()
    partition = ParallelActionPlanCompiler().compile(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=children,
        strategy="scope",
    )
    plans = _projected_plans(partition, parent)
    assignments = _assignments(children)
    record = partition.record(plans, child_work_assignments=assignments)
    record["children"][1]["work_partition_digest"] = "f" * 64
    raw = {key: value for key, value in record.items() if key != "record_digest"}
    record["record_digest"] = hashlib.sha256(json.dumps(
        raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()
    with pytest.raises(ParallelActionPlanError, match="work partition digest"):
        validate_parallel_partition_record(
            record,
            parent_scan_id=PARENT_ID,
            child_plan_digests={
                scan_id: str(plan.plan_digest) for scan_id, plan in plans.items()
            },
        )

    active_contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": True,
            "include_families": ["xss"],
            "exclude_families": ["recon", "nuclei", "sqli", "bola"],
        },
    )
    active_parent = allocate_scan_action_plan(
        ScanActionPlanCompiler().compile(
            scan_id=PARENT_ID,
            execution_plan=active_contract.execution_plan,
            target_binding=_target(),
        ),
        active_contract.budget,
    ).plan
    active_partition = ParallelActionPlanCompiler().compile(
        parent_execution_plan=active_contract.execution_plan,
        parent_action_plan=active_parent,
        target_binding=_target(),
        child_specs=children,
        strategy="scope",
    )
    incomplete = _projected_plans(active_partition, active_parent)
    for child in active_partition.children:
        plan = incomplete[child.scan_id]
        kept = tuple(
            action for action in plan.actions if action.action_id != "verify.xss"
        )
        incomplete[child.scan_id] = replace(
            plan,
            actions=tuple(replace(
                action, ordinal=index, action_digest=None,
            ) for index, action in enumerate(kept)),
            plan_digest=None,
        )
    with pytest.raises(ParallelActionPlanError, match="required parent work"):
        active_partition.record(incomplete)


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
