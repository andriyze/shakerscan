from dataclasses import replace
import hashlib
import json
import uuid

import pytest

from api.runtime.models import TargetBinding
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.contracts import resolve_scan_contract
from api.scan.continuation import ScanContinuationAllocation
from api.scan.jobs import derive_scan_shard_budget
from api.scan.parallel_compiler import (
    ParallelActionPlanCompiler,
    ParallelPlannedChild,
    ParallelActionPlanError,
    ParallelPlacementCapacity,
    ParallelPrincipalLane,
    ParallelRequestWork,
    build_parallel_work_assignment,
    merge_parallel_action_executions,
    merge_parallel_work_assignments,
    summarize_parallel_action_coverage,
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
            "exclude_families": ["nuclei_passive", "nuclei_active", "xss", "sqli", "bola"],
        },
    )
    raw = ScanActionPlanCompiler().compile(
        scan_id=PARENT_ID,
        execution_plan=contract.execution_plan,
        target_binding=_target(),
    )
    parent = allocate_scan_action_plan(raw, contract.budget).plan
    return contract.execution_plan, parent


def _endpoint_authority():
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": True,
            "include_families": ["xss"],
            "exclude_families": ["nuclei_passive", "nuclei_active", "sqli", "bola"],
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


def _projected_plans(partition, parent, *, structural_finalizer=None):
    result = {}
    global_ids = set(partition.globally_assigned_action_ids)
    finalizer = structural_finalizer or next(
        (
            action for action in parent.actions
            if action.capability_name == "scan.finalize"
        ),
        None,
    )
    assert finalizer is not None
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
        actions = (*actions, replace(
            finalizer,
            ordinal=len(actions),
            dependencies=tuple(action.action_id for action in actions),
            action_digest=None,
        ))
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


def _canonical_child_report(plan):
    return {
        "canonical_action_execution": {
            "plan_digest": plan.plan_digest,
            "actions": [
                {
                    "action_id": action.action_id,
                    "observation_manifest": None,
                    "status": "success",
                }
                for action in plan.actions
                if action.action_id != "finalize.report"
            ],
            "finalization_action": {
                "action_id": "finalize.report",
                "status": "success",
            },
        },
        "scan_metadata": {"partial": False},
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
    # Browser proof runs against candidates, which live on the endpoint
    # children. Pinning them to zero made xss.browser_prove_batch structurally
    # unrunnable in every sharded Scan while the backbone held the whole
    # allowance and had nothing to prove.
    assert first.children[1].budget.max_browser_actions > 0
    # tcp stays backbone-only: ports.discover is a target-wide producer.
    assert first.children[2].budget.max_tcp_ports == 0
    assert first.parent_owned_action_ids == ("finalize.report",)
    assert "finalize.report" not in first.globally_assigned_action_ids
    assert "secret=redacted-at-source" not in str(first.canonical_dict())


def test_active_candidate_shard_can_fund_complete_production_verifiers():
    contract = resolve_scan_contract(
        budget_profile="thorough",
        policy={
            "active_testing": True,
            "exclude_families": ["nuclei_passive", "nuclei_active", "xss", "sqli", "bola"],
        },
    )
    parent = allocate_scan_action_plan(
        ScanActionPlanCompiler().compile(
            scan_id=PARENT_ID,
            execution_plan=contract.execution_plan,
            target_binding=_target(),
        ),
        contract.budget,
    ).plan
    children = (
        {
            "scan_id": CHILD_IDS[0], "index": 0, "role": "global",
            "work_weight": 1, "options": {"parallel_backbone": True},
        },
        {
            "scan_id": CHILD_IDS[1], "index": 1, "role": "endpoint",
            "work_weight": 1, "options": {"custom_endpoints": ["GET /"]},
        },
        {
            "scan_id": CHILD_IDS[2], "index": 2, "role": "endpoint",
            "work_weight": 9,
            "options": {"custom_endpoints": ["GET /search?q=one"]},
        },
    )

    partition = ParallelActionPlanCompiler().compile(
        parent_execution_plan=contract.execution_plan,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=children,
        strategy="scope",
    )
    candidate_budget = partition.children[2].budget

    assert candidate_budget.max_http_requests >= 4_000 + 400 + 900
    assert candidate_budget.max_tool_wall_seconds >= 300 + 120 + 300


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
            "exclude_families": ["nuclei_passive", "nuclei_active", "sqli", "bola"],
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
    finalizer = next(
        action for action in ScanActionPlanCompiler().compile(
            scan_id=PARENT_ID,
            execution_plan=contract.execution_plan,
            target_binding=_target(),
        ).actions
        if action.capability_name == "scan.finalize"
    )
    plans = _projected_plans(
        partition, parent, structural_finalizer=finalizer,
    )
    endpoint_id = CHILD_IDS[1]
    seed = parent.actions[0]
    continuation_action = replace(
        seed,
        action_id="verify.xss",
        capability_name="xss.verify",
        ordinal=len(plans[endpoint_id].actions) - 1,
        dependencies=(),
        required=True,
        action_digest=None,
    )
    endpoint_actions = plans[endpoint_id].actions[:-1]
    endpoint_actions = (*endpoint_actions, continuation_action)
    endpoint_actions = (*endpoint_actions, replace(
        plans[endpoint_id].actions[-1],
        ordinal=len(endpoint_actions),
        dependencies=tuple(action.action_id for action in endpoint_actions),
        action_digest=None,
    ))
    plans[endpoint_id] = replace(
        plans[endpoint_id], actions=endpoint_actions, plan_digest=None,
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
    rogue_actions = (*plans[endpoint_id].actions[:-2], rogue)
    rogue_actions = (*rogue_actions, replace(
        plans[endpoint_id].actions[-1],
        ordinal=len(rogue_actions),
        dependencies=tuple(action.action_id for action in rogue_actions),
        action_digest=None,
    ))
    rogue_plans = {
        **plans,
        endpoint_id: replace(
            plans[endpoint_id], actions=rogue_actions, plan_digest=None,
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
    with pytest.raises(ParallelActionPlanError, match="duplicates a global"):
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
    duplicate = replace(
        duplicate, ordinal=0, dependencies=(), action_digest=None,
    )
    endpoint_actions = (
        duplicate,
        replace(
            plans[endpoint_id].actions[-1],
            ordinal=1,
            dependencies=(duplicate.action_id,),
            action_digest=None,
        ),
    )
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
            "exclude_families": ["recon", "nuclei_passive", "nuclei_active", "sqli", "bola"],
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
        kept_ids = {action.action_id for action in kept}
        incomplete[child.scan_id] = replace(
            plan,
            actions=tuple(replace(
                action,
                ordinal=index,
                dependencies=tuple(
                    dependency for dependency in action.dependencies
                    if dependency in kept_ids
                ),
                action_digest=None,
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


def test_typed_parent_plan_is_stable_and_explicitly_isolates_principals():
    execution, parent = _endpoint_authority()
    compiler = ParallelActionPlanCompiler()
    primary = ParallelPrincipalLane("primary", ("profile-primary",))
    secondary = ParallelPrincipalLane("secondary", ("profile-secondary",))
    placements = (
        ParallelPlacementCapacity("broker", 2, {
            "region": "eu-west", "node_scope": "remote",
        }),
        ParallelPlacementCapacity("local", 2, {"node_scope": "local"}),
    )
    request = ParallelRequestWork("a" * 64, "primary")
    endpoints = (
        "GET /v1/z", "GET /v1/a", "GET /v1/z", "POST /v1/items",
    )
    first = compiler.plan_parent(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        endpoint_manifest_entries=endpoints,
        request_work=(request,),
        principal_lanes=(primary, secondary),
        placements=placements,
        scheduling_hint="scope",
    )
    second = compiler.plan_parent(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        endpoint_manifest_entries=tuple(reversed(endpoints)),
        request_work=(request,),
        principal_lanes=(primary, secondary),
        placements=(
            ParallelPlacementCapacity("broker", 2, {
                "node_scope": "remote", "region": "eu-west",
            }),
            ParallelPlacementCapacity("local", 2, {"node_scope": "local"}),
        ),
        scheduling_hint="scope",
    )

    assert first.plan_digest == second.plan_digest
    assert [child.role for child in first.children].count("global") == 1
    endpoint_children = [
        child for child in first.children if child.role == "endpoint"
    ]
    assert {child.principal_lane.name for child in endpoint_children} == {
        "primary", "secondary",
    }
    assert all(
        child.principal_lane.credential_profile_ids
        in {("profile-primary",), ("profile-secondary",)}
        for child in endpoint_children
    )
    assert sum(
        "a" * 64 in child.request_selection_digests
        for child in endpoint_children
    ) == 1
    assert {child.placement.name for child in first.children} == {
        "local", "broker",
    }


def test_typed_parent_plan_allocates_exact_subbudgets_without_legacy_options():
    execution, parent = _endpoint_authority()
    compiler = ParallelActionPlanCompiler()
    planned = compiler.plan_parent(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        endpoint_manifest_entries=("GET /a", "GET /b", "GET /c"),
        principal_lanes=(ParallelPrincipalLane("anonymous"),),
        placements=(
            ParallelPlacementCapacity("local", 3, {"node_scope": "local"}),
        ),
        scheduling_hint="scope",
    )
    partition = compiler.compile(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=tuple(
            child.compiler_spec(scan_id=CHILD_IDS[child.index])
            for child in planned.children
        ),
        strategy=planned.scheduling_hint,
        available_worker_count=3,
    )

    assert len(partition.children) == len(planned.children)
    assert sum(
        child.budget.max_http_requests for child in partition.children
    ) == execution.budget.max_http_requests
    assert all(
        child.principal_lane == planned.children[child.index].principal_lane.name
        for child in partition.children
    )
    serialized = json.dumps([
        child.compiler_spec(scan_id=CHILD_IDS[child.index])
        for child in planned.children
    ])
    assert "exhaustive" not in serialized
    assert "smart_bola" not in serialized
    assert "auth_header" not in serialized


def test_typed_parent_plan_allows_sequential_fanout_under_one_worker_ceiling():
    contract = resolve_scan_contract(
        budget_profile="fast",
        policy={"exclude_families": ["nuclei_passive", "nuclei_active"]},
        advanced={"max_workers": 1},
    )
    raw = ScanActionPlanCompiler().compile(
        scan_id=PARENT_ID,
        execution_plan=contract.execution_plan,
        target_binding=_target(),
        request_collection_refs=({
            "collection_id": "collection-safe",
            "selection_id": "selection-safe",
            "binding_id": "binding-safe",
            "version": 1,
            "selection_digest": "a" * 64,
            "active": False,
            "max_requests": 1,
        },),
        request_manifest_refs={
            "a" * 64: {
                "kind": "request",
                "manifest_id": CHILD_IDS[0],
                "manifest_digest": "b" * 64,
                "entry_count": 1,
                "status": "complete",
                "schema_version": "scan-work-manifest-reference/v1",
                "content_schema": "request-manifest/v2",
            },
        },
    )
    parent = allocate_scan_action_plan(raw, contract.budget).plan

    planned = ParallelActionPlanCompiler().plan_parent(
        parent_execution_plan=contract.execution_plan,
        parent_action_plan=parent,
        target_binding=_target(),
        endpoint_manifest_entries=("GET /", "GET /rest/products/search?q=apple"),
        request_work=(ParallelRequestWork("a" * 64, "anonymous"),),
        principal_lanes=(ParallelPrincipalLane("anonymous"),),
        placements=(
            ParallelPlacementCapacity("local", 1, {"node_scope": "local"}),
        ),
        scheduling_hint="scope",
    )

    assert contract.budget.max_workers == 1
    assert [child.role for child in planned.children] == ["global", "endpoint"]
    assert planned.children[1].request_selection_digests == ("a" * 64,)


def test_typed_parent_plan_preserves_principal_lanes_sequentially():
    execution, parent = _endpoint_authority()
    planned = ParallelActionPlanCompiler().plan_parent(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        endpoint_manifest_entries=("GET /a", "GET /b"),
        principal_lanes=(
            ParallelPrincipalLane("anonymous"),
            ParallelPrincipalLane("primary", ("profile-primary",)),
        ),
        placements=(
            ParallelPlacementCapacity("local", 1, {"node_scope": "local"}),
        ),
        scheduling_hint="scope",
    )

    assert [child.role for child in planned.children] == [
        "global", "endpoint", "endpoint",
    ]
    assert {child.principal_lane.name for child in planned.children[1:]} == {
        "anonymous", "primary",
    }
    assert all(child.placement.capacity == 1 for child in planned.children)


def test_generic_action_merge_is_partition_bound_and_truthful_on_child_loss():
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
    record = partition.record(
        plans,
        child_work_assignments=assignments,
        parent_work_assignment=_parent_assignment(assignments),
    )
    reports = {
        scan_id: _canonical_child_report(plan)
        for scan_id, plan in plans.items()
    }
    reports[CHILD_IDS[1]]["coverage"] = {
        "candidate_coverage": {
            "nuclei_passive": {
                "status": "complete",
                "batch_actions": 1,
                "planned_candidates": 1,
                "attempted_candidates": 1,
                "completed_candidates": 1,
                "incomplete_candidates": 0,
                "unattempted_candidates": 0,
            },
        },
        "family_coverage": [{
            "family": "nuclei_passive",
            "selected": True,
            "required": True,
            "coverage_status": "complete",
            "planned_candidates": 1,
            "attempted_candidates": 1,
            "verified_findings": 0,
            "suspected_findings": 1,
        }],
    }
    merged = merge_parallel_action_executions(
        record,
        child_results=reports,
        child_statuses={scan_id: "completed" for scan_id in plans},
    )
    assert merged["partial"] is False
    assert merged["incomplete_child_scan_ids"] == []
    assert merged["merge_digest"]
    assert all(
        len(action["occurrence_id"]) == 64 for action in merged["actions"]
    )
    assert len({
        action["occurrence_id"] for action in merged["actions"]
    }) == len(merged["actions"])
    assert merged["candidate_coverage"]["nuclei_passive"][
        "attempted_candidates"
    ] == 1
    assert merged["family_coverage"] == [{
        "family": "nuclei_passive",
        "selected": True,
        "required": True,
        "coverage_status": "complete",
        "reason": None,
        "batch_actions": 0,
        "planned_candidates": 1,
        "attempted_candidates": 1,
        "completed_candidates": 0,
        "incomplete_candidates": 0,
        "unattempted_candidates": 0,
        "verified_findings": 0,
        "suspected_findings": 1,
    }]
    coverage = summarize_parallel_action_coverage(merged)
    assert coverage["status"] == "complete"
    assert coverage["grade_reliability"] == {"reliable": True, "reasons": []}
    assert coverage["candidate_coverage"]["nuclei_passive"][
        "attempted_candidates"
    ] == 1
    assert coverage["family_coverage"][0]["coverage_status"] == "complete"

    lost = dict(reports)
    lost[CHILD_IDS[2]] = None
    partial = merge_parallel_action_executions(
        record,
        child_results=lost,
        child_statuses={
            **{scan_id: "completed" for scan_id in plans},
            CHILD_IDS[2]: "failed",
        },
    )
    assert partial["partial"] is True
    assert partial["incomplete_child_scan_ids"] == [CHILD_IDS[2]]
    assert summarize_parallel_action_coverage(partial)["grade_reliability"] == {
        "reliable": False,
        "reasons": ["parallel_child_incomplete"],
    }

    rogue = json.loads(json.dumps(reports))
    rogue[CHILD_IDS[1]]["canonical_action_execution"]["actions"].append({
        "action_id": "rogue.execute",
        "observation_manifest": None,
        "status": "success",
    })
    with pytest.raises(ParallelActionPlanError, match="outside its exact"):
        merge_parallel_action_executions(
            record,
            child_results=rogue,
            child_statuses={scan_id: "completed" for scan_id in plans},
        )


def test_parallel_coverage_uses_merged_terminal_actions_not_parent_placeholders():
    coverage = summarize_parallel_action_coverage({
        "partial": True,
        "actions": [
            {
                "action_id": "baseline.http",
                "capability_name": "http.request",
                "required": True,
                "status": "success",
                "reason_code": None,
            },
            {
                "action_id": "inputs.collection_00",
                "capability_name": "collections.replay_safe",
                "required": True,
                "status": "failed",
                "reason_code": "adapter_failed",
            },
            {
                "action_id": "discover.web_crawl",
                "capability_name": "web.crawl",
                "required": False,
                "status": "skipped",
                "reason_code": "insufficient_plan_budget",
            },
        ],
    })

    assert coverage["status"] == "partial"
    assert coverage["capability_coverage"] == {
        "total": 3,
        "required": 2,
        "completed": 1,
        "partial": 0,
        "blocked": 0,
        "failed": 1,
        "skipped": 1,
        "cancelled": 0,
        "pending": 0,
        "actions": coverage["capability_coverage"]["actions"],
    }
    assert coverage["grade_reliability"] == {
        "reliable": False,
        "reasons": ["adapter_failed", "parallel_child_incomplete"],
    }


def _child_scan_id(index):
    return f"20000000-0000-4000-8000-0000000001{index:02d}"


def _discovery_scope_partition(*, discovery_owned_externally):
    """Plan and compile one partition under an explicit discovery-ownership decision."""
    execution, parent = _endpoint_authority()
    compiler = ParallelActionPlanCompiler()
    planned = compiler.plan_parent(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        endpoint_manifest_entries=(
            "GET /api/a?id=1", "GET /api/b?id=1", "GET /api/c?id=1",
        ),
        placements=(ParallelPlacementCapacity("local", 4, {"node_scope": "local"}),),
        scheduling_hint="scope",
        discovery_owned_externally=discovery_owned_externally,
    )
    partition = compiler.compile(
        parent_execution_plan=execution,
        parent_action_plan=parent,
        target_binding=_target(),
        child_specs=tuple(
            child.compiler_spec(scan_id=_child_scan_id(child.index))
            for child in planned.children
        ),
        strategy=planned.scheduling_hint,
    )
    return execution, parent, planned, partition


def _child_plan(execution, scan_id, scope):
    raw = ScanActionPlanCompiler().compile(
        scan_id=scan_id,
        execution_plan=execution,
        target_binding=_target(),
        action_scope=scope,
    )
    return allocate_scan_action_plan(
        raw, derive_scan_shard_budget({}, execution.budget),
        assign_residual_to_finalizer=False,
    ).plan


def test_placed_discovery_stage_owns_discovery_instead_of_the_backbone():
    """A separate discovery shard already ran, so the backbone must not repeat it."""
    _execution, parent, planned, partition = _discovery_scope_partition(
        discovery_owned_externally=True,
    )
    backbone = next(item for item in planned.children if item.role == "global")
    assert backbone.action_scope == "global"

    discovery_ids = {
        action.action_id for action in parent.actions
        if action.action_id.startswith("discover.")
    }
    baseline_ids = {
        action.action_id for action in parent.actions
        if action.action_id.startswith("baseline.")
    }
    assert discovery_ids, "fixture must contain discovery actions to be meaningful"

    # Discovery is recorded as stage-owned work, not silently dropped, and it is
    # excluded from every fan-out authority list so a child carrying one fails.
    assert set(partition.discovery_stage_action_ids) == discovery_ids
    assert set(partition.globally_assigned_action_ids) == baseline_ids
    assert not discovery_ids & set(partition.assigned_parent_action_ids)
    assert not discovery_ids & set(partition.required_parent_action_ids)


def test_backbone_keeps_discovery_when_no_placed_discovery_stage_ran():
    """Without a discovery stage the backbone is the only owner; never drop it."""
    _execution, parent, planned, partition = _discovery_scope_partition(
        discovery_owned_externally=False,
    )
    backbone = next(item for item in planned.children if item.role == "global")
    assert backbone.action_scope == "full"

    discovery_ids = {
        action.action_id for action in parent.actions
        if action.action_id.startswith("discover.")
    }
    assert partition.discovery_stage_action_ids == ()
    assert discovery_ids <= set(partition.globally_assigned_action_ids)


def test_unset_child_scope_defaults_to_retaining_discovery_coverage():
    """An absent scope must duplicate discovery, never silently lose it.

    Cross-version in-flight shards can reach this build without the scope key.
    Duplicated discovery is wasteful; missing discovery is wrong, so the
    conservative default for a backbone is the discovery-owning ``full`` scope.
    """
    planned = ParallelPlannedChild(
        index=0,
        label="global",
        role="global",
        endpoints=(),
        request_selection_digests=(),
        candidate_manifest_refs=(),
        principal_lane=ParallelPrincipalLane("anonymous"),
        family_scope=(),
        placement=ParallelPlacementCapacity("local", 2, {"node_scope": "local"}),
    )
    assert planned.action_scope == "full"
    assert planned.canonical_dict()["action_scope"] == "full"
    assert planned.compiler_spec(scan_id=_child_scan_id(0))["action_scope"] == "full"

    endpoint_child = ParallelPlannedChild(
        index=1,
        label="work",
        role="endpoint",
        endpoints=("GET /api/a?id=1",),
        request_selection_digests=(),
        candidate_manifest_refs=(),
        principal_lane=ParallelPrincipalLane("anonymous"),
        family_scope=(),
        placement=ParallelPlacementCapacity("local", 2, {"node_scope": "local"}),
    )
    assert endpoint_child.action_scope == "endpoint"

    # A resolved scope may never be re-pointed at the wrong role.
    with pytest.raises(ParallelActionPlanError):
        replace(planned, action_scope="endpoint")
    with pytest.raises(ParallelActionPlanError):
        replace(planned, action_scope="nonsense")


def test_partition_rejects_a_backbone_that_still_carries_stage_owned_discovery():
    """Fail closed when the compiled backbone disagrees with recorded ownership."""
    execution, _parent, planned, partition = _discovery_scope_partition(
        discovery_owned_externally=True,
    )
    plans = {}
    for child in planned.children:
        scan_id = _child_scan_id(child.index)
        # The backbone is compiled at "full", so it still contains discover.*
        # even though the partition recorded discovery as stage-owned work.
        plans[scan_id] = _child_plan(
            execution, scan_id, "full" if child.role == "global" else "endpoint",
        )
    with pytest.raises(ParallelActionPlanError):
        partition.record(plans)


def test_merged_family_reason_agrees_with_its_counters():
    """A family the merged run attempted is incomplete, not unattempted.

    Child reasons merge first-wins, and candidates cluster on whichever shard
    owns the parameterised routes, so a shard with none for a family stamped its
    own zero_attempts onto the parent. Measured on the benchmark application:
    two of four shards ran sqli to success on 854 and 1,067 requests and the
    parent still reported sqli as zero_attempts -- understating work that
    demonstrably happened, which is the one thing coverage must never do.
    """
    from api.scan.parallel_compiler import _reconciled_family_coverage

    # A shard that never attempted contributed the reason, but siblings did.
    attempted = _reconciled_family_coverage({
        "family": "sqli",
        "reason": "zero_attempts",
        "attempted_candidates": 9,
        "coverage_status": "partial",
    })
    assert attempted["reason"] == "child_family_incomplete"

    # Genuinely unattempted across every shard keeps the honest reason.
    untouched = _reconciled_family_coverage({
        "family": "sqli",
        "reason": "zero_attempts",
        "attempted_candidates": 0,
        "coverage_status": "partial",
    })
    assert untouched["reason"] == "zero_attempts"

    # Any other reason is left exactly as the children reported it.
    other = _reconciled_family_coverage({
        "family": "xss",
        "reason": "action_incomplete",
        "attempted_candidates": 9,
        "coverage_status": "partial",
    })
    assert other["reason"] == "action_incomplete"


def test_fan_out_width_is_bounded_by_injectable_surface():
    """More children only help when there are candidates to give them.

    Endpoint count decides how many children are possible; candidate count
    decides whether more help. Active verifiers are candidate-driven, and
    candidates come from parameterised routes -- a fraction of the crawl.
    Splitting by endpoints alone fragments a small injectable surface AND
    divides each child's verifier ledger, dropping every child to a smaller
    batch tier at once.

    Measured on the benchmark application: 138 endpoints yielded 9 candidates.
    Unsharded those verified at the thorough tier and produced 13 verified
    findings; split four ways they landed 5/4/0/0 -- three children with nothing
    to do -- each at the fast tier, and the run produced none.
    """
    execution, parent = _endpoint_authority()
    placements = (ParallelPlacementCapacity("local", 5, {"node_scope": "local"}),)

    def endpoint_children(plan_execution, endpoints):
        planned = ParallelActionPlanCompiler().plan_parent(
            parent_execution_plan=plan_execution,
            parent_action_plan=parent,
            target_binding=_target(),
            endpoint_manifest_entries=endpoints,
            placements=placements,
            discovery_owned_externally=True,
        )
        return [child for child in planned.children if child.role == "endpoint"]

    # A wide crawl with a narrow injectable surface: one child, because a second
    # could not fill a verifier batch and would only take budget from the first.
    narrow = [f"GET /page{index}" for index in range(120)]
    narrow += [f"GET /api/item{index}?id=1" for index in range(9)]
    assert len(endpoint_children(execution, narrow)) == 1

    # A genuinely wide injectable surface still fans out.
    wide = [f"GET /api/item{index}?id=1" for index in range(120)]
    assert len(endpoint_children(execution, wide)) > 1

    # Passive Scans are untouched by construction: the bound sits inside the
    # active_testing branch, because template breadth scales with endpoints
    # rather than candidates. Asserting that here would need a passive plan that
    # carries endpoint-scoped work, which a recon-only plan does not.
