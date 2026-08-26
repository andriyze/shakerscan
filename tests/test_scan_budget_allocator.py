from __future__ import annotations

import uuid

import pytest

from api.runtime.models import ScanBudget, ScanPolicy, TargetBinding
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.budget_allocator import (
    ScanBudgetAllocationError,
    allocate_scan_action_plan,
)
from api.scan.execution import ScanExecutionPlan
from api.scan.work_manifests import build_canonical_scan_nuclei_template_manifest


SCAN_ID = "30000000-0000-4000-8000-000000000001"


def _target() -> TargetBinding:
    return TargetBinding(
        target_id="30000000-0000-4000-8000-000000000002",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.12",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="30000000-0000-4000-8000-000000000003",
    )


def _compile(budget: ScanBudget, *, include=(), active=True):
    execution = ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=active,
            include_families=tuple(include),
            scope_receipt_id=_target().scope_receipt_id,
            approval_receipt_id=(
                str(uuid.UUID("30000000-0000-4000-8000-000000000004"))
                if active else None
            ),
        ),
        budget_profile="fast",
        budget=budget,
    )
    template = (
        build_canonical_scan_nuclei_template_manifest(
            scan_id=SCAN_ID,
            target_binding_digest=_target().digest,
            include_active=active,
        )
        if not include or "nuclei" in include else None
    )
    return ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        template_manifest_ref=(
            template.reference().canonical_dict() if template is not None else None
        ),
    )


def test_allocator_admits_whole_plan_and_leaves_residual_unallocated():
    budget = ScanBudget(300, 1_000, 500, 50, 1_000, 180, 2, 0, 25)
    allocation = allocate_scan_action_plan(_compile(budget, active=False), budget)

    assert allocation.allocated != budget.ledger_limits()
    assert allocation.residual_scan_execute_budget["http_requests"] > 0
    assert allocation.residual_scan_execute_budget["tool_wall_seconds"] > 0
    assert allocation.unallocated_budget == allocation.residual_scan_execute_budget
    assert all(
        allocation.allocated[name] + allocation.unallocated_budget[name] == limit
        for name, limit in budget.ledger_limits().items()
    )
    assert all(
        sum(
            action.requested_budget.get(name, 0)
            for action in allocation.plan.actions
            if action.admission_status == "planned"
        ) <= limit
        for name, limit in budget.ledger_limits().items()
    )
    finalizer = allocation.plan.actions[-1]
    assert finalizer.action_id == "finalize.report"
    assert finalizer.capability_name == "scan.finalize"
    assert finalizer.requested_budget == {"tool_wall_seconds": 1}


def test_allocator_rejects_legacy_residual_assignment_for_pure_finalizer():
    budget = ScanBudget(300, 1_000, 500, 50, 1_000, 180, 2, 0, 25)

    with pytest.raises(
        ScanBudgetAllocationError, match="legacy_residual_assignment"
    ):
        allocate_scan_action_plan(
            _compile(budget, active=False),
            budget,
            assign_residual_to_finalizer=True,
        )


def test_allocator_preserves_explicit_continuation_hold():
    budget = ScanBudget(300, 1_000, 500, 50, 1_000, 180, 2, 0, 25)
    plan = _compile(budget, active=False)

    allocation = allocate_scan_action_plan(
        plan,
        budget,
        reserved_budget={"tool_wall_seconds": 1},
    )

    assert allocation.residual_scan_execute_budget["tool_wall_seconds"] >= 1
    assert allocation.plan.actions[-1].capability_name == "scan.finalize"


def test_shard_allocator_leaves_unassigned_residual_outside_pure_finalizer():
    budget = ScanBudget(300, 100, 50, 10, 10, 30, 1, 0, 10)
    execution = ScanExecutionPlan(
        # This fixture exercises residual accounting for a pure-finalizer
        # endpoint shard. Keep Nuclei out of scope explicitly so the compiler
        # does not (correctly) require the canonical immutable template pack.
        policy=ScanPolicy(
            active_testing=False,
            exclude_families=("nuclei",),
        ),
        budget_profile="fast",
        budget=budget,
    )
    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        action_scope="endpoint",
        shard_authority={"options_digest": "a" * 64},
        action_budgets={"finalize.report": {}},
    )

    allocation = allocate_scan_action_plan(
        plan, budget, assign_residual_to_finalizer=False,
    )

    assert allocation.allocated == {
        name: 0 for name in budget.ledger_limits()
    }
    assert allocation.plan.actions[0].action_id == "finalize.report"
    assert allocation.plan.actions[0].requested_budget == {}


def test_allocator_skips_optional_actions_with_stable_dependency_reasons():
    budget = ScanBudget(300, 1_000, 500, 50, 1_000, 180, 2, 0, 25)
    compiled = _compile(budget)
    maximum_digest = next(
        action.action_digest for action in compiled.actions
        if action.action_id == "active.templates"
    )
    allocation = allocate_scan_action_plan(compiled, budget)
    rows = {action.action_id: action for action in allocation.plan.actions}

    assert rows["discover.web_crawl"].admission_status == "planned"
    assert rows["passive.templates"].requested_budget == {
        "http_requests": 7, "tool_wall_seconds": 30,
    }
    assert rows["active.templates"].requested_budget == {
        "http_requests": 11, "tool_wall_seconds": 10,
    }
    assert rows["active.templates"].action_digest != maximum_digest
    assert rows["verify.xss"].reason_code == "insufficient_plan_budget"
    assert rows["verify.sqli"].reason_code == "insufficient_plan_budget"
    assert rows["finalize.report"].admission_status == "planned"


def test_allocator_scales_required_passive_pack_inside_parallel_child_budget():
    budget = ScanBudget(120, 10, 10, 1, 1, 21, 1, 0, 1)
    execution = ScanExecutionPlan(
        policy=ScanPolicy(active_testing=False),
        budget_profile="fast",
        budget=budget,
    )
    templates = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=_target().digest,
        include_active=False,
    )
    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        template_manifest_ref=templates.reference().canonical_dict(),
        action_scope="endpoint",
        shard_authority={"options_digest": "a" * 64},
    )

    allocation = allocate_scan_action_plan(plan, budget)
    rows = {action.action_id: action for action in allocation.plan.actions}

    assert rows["passive.templates"].requested_budget == {
        "http_requests": 7,
        "tool_wall_seconds": 20,
    }
    assert rows["passive.templates"].admission_status == "planned"
    assert rows["finalize.report"].requested_budget == {
        "tool_wall_seconds": 1,
    }
    assert allocation.allocated["tool_wall_seconds"] == 21


def test_allocator_fails_admission_when_focused_required_graph_cannot_fit():
    budget = ScanBudget(300, 200, 100, 10, 10, 129, 1, 0, 10)
    plan = _compile(budget, include=("xss",))
    with pytest.raises(ScanBudgetAllocationError, match="required Scan action"):
        allocate_scan_action_plan(plan, budget)


def test_allocator_result_is_independent_of_override_mapping_order():
    budget = ScanBudget(1_200, 5_000, 2_000, 200, 5_000, 900, 4, 100, 100)
    compiler = ScanActionPlanCompiler()
    execution = ScanExecutionPlan(
        policy=ScanPolicy(active_testing=False),
        budget_profile="balanced",
        budget=budget,
    )
    overrides = {
        "baseline.http": {"http_requests": 1, "tool_wall_seconds": 15},
        "discover.web_probe": {"http_requests": 4, "tool_wall_seconds": 30},
    }
    templates = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=_target().digest,
        include_active=False,
    )
    first = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        template_manifest_ref=templates.reference().canonical_dict(),
        action_budgets=overrides,
    )
    second = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        template_manifest_ref=templates.reference().canonical_dict(),
        action_budgets=dict(reversed(tuple(overrides.items()))),
    )
    assert allocate_scan_action_plan(first, budget).plan == allocate_scan_action_plan(
        second, budget,
    ).plan
