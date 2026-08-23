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
    return ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID, execution_plan=execution, target_binding=_target(),
    )


def test_allocator_admits_whole_plan_and_assigns_only_precomputed_residual():
    budget = ScanBudget(300, 1_000, 500, 50, 1_000, 180, 2, 0, 25)
    allocation = allocate_scan_action_plan(_compile(budget, active=False), budget)

    assert allocation.allocated == budget.ledger_limits()
    assert allocation.residual_scan_execute_budget["http_requests"] > 0
    assert allocation.residual_scan_execute_budget["tool_wall_seconds"] > 0
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
    assert finalizer.requested_budget["http_requests"] > 0


def test_allocator_skips_optional_actions_with_stable_dependency_reasons():
    budget = ScanBudget(300, 1_000, 500, 50, 1_000, 180, 2, 0, 25)
    allocation = allocate_scan_action_plan(_compile(budget), budget)
    rows = {action.action_id: action for action in allocation.plan.actions}

    assert rows["discover.web_crawl"].admission_status == "planned"
    assert rows["active.templates"].reason_code == "insufficient_plan_budget"
    assert rows["verify.xss"].reason_code == "insufficient_plan_budget"
    assert rows["verify.sqli"].reason_code == "insufficient_plan_budget"
    assert rows["finalize.report"].admission_status == "planned"


def test_allocator_fails_admission_when_focused_required_graph_cannot_fit():
    budget = ScanBudget(300, 200, 100, 10, 10, 180, 1, 0, 10)
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
    first = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        action_budgets=overrides,
    )
    second = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        action_budgets=dict(reversed(tuple(overrides.items()))),
    )
    assert allocate_scan_action_plan(first, budget).plan == allocate_scan_action_plan(
        second, budget,
    ).plan
