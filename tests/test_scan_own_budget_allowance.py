"""Product recipes (web.identify) are funded by their own allowance (unit fixtures).

Adding them to a plan must not move any other action's admission, its frozen budget, or the
residual that continuation rounds are sized from.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from api.scan.budget_allocator import allocate_scan_action_plan, own_budget_allowance, with_own_budget
from api.scan.action_plan import ScanActionPlan
from tests.scan_round_fixtures import admitted_round_fixture


def _without_identify(plan):
    return ScanActionPlan(
        scan_id=plan.scan_id, execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=plan.target_binding_digest,
        actions=tuple(replace(action, ordinal=index, action_digest=None) for index, action in enumerate(
            a for a in plan.actions if a.capability_name != "web.identify")),
    )


@pytest.mark.parametrize("profile", ["fast", "balanced", "thorough"])
def test_identify_never_displaces_a_shared_budget_action(profile):
    fixture = admitted_round_fixture(profile, endpoints=215, queries=14, body=True, state_changing=True,
                                     families=("recon", "nuclei_passive", "xss", "sqli"))
    plan = fixture["parent_plan"]
    identify = [a for a in plan.actions if a.capability_name == "web.identify"]
    assert len(identify) == 1 and identify[0].admission_status == "planned"
    budget = fixture["execution_plan"].budget
    raw = [replace(a, admission_status="planned", reason_code=None, action_digest=None) for a in plan.actions]
    with_it = allocate_scan_action_plan(replace(plan, actions=tuple(raw)), budget, require_finalizer=False)
    without = allocate_scan_action_plan(_without_identify(replace(plan, actions=tuple(raw))), budget,
                                        require_finalizer=False)
    others = {a.action_id: (a.admission_status, dict(a.requested_budget))
              for a in with_it.plan.actions if a.capability_name != "web.identify"}
    assert others == {a.action_id: (a.admission_status, dict(a.requested_budget)) for a in without.plan.actions}
    assert dict(with_it.residual_scan_execute_budget) == dict(without.residual_scan_execute_budget)


def test_the_allowance_is_the_identify_hold_and_only_extends_declared_dimensions():
    fixture = admitted_round_fixture("fast", endpoints=1, queries=0, state_changing=False,
                                     families=("recon", "nuclei_passive", "nuclei_active", "xss", "sqli"))
    plan = fixture["parent_plan"]
    identify, = [a for a in plan.actions if a.capability_name == "web.identify"]
    assert own_budget_allowance(plan.actions) == dict(identify.requested_budget)
    limits = fixture["execution_plan"].budget.ledger_limits()
    extended = with_own_budget(limits, plan.actions)
    assert set(extended) == set(limits)
    assert extended["http_requests"] == limits["http_requests"] + identify.requested_budget["http_requests"]
    skipped = replace(identify, admission_status="skipped", requested_budget={}, reason_code="insufficient_plan_budget", action_digest=None)
    assert own_budget_allowance([skipped]) == {}
