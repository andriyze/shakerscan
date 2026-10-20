"""A thorough or deep parallel parent keeps its profile's tool wall when its duration is lowered.

A lowered ``max_duration_seconds`` lowers a thorough or deep Scan's tool wall (unless the tool
wall is given explicitly): a Scan runs its actions one at a time, so a 3,600 s Scan that kept the
profile's 10,800 s planned three times the work its deadline lets run. A parallel parent is
different: the parallel compiler divides its tool wall among children that run at the same time,
each under the parent's whole duration. Lowered there, every child's share fell by the same
factor -- a backbone and four endpoint children at 3,600 s held about 1,200 and 600 s each
instead of about 3,600 and 1,800 s. Such a parent keeps the profile's tool wall, exactly as it
resolved before; ``api.py`` binds it when a Scan becomes a parallel parent (submission and
schedules, see ``test_api_helpers``).

These are contract and partition fixtures; no Scan runs.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.contracts import BUDGET_PROFILES, bind_scan_fan_out, resolve_scan_contract
from api.scan.parallel_compiler import ParallelActionPlanCompiler
from tests.test_parallel_action_compiler import PARENT_ID, _target

POLICY = {
    "active_testing": True,
    "exclude_families": ["nuclei_passive", "nuclei_active", "xss", "sqli", "bola"],
}
LOWERED = {"max_duration_seconds": 3_600}
CHILD_IDS = tuple(f"30000000-0000-4000-8000-00000000000{index}" for index in range(5))


def _contract(profile, advanced):
    return resolve_scan_contract(budget_profile=profile, policy=dict(POLICY), advanced=advanced)


@pytest.mark.parametrize("profile", ["thorough", "deep"])
def test_a_parallel_parent_keeps_the_tool_wall_it_resolved_before_the_duration_lowered_it(profile):
    lowered = _contract(profile, LOWERED)
    profile_wall = BUDGET_PROFILES[profile].max_tool_wall_seconds
    assert lowered.budget.max_tool_wall_seconds == 3_600
    bound = bind_scan_fan_out(lowered, LOWERED)
    assert bound.budget == replace(lowered.budget, max_tool_wall_seconds=profile_wall)
    assert bound.policy == lowered.policy
    assert bound.execution_plan.resolved_families == lowered.execution_plan.resolved_families
    # Exactly the plan the same request resolved to before a lowered duration lowered the wall.
    before = _contract(profile, {**LOWERED, "max_tool_wall_seconds": profile_wall})
    assert bound.execution_plan.digest == before.execution_plan.digest
    assert bound.option_metadata() == before.option_metadata()


@pytest.mark.parametrize(("profile", "advanced"), [
    pytest.param("thorough", {**LOWERED, "max_tool_wall_seconds": 2_000}, id="explicit-tool-wall"),
    pytest.param("thorough", None, id="profile-duration"),
    pytest.param("thorough", {"max_http_requests": 9_000}, id="other-limit"),
    pytest.param("balanced", {"max_duration_seconds": 1_800}, id="balanced"),
    pytest.param("fast", {"max_duration_seconds": 900}, id="fast"),
])
def test_every_other_parent_is_left_as_it_resolved(profile, advanced):
    contract = _contract(profile, advanced)
    assert bind_scan_fan_out(contract, advanced) is contract


def _children():
    specs = []
    for index, scan_id in enumerate(CHILD_IDS):
        options = {"auth_state": "anonymous"}
        if index == 0:
            options["parallel_backbone"] = True
        else:
            options["custom_endpoints"] = [f"GET /v1/items/{index}?id=1"]
        specs.append({
            "scan_id": scan_id, "index": index,
            "label": "global-backbone" if index == 0 else f"scope[{index}]",
            "options": options,
        })
    return tuple(specs)


def _partition(contract):
    raw = ScanActionPlanCompiler().compile(
        scan_id=PARENT_ID, execution_plan=contract.execution_plan, target_binding=_target(),
    )
    parent = allocate_scan_action_plan(raw, contract.budget).plan
    return ParallelActionPlanCompiler().compile(
        parent_execution_plan=contract.execution_plan, parent_action_plan=parent,
        target_binding=_target(), child_specs=_children(), strategy="scope",
        available_worker_count=len(CHILD_IDS),
    )


def test_children_that_run_at_the_same_time_share_the_profile_tool_wall():
    lowered = _contract("thorough", LOWERED)
    kept = _partition(bind_scan_fan_out(lowered, LOWERED))
    cut = _partition(lowered)
    # Every child runs under the parent's whole duration, at the same time as its siblings.
    assert {child.budget.max_duration_seconds for child in kept.children} == {3_600}
    assert sum(child.budget.max_tool_wall_seconds for child in kept.children) == 10_800
    assert sum(child.budget.max_tool_wall_seconds for child in cut.children) == 3_600
    for full, third in zip(kept.children, cut.children):
        assert full.budget.max_tool_wall_seconds >= 3 * third.budget.max_tool_wall_seconds - 3
        # Nothing else about a child's share changes.
        assert replace(full.budget, max_tool_wall_seconds=0) == replace(
            third.budget, max_tool_wall_seconds=0,
        )
