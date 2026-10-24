"""Thorough and deep Scans plan their work to fit, and later rounds step down to what is left.

Two planning faults of thorough Scans, measured on 2.11 lab runs (these tests
use planner fixtures, not live Scans):

* A lowered ``max_duration_seconds`` left the tool wall at the profile's 10,800 s, against the
  rule that tool wall never exceeds total wall. Actions run one at a time, so a 3,600 s Scan
  planned about three times the work its deadline lets run, and the deadline killed it.
* Every continuation round chose each lane's slice size against the full profile ceiling. An
  active-template slice reserves one mutation per request, so the thorough slice (3,960) did
  not fit the 3,833 state-changing requests left after the first round, the allocator skipped
  it, and no second-round sweep was compiled on any large target.
"""

from __future__ import annotations

import pytest

from api.scan.action_plan import ScanActionPlanCompiler, batch_profile_shape
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.capability_result import CapabilityResultStatus
from api.scan.continuation import ContinuationBudgetCeiling, reconciled_continuation_ceiling
from api.scan.contracts import (
    BUDGET_PROFILES,
    BUDGET_SUFFICIENCY_PROFILES,
    budget_sufficiency,
    resolve_scan_contract,
)
from tests.scan_round_fixtures import (
    admitted_round_fixture,
    appended_actions,
    compile_round,
    settle_lightly,
    settle_round,
)

ACTIVE = {"active_testing": True, "allow_state_changing_http": True}
LAB_FAMILIES = (
    "recon", "nuclei_passive", "nuclei_active", "xss", "sqli",
    "sensitive_exposure", "nosqli", "graphql",
)
LOWERED = {"max_duration_seconds": 3_600, "max_state_changing_requests": 6_000}


def _budget(profile, advanced=None):
    return resolve_scan_contract(
        budget_profile=profile, policy=dict(ACTIVE), advanced=advanced,
        approval_receipt_id="approval-1",
    ).budget


def test_only_thorough_and_deep_are_planned_to_completion():
    assert BUDGET_SUFFICIENCY_PROFILES == {"thorough", "deep"}
    assert [name for name in BUDGET_PROFILES if budget_sufficiency(name)] == ["thorough", "deep"]
    assert not budget_sufficiency(None) and budget_sufficiency(" Thorough ")


@pytest.mark.parametrize("profile", ["thorough", "deep"])
def test_a_lowered_duration_lowers_the_tool_wall(profile):
    budget = _budget(profile, {"max_duration_seconds": 3_600})
    assert budget.max_duration_seconds == 3_600
    assert budget.max_tool_wall_seconds == 3_600
    # Without a lowered duration the profile's own wall stands.
    assert _budget(profile).max_tool_wall_seconds == BUDGET_PROFILES[profile].max_tool_wall_seconds


def test_an_explicit_tool_wall_is_kept_as_given():
    budget = _budget("thorough", {"max_duration_seconds": 3_600, "max_tool_wall_seconds": 7_200})
    assert budget.max_tool_wall_seconds == 7_200
    assert _budget("thorough", {"max_duration_seconds": 3_600, "max_tool_wall_seconds": None}) \
        .max_tool_wall_seconds == 3_600


@pytest.mark.parametrize("profile", ["fast", "balanced"])
def test_fast_and_balanced_keep_their_tool_wall(profile):
    budget = _budget(profile, {"max_duration_seconds": 900})
    assert budget.max_duration_seconds == 900
    assert budget.max_tool_wall_seconds == BUDGET_PROFILES[profile].max_tool_wall_seconds


@pytest.mark.parametrize("shape", [
    pytest.param(dict(endpoints=215, queries=14, body=3), id="large-app"),
    pytest.param(dict(endpoints=30, queries=0, body=14), id="body-heavy-api"),
    pytest.param(dict(endpoints=2, queries=1, body=0), id="small-host"),
])
def test_a_3600_second_thorough_scan_admits_and_plans_inside_its_wall(shape):
    """Lab Scans run thorough with a 3,600 s duration: such a Scan must still admit, and no
    round may hold more tool wall than the Scan has."""
    fixture = admitted_round_fixture(
        "thorough", families=LAB_FAMILIES, advanced=LOWERED, **shape,
    )
    assert fixture["execution_plan"].budget.max_tool_wall_seconds == 3_600
    assert fixture["allocation"].budget_ceiling["tool_wall_seconds"] <= 3_600
    for number in (1, 2, 3):
        settle_round(fixture)
        residual = reconciled_continuation_ceiling(fixture["allocation"], fixture["parent_results"])
        parent_count = len(fixture["parent_plan"].actions)
        appended = appended_actions(compile_round(fixture, number), parent_count)
        held = sum(action.requested_budget.get("tool_wall_seconds", 0) for action in appended)
        assert held <= residual["tool_wall_seconds"]
        if any(action.action_id == "finalize.report" for action in appended):
            break


def _large_host_round_two():
    """A thorough large host whose first sweep left 3,833 state-changing requests."""
    fixture = admitted_round_fixture(
        "thorough", endpoints=215, queries=0, body=False,
        families=("recon", "nuclei_passive", "nuclei_active"),
    )
    settle_round(fixture)
    compile_round(fixture, 1)
    root_sc = 6_000 - reconciled_continuation_ceiling(
        fixture["allocation"], fixture["parent_results"],
    )["state_changing_requests"]

    def outcome(action):
        if action.capability_name == "templates.active_batch":
            spent = 6_000 - 3_833 - root_sc
            return (CapabilityResultStatus.SUCCESS, None, {
                "http_requests": spent, "state_changing_requests": spent,
                "tool_wall_seconds": 1_191,
            })
        return settle_lightly(action)

    settle_round(fixture, outcome)
    residual = reconciled_continuation_ceiling(fixture["allocation"], fixture["parent_results"])
    assert residual["state_changing_requests"] == 3_833
    return fixture, residual


def test_a_later_round_steps_down_to_the_tier_the_residual_funds():
    fixture, residual = _large_host_round_two()
    parent_count = len(fixture["parent_plan"].actions)
    appended = appended_actions(compile_round(fixture, 2), parent_count)
    sweeps = [action for action in appended if action.capability_name == "templates.active_batch"]
    # The thorough tier (33 positions, 3,960 mutations) does not fit 3,833; the balanced tier
    # (11 positions, 1,320) does, twice. Before, no second-round sweep was compiled at all.
    balanced_size, balanced = batch_profile_shape(
        "balanced", "templates.active_batch", allow_state_changing_http=True,
    )
    assert balanced_size == 11
    assert dict(balanced) == {
        "http_requests": 1_320, "state_changing_requests": 1_320, "tool_wall_seconds": 495,
    }
    assert [action.capability_args["slice"] for action in sweeps] == [
        {"start": 33, "count": 11}, {"start": 44, "count": 11},
    ]
    assert all(dict(action.requested_budget) == dict(balanced) for action in sweeps)
    assert sum(action.requested_budget["state_changing_requests"] for action in sweeps) <= (
        residual["state_changing_requests"]
    )


def test_the_lane_share_is_of_the_frozen_profile_wall_not_the_residual():
    """Compiled against a residual of 1,800 s, a lane share of the residual (450 s) would hold
    one 495 s slice; the share is of the profile's 10,800 s wall (2,700 // 495 = 5 slices), so
    the lane is bounded only by what the residual funds (2 slices by mutations)."""
    fixture, residual = _large_host_round_two()
    execution_plan = fixture["execution_plan"]
    limits = {
        **{name: min(limit, residual.get(name, limit))
           for name, limit in execution_plan.budget.ledger_limits().items()},
        "tool_wall_seconds": 1_800,
    }
    endpoints_ref = fixture["options"]["endpoint_manifest_ref"]
    raw = ScanActionPlanCompiler().compile(
        scan_id=fixture["parent_plan"].scan_id, execution_plan=execution_plan,
        target_binding=fixture["target"], action_scope="endpoint",
        endpoint_manifest_ref=endpoints_ref,
        candidate_manifest_ref=fixture["options"]["candidate_manifest_ref"],
        template_manifest_ref=fixture["options"]["template_manifest_ref"],
        continuation_round=2, manifest_offsets={"active.templates": 33},
        ledger_limits=limits, active_template_windows=True,
        require_family_minimums=False,
    )
    sweeps = [action for action in raw.actions if action.capability_name == "templates.active_batch"]
    assert int(BUDGET_PROFILES["thorough"].max_tool_wall_seconds * 0.25) // 495 == 5
    assert len(sweeps) == 2
    allocated = allocate_scan_action_plan(raw, ContinuationBudgetCeiling(limits)).plan
    assert {action.action_id for action in allocated.actions} >= {
        action.action_id for action in sweeps
    }


def test_a_later_round_that_cannot_fund_a_mutation_hold_leaves_its_sweep_positions_unscheduled():
    """Under state-changing authority every position runs the allowlist with state-changing
    templates. A later round whose residual funds no mutation hold (240 left, under the
    smallest tier's 480) appends no sweep: the floor shape would run the GET-only allowlist
    where those windows were planned and read as scheduled. The report names the positions
    unscheduled instead."""
    import hashlib
    from dataclasses import replace

    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_finalizer import _result_with_observation_count

    fixture = admitted_round_fixture(
        "thorough", endpoints=215, queries=0, body=False,
        families=("recon", "nuclei_passive", "nuclei_active"),
        advanced={"max_state_changing_requests": 4_200},
    )
    settle_round(fixture)
    compile_round(fixture, 1)

    def outcome(action):
        if action.capability_name == "templates.active_batch":
            return (CapabilityResultStatus.SUCCESS, None, dict(action.requested_budget))
        return settle_lightly(action)

    def attempts(action):
        if action.capability_name != "templates.active_batch":
            return ()
        start, count = action.capability_args["slice"]["start"], action.capability_args["slice"]["count"]
        return tuple({
            "kind": "candidate_attempt", "family": "nuclei_active", "status": "success",
            "attempt_id": hashlib.sha256(f"{action.action_id}:{position}".encode()).hexdigest(),
            "candidate_id": f"endpoint-{position}",
        } for position in range(start, start + count))

    settle_round(fixture, outcome, observations=attempts)
    residual = reconciled_continuation_ceiling(fixture["allocation"], fixture["parent_results"])
    assert 0 < residual["state_changing_requests"] < 480
    appended = []
    for number in (2, 3, 4):
        parent_count = len(fixture["parent_plan"].actions)
        prepared = compile_round(fixture, number)
        appended.extend(appended_actions(prepared, parent_count))
        settle_round(fixture, outcome, observations=attempts)
        if any(action.action_id == "finalize.report" for action in appended):
            break
    assert not [action for action in appended if action.capability_name == "templates.active_batch"]
    actions = {action.action_id: action for action in fixture["parent_plan"].actions}
    results = {
        action_id: replace(
            _result_with_observation_count(actions[action_id], len(fixture["observations"][action_id])),
            budget_consumed=dict(result.budget_consumed), result_digest=None,
        ) if fixture["observations"].get(action_id) else result
        for action_id, result in fixture["parent_results"].items() if action_id != "finalize.report"
    }
    report = finalize_scan_report(
        plan=fixture["parent_plan"], target_url="https://app.example.test", action_results=results,
        observations=fixture["observations"], plan_revision=prepared.revision,
    )
    family = next(row for row in report["coverage"]["family_coverage"] if row["family"] == "nuclei_active")
    assert family["coverage_status"] == "partial"
    assert family["reason"] == "manifest_entries_unscheduled"
    assert (family["manifest_candidates"], family["unscheduled_candidates"]) == (215, 182)
    assert report["result"]["grade_reliable"] is False


def test_a_round_admits_a_lanes_first_sweep_before_its_next_one():
    """A large thorough application whose round-2 verifiers took part of the mutation residual:
    it funds one balanced sweep, not two. The allocator admitted ``active.templates.001.r02``
    before ``active.templates.r02`` (by id), skipped the first, and the round then dropped
    both, because a lane's appended slices must be a contiguous prefix: no sweep ran in round
    2. A lane's first slice is admitted first, so the round appends it."""
    fixture = admitted_round_fixture(
        "thorough", families=LAB_FAMILIES, endpoints=215, queries=14, body=3,
    )

    def outcome(action):
        held = action.requested_budget
        if action.capability_name == "templates.active_batch":
            count = int(action.capability_args["slice"]["count"])
            http = min(held.get("http_requests", 0), 60 * count)
            return (CapabilityResultStatus.SUCCESS, None, {
                "http_requests": http,
                "state_changing_requests": http if held.get("state_changing_requests") else 0,
                "tool_wall_seconds": min(held.get("tool_wall_seconds", 0), 30 * count),
            })
        share = 0.7 if action.capability_name in {"sqli.verify_batch", "xss.verify_batch"} else 0.5
        return (CapabilityResultStatus.SUCCESS, None, {
            name: int(amount * share) for name, amount in held.items()
        })

    settle_round(fixture, outcome)
    compile_round(fixture, 1)
    settle_round(fixture, outcome)
    residual = reconciled_continuation_ceiling(fixture["allocation"], fixture["parent_results"])
    parent_count = len(fixture["parent_plan"].actions)
    appended = appended_actions(compile_round(fixture, 2), parent_count)
    verifiers = sum(
        action.requested_budget.get("state_changing_requests", 0) for action in appended
        if action.capability_name in {"sqli.verify_batch", "xss.verify_batch"}
    )
    _size, balanced = batch_profile_shape(
        "balanced", "templates.active_batch", allow_state_changing_http=True,
    )
    # Two balanced sweeps fit the residual alone, one beside the round's verifiers.
    assert residual["state_changing_requests"] >= 2 * balanced["state_changing_requests"]
    assert residual["state_changing_requests"] - verifiers < 2 * balanced["state_changing_requests"]
    sweeps = _sweeps_of(appended)
    assert [action.action_id for action in sweeps] == ["active.templates.r02"]
    assert sweeps[0].capability_args["slice"] == {"start": 33, "count": 11}


def _sweeps_of(actions):
    return [action for action in actions if action.capability_name == "templates.active_batch"]
