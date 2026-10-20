"""Thorough and deep direct Scans run every active-template window, not one per endpoint.

Each active-template attempt runs one window of 30 templates, chosen by the endpoint's manifest
ordinal, out of 1,146 permitted templates (39 windows). A host with E endpoints therefore ran E
of 39 windows: a two-endpoint host about 60 templates in 54 s, while its family read
``complete`` because completeness was measured in endpoints. A thorough or deep direct Scan now
plans 39 positions: position o runs window o on endpoint o % E. The first continuation round
plans the endpoints' own positions exactly as before; later rounds plan the remaining windows.

These are planner and report fixtures (operator-supplied endpoints, synthetic results); the
adapter half is ``test_active_template_window_attempts.py``.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from api.scan.action_plan import (
    ScanAction,
    ScanActionPlan,
    ScanActionPlanCompiler,
    window_retry_hold,
)
from api.scan.capability_result import CapabilityResultStatus
from api.scan.external_process import (
    ACTIVE_TEMPLATE_PLANNED_GET_ONLY_WINDOWS,
    ACTIVE_TEMPLATE_PLANNED_WINDOWS,
    ACTIVE_TEMPLATE_WINDOW_RETRY_SECONDS,
)
from api.scan.finalizer import finalize_scan_report
from tests.scan_round_fixtures import (
    admitted_round_fixture,
    appended_actions,
    compile_round,
    settle_lightly,
    settle_round,
)
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID
from tests.test_scan_orchestrator import _action as plan_action

NUCLEI_ONLY = ("recon", "nuclei_passive", "nuclei_active")
POSITION = {"http_requests": 120, "state_changing_requests": 120, "tool_wall_seconds": 45}


# --- planner -------------------------------------------------------------------------------


def _sweeps(actions):
    return [action for action in actions if action.capability_name == "templates.active_batch"]


def _plan_rounds(profile, *, endpoints, rounds=4, options=None, state_changing=True):
    fixture = admitted_round_fixture(
        profile, endpoints=endpoints, queries=0, families=NUCLEI_ONLY, extra_options=options,
        state_changing=state_changing,
    )

    def outcome(action):
        if action.capability_name == "templates.active_batch":
            return (CapabilityResultStatus.SUCCESS, None, dict(action.requested_budget))
        return settle_lightly(action)

    planned = {}
    for number in range(1, rounds + 1):
        settle_round(fixture, outcome)
        parent_count = len(fixture["parent_plan"].actions)
        appended = appended_actions(compile_round(fixture, number), parent_count)
        planned[number] = _sweeps(appended)
        if any(action.action_id == "finalize.report" for action in appended):
            break
    return planned


@pytest.mark.parametrize("profile", ["thorough", "deep"])
def test_a_two_endpoint_host_plans_all_39_windows_over_three_rounds(profile):
    planned = _plan_rounds(profile, endpoints=2)
    r01, = planned[1]
    # The first round is exactly the endpoints' own positions and holds.
    assert r01.capability_args["slice"] == {"start": 0, "count": 2}
    assert dict(r01.requested_budget) == {
        "http_requests": 240, "state_changing_requests": 240, "tool_wall_seconds": 90,
    }
    assert r01.capability_args["manifest_entries"] == ACTIVE_TEMPLATE_PLANNED_WINDOWS == 39
    assert r01.capability_args["endpoint_entries"] == 2
    slices = [action.capability_args["slice"] for number in (2, 3) for action in planned[number]]
    if profile == "thorough":
        assert slices == [{"start": 2, "count": 33}, {"start": 35, "count": 4}]
    covered = sorted(
        position for number in planned for action in planned[number]
        for position in range(
            action.capability_args["slice"]["start"],
            action.capability_args["slice"]["start"] + action.capability_args["slice"]["count"],
        )
    )
    assert covered == list(range(39))
    # Each position holds what one endpoint attempt always held; a slice of further windows also
    # holds one retry of a window its wall cut off: up to 135 s and the requests (and mutations)
    # that wall paces at the positions' 2 requests/s, as far as the ledger leaves them (this
    # fixture's mutation allowance trims the last one). The first round's slice holds no retry.
    assert "window_retry_hold" not in r01.capability_args
    for number in planned:
        for action in planned[number]:
            count = action.capability_args["slice"]["count"]
            retry = dict(action.capability_args.get("window_retry_hold") or {})
            if action.capability_args["slice"]["start"] >= 2:
                assert 45 < retry["tool_wall_seconds"] <= ACTIVE_TEMPLATE_WINDOW_RETRY_SECONDS
                assert retry["http_requests"] == retry["state_changing_requests"] == (
                    2 * retry["tool_wall_seconds"]
                )
            else:
                assert retry == {}
            assert dict(action.requested_budget) == {
                name: amount * count + retry.get(name, 0) for name, amount in POSITION.items()
            }


def test_a_window_retry_hold_is_capped_by_what_the_lane_leaves_of_the_ledger():
    shape = {"http_requests": 3960, "state_changing_requests": 3960, "tool_wall_seconds": 1485}
    roomy = {"http_requests": 60_000, "state_changing_requests": 6_000, "tool_wall_seconds": 10_800}
    assert window_retry_hold(shape, limits=roomy, reserved={}, slices=1) == {
        "tool_wall_seconds": ACTIVE_TEMPLATE_WINDOW_RETRY_SECONDS,
        "http_requests": 270, "state_changing_requests": 270,
    }
    # Mutations left after the lane's two slices and the required work: 100 a slice, so the
    # retry holds 100 requests and the 50 s they pace at 2 requests/s.
    tight = {**roomy, "state_changing_requests": 2 * 3960 + 200 + 300}
    assert window_retry_hold(shape, limits=tight, reserved={"state_changing_requests": 300}, slices=2) == {
        "tool_wall_seconds": 50, "http_requests": 100, "state_changing_requests": 100,
    }
    # Wall left: 40 s, so 80 requests.
    short = {**roomy, "tool_wall_seconds": 1485 + 40}
    assert window_retry_hold(shape, limits=short, reserved={}, slices=1) == {
        "tool_wall_seconds": 40, "http_requests": 80, "state_changing_requests": 80,
    }
    # Nothing left in any one dimension: no retry hold at all.
    assert window_retry_hold(shape, limits={**roomy, "tool_wall_seconds": 1485}, reserved={}, slices=1) == {}
    # A GET-only slice holds no mutations for its retry either.
    get_only = {"http_requests": 3960, "tool_wall_seconds": 1485}
    assert window_retry_hold(get_only, limits=roomy, reserved={}, slices=1) == {
        "tool_wall_seconds": 135, "http_requests": 270,
    }



@pytest.mark.parametrize("profile", ["thorough", "deep"])
def test_without_state_changing_http_a_host_plans_the_get_only_allowlists_windows(profile):
    """Without state-changing authority every position runs the GET-only allowlist, which has
    26 windows on the pinned bundle. Planning 39 held 13 positions (1,560 requests, 585 s) that
    could only run nothing, and a deadline that cut them read the family as partial."""
    planned = _plan_rounds(profile, endpoints=2, state_changing=False)
    actions = [action for number in planned for action in planned[number]]
    assert {action.capability_args["manifest_entries"] for action in actions} == {
        ACTIVE_TEMPLATE_PLANNED_GET_ONLY_WINDOWS,
    } == {26}
    covered = sorted(
        position for action in actions
        for position in range(
            action.capability_args["slice"]["start"],
            action.capability_args["slice"]["start"] + action.capability_args["slice"]["count"],
        )
    )
    assert covered == list(range(26))
    assert all("state_changing_requests" not in action.requested_budget for action in actions)

@pytest.mark.parametrize("profile", ["fast", "balanced"])
def test_fast_and_balanced_plan_one_position_per_endpoint(profile):
    # Explicitly selected active templates hold the registry's mutation cost at admission,
    # which these ledgers cannot fund with state-changing authority; GET-only they admit.
    planned = _plan_rounds(profile, endpoints=2, state_changing=False)
    assert [action.capability_args["slice"] for action in planned[1]] == [{"start": 0, "count": 2}]
    assert all(not planned[number] for number in planned if number > 1)
    assert planned[1][0].capability_args["manifest_entries"] == 2
    assert "endpoint_entries" not in planned[1][0].capability_args


def test_a_host_with_as_many_endpoints_as_windows_is_planned_as_before():
    planned = _plan_rounds("thorough", endpoints=40, rounds=3)
    for number in planned:
        for action in planned[number]:
            assert action.capability_args["manifest_entries"] == 40
            assert "endpoint_entries" not in action.capability_args
            assert action.capability_args["slice"]["start"] + action.capability_args["slice"]["count"] <= 40


def test_a_verify_scan_runs_its_named_checks_once_per_endpoint():
    planned = _plan_rounds("thorough", endpoints=2, options={"verify_templates": ["x-check"]})
    assert [action.capability_args["slice"] for action in planned[1]] == [{"start": 0, "count": 2}]
    assert planned[1][0].capability_args["manifest_entries"] == 2
    assert all(not planned[number] for number in planned if number > 1)


def test_parallel_shards_keep_one_position_per_endpoint():
    """Each endpoint shard would otherwise repeat the whole allowlist over its own slice."""
    fixture = admitted_round_fixture("thorough", endpoints=8, queries=0, families=NUCLEI_ONLY)
    settle_round(fixture)
    compile_round(fixture, 1)
    options = fixture["options"]
    for shard in range(4):
        plan = ScanActionPlanCompiler().compile(
            scan_id=fixture["parent_plan"].scan_id,
            execution_plan=fixture["execution_plan"], target_binding=fixture["target"],
            action_scope="endpoint",
            endpoint_manifest_ref=options["endpoint_manifest_ref"],
            candidate_manifest_ref=options["candidate_manifest_ref"],
            template_manifest_ref=options["template_manifest_ref"],
            shard_authority={"options_digest": f"{shard}" * 64},
            continuation_round=2, manifest_offsets={"active.templates": 8},
            active_template_windows=True, action_budgets={},
        )
        assert not _sweeps(plan.actions)


# --- the report -------------------------------------------------------------------------------


def _report_slice(action_id, ordinal, *, start, count, windows, required):
    return ScanAction(
        action_id=action_id, stage="deterministic_active", ordinal=ordinal,
        capability_name="templates.active_batch",
        capability_args={
            "slice": {"start": start, "count": count},
            "manifest_entries": ACTIVE_TEMPLATE_PLANNED_WINDOWS if windows else 2,
            **({"endpoint_entries": 2} if windows else {}),
            "profile": "thorough_batch_v1" if windows else "balanced_batch_v1",
            "proof_policy": "deterministic_proof_contract_required",
        },
        target_binding_digest="a" * 64,
        input_binding_digest=hashlib.sha256(action_id.encode()).hexdigest(),
        requested_budget={"http_requests": 120 * count, "tool_wall_seconds": 45 * count},
        placement={
            "schema_version": "scan-action-placement/v1", "eligible_backends": ["local"],
            "adapter_name": "internal", "adapter_version": "1",
        },
        dependencies=(), required=required, supporting=False, output_schema="candidate-attempt/v1",
    )


def _report(slices, *, windows):

    actions = [
        _report_slice(f"active.templates.r{number:02d}", index, start=start, count=count,
                      windows=windows, required=index == 0)
        for index, (number, start, count) in enumerate(slices)
    ]
    final = plan_action("finalize.report", len(actions), dependencies=tuple(a.action_id for a in actions))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
        actions=(*actions, final),
    )
    observations = {}
    for action in actions:
        start = action.capability_args["slice"]["start"]
        count = action.capability_args["slice"]["count"]
        observations[action.action_id] = (
            *({
                "kind": "candidate_attempt", "family": "nuclei_active", "status": "success",
                "attempt_id": hashlib.sha256(f"{action.action_id}:{position}".encode()).hexdigest(),
                "candidate_id": f"endpoint-{position % 2}",
            } for position in range(start, start + count)),
            {"kind": "active_template_windows", "family": "nuclei_active",
             "windows_run": list(range(start, start + count)), "window_count": 39},
        )
    results = {
        action.action_id: _result_with_observation_count(action, len(observations[action.action_id]))
        for action in actions
    }
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test", action_results=results,
        observations=observations,
    )
    family = next(row for row in report["coverage"]["family_coverage"] if row["family"] == "nuclei_active")
    return report, family


def test_a_thorough_host_whose_later_windows_never_ran_is_partial():
    report, family = _report([(1, 0, 2)], windows=True)
    assert family["coverage_status"] == "partial"
    assert family["reason"] == "manifest_entries_unscheduled"
    assert family["unscheduled_candidates"] == 37
    assert family["template_windows"] == {"run": 2, "total": 39}
    assert report["result"]["grade_reliable"] is False


def test_a_thorough_host_that_ran_every_window_is_complete():
    report, family = _report([(1, 0, 2), (2, 2, 33), (3, 35, 4)], windows=True)
    assert family["coverage_status"] == "complete"
    assert family["template_windows"] == {"run": 39, "total": 39}
    assert family["manifest_candidates"] == 39 and family["unscheduled_candidates"] == 0


def test_a_balanced_host_keeps_its_status_and_now_says_how_much_of_the_allowlist_ran():
    report, family = _report([(1, 0, 2)], windows=False)
    assert family["coverage_status"] == "complete"
    assert family["template_windows"] == {"run": 2, "total": 39}


def test_a_scan_continued_after_an_upgrade_appends_the_remaining_windows(monkeypatch):
    """A first round compiled by the previous release declared one position per endpoint; the
    next rounds, compiled by this one, append positions E.. and the report reads 39 of 39."""
    import api.scan.action_plan as planner

    fixture = admitted_round_fixture("thorough", endpoints=2, queries=0, families=NUCLEI_ONLY)

    def outcome(action):
        if action.capability_name == "templates.active_batch":
            return (CapabilityResultStatus.SUCCESS, None, dict(action.requested_budget))
        return settle_lightly(action)

    settle_round(fixture, outcome)
    with monkeypatch.context() as previous_release:
        previous_release.setattr(planner, "budget_sufficiency", lambda _profile: False)
        parent_count = len(fixture["parent_plan"].actions)
        r01, = _sweeps(appended_actions(compile_round(fixture, 1), parent_count))
    assert r01.capability_args["manifest_entries"] == 2
    assert "endpoint_entries" not in r01.capability_args
    later = []
    for number in (2, 3, 4):
        settle_round(fixture, outcome)
        parent_count = len(fixture["parent_plan"].actions)
        appended = appended_actions(compile_round(fixture, number), parent_count)
        later.extend(_sweeps(appended))
        if any(action.action_id == "finalize.report" for action in appended):
            break
    assert [action.capability_args["slice"] for action in later] == [
        {"start": 2, "count": 33}, {"start": 35, "count": 4},
    ]
    # Rounds are append-only: the first round's slice runs exactly as the previous release
    # planned it, so its attempts keep their identities.
    assert r01 in fixture["parent_plan"].actions
    manifest = max(
        action.capability_args["manifest_entries"]
        for action in fixture["parent_plan"].actions
        if action.capability_name == "templates.active_batch"
    )
    scheduled = sum(
        action.capability_args["slice"]["count"]
        for action in fixture["parent_plan"].actions
        if action.capability_name == "templates.active_batch"
    )
    assert (manifest, scheduled) == (39, 39)


def test_a_slice_whose_every_position_was_past_the_allowlist_is_not_a_zero_attempt_verifier():
    """It ran nothing by design (a GET-only allowlist has fewer windows than were planned)."""

    ran = _report_slice("active.templates.r02", 0, start=1, count=33, windows=True, required=False)
    beyond = _report_slice("active.templates.r03", 1, start=34, count=5, windows=True, required=False)
    final = plan_action("finalize.report", 2, dependencies=(ran.action_id, beyond.action_id))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
        actions=(ran, beyond, final),
    )
    observations = {
        ran.action_id: tuple(
            {"kind": "candidate_attempt", "family": "nuclei_active", "status": "success",
             "attempt_id": f"{position:064x}", "candidate_id": "endpoint-0"}
            for position in range(1, 34)
        ),
        beyond.action_id: tuple(
            {"kind": "candidate_inapplicable", "family": "nuclei_active",
             "candidate_id": f"endpoint-0:window:{position}",
             "reason": "template_window_beyond_allowlist"}
            for position in range(34, 39)
        ),
    }
    results = {
        action.action_id: _result_with_observation_count(action, len(observations[action.action_id]))
        for action in (ran, beyond)
    }
    results[beyond.action_id] = replace(
        results[beyond.action_id],
        budget_consumed={name: 0 for name in beyond.requested_budget}, result_digest=None,
    )
    results[ran.action_id] = replace(
        results[ran.action_id],
        budget_consumed=dict(ran.requested_budget), result_digest=None,
    )
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test", action_results=results,
        observations=observations,
        work_manifest_references=({"kind": "candidate", "status": "complete", "entry_count": 3},),
    )
    assert report["coverage"]["active_zero_attempt_actions"] == []
    family = next(row for row in report["coverage"]["family_coverage"] if row["family"] == "nuclei_active")
    assert family["planned_candidates"] == 33
    assert family["attempted_candidates"] == 33


def test_a_sharded_scan_reports_how_much_of_the_allowlist_its_shards_ran():
    """Shards keep one position per endpoint, so each runs the allowlist's leading windows on
    its own endpoints. The merged family row says how many windows ran, as a direct Scan's
    report does: those of the shard that ran the most, of the largest allowlist."""
    from api.scan.parallel_compiler import (
        ParallelActionPlanCompiler,
        merge_parallel_action_executions,
        summarize_parallel_action_coverage,
    )
    from tests.test_parallel_action_compiler import (
        _assignments,
        _authority,
        _canonical_child_report,
        _children,
        _parent_assignment,
        _projected_plans,
        _target,
    )

    execution, parent = _authority()
    children = _children()
    partition = ParallelActionPlanCompiler().compile(
        parent_execution_plan=execution, parent_action_plan=parent, target_binding=_target(),
        child_specs=children, strategy="scope",
    )
    plans = _projected_plans(partition, parent)
    assignments = _assignments(children)
    record = partition.record(
        plans, child_work_assignments=assignments,
        parent_work_assignment=_parent_assignment(assignments),
    )
    reports = {scan_id: _canonical_child_report(plan) for scan_id, plan in plans.items()}
    for scan_id, windows in zip(sorted(plans)[1:], ({"run": 3, "total": 39}, {"run": 2, "total": 39})):
        reports[scan_id]["coverage"] = {"family_coverage": [{
            "family": "nuclei_active", "selected": True, "required": True,
            "coverage_status": "complete", "batch_actions": 1, "planned_candidates": windows["run"],
            "attempted_candidates": windows["run"], "template_windows": windows,
        }]}
    merged = merge_parallel_action_executions(
        record, child_results=reports, child_statuses=dict.fromkeys(plans, "completed"),
    )
    family, = merged["family_coverage"]
    assert family["template_windows"] == {"run": 3, "total": 39}
    assert summarize_parallel_action_coverage(merged)["family_coverage"][0]["template_windows"] == {
        "run": 3, "total": 39,
    }
