"""Every wall-killed SQLi candidate gets extension rounds, shared fairly (soak N30).

Soak scan 44e393ba (Balanced honey, state-changing allowed, ~3 s responses) had four SQLi
candidates in four slices. Round 2 gave the first slice's extension the SQLi lane's whole
900-second share, so the second slice -- wall-killed in technique B like the two slices
compiled in round 2 -- was never extended. Round 3 then had 519 seconds of tool wall left,
less than the 1.25x of a 420-second slice the planner demanded, and finalized with no verdict
for any candidate. These tests replay the plan and settled budgets those rounds saw.
"""

from __future__ import annotations

from types import SimpleNamespace

from api.scan.verification_extension import EXTENDS_ARG, plan_verification_extensions

BALANCED = {"http_requests": 20_000, "state_changing_requests": 2_000, "tool_wall_seconds": 3_600}
SLICE_RESERVED = {"http_requests": 800, "state_changing_requests": 480, "tool_wall_seconds": 420}


def _action(action_id, *, extends=None):
    args = {"slice": {"start": 0, "count": 1}, "candidate_manifest_ref": {"kind": "candidate"}}
    if extends:
        args[EXTENDS_ARG] = extends
    return SimpleNamespace(
        action_id=action_id, capability_name="sqli.verify_batch", stage="verify_candidates",
        capability_args=args, dependencies=(), requested_budget=dict(SLICE_RESERVED),
    )


def _timed_out(sent, *, reserved=SLICE_RESERVED, state_changing=0):
    wall = reserved["tool_wall_seconds"]
    return SimpleNamespace(
        status=SimpleNamespace(value="timed_out"),
        budget_reserved=dict(reserved),
        budget_consumed={
            "http_requests": sent, "state_changing_requests": state_changing,
            "tool_wall_seconds": wall,
        },
    )


def _residual(http, state, wall):
    return {
        "http_requests": BALANCED["http_requests"] - http,
        "state_changing_requests": BALANCED["state_changing_requests"] - state,
        "tool_wall_seconds": BALANCED["tool_wall_seconds"] - wall,
    }


def test_round_two_extends_both_wall_killed_slices_within_one_lane_share():
    # Settled before round 2: 1,341 s of tool wall; verify.sqli.r01 (GET, 116 sent) and
    # verify.sqli.001.r01 (POST, 104 sent, all state-changing) each spent their 420 s.
    planned = plan_verification_extensions(
        parent_plan=SimpleNamespace(actions=(
            _action("verify.sqli.r01"), _action("verify.sqli.001.r01"),
        )),
        parent_results={
            "verify.sqli.r01": _timed_out(116),
            "verify.sqli.001.r01": _timed_out(104, state_changing=104),
        },
        profile_limits=BALANCED,
        residual=_residual(2_190, 104, 1_341),
    )

    assert [item["action_id"] for item in planned] == [
        "verify.sqli.r01.ext", "verify.sqli.001.r01.ext",
    ]
    walls = [item["budget"]["tool_wall_seconds"] for item in planned]
    assert walls == [450, 450]
    # One lane share (a quarter of the profile wall) for the round, as before.
    assert sum(walls) <= BALANCED["tool_wall_seconds"] // 4
    # Each extension keeps its slice's paced ratio and more wall than the slice ran out of.
    for item in planned:
        assert item["budget"]["tool_wall_seconds"] > SLICE_RESERVED["tool_wall_seconds"]
        assert item["budget"]["http_requests"] == 800 * 450 // 420


def test_round_three_extends_a_never_extended_candidate_with_the_last_residual():
    # The soak plan as it stood before round 3: the first slice's 900 s extension and the two
    # slices compiled in round 2 all timed out, leaving 519 s of the 3,600 s tool wall.
    ext_reserved = {"http_requests": 1_714, "state_changing_requests": 0, "tool_wall_seconds": 900}
    actions = (
        _action("verify.sqli.r01"),
        _action("verify.sqli.001.r01"),
        _action("verify.sqli.r02"),
        _action("verify.sqli.001.r02"),
        _action("verify.sqli.r01.ext.r02", extends="verify.sqli.r01"),
    )
    planned = plan_verification_extensions(
        parent_plan=SimpleNamespace(actions=actions),
        parent_results={
            "verify.sqli.r01": _timed_out(116),
            "verify.sqli.001.r01": _timed_out(104, state_changing=104),
            "verify.sqli.r02": _timed_out(105, state_changing=105),
            "verify.sqli.001.r02": _timed_out(110, state_changing=110),
            "verify.sqli.r01.ext.r02": _timed_out(296, reserved=ext_reserved),
        },
        profile_limits=BALANCED,
        residual=_residual(2_726, 336, 3_081),
    )

    # Never-extended candidates come before a second link of one that already had a round,
    # in plan order; the residual funds one progress floor (420 s + one stage minimum).
    assert [item["action_id"] for item in planned] == ["verify.sqli.001.r01.ext"]
    assert planned[0]["capability_args"][EXTENDS_ARG] == "verify.sqli.001.r01"
    # Everything but the finalizer's one second, and never more than the lane share.
    assert planned[0]["budget"]["tool_wall_seconds"] == 518


def test_a_candidate_already_extended_waits_for_the_ones_that_were_not():
    ext_reserved = {"http_requests": 857, "state_changing_requests": 0, "tool_wall_seconds": 450}
    actions = (
        _action("verify.sqli.r01"),
        _action("verify.sqli.r02"),
        _action("verify.sqli.r01.ext.r02", extends="verify.sqli.r01"),
    )
    # The chained link's checkpoint: its interrupted stage ran out of 430 s of its 450 s.
    resume_walls = {"verify.sqli.r01.ext.r02": 450}
    planned = plan_verification_extensions(
        parent_plan=SimpleNamespace(actions=actions),
        parent_results={
            "verify.sqli.r01": _timed_out(116),
            "verify.sqli.r02": _timed_out(105),
            "verify.sqli.r01.ext.r02": _timed_out(140, reserved=ext_reserved),
        },
        profile_limits=BALANCED,
        # Enough for both floors (440 + 450): both progress, the share split between them.
        residual=_residual(3_000, 0, 2_000),
        stage_resume_walls=resume_walls,
    )
    assert [item["action_id"] for item in planned] == [
        "verify.sqli.r02.ext", "verify.sqli.r01.ext.r02.ext",
    ]
    assert sum(item["budget"]["tool_wall_seconds"] for item in planned) <= 900
    assert all(item["budget"]["tool_wall_seconds"] >= 440 for item in planned)

    tight = plan_verification_extensions(
        parent_plan=SimpleNamespace(actions=actions),
        parent_results={
            "verify.sqli.r01": _timed_out(116),
            "verify.sqli.r02": _timed_out(105),
            "verify.sqli.r01.ext.r02": _timed_out(140, reserved=ext_reserved),
        },
        profile_limits=BALANCED,
        residual=_residual(3_000, 0, 3_000),
        stage_resume_walls=resume_walls,
    )
    # 599 s funds one floor: the candidate never extended goes first.
    assert [item["action_id"] for item in tight] == ["verify.sqli.r02.ext"]


def test_a_wall_killed_extension_never_counts_its_candidate_as_tested():
    from dataclasses import replace

    from api.scan.action_plan import ScanActionPlan
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_orchestrator import SCAN_ID, _action as plan_action, _result as settle

    slice_args = {"slice": {"start": 0, "count": 1}, "manifest_entries": 2}
    first = replace(
        plan_action("verify.sqli.r01", 0, capability_name="sqli.verify_batch"),
        capability_args=dict(slice_args), output_schema="sqlmap-batch/v1", action_digest=None,
    )
    second = replace(
        plan_action("verify.sqli.001.r01", 1, capability_name="sqli.verify_batch"),
        capability_args={**slice_args, "slice": {"start": 1, "count": 1}},
        output_schema="sqlmap-batch/v1", action_digest=None,
    )
    extensions = tuple(
        replace(
            plan_action(f"{item.action_id}.ext.r02", 2 + index, capability_name="sqli.verify_batch"),
            capability_args={**item.capability_args, EXTENDS_ARG: item.action_id},
            output_schema="sqlmap-batch/v1", required=False, action_digest=None,
        )
        for index, item in enumerate((first, second))
    )
    final = plan_action(
        "finalize.report", 4,
        dependencies=(first.action_id, second.action_id, *(e.action_id for e in extensions)),
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(first, second, *extensions, final),
    )
    killed = dict(status=CapabilityResultStatus.TIMED_OUT, reason=CapabilityResultReason.TIMED_OUT)
    results = {
        first.action_id: settle(first, **killed),
        second.action_id: settle(second, **killed),
        extensions[0].action_id: settle(extensions[0], status=CapabilityResultStatus.SUCCESS),
        extensions[1].action_id: settle(extensions[1], **killed),
    }
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test", action_results=results,
        observations={},
    )
    coverage = report["coverage"]
    family = next(row for row in coverage["family_coverage"] if row["family"] == "sqli")
    assert family["coverage_status"] == "partial"
    assert coverage["status"] == "partial"
    assert "timed_out" in coverage["grade_reliability"]["reasons"]


def test_the_round_compiler_extends_every_starved_sqli_slice():
    from dataclasses import replace

    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from api.scan.continuation import reconciled_continuation_ceiling
    from api.scan.continuation_rounds import compile_next_continuation
    from tests.test_continuation_rounds import _settle_round_fixture
    from tests.test_scan_orchestrator import _result
    from tests.test_sqli_extension_chain import _sqli_round_fixture

    fixture = _sqli_round_fixture()
    _settle_round_fixture(fixture)
    first = compile_next_continuation(**fixture, revision_number=1)
    fixture["parent_plan"] = first.plan
    slices = [
        action for action in first.plan.actions if action.capability_name == "sqli.verify_batch"
    ]
    assert len(slices) == 4
    for action in slices:
        sent = max(1, action.requested_budget["http_requests"] // 10)
        fixture["parent_results"][action.action_id] = replace(
            _result(
                action, status=CapabilityResultStatus.TIMED_OUT,
                reason=CapabilityResultReason.TIMED_OUT,
            ),
            budget_consumed={
                "http_requests": sent,
                "tool_wall_seconds": action.requested_budget["tool_wall_seconds"],
            },
            result_digest=None,
        )
    _settle_round_fixture(fixture)

    second = compile_next_continuation(**fixture, revision_number=2)

    appended = second.plan.actions[len(first.plan.actions):]
    extensions = [action for action in appended if action.capability_args.get(EXTENDS_ARG)
                  and action.capability_name == "sqli.verify_batch"]
    assert sorted(action.capability_args[EXTENDS_ARG] for action in extensions) == sorted(
        action.action_id for action in slices
    )
    walls = [action.requested_budget["tool_wall_seconds"] for action in extensions]
    assert sum(walls) <= BALANCED["tool_wall_seconds"] // 4
    assert all(wall > 180 for wall in walls)
    ceiling = reconciled_continuation_ceiling(fixture["allocation"], fixture["parent_results"])
    for name, limit in ceiling.items():
        assert sum(action.requested_budget.get(name, 0) for action in appended) <= limit


def test_a_checkpoint_floor_never_shrinks_the_slice_holds():
    """A body link whose stage needs less wall than it held still gets every hold it had:
    its mutation hold below the body attempt floor would be unfundable (audit S002 review)."""
    body = {"http_requests": 1_441, "state_changing_requests": 480, "tool_wall_seconds": 720}
    actions = (_action("verify.sqli.r01"), _action("verify.sqli.r01.ext.r02", extends="verify.sqli.r01"))
    planned = plan_verification_extensions(
        parent_plan=SimpleNamespace(actions=actions),
        parent_results={
            "verify.sqli.r01": _timed_out(116),
            "verify.sqli.r01.ext.r02": _timed_out(100, reserved=body, state_changing=100),
        },
        profile_limits=BALANCED,
        residual=_residual(0, 0, BALANCED["tool_wall_seconds"] - 520),
        stage_resume_walls={"verify.sqli.r01.ext.r02": 420},
    )
    # 519 s cannot fund a link at least as large as the 720 s one: nothing is planned rather
    # than a link that could fund no candidate.
    assert planned == ()
    roomy = plan_verification_extensions(
        parent_plan=SimpleNamespace(actions=actions),
        parent_results={
            "verify.sqli.r01": _timed_out(116),
            "verify.sqli.r01.ext.r02": _timed_out(100, reserved=body, state_changing=100),
        },
        profile_limits=BALANCED,
        residual=_residual(0, 0, 0),
        stage_resume_walls={"verify.sqli.r01.ext.r02": 420},
    )
    assert [item["action_id"] for item in roomy] == ["verify.sqli.r01.ext.r02.ext"]
    for name, amount in body.items():
        assert roomy[0]["budget"][name] >= amount
