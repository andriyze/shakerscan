"""The bounded continuation rounds spend the residual and always end in a finalizer.

The worker used to run exactly one continuation round; a thorough Scan of the benchmark
finished after 23 minutes of a 90-minute ceiling with `coverage: partial` because both
template batches timed out at their slice and nothing re-planned the rest. These tests drive
the round runner and the round-selection logic with fakes: the loop must keep appending
revisions while a round admits work, stop at exhaustion or the bound, surface cancellation,
and end with the terminal finalizer revision.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from api.scan.action_plan import ScanActionPlan
from api.scan.continuation import MAX_SCAN_CONTINUATION_ROUNDS, ScanContinuationError
from api.scan.continuation_rounds import (
    round_progress_window,
    run_continuation_rounds,
    select_continuation_actions,
)
from tests.test_scan_continuation import _plans


class _Status:
    def __init__(self, value):
        self.value = value


def _orchestration(*ids, status="success"):
    return SimpleNamespace(action_results={
        action_id: SimpleNamespace(status=_Status(status)) for action_id in ids
    })


def _runner(*, admit_rounds, cancel_on_round=None):
    """A materialize/run_round pair that admits work for the first `admit_rounds` rounds."""
    calls = {"materialize": [], "rounds": []}

    async def materialize(*, parent_plan, parent_results, revision_number, include_finalizer, finalize_only):
        calls["materialize"].append((revision_number, include_finalizer, finalize_only))
        if finalize_only:
            return (f"plan-final-{revision_number}", SimpleNamespace(revision=revision_number))
        if revision_number > admit_rounds:
            return None
        return (f"plan-r{revision_number}", SimpleNamespace(revision=revision_number))

    async def run_round(plan, revision, *, progress_start, progress_end):
        calls["rounds"].append((plan, revision.revision, progress_start, progress_end))
        if cancel_on_round == revision.revision:
            return _orchestration(f"work.r{revision.revision:02d}", status="cancelled")
        return _orchestration(f"work.r{revision.revision:02d}")

    return calls, materialize, run_round


def test_rounds_continue_while_work_is_admitted_then_finalize():
    calls, materialize, run_round = _runner(admit_rounds=3)
    plan, revision, orchestration = asyncio.run(run_continuation_rounds(
        plan="root", plan_revision=None, initial_results={},
        materialize=materialize, run_round=run_round,
    ))
    # Rounds 1..3 ran, round 4 admitted nothing, then the finalizer revision (4) ran.
    assert [c[0] for c in calls["materialize"]] == [1, 2, 3, 4, 4]
    assert calls["materialize"][-1] == (4, True, True)
    assert [r[1] for r in calls["rounds"]] == [1, 2, 3, 4]
    assert plan == "plan-final-4" and revision.revision == 4
    assert calls["rounds"][-1][2:] == (90, 95)
    # Progress advances monotonically across the work rounds.
    windows = [r[2:] for r in calls["rounds"][:-1]]
    assert windows == sorted(windows) and windows[0][0] == 40


def test_rounds_stop_at_the_bound_and_still_finalize():
    calls, materialize, run_round = _runner(admit_rounds=100)
    plan, revision, _ = asyncio.run(run_continuation_rounds(
        plan="root", plan_revision=None, initial_results={},
        materialize=materialize, run_round=run_round,
    ))
    work_rounds = [c for c in calls["materialize"] if not c[2]]
    assert len(work_rounds) == MAX_SCAN_CONTINUATION_ROUNDS
    assert revision.revision == MAX_SCAN_CONTINUATION_ROUNDS + 1
    assert plan == f"plan-final-{MAX_SCAN_CONTINUATION_ROUNDS + 1}"


def test_a_cancelled_round_stops_the_scan_before_more_traffic():
    calls, materialize, run_round = _runner(admit_rounds=5, cancel_on_round=2)
    with pytest.raises(ValueError, match="Cancelled by user"):
        asyncio.run(run_continuation_rounds(
            plan="root", plan_revision=None, initial_results={},
            materialize=materialize, run_round=run_round,
        ))
    assert [r[1] for r in calls["rounds"]] == [1, 2]
    assert not any(c[2] for c in calls["materialize"]), "no finalizer after cancellation"


def test_a_missing_terminal_finalizer_is_an_error_not_a_silent_end():
    async def materialize(**kwargs):
        return None

    async def run_round(*args, **kwargs):
        raise AssertionError("nothing to run")

    with pytest.raises(ScanContinuationError, match="no finalizer"):
        asyncio.run(run_continuation_rounds(
            plan="root", plan_revision=SimpleNamespace(revision=3), initial_results={},
            materialize=materialize, run_round=run_round,
        ))


def test_progress_windows_partition_the_span_evenly():
    windows = [round_progress_window(n) for n in range(1, MAX_SCAN_CONTINUATION_ROUNDS + 1)]
    assert windows[0][0] == 40 and windows[-1][1] == 90
    assert all(a[1] == b[0] for a, b in zip(windows, windows[1:]))


def test_selection_keeps_admitted_work_and_reports_an_empty_round():
    _parent, continuation, _allocation = _plans()
    work_only = select_continuation_actions(
        continuation, parent_action_count=10, include_finalizer=False, finalize_only=False,
    )
    assert work_only is not None
    ids = [action.action_id for action in work_only.actions]
    assert "finalize.report" not in ids and len(ids) > 0
    assert [action.ordinal for action in work_only.actions] == list(range(len(ids)))

    with_finalizer = select_continuation_actions(
        continuation, parent_action_count=10, include_finalizer=True, finalize_only=True,
    )
    assert with_finalizer is not None
    finalizer = with_finalizer.actions[-1]
    assert finalizer.action_id == "finalize.report"
    assert set(finalizer.dependencies) == {a.action_id for a in with_finalizer.actions[:-1]}

    # A round whose every optional action was skipped admits nothing: the loop's stop signal.
    skipped = ScanActionPlan(
        scan_id=continuation.scan_id,
        execution_plan_digest=continuation.execution_plan_digest,
        target_binding_digest=continuation.target_binding_digest,
        actions=tuple(
            replace(action, admission_status="skipped", reason_code="insufficient_plan_budget", action_digest=None)
            if action.action_id != "finalize.report" and not action.action_id.startswith("inputs.")
            else action
            for action in continuation.actions
        ),
    )
    assert select_continuation_actions(
        skipped, parent_action_count=10, include_finalizer=False, finalize_only=False,
    ) is None


def _shared_round_fixture(endpoint_count=16):
    from api.scan.contracts import resolve_scan_contract
    from api.scan.work_manifests import build_canonical_scan_nuclei_template_manifest
    from tests.test_scan_continuation import _target

    parent, _, allocation = _plans()
    target = _target()
    template = build_canonical_scan_nuclei_template_manifest(
        scan_id=parent.scan_id, target_binding_digest=target.digest, include_active=False,
    )
    return dict(
        parent_plan=parent, allocation=allocation, parent_results={},
        execution_plan=resolve_scan_contract(
            budget_profile="balanced", policy={"active_testing": True, "include_families": ["xss"]},
        ).execution_plan,
        target=target, target_url="https://app.example.test", observations={}, request_manifests=(),
        options={"template_manifest_ref": template.reference().canonical_dict(), "custom_endpoints": [
            f"GET /route_{chr(97 + i // 26)}{chr(97 + i % 26)}?q=1" for i in range(endpoint_count)
        ]},
    )


def _settle_round_fixture(fixture):
    from api.scan.capability_result import CapabilityResultStatus
    from tests.test_scan_orchestrator import _result
    for action in fixture["parent_plan"].actions:
        if action.action_id not in fixture["parent_results"]:
            fixture["parent_results"][action.action_id] = replace(
                _result(action, status=CapabilityResultStatus.SUCCESS),
                budget_consumed={name: min(1, value) for name, value in action.requested_budget.items()},
                result_digest=None,
            )


def test_real_local_and_broker_rounds_match_offsets_budgets_and_finalization():
    from api.scan.continuation import reconciled_continuation_ceiling
    from api.scan.continuation_rounds import compile_continuation_round, compile_next_continuation

    fixture = _shared_round_fixture()
    original_ceiling = None
    seen = set()
    rounds = []
    for number in range(1, MAX_SCAN_CONTINUATION_ROUNDS + 2):
        _settle_round_fixture(fixture)
        ceiling = reconciled_continuation_ceiling(fixture["allocation"], fixture["parent_results"])
        original_ceiling = original_ceiling or ceiling.copy()
        assert all(value <= original_ceiling[key] for key, value in ceiling.items())
        parent = fixture["parent_plan"]
        broker = compile_next_continuation(**fixture, revision_number=number)
        local = compile_continuation_round(
            **fixture, revision_number=number, include_finalizer=False, finalize_only=False,
        )
        if local is None:
            local = compile_continuation_round(
                **fixture, revision_number=number, include_finalizer=True, finalize_only=True,
            )
        assert broker == local
        assert broker.plan.actions[:len(parent.actions)] == parent.actions
        assert broker.revision.parent_plan_digest == parent.plan_digest
        appended = broker.plan.actions[len(parent.actions):]
        for name, limit in ceiling.items():
            assert sum(action.requested_budget.get(name, 0) for action in appended) <= limit
        for action in appended:
            lane = action.capability_args.get("continuation_work_key")
            work = action.capability_args.get("slice")
            if lane and work:
                for index in range(work["start"], work["start"] + work["count"]):
                    assert (lane, index) not in seen
                    seen.add((lane, index))
        rounds.append(broker)
        fixture["parent_plan"] = broker.plan
        if appended[-1].action_id == "finalize.report":
            break
    assert len(rounds) > 2
    assert sum(action.action_id == "finalize.report" for action in rounds[-1].plan.actions) == 1
    assert {index for lane, index in seen if lane == "verify.xss"} == set(range(16))
    _settle_round_fixture(fixture)
    with pytest.raises(ScanContinuationError, match="after the finalizer"):
        compile_next_continuation(**fixture, revision_number=rounds[-1].revision.revision + 1)


def test_real_round_compiler_requires_all_settlements_and_refuses_cancellation():
    from api.scan.capability_result import CapabilityResultStatus, CapabilityResultReason
    from api.scan.continuation_rounds import compile_next_continuation
    from tests.test_scan_orchestrator import _result

    fixture = _shared_round_fixture()
    with pytest.raises(ScanContinuationError, match="terminal parent"):
        compile_next_continuation(**fixture, revision_number=1)
    _settle_round_fixture(fixture)
    action = fixture["parent_plan"].actions[0]
    fixture["parent_results"][action.action_id] = _result(
        action, status=CapabilityResultStatus.CANCELLED, reason=CapabilityResultReason.CANCELLED,
    )
    with pytest.raises(ScanContinuationError, match="cancelled"):
        compile_next_continuation(**fixture, revision_number=1)


def test_materialized_empty_candidate_lane_stops_instead_of_replanning_placeholder_work():
    from api.scan.continuation_rounds import compile_next_continuation
    fixture = _shared_round_fixture(endpoint_count=0)
    _settle_round_fixture(fixture)
    first = compile_next_continuation(**fixture, revision_number=1)
    assert not any(action.capability_name == "xss.verify_batch" for action in first.plan.actions)
    fixture["parent_plan"] = first.plan
    _settle_round_fixture(fixture)
    last = compile_next_continuation(**fixture, revision_number=2)
    assert last.plan.actions[-1].action_id == "finalize.report"


def test_shared_compiler_accepts_static_principal_without_inventing_an_auth_action():
    from api.scan.continuation_rounds import compile_next_continuation
    fixture = _shared_round_fixture()
    fixture["options"]["credential_profile_refs"] = [{
        "profile_id": "90000000-0000-4000-8000-000000000001",
        "version": 1, "digest": "a" * 64, "lane": "primary", "auth_kind": "bearer_token",
    }]
    _settle_round_fixture(fixture)
    prepared = compile_next_continuation(**fixture, revision_number=1)
    assert prepared is not None
    assert not any(action.action_id.startswith("inputs.auth_") for action in prepared.plan.actions)
