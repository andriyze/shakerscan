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
