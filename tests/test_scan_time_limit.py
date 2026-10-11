"""The Scan's own time limit (``max_duration_seconds``) is kept by the worker (unit level).

Before 2.9.0 nothing in the V2 action path read the limit: a juice-shop Scan with a 900 s limit
ran until the stale-scan sweep found it at about 23 minutes and marked it ``failed`` with no
findings. These tests drive the real ``ReceiptScanActionExecutor`` with fixture dispatchers;
no target is contacted. The PostgreSQL composition is in ``test_scan_time_limit_postgres.py``.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import time

import pytest

from scan.action_interruption import action_interrupted
from scan.capability_result import CapabilityResultReason, CapabilityResultStatus
from scan.cancelled_report import is_kept_cancelled_report, mark_cancelled_scan_report
from scan.execution_backend import PostgresScanExecutionBackend
from scan.scan_deadline import (
    SCAN_TIME_LIMIT,
    ScanDeadline,
    finalization_reserve_seconds,
)
from scan.worker_action_executor import ReceiptScanActionExecutor
from tests.test_scan_action_adapter import TARGET, _lease
from tests.toplevel_scan_fixtures import SCAN_ID, WORKER_ID, baseline_plan as _plan
from tests.toplevel_scan_fixtures import receipt as _receipt


def _deadline_in(seconds: float, *, limit: int = 100, grace: float = 0.5) -> ScanDeadline:
    """A deadline whose work deadline is ``seconds`` from now (negative: already passed)."""
    started = time.time() - (limit - finalization_reserve_seconds(limit)) + seconds
    deadline = ScanDeadline.for_scan(started_at=started, max_duration_seconds=limit)
    assert deadline is not None
    deadline.stop_grace_seconds = grace
    return deadline


async def _noop_heartbeat():
    return None


def _executor(dispatch, deadline):
    return ReceiptScanActionExecutor(
        scan_id=SCAN_ID, target_id=TARGET.target_id, worker_id=WORKER_ID,
        dispatcher=dispatch, deadline=deadline,
    )


# --- the deadline itself ------------------------------------------------------------------


def test_the_work_deadline_holds_back_a_bounded_reserve_for_the_report():
    assert finalization_reserve_seconds(900) == 45.0          # 5 %
    assert finalization_reserve_seconds(3600) == 120.0        # ceiling
    assert finalization_reserve_seconds(120) == 15.0          # floor
    assert finalization_reserve_seconds(40) == 10.0           # never more than a quarter
    deadline = ScanDeadline.for_scan(started_at=1_000.0, max_duration_seconds=900)
    assert deadline.deadline_at == 1_000.0 + 900 - 45


@pytest.mark.parametrize("limit", [None, 0, -5, "", "soon", float("nan")])
def test_no_or_invalid_limit_means_no_deadline(limit):
    assert ScanDeadline.for_scan(started_at=time.time(), max_duration_seconds=limit) is None


def test_a_naive_database_start_is_utc_and_an_unreadable_start_is_now():
    naive = datetime(2026, 10, 10, 12, 0, 0)
    aware = naive.replace(tzinfo=timezone.utc)
    assert ScanDeadline.for_scan(started_at=naive, max_duration_seconds=60).started_at == aware.timestamp()
    clock = lambda: 5_000.0  # noqa: E731
    for hostile in (None, "2026-10-10", True, float("inf")):
        deadline = ScanDeadline.for_scan(started_at=hostile, max_duration_seconds=60, clock=clock)
        assert deadline.started_at == 5_000.0


def test_annotate_marks_the_report_partial_and_names_the_stop_only_after_a_stop():
    deadline = _deadline_in(-1)
    untouched = {"coverage": {"status": "complete", "reasons": []}, "findings": [{"title": "x"}]}
    assert deadline.annotate(dict(untouched)) == untouched  # nothing was stopped
    deadline.record_not_run("verify.sqli.r01")
    deadline.record_interrupted("active.templates.r01")
    report = deadline.annotate({
        "coverage": {"status": "complete", "reasons": []},
        "findings": [{"title": "kept"}],
        "scan_metadata": {"grade_reliability_reasons": ["x"]},
    })
    assert report["findings"] == [{"title": "kept"}]
    assert report["coverage"] == {"status": "partial", "reasons": [SCAN_TIME_LIMIT]}
    metadata = report["scan_metadata"]
    assert metadata["stopped_at_time_limit"] is True and metadata["partial"] is True
    assert metadata["grade_reliable"] is False
    assert metadata["grade_reliability_reasons"] == ["x", SCAN_TIME_LIMIT]
    stop = metadata["time_limit_stop"]
    assert stop["max_duration_seconds"] == 100
    assert stop["interrupted_actions"] == ["active.templates.r01"]
    assert stop["not_run_actions"] == ["verify.sqli.r01"]
    # A worse status (cancelled, failed) is kept, never upgraded to partial.
    worse = deadline.annotate({"coverage": {"status": "failed", "reasons": ["adapter_failed"]}})
    assert worse["coverage"]["status"] == "failed"


# --- the executor ---------------------------------------------------------------------------


def test_an_action_that_has_not_started_by_the_deadline_is_not_started_and_costs_nothing():
    plan = _plan()
    action = plan.actions[0]
    deadline = _deadline_in(-1)

    async def dispatch(*_args):
        raise AssertionError("an action past the deadline must not run")

    receipt = asyncio.run(_executor(dispatch, deadline).execute(
        action, _lease(plan, action), _noop_heartbeat,
    ))
    assert receipt.status == "timed_out"
    assert receipt.errors == (SCAN_TIME_LIMIT,)
    assert set(receipt.budget_consumed.values()) == {0}
    assert receipt.redacted_execution["execution_started"] is False
    assert deadline.not_run_actions == [action.action_id]


def test_the_report_still_runs_after_the_deadline():
    plan = _plan()
    final = plan.actions[-1]
    assert final.action_id == "finalize.report"
    deadline = _deadline_in(-1)
    ran = []

    async def dispatch(action, *_args):
        ran.append(action.action_id)
        return _receipt(action)

    receipt = asyncio.run(_executor(dispatch, deadline).execute(
        final, _lease(plan, final), _noop_heartbeat,
    ))
    assert ran == ["finalize.report"] and receipt.status == "success"
    assert deadline.not_run_actions == [] and deadline.interrupted_actions == []


def test_an_action_running_at_the_deadline_is_stopped_and_keeps_what_it_observed():
    plan = _plan()
    action = plan.actions[0]
    deadline = _deadline_in(0.3)
    observed = []

    async def dispatch(*_args):
        started = time.monotonic()
        while not action_interrupted():  # the adapter's own stop check
            observed.append({"kind": "http_response", "status_code": 200, "n": len(observed)})
            await asyncio.sleep(0.05)
            assert time.monotonic() - started < 5, "the deadline never interrupted the action"
        return _receipt(action, status="cancelled", errors=("cancelled",), observations=observed)

    started = time.monotonic()
    receipt = asyncio.run(_executor(dispatch, deadline).execute(
        action, _lease(plan, action), _noop_heartbeat,
    ))
    assert time.monotonic() - started < 2.0
    assert receipt.status == "partial" and receipt.partial is True and receipt.timed_out is False
    assert receipt.errors[0] == SCAN_TIME_LIMIT and "cancelled" not in receipt.errors
    assert len(receipt.observations) == len(observed) > 0
    assert receipt.redacted_execution["scan_time_limit"]["reason_code"] == SCAN_TIME_LIMIT
    assert deadline.interrupted_actions == [action.action_id]


def test_an_action_that_ignores_the_stop_is_cancelled_after_the_grace_and_fails_charged():
    plan = _plan()
    action = plan.actions[0]
    deadline = _deadline_in(0.2, grace=0.3)

    async def stubborn(*_args):
        await asyncio.sleep(30)
        raise AssertionError("not reached")

    started = time.monotonic()
    receipt = asyncio.run(_executor(stubborn, deadline).execute(
        action, _lease(plan, action), _noop_heartbeat,
    ))
    assert time.monotonic() - started < 3.0
    assert receipt.status == "failed" and receipt.errors == (SCAN_TIME_LIMIT,)
    assert dict(receipt.budget_consumed) == dict(action.requested_budget)


def test_an_action_that_finishes_before_the_deadline_is_untouched():
    plan = _plan()
    action = plan.actions[0]
    deadline = _deadline_in(60)

    async def dispatch(*_args):
        return _receipt(action)

    receipt = asyncio.run(_executor(dispatch, deadline).execute(
        action, _lease(plan, action), _noop_heartbeat,
    ))
    assert receipt.status == "success" and receipt.errors == ()
    assert not deadline.stopped


# --- settlement ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "timed_out", "expected"),
    [
        ("timed_out", True, CapabilityResultStatus.TIMED_OUT),
        ("partial", False, CapabilityResultStatus.PARTIAL),
    ],
)
def test_a_time_limit_receipt_settles_with_the_scan_time_limit_reason(status, timed_out, expected):
    action = _plan().actions[0]
    backend = object.__new__(PostgresScanExecutionBackend)  # the pure receipt mapping only
    receipt = _receipt(action, status=status, errors=(SCAN_TIME_LIMIT,), timed_out=timed_out)
    assert backend._receipt_outcome(receipt) == (expected, CapabilityResultReason.SCAN_TIME_LIMIT)


def test_an_ordinary_timeout_still_settles_as_timed_out():
    action = _plan().actions[0]
    backend = object.__new__(PostgresScanExecutionBackend)
    receipt = _receipt(action, status="timed_out", errors=("timeout",), timed_out=True)
    assert backend._receipt_outcome(receipt) == (
        CapabilityResultStatus.TIMED_OUT, CapabilityResultReason.TIMED_OUT,
    )


# --- cancellation keeps the report ------------------------------------------------------------


def test_a_cancelled_report_keeps_its_findings_and_says_cancelled():
    report = mark_cancelled_scan_report({
        "findings": [{"title": "Missing HTTP response header: X-Frame-Options"}],
        "coverage": {"status": "complete", "reasons": []},
        "scan_metadata": {},
    })
    assert report["findings"] and report["coverage"]["status"] == "cancelled"
    assert report["coverage"]["reasons"] == ["cancelled"]
    assert report["scan_metadata"]["cancelled"] is True
    assert report["scan_metadata"]["grade_reliable"] is False
    assert is_kept_cancelled_report(report)


@pytest.mark.parametrize("hostile", [
    None, [], "cancelled", {}, {"scan_metadata": "x"},
    {"scan_metadata": {"cancelled_report_kept": "true"}},
    {"scan_metadata": {"cancelled_report_kept": True}, "error": "Cancelled by user"},
])
def test_only_a_marked_error_free_report_is_kept_as_cancelled(hostile):
    assert is_kept_cancelled_report(hostile) is False


def test_a_deadline_passing_after_the_dispatch_returned_changes_nothing():
    """The closing credential check may outlast the deadline; the finished action is kept as is.

    Before the dispatch flag, the deadline watcher fired during that check, tried to move the
    already-finished hard stop (RuntimeError on Python 3.12+) and the action was settled failed.
    """
    plan = _plan()
    action = plan.actions[0]
    deadline = _deadline_in(0.3)
    calls = []

    async def credential_check(_action):
        calls.append(time.monotonic())
        if len(calls) > 1:
            await asyncio.sleep(1.0)  # the closing check runs past the deadline
        return None

    async def dispatch(*_args):
        return _receipt(action)

    executor = ReceiptScanActionExecutor(
        scan_id=SCAN_ID, target_id=TARGET.target_id, worker_id=WORKER_ID,
        dispatcher=dispatch, deadline=deadline, credential_check=credential_check,
    )
    receipt = asyncio.run(executor.execute(action, _lease(plan, action), _noop_heartbeat))
    assert len(calls) >= 2  # before, polled while running, and the closing check
    assert receipt.status == "success" and receipt.errors == ()
    assert deadline.interrupted_actions == [] and deadline.not_run_actions == []


def test_a_round_refused_between_rounds_is_reported_as_a_time_limit_stop():
    """The limit passing between continuation rounds stops the Scan as much as mid-round."""
    deadline = ScanDeadline.for_scan(started_at=0, max_duration_seconds=60, clock=lambda: 10_000.0)
    assert deadline.reached() is True
    assert deadline.stopped is False  # reaching it alone is not yet a stop
    deadline.record_refused_round()  # what the worker's materialize_round now records
    report = deadline.annotate({"coverage": {"status": "complete", "reasons": []}, "scan_metadata": {}})
    assert report["coverage"] == {"status": "partial", "reasons": [SCAN_TIME_LIMIT]}
    stop = report["scan_metadata"]["time_limit_stop"]
    assert stop["continuation_rounds_not_run"] == 1
    assert report["scan_metadata"]["stopped_at_time_limit"] is True


def test_the_worker_records_the_refused_round():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "api" / "worker.py").read_text()
    refused = source.index("deadline.reached():\n                deadline.record_refused_round()")
    assert source.index("return None  # nor once the Scan has reached its time limit") > refused


@pytest.mark.parametrize(("options", "expected"), [
    ({"scan_execution_plan": {"budget": {"max_duration_seconds": 900}}}, 900),
    ({"scan_execution_plan": {"budget": {"max_duration_seconds": 900}},
      "canonical_shard_authority": {"sub_budget": {"max_duration_seconds": 180}}}, 180),
    ({"scan_execution_plan": {"budget": {"max_duration_seconds": "x"}}}, None),
    ({"scan_execution_plan": "hostile"}, None),
    ({}, None),
])
def test_a_fleet_node_keeps_the_limit_from_its_own_start(options, expected):
    from scan.scan_deadline import node_scan_deadline

    deadline = node_scan_deadline(options, clock=lambda: 5_000.0)
    if expected is None:
        assert deadline is None
    else:
        assert deadline.max_duration_seconds == expected and deadline.started_at == 5_000.0


def test_fleet_node_executors_are_given_the_deadline():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "api" / "broker_worker.py").read_text()
    assert source.count("deadline=deadline,") == 2  # the first round and every continuation
    assert "return deadline.annotate(report)" in source
