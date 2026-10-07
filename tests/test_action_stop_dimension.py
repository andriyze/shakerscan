"""An action reports the budget dimension that stopped it; only the wall is a timeout.

Soak scans d63bc2ba and 2c637857 settled their required `passive.templates.r01` batch
as `timed_out` -- "The action reached its fixed time limit" -- with 126 of 126 HTTP
requests charged in 83 of its 216 seconds. Two rules made every such batch a timeout:
the batch treated any `partial` attempt as wall-killed, and the backend turned any
receipt carrying `timed_out` into TIMED_OUT whatever reason the batch stated. A tool the
pinned transport stopped at its request ceiling was also settled `failed` and discarded
the output it had already written.
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest

from scan.capability_result import CapabilityResultReason, CapabilityResultStatus
from scan.execution_backend import PostgresScanExecutionBackend
from tests.test_template_batch_empty_timeout_retry import _matched, _run


def _outcome(receipt):
    backend = object.__new__(PostgresScanExecutionBackend)
    return backend._receipt_outcome(receipt)


def _ceiling_stopped(path, granted):
    """The worker's result for a tool the pinned transport stopped at its request ceiling."""
    matched = _matched(path, granted, seconds=3)
    return dataclasses.replace(
        matched, status="partial", partial=True, timed_out=False,
        errors=("connection_limit_exceeded",),
        actual_budget={"http_requests": granted["http_requests"], "tool_wall_seconds": 3},
    )


def _wall_killed(path, granted):
    matched = _matched(path, granted, seconds=granted["tool_wall_seconds"])
    return dataclasses.replace(
        matched, status="partial", partial=True, timed_out=True, errors=("timeout",),
    )


def test_a_template_batch_stopped_at_its_request_ceiling_names_http_requests(monkeypatch):
    def outcome(path, call, granted):
        return _ceiling_stopped(path, granted) if path == "/slow" else _matched(path, granted)

    receipt, _calls, _backend, _ = _run(monkeypatch, outcome)

    assert receipt.status == "partial"
    assert receipt.timed_out is False, "a request ceiling is not a timeout"
    assert receipt.errors[0] == "http_request_budget_exhausted"
    assert _outcome(receipt) == (
        CapabilityResultStatus.PARTIAL,
        CapabilityResultReason.HTTP_REQUEST_BUDGET_EXHAUSTED,
    )


def test_the_request_ceiling_wins_over_a_sibling_attempt_that_timed_out(monkeypatch):
    def outcome(path, call, granted):
        if path == "/slow":
            return _wall_killed(path, granted)
        if path == "/fast-one":
            return _ceiling_stopped(path, granted)
        return _matched(path, granted)

    receipt, _calls, _backend, _ = _run(monkeypatch, outcome)

    # The wall-killed attempt stays visible on the receipt, but it is not what the
    # durable result says stopped the action.
    assert receipt.timed_out is True
    assert receipt.errors[0] == "http_request_budget_exhausted"
    assert _outcome(receipt) == (
        CapabilityResultStatus.PARTIAL,
        CapabilityResultReason.HTTP_REQUEST_BUDGET_EXHAUSTED,
    )


def test_a_batch_whose_attempts_were_all_wall_killed_is_still_timed_out(monkeypatch):
    receipt, _calls, _backend, _ = _run(
        monkeypatch, lambda path, call, granted: _wall_killed(path, granted),
    )

    assert receipt.timed_out is True
    assert receipt.errors[0] == "timed_out"
    assert _outcome(receipt) == (
        CapabilityResultStatus.TIMED_OUT, CapabilityResultReason.TIMED_OUT,
    )


def test_a_partial_attempt_that_was_not_wall_killed_is_not_a_timeout(monkeypatch):
    def outcome(path, call, granted):
        if path == "/slow":
            return dataclasses.replace(
                _matched(path, granted), status="partial", partial=True,
                errors=("output_truncated",),
            )
        return _matched(path, granted)

    receipt, _calls, _backend, _ = _run(monkeypatch, outcome)

    assert receipt.status == "partial"
    assert receipt.timed_out is False
    status, _reason = _outcome(receipt)
    assert status is CapabilityResultStatus.PARTIAL


@pytest.mark.parametrize("raw_status, expected_status", [
    ("partial", CapabilityResultStatus.PARTIAL),
    ("failed", CapabilityResultStatus.FAILED),
])
def test_a_single_tool_stopped_by_the_transport_ceiling_names_http_requests(
    raw_status, expected_status,
):
    receipt = SimpleNamespace(
        status=raw_status, timed_out=False, partial=raw_status == "partial",
        errors=("connection_limit_exceeded",),
    )
    assert _outcome(receipt) == (
        expected_status, CapabilityResultReason.HTTP_REQUEST_BUDGET_EXHAUSTED,
    )


def test_a_single_tool_wall_kill_is_still_a_timeout():
    receipt = SimpleNamespace(status="partial", timed_out=True, partial=True, errors=("timeout",))
    assert _outcome(receipt) == (
        CapabilityResultStatus.TIMED_OUT, CapabilityResultReason.TIMED_OUT,
    )


def test_every_budget_reason_has_an_operator_label():
    from scan.explanation import _REASON_LABELS

    for reason in (
        CapabilityResultReason.HTTP_REQUEST_BUDGET_EXHAUSTED,
        CapabilityResultReason.STATE_CHANGING_BUDGET_EXHAUSTED,
    ):
        assert "allowance" in _REASON_LABELS[reason.value]
    assert "fixed time limit" not in _REASON_LABELS["timed_out"]


def test_a_ceiling_stop_with_output_is_partial_not_failed(monkeypatch):
    from tests import test_crawler_memory_ceiling as crawl

    class _LimitedProxy(crawl._PinnedProxy):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.limit_exceeded.set()

    running = []

    async def launch(*_cmd, **_kwargs):
        running.append(crawl._RunningCrawler())
        return running[-1]

    monkeypatch.setattr(crawl, "_PinnedProxy", _LimitedProxy)
    monkeypatch.setattr(crawl.worker, "_terminate_agent_tool_process_group", lambda proc: proc.kill())
    monkeypatch.setattr(crawl.worker.deployment_policy, "container_memory_limit_bytes", lambda: None)
    result = crawl._run_crawl(monkeypatch, launch=launch)

    assert result["error"] == "connection_limit_exceeded"
    assert result["line_count"] == 1
    assert result["timed_out"] is False
    assert result["partial"] is True, "records written before the ceiling are trustworthy"
