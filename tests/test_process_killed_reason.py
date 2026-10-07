"""A tool killed by a signal the worker did not send is `process_killed`, not `timed_out`.

The worker reports its own deadline as `timeout` and sets timed_out. A tool the kernel's
OOM killer or a container limit killed exits `exit_-9` with timed_out unset, yet a batch
of such attempts stated `timed_out` while its receipt said it had not timed out, and a
single killed tool settled with the `output_truncated` fallback. Both now say
`process_killed`, and the receipt and the stated reason agree.
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

from scan.capability_result import (
    CapabilityResultReason,
    CapabilityResultStatus,
    is_process_kill_error,
)
from tests.test_action_stop_dimension import _outcome, _wall_killed
from tests.test_template_batch_empty_timeout_retry import _matched, _run


def _killed(path, granted):
    return dataclasses.replace(
        _matched(path, granted), status="partial", partial=True, timed_out=False,
        errors=("exit_-9",),
    )


def test_a_batch_of_killed_attempts_is_process_killed_not_timed_out(monkeypatch):
    receipt, _calls, _backend, _ = _run(
        monkeypatch, lambda path, call, granted: _killed(path, granted),
    )

    assert receipt.status == "partial"
    assert receipt.timed_out is False
    assert receipt.errors[0] == "process_killed"
    assert _outcome(receipt) == (
        CapabilityResultStatus.PARTIAL, CapabilityResultReason.PROCESS_KILLED,
    )


def test_a_wall_kill_beside_a_killed_attempt_is_still_a_timeout(monkeypatch):
    def outcome(path, call, granted):
        return _wall_killed(path, granted) if path == "/slow" else _killed(path, granted)

    receipt, _calls, _backend, _ = _run(monkeypatch, outcome)

    assert receipt.timed_out is True
    assert receipt.errors[0] == "timed_out"
    assert _outcome(receipt) == (
        CapabilityResultStatus.TIMED_OUT, CapabilityResultReason.TIMED_OUT,
    )


def test_a_single_killed_tool_says_it_was_killed():
    partial = SimpleNamespace(status="partial", timed_out=False, partial=True, errors=("exit_-9",))
    failed = SimpleNamespace(status="failed", timed_out=False, partial=False, errors=("exit_-15",))

    assert _outcome(partial) == (
        CapabilityResultStatus.PARTIAL, CapabilityResultReason.PROCESS_KILLED,
    )
    assert _outcome(failed) == (
        CapabilityResultStatus.FAILED, CapabilityResultReason.PROCESS_KILLED,
    )


def test_only_negative_exit_codes_are_kills():
    assert is_process_kill_error("exit_-9") and is_process_kill_error("EXIT_-15")
    assert not is_process_kill_error("exit_2")
    assert not is_process_kill_error("timeout")


def test_a_crawl_killed_mid_run_is_truncated_discovery():
    from api.scan.capability_result import (
        CapabilityResultReason as Reason,
        CapabilityResultStatus as Status,
    )
    from tests.test_discovery_truncation_coverage import _report

    coverage = _report(Status.PARTIAL, Reason.PROCESS_KILLED)["coverage"]

    assert coverage["status"] == "partial"
    assert "discovery_truncated" in coverage["reasons"]
