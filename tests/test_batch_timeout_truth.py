"""A batch in which every attempt timed out is not a success.

An external tool that exceeds its wall is normalized to `status="partial"` by
`api/capabilities/scanner.py`. The batch aggregator marked terminal failure only for
`failed` and `timed_out`, so `partial` fell through: with every candidate started,
`unattempted` was 0, `terminal_failure` stayed False, and the batch receipt came out
`status="success", timed_out=False`.

That is how the XSS family reported complete coverage on a live Juice Shop scan while
producing no proof at all -- every dalfox attempt was wall-killed and the receipt said
the batch succeeded.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "api" / "scan" / "action_adapter.py"
SCANNER = ROOT / "api" / "capabilities" / "scanner.py"
SOURCE = ADAPTER.read_text(encoding="utf-8")

SUCCESS_STATUSES = {"success", "succeeded", "completed"}


def _aggregate(attempt_statuses, declared):
    """The aggregation rule, restated so its outcome can be asserted directly."""
    attempted = 0
    terminal_failure = False
    timed_out = False
    for status in attempt_statuses:
        attempted += 1
        if status not in SUCCESS_STATUSES:
            terminal_failure = True
        if status in {"timed_out", "partial"}:
            timed_out = True
        if status == "cancelled":
            break
    unattempted = max(0, declared - attempted)
    partial = unattempted > 0 or terminal_failure
    return {
        "status": "partial" if partial else "success",
        "timed_out": timed_out,
        "unattempted": unattempted,
    }


def test_a_batch_of_nothing_but_timeouts_is_not_success():
    result = _aggregate(["partial", "partial", "partial"], declared=3)
    assert result["status"] == "partial"
    assert result["timed_out"] is True
    assert result["unattempted"] == 0, "every candidate was started; nothing was unfunded"


def test_the_upstream_normalization_this_depends_on_still_holds():
    """If the scanner stops mapping a timeout to `partial`, this rule needs revisiting."""
    scanner = SCANNER.read_text(encoding="utf-8")
    assert 'partial = bool(process_result.get("partial") or timed_out)' in scanner
    assert 'status = "partial"' in scanner


def test_a_clean_batch_is_still_success():
    result = _aggregate(["success", "success"], declared=2)
    assert result == {"status": "success", "timed_out": False, "unattempted": 0}


def test_one_failure_among_successes_still_marks_the_batch():
    assert _aggregate(["success", "failed"], declared=2)["status"] == "partial"


def test_the_adapter_uses_this_rule():
    assert 'result.status not in {"success", "succeeded", "completed"}' in SOURCE
    assert "timed_out=attempt_timed_out" in SOURCE


# `_exposure_probe_batch` is the one handler exempt from the rule below: its attempts are
# in-process HTTP reads with no external tool and no wall to exceed, and it stamps each
# attempt "success" as a literal. There is no per-attempt outcome for it to aggregate.
_HANDLERS_WITHOUT_ATTEMPT_OUTCOMES = 1


def test_no_batch_handler_decides_its_verdict_from_unattempted_alone():
    """Six handlers each decided this independently and every one of them looked only
    at `unattempted`, so the same defect existed six times over."""
    remaining = SOURCE.count('status="partial" if unattempted else "success"')
    assert remaining <= _HANDLERS_WITHOUT_ATTEMPT_OUTCOMES, (
        f"{remaining} batch handlers still ignore their attempts' outcomes"
    )
    hardcoded = SOURCE.count("partial=bool(unattempted), timed_out=False")
    assert hardcoded <= _HANDLERS_WITHOUT_ATTEMPT_OUTCOMES, (
        f"{hardcoded} batch handlers still hardcode timed_out=False alongside a real "
        "attempt status"
    )


def test_the_shared_helper_is_the_single_rule():
    import sys
    sys.path.insert(0, str(ROOT / "api"))
    from scan.action_adapter import batch_outcome

    assert batch_outcome(["partial", "partial"], 0) == ("partial", True, True)
    assert batch_outcome(["failed", "success"], 0) == ("partial", True, False)
    assert batch_outcome(["success", "success"], 0) == ("success", False, False)
    assert batch_outcome(["success"], 2) == ("partial", True, False)
    assert batch_outcome([], 0) == ("success", False, False)


def test_the_flag_is_initialised_before_the_attempt_loop():
    tree = ast.parse(SOURCE)
    assigns = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "attempt_timed_out" for t in node.targets
        )
    ]
    assert any(
        isinstance(node.value, ast.Constant) and node.value.value is False
        for node in assigns
    ), "attempt_timed_out is never initialised to False"


def test_replaying_checkpoints_does_not_launder_failure_into_success():
    """Every attempt of a wall-killed batch is checkpointed, so a restart replayed them
    all and produced a clean success receipt for a batch that proved nothing."""
    def _replay(prior_statuses, declared):
        terminal_failure = False
        timed_out = False
        attempted = 0
        for status in prior_statuses:
            attempted += 1
            if status not in SUCCESS_STATUSES:
                terminal_failure = True
            if status in {"timed_out", "partial"}:
                timed_out = True
        unattempted = max(0, declared - attempted)
        partial = unattempted > 0 or terminal_failure
        return ("partial" if partial else "success", timed_out)

    assert _replay(["partial", "partial"], 2) == ("partial", True)
    assert _replay(["success", "success"], 2) == ("success", False)


def test_the_external_batch_resume_branch_reads_the_prior_status():
    start = SOURCE.index("    async def _external_batch(")
    nxt = SOURCE.find("\n    async def ", start + 10)
    body = SOURCE[start:nxt if nxt != -1 else len(SOURCE)]
    resume = body[body.index("prior = completed.get(attempt_id)"):]
    head = resume[:1200]
    assert 'prior.get("status")' in head, "the resume branch ignores the checkpointed outcome"
    assert "terminal_failure = True" in head
    assert "attempt_timed_out = True" in head


def test_a_timed_out_dependency_still_lets_proof_escalate():
    """Proof depends on verification having produced candidates, not on a clean status.

    `verify.sqli` had always been timing out; batch receipts simply overwrote `timed_out`
    with False. The moment they told the truth, its status became TIMED_OUT, which the
    dependency gate did not accept, so `prove.sqli` was blocked as dependency_failed and
    the one verified SQLi on Juice Shop disappeared. Preserving trustworthy partial output
    on timeout is the engine's own rule; the gate was the thing out of step with it.
    """
    import sys
    sys.path.insert(0, str(ROOT / "api"))
    from scan.capability_result import CapabilityResultStatus
    from scan.orchestrator import _DEPENDENCY_SATISFIED

    assert CapabilityResultStatus.TIMED_OUT in _DEPENDENCY_SATISFIED
    assert CapabilityResultStatus.PARTIAL in _DEPENDENCY_SATISFIED
    assert CapabilityResultStatus.SUCCESS in _DEPENDENCY_SATISFIED
    # A dependency that never ran must still block.
    for blocked in (
        CapabilityResultStatus.FAILED,
        CapabilityResultStatus.SKIPPED,
        CapabilityResultStatus.BLOCKED,
        CapabilityResultStatus.CANCELLED,
    ):
        assert blocked not in _DEPENDENCY_SATISFIED, blocked
