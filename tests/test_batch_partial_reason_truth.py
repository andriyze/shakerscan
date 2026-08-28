"""A partial batch must name the reason it is actually partial.

`verify.xss` reported `insufficient_plan_budget` on a run where it attempted every
candidate it had and left 650 of its 2,210 reserved requests unspent. Its attempts had
been wall-killed (`exit_-9`) -- a timeout, not a shortage. Because `verify.xss` is a
required action, that false reason made the whole grade unreliable and pointed every
reader at plan budget instead of at the tool's own wall.

The rule the reason has to satisfy: only a batch that could not fund an attempt it still
had ran out of budget.
"""


def _stated_reason(attempt_errors, unattempted):
    """The decision in `_batch_receipt`, restated so it can be tested directly."""
    lowered = [str(item).strip().lower() for item in attempt_errors]
    wall_killed = lowered and all(
        item == "timeout" or item.startswith("exit_-") for item in lowered
    )
    if wall_killed:
        return "timed_out"
    if unattempted:
        return "insufficient_plan_budget"
    return "adapter_failed"


def test_wall_killed_attempts_are_a_timeout_not_a_shortage():
    # The exact errors the live scan recorded.
    assert _stated_reason(["exit_-9", "exit_-9", "exit_-9"], unattempted=0) == "timed_out"
    assert _stated_reason(["exit_-9", "exit_-9", "timeout"], unattempted=0) == "timed_out"
    assert _stated_reason(["timeout"], unattempted=0) == "timed_out"


def test_only_unfunded_candidates_mean_insufficient_budget():
    assert _stated_reason([], unattempted=4) == "insufficient_plan_budget"
    assert _stated_reason(["connection refused"], unattempted=4) == "insufficient_plan_budget"


def test_a_failed_attempt_with_nothing_left_over_is_an_adapter_failure():
    assert _stated_reason(["connection refused"], unattempted=0) == "adapter_failed"
    assert _stated_reason(["exit_-9", "connection refused"], unattempted=0) == "adapter_failed"


def test_the_adapter_uses_this_rule():
    from pathlib import Path
    source = (
        Path(__file__).resolve().parents[1] / "api" / "scan" / "action_adapter.py"
    ).read_text(encoding="utf-8")
    assert 'item.startswith("exit_-")' in source
    assert "CapabilityResultReason.ADAPTER_FAILED.value" in source
    # The budget reason must be reachable only behind `unattempted`.
    block = source[source.index("wall_killed = attempt_errors and all("):]
    budget_at = block.index("INSUFFICIENT_PLAN_BUDGET")
    assert "elif unattempted:" in block[:budget_at]
