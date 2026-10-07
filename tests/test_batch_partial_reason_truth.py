"""A partial batch must name the reason it is actually partial.

`verify.xss` reported `insufficient_plan_budget` on a run where it attempted every
candidate it had and left 650 of its 2,210 reserved requests unspent. Its attempts had
been wall-killed (`exit_-9`) -- a timeout, not a shortage. Because `verify.xss` is a
required action, that false reason made the whole grade unreliable and pointed every
reader at plan budget instead of at the tool's own wall.

The converse also held: a required template batch whose request ceiling stopped it
(126 of 126 requests in 83 of 216 seconds) was reported `timed_out`. The reason has to
name the dimension that stopped the batch. Only wall-clock exhaustion is a timeout, and
only a batch that could not fund an attempt it still had ran out of budget.
"""

from scan.action_adapter import attempt_ceiling_stops, batch_stop_reason


def _stated_reason(attempt_errors, unattempted, **kwargs):
    return batch_stop_reason(attempt_errors, unattempted=unattempted, **kwargs)


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


def test_a_request_ceiling_stop_names_http_requests_not_the_wall():
    stops = attempt_ceiling_stops(["timeout", "connection_limit_exceeded"])
    assert stops == {"http_requests"}
    # Mixed with wall-killed attempts, the ceiling is still what stopped the batch.
    assert _stated_reason(
        ["timeout", "connection_limit_exceeded"], unattempted=0, ceiling_stops=stops,
    ) == "http_request_budget_exhausted"
    assert _stated_reason(
        ["connection_limit_exceeded"], unattempted=0, ceiling_stops=stops,
    ) == "http_request_budget_exhausted"


def test_an_unfunded_candidate_names_the_dimension_that_ran_out():
    assert _stated_reason(
        [], unattempted=1, exhausted={"state_changing_requests"},
    ) == "state_changing_budget_exhausted"
    assert _stated_reason(
        [], unattempted=3, exhausted={"http_requests"},
    ) == "http_request_budget_exhausted"
    # The action's own wall running out with candidates left IS a timeout.
    assert _stated_reason([], unattempted=2, exhausted={"tool_wall_seconds"}) == "timed_out"
    # An exhausted dimension means nothing when every candidate was attempted.
    assert _stated_reason(
        ["connection refused"], unattempted=0, exhausted={"http_requests"},
    ) == "adapter_failed"


def test_every_stated_reason_is_a_durable_reason_code():
    from scan.capability_result import CapabilityResultReason

    known = {item.value for item in CapabilityResultReason}
    for errors, unattempted, extra in (
        (["timeout"], 0, {}),
        ([], 1, {"exhausted": {"http_requests"}}),
        ([], 1, {"exhausted": {"state_changing_requests"}}),
        ([], 1, {}),
        (["x"], 0, {}),
    ):
        assert _stated_reason(errors, unattempted, **extra) in known


def test_the_adapter_uses_this_rule():
    from pathlib import Path
    source = (
        Path(__file__).resolve().parents[1] / "api" / "scan" / "action_adapter.py"
    ).read_text(encoding="utf-8")
    batch = source[source.index("    async def _external_batch("):]
    batch = batch[:batch.index("    @staticmethod")]
    assert "stated = batch_stop_reason(" in batch
    assert "ceiling_stops=ceiling_stops, exhausted=exhausted" in batch
