from api.scan.parallel_outcome import (
    apply_parallel_action_budget,
    mark_parallel_parent_coverage_incomplete,
    mark_parallel_parent_degraded,
)


def test_parallel_action_budget_is_summed_from_the_canonical_action_ledger():
    merged = {"scan_metadata": {"budget_used": {"http_requests": 999}}}
    budget = apply_parallel_action_budget(merged, {
        "actions": [
            {"budget_consumed": {"http_requests": 3, "tool_wall_seconds": 2}},
            {"budget_consumed": {"http_requests": 4, "tool_wall_seconds": "bad"}},
        ],
    })

    assert budget == {"http_requests": 7, "tool_wall_seconds": 2}
    assert merged["scan_metadata"]["budget_used"] == budget


def test_incomplete_coverage_withholds_a_clean_parallel_grade():
    merged = {
        "coverage": {"status": "partial", "reasons": ["required_action_incomplete"]},
        "result": {"grade": "A", "grade_reliable": True},
    }

    assert mark_parallel_parent_coverage_incomplete(merged) is True
    assert merged["result"]["grade"] == "A*"
    assert merged["result"]["grade_reliable"] is False


def test_failed_shard_marks_the_parent_degraded():
    merged = {"result": {"grade": "B", "grade_reliable": True}}

    assert mark_parallel_parent_degraded(
        merged, failed_count=1, total_count=3,
    ) is True
    assert merged["parallel"]["degraded"] is True
    assert merged["result"]["grade"] == "B*"
