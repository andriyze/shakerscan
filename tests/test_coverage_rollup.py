"""A required action that fell short never leaves the scan claiming complete coverage."""

from api.scan.coverage_rollup import action_coverage_reasons, apply_action_coverage


def _row(capability, status, required=True, reason_code=None):
    return {"capability_name": capability, "status": status, "required": required, "reason_code": reason_code}


def test_partial_crawl_turns_complete_coverage_into_partial_with_a_reason():
    rows = [_row("web.probe", "success"), _row("web.crawl", "partial", reason_code="exit_-9")]
    coverage = apply_action_coverage({"status": "complete", "reasons": []}, rows)
    assert coverage["status"] == "partial"
    assert coverage["reasons"] == ["web_crawl_partial:exit_-9"]


def test_optional_and_successful_actions_leave_coverage_untouched():
    rows = [_row("web.crawl", "success"), _row("web.browser_crawl", "failed", required=False)]
    assert apply_action_coverage({"status": "complete", "reasons": []}, rows) == {
        "status": "complete", "reasons": [],
    }
    assert action_coverage_reasons(rows) == []


def test_worse_statuses_are_kept_and_reasons_accumulate_without_duplicates():
    rows = [_row("web.crawl", "timed_out"), _row("web.crawl", "timed_out")]
    failed = apply_action_coverage({"status": "failed", "reasons": ["engine_error"]}, rows)
    assert failed["status"] == "failed"
    assert failed["reasons"] == ["engine_error", "web_crawl_timed_out"]
    empty = apply_action_coverage(None, rows)
    assert empty == {"reasons": ["web_crawl_timed_out"], "status": "partial"}
