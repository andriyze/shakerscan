from scanner.scanner_tools.active_enrichment_policy import (
    record_active_enrichment_skip,
    should_run_active_enrichment,
)
from scanner.scanner_tools.completion_status import build_scan_completion_status


def test_enrichment_decision_uses_canonical_post_active_skip_reason():
    active_block = {"post_active_enrichment_skipped": "primary_family_budget_exhausted"}

    decision = should_run_active_enrichment(
        "dom_xss",
        post_active_budget_exhausted=True,
        active_block=active_block,
    )

    assert decision.run is False
    assert decision.reason == "primary_family_budget_exhausted"
    assert active_block["active_enrichment_decisions"]["dom_xss"] == {
        "run": False,
        "reason": "primary_family_budget_exhausted",
    }


def test_enrichment_skip_records_existing_report_keys():
    active_block = {}

    record_active_enrichment_skip(active_block, "dom_xss", "active_time_budget_exhausted")
    record_active_enrichment_skip(
        active_block,
        "sqlmap",
        "primary_family_budget_exhausted",
        candidate_reason="post_active_budget",
    )

    assert active_block["dom_xss_skipped"] == "active_time_budget_exhausted"
    assert active_block["sqlmap_skipped"] == [
        {
            "skip_reason": "primary_family_budget_exhausted",
            "candidate_reason": "post_active_budget",
        }
    ]


def test_record_skip_dedupes_identical_calls():
    active_block: dict = {}
    record_active_enrichment_skip(active_block, "dom_xss", "active_time_budget_exhausted")
    record_active_enrichment_skip(active_block, "dom_xss", "active_time_budget_exhausted")
    record_active_enrichment_skip(
        active_block,
        "sqlmap",
        "primary_family_budget_exhausted",
        candidate_reason="post_active_budget",
    )
    record_active_enrichment_skip(
        active_block,
        "sqlmap",
        "primary_family_budget_exhausted",
        candidate_reason="post_active_budget",
    )

    # Flat-string shape: identical second write is a no-op.
    assert active_block["dom_xss_skipped"] == "active_time_budget_exhausted"
    # List shape: duplicate sqlmap entry is not appended.
    assert len(active_block["sqlmap_skipped"]) == 1


def test_record_skip_preserves_first_string_reason():
    active_block: dict = {}
    record_active_enrichment_skip(active_block, "dom_xss", "primary_family_budget_exhausted")
    record_active_enrichment_skip(active_block, "dom_xss", "different_reason_later")

    # Earlier, more specific reason wins; the later call does not overwrite.
    assert active_block["dom_xss_skipped"] == "primary_family_budget_exhausted"


def test_completion_status_consumes_shared_skip_keys():
    active_block = {}
    record_active_enrichment_skip(active_block, "bola_idor", "primary_family_budget_exhausted")

    status = build_scan_completion_status(
        coverage_status="complete",
        active_block=active_block,
    )

    assert status["skipped_modules"] == [
        {
            "module": "bola_idor",
            "phase": "active_enrichment",
            "impact": "not_tested",
            "configured": False,
            "reason": "primary_family_budget_exhausted",
        }
    ]
