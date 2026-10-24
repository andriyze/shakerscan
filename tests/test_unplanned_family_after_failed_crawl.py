"""A family with no candidates because no crawl ran is a gap, not "no candidates".

Both crawls of a Scan failed before they started, so the endpoint manifest held only the seeds
and content discovery, and the candidate manifest was empty. The continuation (correctly)
planned no XSS, SQLi or NoSQLi verifier, and the unplanned families then read
``complete / no_candidates`` with a reliable grade: nothing was tested and nothing showed the
surface had nothing to test.

Unit fixtures: the real admission and continuation compilers over a synthetic target, with
synthetic receipts; no live Scan.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from api.scan.capability_result import CapabilityResultReason as Reason
from api.scan.capability_result import CapabilityResultStatus as Status
from tests.test_selected_family_without_work import HONEY_SURFACE, _first_round

FAMILIES = ["recon", "nuclei_passive", "xss", "sqli", "sensitive_exposure", "nosqli"]
EMPTY_PARTIAL_CANDIDATES = {
    "kind": "candidate", "status": "partial", "entry_count": 0,
    "manifest_id": "0" * 8 + "-0000-5000-8000-" + "0" * 12,
    "manifest_digest": "d" * 64, "content_schema": "candidate-manifest/v1",
    "schema_version": "scan-work-manifest-reference/v1",
}


def _finalized(crawl_outcomes):
    import hashlib

    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import _result

    parent, final_round, fixture = _first_round(HONEY_SURFACE, include_finalizer=True)
    results = dict(fixture["parent_results"])
    for action in parent.actions:
        if action.capability_name in crawl_outcomes:
            status, reason = crawl_outcomes[action.capability_name]
            results[action.action_id] = replace(
                _result(action, status=status, reason=reason, charge_full=True), result_digest=None,
            )
    observations = {}
    for action in final_round.plan.actions[len(parent.actions):]:
        if action.action_id == "finalize.report":
            continue
        count = min(
            int(action.capability_args["slice"]["count"]),
            int(action.capability_args.get("manifest_entries", 10**6)),
        )
        observations[action.action_id] = tuple({
            "kind": "candidate_attempt", "status": "success",
            "attempt_id": hashlib.sha256(f"{action.action_id}:{index}".encode()).hexdigest(),
        } for index in range(count))
        results[action.action_id] = _result_with_observation_count(action, count)
    return finalize_scan_report(
        plan=final_round.plan, plan_revision=final_round.revision,
        target_url="https://app.example.test",
        action_results=results, observations=observations,
        resolved_families=FAMILIES,
        work_manifest_references=(EMPTY_PARTIAL_CANDIDATES,),
    )


def _row(report, family):
    return next(row for row in report["coverage"]["family_coverage"] if row["family"] == family)


BOTH_FAILED = {
    "web.crawl": (Status.FAILED, Reason.ADAPTER_FAILED),
    "web.browser_crawl": (Status.FAILED, Reason.ADAPTER_FAILED),
}


def test_an_empty_candidate_manifest_after_both_crawls_failed_is_a_family_gap():
    report = _finalized(BOTH_FAILED)
    coverage = report["coverage"]
    for family in ("xss", "sqli", "nosqli"):
        row = _row(report, family)
        assert (row["coverage_status"], row["reason"]) == ("partial", "discovery_failed"), family
        assert family in coverage["selected_family_gaps"]
    # The fixture's static crawl is required (no seeded endpoint manifest), so the Scan fails;
    # with an optional one it is partial. Either way it is not complete, and the grade says why.
    assert coverage["status"] in {"partial", "failed"}
    assert "selected_family_incomplete" in coverage["grade_reliability"]["reasons"]
    assert report["result"]["grade_reliable"] is False


@pytest.mark.parametrize("outcome", [
    (Status.BLOCKED, Reason.POLICY_DISABLED),
    (Status.SKIPPED, Reason.DEPENDENCY_FAILED),
    (Status.CANCELLED, Reason.CANCELLED),
], ids=lambda item: item[0].value)
def test_no_crawl_that_ran_is_the_same_gap_however_it_was_stopped(outcome):
    report = _finalized({"web.crawl": outcome, "web.browser_crawl": outcome})
    assert _row(report, "xss")["reason"] == "discovery_failed"


def test_one_crawl_that_ran_still_shows_there_was_nothing_to_test():
    """A target without a browser runtime: the static crawl ran and found no parameter."""
    report = _finalized({"web.browser_crawl": (Status.FAILED, Reason.ADAPTER_FAILED)})
    for family in ("xss", "sqli", "nosqli"):
        row = _row(report, family)
        assert (row["coverage_status"], row["reason"]) == ("complete", "no_candidates"), family


@pytest.mark.parametrize("outcome", [
    (Status.PARTIAL, Reason.OUTPUT_TRUNCATED),
    (Status.TIMED_OUT, Reason.TIMED_OUT),
], ids=lambda item: item[0].value)
def test_crawls_cut_short_still_examined_the_surface(outcome):
    """A crawl stopped by its own bound ran; the Scan states the truncation, not this family."""
    report = _finalized({"web.crawl": outcome, "web.browser_crawl": outcome})
    assert (_row(report, "xss")["coverage_status"], _row(report, "xss")["reason"]) == (
        "complete", "no_candidates",
    )


def test_crawls_that_ran_keep_the_no_candidates_outcome():
    report = _finalized({})
    assert (_row(report, "xss")["coverage_status"], _row(report, "xss")["reason"]) == (
        "complete", "no_candidates",
    )


def _minimal(crawl_status=None):
    """A Scan of two actions besides the report: a companion family that did its work and, when
    ``crawl_status`` is given, one optional crawl that settled so. XSS is selected and unplanned."""
    from tests.test_honest_family_coverage_sweep import _companion_that_worked, _finalize
    from tests.test_scan_orchestrator import _action as plain_action
    from tests.test_scan_orchestrator import _result

    passive, passive_result, passive_rows = _companion_that_worked("xss")
    actions, results = [passive], {passive.action_id: passive_result}
    if crawl_status is not None:
        crawl = replace(
            plain_action("discover.web_crawl", 1, capability_name="web.crawl"),
            required=False, action_digest=None,
        )
        actions.append(crawl)
        results[crawl.action_id] = _result(crawl, status=crawl_status[0], reason=crawl_status[1])
    _report, row = _finalize(
        tuple(actions), results, {passive.action_id: passive_rows}, "xss",
        work_manifests=(EMPTY_PARTIAL_CANDIDATES,),
    )
    return row


def test_a_plan_without_a_crawl_keeps_no_candidates():
    """A Scan that planned no crawl at all (its surface came from elsewhere: a collection, a
    spec, the declared endpoints) is not a failed discovery."""
    row = _minimal()
    assert (row["coverage_status"], row["reason"]) == ("complete", "no_candidates")
    # The same Scan with a crawl that failed is the gap.
    row = _minimal((Status.FAILED, Reason.ADAPTER_FAILED))
    assert (row["coverage_status"], row["reason"]) == ("partial", "discovery_failed")
