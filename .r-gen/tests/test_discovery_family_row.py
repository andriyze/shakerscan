"""A selected discovery family has a row in the family coverage.

``recon`` is a family an operator selects and the Scan shows as selected, but the family
coverage listed only the check families with a verifier, so the selected set and the coverage
rows disagreed and nothing said whether discovery itself settled. The row is built from the
plan's discovery actions by the rules the Scan's own coverage already applies to them.

It is not a check family: it adds no selected-family gap (the discovery reasons carry that) and
earns no family credit in the assurance score.

Package import layout, like tests/test_selected_family_without_work.py.
"""
from __future__ import annotations

from dataclasses import replace


def _report(outcomes: dict | None = None, *, resolved_families=("recon",), with_discovery=True):
    """A plan of a required probe, an optional crawl and an optional spec read."""
    from api.scan.action_plan import ScanActionPlan
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_orchestrator import SCAN_ID, _action as plan_action, _result as settle

    baseline = plan_action("baseline.http", 0)
    discovery = [
        replace(
            plan_action(action_id, ordinal, capability_name=capability),
            capability_args={}, required=required, action_digest=None,
        )
        for ordinal, (action_id, capability, required) in enumerate((
            ("discover.web_probe", "web.probe", True),
            ("discover.crawl", "web.crawl", False),
            ("discover.spec", "web.spec_ingest", False),
        ), start=1)
    ] if with_discovery else []
    actions = (baseline, *discovery)
    final = plan_action(
        "finalize.report", len(actions), dependencies=tuple(item.action_id for item in actions),
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(*actions, final),
    )
    settled = {
        # A target that publishes no API description: the spec read has nothing to read.
        "discover.spec": {
            "status": CapabilityResultStatus.PARTIAL,
            "reason": CapabilityResultReason.SOURCE_NOT_PUBLISHED,
        },
        **(outcomes or {}),
    }
    results = {
        action.action_id: settle(
            action, **settled.get(action.action_id, {"status": CapabilityResultStatus.SUCCESS}),
        )
        for action in actions
    }
    return finalize_scan_report(
        plan=plan, target_url="https://app.example.test", action_results=results,
        observations={}, resolved_families=resolved_families,
    )


def _rows(report):
    return {row["family"]: row for row in report["coverage"]["family_coverage"]}


def test_a_selected_discovery_family_reports_whether_discovery_settled():
    report = _report()
    row = _rows(report)["recon"]

    assert (row["selected"], row["required"]) == (True, True)
    assert (row["coverage_status"], row["reason"]) == ("complete", None)
    assert row["batch_actions"] == 3
    # A spec read with nothing published to read is not a discovery gap, here as for the Scan.
    assert row["action_statuses"] == {"partial": 1, "success": 2}
    assert report["coverage"]["truncated_discovery_actions"] == []
    # Discovery has no candidates and no verifier.
    assert row["planned_candidates"] == row["attempted_candidates"] == 0
    assert "proof_escalation" not in row
    assert row["budget_reserved"]["http_requests"] == 3


def test_discovery_cut_short_makes_its_row_partial_without_a_second_gap():
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus

    report = _report({"discover.crawl": {
        "status": CapabilityResultStatus.PARTIAL, "reason": CapabilityResultReason.OUTPUT_TRUNCATED,
    }})
    coverage = report["coverage"]
    row = _rows(report)["recon"]

    assert (row["coverage_status"], row["reason"]) == ("partial", "discovery_truncated")
    assert coverage["truncated_discovery_actions"] == ["discover.crawl"]
    # The Scan already says so; the row adds no selected-family gap on top.
    assert "discovery_truncated" in coverage["grade_reliability"]["reasons"]
    assert "recon" not in coverage["selected_family_gaps"]
    assert "selected_family_incomplete" not in coverage["grade_reliability"]["reasons"]


def test_a_required_discovery_action_that_fell_short_names_its_reason():
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus

    report = _report({"discover.web_probe": {
        "status": CapabilityResultStatus.TIMED_OUT, "reason": CapabilityResultReason.TIMED_OUT,
    }})
    row = _rows(report)["recon"]

    assert (row["coverage_status"], row["reason"]) == ("partial", "timed_out")
    assert "recon" not in report["coverage"]["selected_family_gaps"]


def test_no_row_without_the_selection_or_without_a_discovery_action():
    # A caller without the execution plan (the offline report rebuild): its digest must not move.
    assert "recon" not in _rows(_report(resolved_families=None))
    assert "recon" not in _rows(_report(resolved_families=("sensitive_exposure",)))
    # A plan that runs no discovery action (an endpoint shard) has nothing to report.
    assert "recon" not in _rows(_report(with_discovery=False))


def test_the_discovery_row_earns_no_family_credit_in_the_assurance_score():
    from api.scan import scoring

    check = {
        "family": "sqli", "selected": True, "required": True, "coverage_status": "complete",
        "planned_candidates": 2, "attempted_candidates": 2, "verified_findings": 0,
    }
    discovery = {
        "family": "recon", "selected": True, "required": True, "coverage_status": "partial",
        "reason": "discovery_truncated", "planned_candidates": 0, "attempted_candidates": 0,
        "verified_findings": 0,
    }
    base = {
        "status": "partial", "planned_action_count": 4, "terminal_action_count": 4,
        "grade_reliability": {"reliable": False, "reasons": ["discovery_truncated"]},
    }
    without = scoring.assurance({**base, "family_coverage": [check]})
    with_row = scoring.assurance({**base, "family_coverage": [check, discovery]})

    assert with_row == without
    assert without["components"]["selected_families_complete"]["value"] == 1.0


def test_the_parallel_summary_does_not_list_discovery_as_a_selected_family_gap():
    from api.scan.parallel_compiler import summarize_parallel_action_coverage

    summary = summarize_parallel_action_coverage({
        "actions": [{"action_id": "discover.web_probe", "status": "success", "required": True}],
        "family_coverage": [
            {"family": "recon", "selected": True, "required": True, "coverage_status": "partial",
             "reason": "discovery_truncated"},
            {"family": "sqli", "selected": True, "required": True, "coverage_status": "partial",
             "reason": "candidates_unattempted"},
        ],
    })

    assert summary["selected_family_gaps"] == ["sqli"]
    assert [row["family"] for row in summary["family_coverage"]] == ["recon", "sqli"]
