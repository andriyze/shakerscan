"""A slice an extension finished does not keep its own timeout in the coverage reasons (N35).

Balanced honey scans b723d50d and 47449681: the first SQLi slice timed out and its
verification extension in the next round reached the verdict, so the finalizer (which reads a
superseded slice through its newest extension) had every family complete. The worker's
roll-up over the raw action rows still added `sqli_verify_batch_timed_out:timed_out` and
turned the scan's coverage partial.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from api.scan.coverage_rollup import action_coverage_reasons, apply_action_coverage

ROWS = [
    {"action_id": "verify.sqli", "capability_name": "sqli.verify_batch", "status": "timed_out",
     "required": True, "reason_code": "timed_out"},
    {"action_id": "verify.sqli.ext.r01", "capability_name": "sqli.verify_batch",
     "status": "success", "required": True, "reason_code": None},
]


def test_a_superseded_slice_adds_no_coverage_reason():
    coverage = {"status": "complete", "reasons": [], "superseded_action_ids": ["verify.sqli"]}
    assert apply_action_coverage(coverage, ROWS) == coverage
    assert action_coverage_reasons(ROWS, superseded=["verify.sqli"]) == []


def test_an_unsuperseded_shortfall_still_makes_coverage_partial():
    coverage = apply_action_coverage({"status": "complete", "reasons": []}, ROWS)
    assert coverage["status"] == "partial"
    assert coverage["reasons"] == ["sqli_verify_batch_timed_out:timed_out"]
    # An extension that itself fell short is still reported.
    failed_extension = [ROWS[0], {**ROWS[1], "status": "partial", "reason_code": "timed_out"}]
    still = apply_action_coverage(
        {"status": "complete", "reasons": [], "superseded_action_ids": ["verify.sqli"]},
        failed_extension,
    )
    assert still["status"] == "partial"
    assert still["reasons"] == ["sqli_verify_batch_partial:timed_out"]


def test_the_finalizer_names_the_slices_an_extension_superseded():
    from api.scan.action_plan import ScanActionPlan
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from api.scan.finalizer import finalize_scan_report
    from api.scan.verification_extension import EXTENDS_ARG
    from tests.test_scan_orchestrator import SCAN_ID, _action, _result

    slice_action = _action("baseline.http", 0)
    extension = replace(
        _action("baseline.http.ext", 1),
        capability_args={"method": "GET", EXTENDS_ARG: slice_action.action_id},
        action_digest=None,
    )
    final = _action(
        "finalize.report", 2, dependencies=(slice_action.action_id, extension.action_id),
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(slice_action, extension, final),
    )
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results={
            slice_action.action_id: _result(
                slice_action, status=CapabilityResultStatus.TIMED_OUT,
                reason=CapabilityResultReason.TIMED_OUT,
            ),
            extension.action_id: _result(extension, status=CapabilityResultStatus.SUCCESS),
        },
        observations={},
    )
    assert report["coverage"]["superseded_action_ids"] == [slice_action.action_id]


def test_the_worker_reads_the_action_id_it_matches_on():
    source = Path(__file__).resolve().parents[1].joinpath("api", "worker.py").read_text()
    assert '"SELECT action_id, capability_name, status, required, reason_code "' in source
