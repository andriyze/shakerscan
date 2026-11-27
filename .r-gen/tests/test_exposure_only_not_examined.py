"""A plan whose families cannot examine the application is never a clean A 100 (soak N46).

N27's fix refuses a policy that excludes every family. The residual: `exclude_families:
[recon, nuclei_passive]` leaves `sensitive_exposure`, so it was admitted, and 5d4387d7 on
shakerscan.com ran 44 seed probes and no discovery and reported A 100, coverage complete, after
19 s. Exposure alone reads a fixed list of well-known locations; it never looks at the
application, so a run of it with nothing found is "not examined", like a target that never
answered, and a run that did find something keeps that grade but not as a reliable, complete
assessment.
"""

from __future__ import annotations

from dataclasses import replace

from api.runtime.observation_manifests import ObservationManifest
from api.scan.action_plan import ScanActionPlan
from api.scan.capability_result import CapabilityResultStatus
from api.scan.finalizer import finalize_scan_report
from tests.test_scan_orchestrator import SCAN_ID, _action, _result

TARGET = "https://app.example.test"
BASELINE_ROWS = ({
    "kind": "http_observation",
    "request": {"origin": TARGET},
    "response": {"status": 200, "final_url": TARGET + "/", "security_headers": {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff", "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
    }},
},)


def _with_rows(result, action, rows, suffix):
    return replace(result, observation_manifest_ref=ObservationManifest(
        manifest_id=f"00000000-0000-4000-8000-0000000000{suffix}", owner_id=SCAN_ID,
        action_id=action.action_id, capability_name=action.capability_name,
        output_schema=action.output_schema, observation_count=len(rows),
        content_sha256="0" * 64, size_bytes=512, object_key=f"scans/{suffix}.jsonl",
    ).reference(), result_digest=None)


def _report(resolved_families, *, exposure_rows=()):
    baseline = _action("baseline.http", 0)
    exposure = replace(
        _action("verify.exposure", 1, capability_name="exposure.verify_batch"),
        capability_args={"slice": {"start": 0, "count": 1}, "manifest_entries": 1},
        output_schema="exposure-probe-batch/v1", action_digest=None,
    )
    final = _action(
        "finalize.report", 2, dependencies=(baseline.action_id, exposure.action_id),
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(baseline, exposure, final),
    )
    exposure_observations = (
        {"kind": "candidate_attempt", "attempt_id": "1" * 64, "candidate_id": "c1",
         "family": "sensitive_exposure", "status": "success", "proof_state": "not_proven"},
        *exposure_rows,
    )
    results = {
        baseline.action_id: _with_rows(
            _result(baseline, status=CapabilityResultStatus.SUCCESS), baseline, BASELINE_ROWS, "b1",
        ),
        exposure.action_id: _with_rows(
            _result(exposure, status=CapabilityResultStatus.SUCCESS), exposure,
            exposure_observations, "e1",
        ),
    }
    return finalize_scan_report(
        plan=plan, target_url=TARGET, action_results=results,
        observations={
            baseline.action_id: BASELINE_ROWS, exposure.action_id: exposure_observations,
        },
        resolved_families=resolved_families,
    )


def test_exposure_only_with_nothing_found_is_not_examined_and_ungraded():
    report = _report(("sensitive_exposure",))
    summary, coverage = report["result"], report["coverage"]
    assert summary["grade"] is None and summary["score"] is None
    assert summary["risk_assessment_state"] == "not_examined"
    assert summary["application_observed"] is False
    assert coverage["status"] == "partial"
    assert "application_surface_not_examined" in coverage["reasons"]
    assert "application_not_observed" in coverage["reasons"]
    assert coverage["grade_reliability"]["reliable"] is False
    assert "application_surface_not_examined" in coverage["grade_reliability"]["reasons"]
    assert "fixed, well-known locations" in coverage["not_examined_reason"]
    assert summary["assurance_score"] == 0


def test_a_plan_that_examines_the_application_is_unaffected():
    for families in (("recon", "sensitive_exposure"), ("nuclei_passive", "sensitive_exposure"), None):
        report = _report(families)
        assert "application_surface_not_examined" not in report["coverage"]["reasons"], families
        assert report["result"]["risk_assessment_state"] != "not_examined", families


def test_the_reason_has_an_operator_label():
    from api.scan.explanation import _REASON_LABELS

    assert _REASON_LABELS["application_surface_not_examined"]
