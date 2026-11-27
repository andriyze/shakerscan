"""Coverage names the paced, bounded probe set on the credential profile's sign-in endpoint.

The batch side is tests/test_auth_endpoint_probe_limit.py; this file reads its records through the
finalizer in the package import layout, as tests/test_slow_endpoint_coverage.py does.
"""
from __future__ import annotations

from dataclasses import replace

from api.scan.auth_endpoint_probe import AUTH_ENDPOINT_PROBE_LIMITED

ORIGIN = "https://app.example.test"
LOGIN = "/hub/login"


def test_coverage_names_the_limited_sign_in_endpoint():
    from api.runtime.observation_manifests import ObservationManifest
    from api.scan.action_plan import ScanActionPlan as PackagePlan
    from api.scan.capability_result import CapabilityResultStatus
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_orchestrator import SCAN_ID, _action as plan_action, _result as settle

    batch = replace(
        plan_action("verify.sqli.r01", 0, capability_name="sqli.verify_batch"),
        capability_args={"slice": {"start": 0, "count": 2}, "manifest_entries": 2},
        output_schema="sqlmap-batch/v1", action_digest=None,
    )
    final = plan_action("finalize.report", 1, dependencies=(batch.action_id,))
    plan = PackagePlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                       target_binding_digest="a" * 64, actions=(batch, final))
    rows = (
        {"kind": "candidate_attempt", "attempt_id": "1" * 64, "candidate_id": "c1", "family": "sqli",
         "status": "success", "proof_state": "unproven", "verdict": "inconclusive",
         "inconclusive_reason": AUTH_ENDPOINT_PROBE_LIMITED, "sign_in_endpoint": LOGIN,
         "sign_in_endpoint_requests": 120},
        {"kind": "candidate_attempt", "attempt_id": "2" * 64, "candidate_id": "c2", "family": "sqli",
         "status": "success", "proof_state": "unproven"},
    )
    result = settle(batch, status=CapabilityResultStatus.SUCCESS)
    result = replace(result, observation_manifest_ref=ObservationManifest(
        manifest_id="00000000-0000-4000-8000-0000000000ad", owner_id=SCAN_ID,
        action_id=batch.action_id, capability_name=batch.capability_name,
        output_schema=batch.output_schema, observation_count=len(rows),
        content_sha256="0" * 64, size_bytes=512, object_key="scans/x.jsonl",
    ).reference(), result_digest=None)
    report = finalize_scan_report(plan=plan, target_url=ORIGIN,
                                  action_results={batch.action_id: result},
                                  observations={batch.action_id: rows})
    coverage = report["coverage"]
    family = next(row for row in coverage["family_coverage"] if row["family"] == "sqli")
    assert family["sign_in_probe_limited"] == {"endpoints": [LOGIN], "candidates": 1}
    assert AUTH_ENDPOINT_PROBE_LIMITED in coverage["reasons"]
    # A candidate the probe set left inconclusive is not a verdict: the family is partial for that
    # reason, and the grade over it is not called reliable.
    assert family["coverage_status"] == "partial"
    assert family["reason"] == AUTH_ENDPOINT_PROBE_LIMITED
    assert "sqli" in coverage["selected_family_gaps"]
    assert coverage["status"] == "partial"
    assert report["scan_metadata"]["grade_reliable"] is False
    assert coverage["grade_reliability"]["reliable"] is False
