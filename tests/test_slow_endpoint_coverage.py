"""Coverage names the endpoints a passive batch could not finish, not a generic timeout (N32).

The batch side is tests/test_passive_batch_slow_endpoints_measured.py; this file reads its
`slow_endpoints` receipt through the finalizer, in the package import layout.
"""

from __future__ import annotations

from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus


def test_coverage_says_partial_because_of_the_named_slow_endpoints():
    from dataclasses import replace

    from api.runtime.observation_manifests import ObservationManifest
    from api.scan.action_plan import ScanActionPlan
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_orchestrator import SCAN_ID, _action as plan_action, _result as settle

    batch = replace(
        plan_action("passive.templates.r01", 0, capability_name="templates.passive_batch"),
        capability_args={"slice": {"start": 0, "count": 2}, "manifest_entries": 2},
        output_schema="nuclei-batch/v1", action_digest=None,
    )
    final = plan_action("finalize.report", 1, dependencies=(batch.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(batch, final),
    )
    rows = (
        {"kind": "candidate_attempt", "attempt_id": "1" * 64, "candidate_id": "c1", "status": "success"},
        {"kind": "candidate_attempt", "attempt_id": "2" * 64, "candidate_id": "c2", "status": "partial"},
        {
            "kind": "template_slow_endpoint", "candidate_id": "c2",
            "url": "https://app.example.test/api/v1/chat",
            "first_attempt_wall_seconds": 12, "retry_wall_seconds": 24,
        },
    )
    result = settle(
        batch, status=CapabilityResultStatus.PARTIAL,
        reason=CapabilityResultReason.SLOW_ENDPOINTS,
    )
    result = replace(result, observation_manifest_ref=ObservationManifest(
        manifest_id="00000000-0000-4000-8000-0000000000aa", owner_id=SCAN_ID,
        action_id=batch.action_id, capability_name=batch.capability_name,
        output_schema=batch.output_schema, observation_count=len(rows),
        content_sha256="0" * 64, size_bytes=512, object_key="scans/x.jsonl",
    ).reference(), result_digest=None)
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results={batch.action_id: result}, observations={batch.action_id: rows},
    )
    coverage = report["coverage"]
    family = next(row for row in coverage["family_coverage"] if row["family"] == "nuclei_passive")
    assert family["coverage_status"] == "partial"
    assert family["reason"] == "slow_endpoints"
    assert family["slow_endpoint_count"] == 1
    assert family["slow_endpoints"] == ["https://app.example.test/api/v1/chat"]
    assert "slow_endpoints" in coverage["reasons"]
    assert "timed_out" not in coverage["reasons"]
