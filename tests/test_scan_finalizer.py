from __future__ import annotations

import hashlib
import uuid

from api.runtime.observation_manifests import ObservationManifest
from api.scan.action_plan import ScanActionPlan
from api.scan.capability_result import (
    CapabilityResultReason,
    CapabilityResultReference,
    CapabilityResultStatus,
)
from api.scan.finalizer import finalize_scan_report
from tests.test_scan_orchestrator import SCAN_ID, _action, _plan, _result


def _results(plan):
    return {
        action.action_id: _result(action, status=CapabilityResultStatus.SUCCESS)
        for action in plan.actions if action.action_id != "finalize.report"
    }


def _result_with_observation_count(action, count: int) -> CapabilityResultReference:
    content = b"{}\n" * count
    manifest = ObservationManifest(
        manifest_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"finalizer:{action.action_id}:{count}")),
        owner_id=SCAN_ID,
        action_id=action.action_id,
        capability_name=action.capability_name,
        output_schema=action.output_schema,
        observation_count=count,
        content_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        object_key=f"scans/{SCAN_ID}/{action.action_id}.jsonl",
    ).reference()
    base = _result(action, status=CapabilityResultStatus.SUCCESS)
    return CapabilityResultReference(
        **{
            **base.digest_material(),
            "receipt_ref": base.receipt_ref,
            "observation_manifest_ref": manifest,
        }
    )


def test_finalizer_is_a_pure_deterministic_projection_of_receipts():
    plan = _plan()
    results = _results(plan)
    observations = {action.action_id: () for action in plan.actions}

    first = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )
    second = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )

    assert first == second
    assert first["schema_version"] == "canonical-scan-report/v2"
    assert first["coverage"]["status"] == "complete"
    assert first["scan_metadata"]["finalizer"] == "pure_receipt_projection/v1"


def test_finalizer_projects_content_free_runtime_destinations_from_observations():
    baseline = _action("baseline.http", 0, capability_name="http.request")
    final = _action("finalize.report", 1, dependencies=(baseline.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID,
        execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64,
        actions=(baseline, final),
    )
    results = {baseline.action_id: _result_with_observation_count(baseline, 1)}
    observations = {baseline.action_id: ({
        "kind": "http_observation",
        "request": {
            "origin": "https://app.example.test",
            "path": "/reset?token=<redacted>",
            "pinned_address": "192.0.2.10",
        },
        "response": {
            "final_url": "https://app.example.test/account?key=<redacted>",
        },
        "redirect_chain": [{"location": "https://app.example.test/account"}],
    },)}

    report = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )

    assert report["runtime_destinations"] == [{
        "label": "baseline.http:0:0",
        "url": "https://app.example.test",
        "final_url": "https://app.example.test",
        "source": "http.request",
        "resolved_host": "app.example.test",
        "resolved_ips": ["192.0.2.10"],
    }]
    assert "token" not in str(report["runtime_destinations"])


def test_finalizer_promotes_only_deterministic_proof_contracts():
    xss = _action("verify.xss", 0, capability_name="xss.verify")
    sqli = _action(
        "verify.sqli", 1, dependencies=(xss.action_id,), capability_name="sqli.verify",
    )
    final = _action(
        "finalize.report", 2, dependencies=(xss.action_id, sqli.action_id),
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID,
        execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64,
        actions=(xss, sqli, final),
    )
    results = _results(plan)
    results[xss.action_id] = _result_with_observation_count(xss, 2)
    results[sqli.action_id] = _result_with_observation_count(sqli, 1)
    observations = {action.action_id: () for action in plan.actions[:-1]}
    observations[xss.action_id] = (
        {"kind": "xss_alert", "proof_state": "verified", "url": "https://app.example.test/x", "param": "q"},
        {"kind": "xss_alert", "proof_state": "candidate", "url": "https://app.example.test/no"},
    )
    observations[sqli.action_id] = (
        {"kind": "sqli_finding", "url": "https://app.example.test/s", "param": "id"},
    )

    report = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )

    assert len(report["findings"]) == 2
    xss = next(item for item in report["findings"] if item["tool"] == "dalfox")
    sqli = next(item for item in report["findings"] if item["tool"] == "sqlmap")
    assert xss["verified"] is True
    assert sqli["verified"] is False and sqli["suspected"] is True
    assert report["verification_summary"] == {
        "verified": 1, "suspected": 1, "unproven_critical_high": 1,
    }
    assert report["result"] == {
        "score": 80,
        "grade": "B*",
        "grade_reliable": False,
        "score_policy": "verified_and_suspected_severity_weight/v1",
    }
    assert report["coverage"]["grade_reliability"]["reasons"] == [
        "unproven_critical_high"
    ]


def test_finalizer_explains_required_action_degradation():
    plan = _plan()
    results = _results(plan)
    failed_action = plan.actions[0]
    results[failed_action.action_id] = _result(
        failed_action,
        status=CapabilityResultStatus.FAILED,
        reason=CapabilityResultReason.ADAPTER_FAILED,
        charge_full=True,
    )
    observations = {action.action_id: () for action in plan.actions}

    report = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )

    assert report["coverage"]["status"] == "failed"
    assert report["coverage"]["reasons"] == ["adapter_failed"]
    assert report["coverage"]["capability_coverage"] == {
        "total": 2,
        "required": 2,
        "completed": 1,
        "partial": 0,
        "blocked": 0,
        "failed": 1,
        "skipped": 0,
        "cancelled": 0,
        "actions": [
            {
                "action_id": "baseline.http",
                "capability_name": "http.request",
                "required": True,
                "status": "failed",
                "reason_code": "adapter_failed",
            },
            {
                "action_id": "baseline.security_txt",
                "capability_name": "http.request",
                "required": True,
                "status": "success",
                "reason_code": None,
            },
        ],
    }
    assert report["result"]["grade"] == "A*"
    assert report["result"]["grade_reliable"] is False
    assert report["scan_metadata"]["grade_reliability_reasons"] == ["adapter_failed"]
    row = report["canonical_action_execution"]["actions"][0]
    assert row["status"] == "failed"
    assert row["reason_code"] == "adapter_failed"


def test_finalizer_promotes_only_typed_pinned_tls_posture_issues():
    tls = _action("baseline.tls", 0, capability_name="tls.inspect")
    final = _action("finalize.report", 1, dependencies=(tls.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID,
        execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64,
        actions=(tls, final),
    )
    results = _results(plan)
    results[tls.action_id] = _result_with_observation_count(tls, 1)
    observations = {
        tls.action_id: ({
            "kind": "tls_protocol",
            "origin": "https://app.example.test",
            "pinned_address": "192.0.2.10",
            "port": 443,
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_sha256": "c" * 64,
            "certificate_expired": True,
            "certificate_hostname_matches": False,
            "certificate_trust": "untrusted",
        },),
    }

    report = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )

    assert {item["title"] for item in report["findings"]} == {
        "TLS certificate is expired",
        "TLS certificate hostname mismatch",
        "TLS certificate chain is not trusted",
    }
    assert all(item["verified"] is True for item in report["findings"])
    assert report["verification_summary"]["verified"] == 3


def test_finalizer_degrades_when_candidates_receive_zero_active_attempts():
    xss = _action("verify.xss.0", 0, capability_name="xss.verify")
    final = _action("finalize.report", 1, dependencies=(xss.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID,
        execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64,
        actions=(xss, final),
    )
    results = _results(plan)
    report = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=results,
        observations={xss.action_id: ()},
        work_manifest_references=({
            "kind": "candidate",
            "entry_count": 1,
            "status": "complete",
            "manifest_id": str(uuid.uuid4()),
            "manifest_digest": "f" * 64,
        },),
    )

    assert report["coverage"]["status"] == "partial"
    assert report["coverage"]["active_zero_attempt_actions"] == ["verify.xss.0"]
    assert report["coverage"]["grade_reliability"]["reliable"] is False
    assert report["result"]["grade"] == "A*"
