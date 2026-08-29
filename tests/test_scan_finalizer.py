from __future__ import annotations

import hashlib
import json
import uuid

from api.runtime.observation_manifests import ObservationManifest
from api.scan.action_plan import ScanActionPlan
from api.scan.capability_result import (
    CapabilityResultReason,
    CapabilityResultReference,
    CapabilityResultStatus,
)
from api.scan.finalizer import finalize_scan_report
from api.scan.continuation import ScanPlanRevision
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
    assert first["canonical_action_execution"]["plan_revision"]["revision"] == 0
    asserted_digest = first["report_digest"]
    digest_material = dict(first)
    digest_material.pop("report_digest")
    assert asserted_digest == hashlib.sha256(json.dumps(
        digest_material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def test_finalizer_digest_binds_complete_plan_revision_chain():
    plan = _plan()
    results = _results(plan)
    observations = {action.action_id: () for action in plan.actions}
    amendment = ScanPlanRevision(
        scan_id=plan.scan_id,
        revision=1,
        plan_digest=plan.plan_digest,
        parent_plan_digest="a" * 64,
        continuation_allocation_digest="b" * 64,
        discovery_result_digest="c" * 64,
        work_manifest_references=({
            "schema_version": "scan-work-manifest-reference/v1",
            "manifest_id": "55555555-5555-4555-8555-555555555555",
            "kind": "candidate",
            "content_schema": "candidate-manifest/v1",
            "manifest_digest": "d" * 64,
            "entry_count": 1,
            "status": "complete",
        },),
        continuation_plan_digest="e" * 64,
    )

    root_report = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )
    amended_report = finalize_scan_report(
        plan=plan,
        plan_revision=amendment,
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )

    assert amended_report["report_digest"] != root_report["report_digest"]
    assert amended_report["canonical_action_execution"]["plan_revision"] == (
        amendment.canonical_dict()
    )


def test_finalizer_projects_server_observed_principal_contexts():
    baseline = _action("baseline.http", 0, capability_name="http.request")
    final = _action("finalize.report", 1, dependencies=(baseline.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(baseline, final),
    )
    results = {baseline.action_id: _result_with_observation_count(baseline, 1)}
    observations = {baseline.action_id: ({
        "kind": "principal_context", "lane": "primary", "authenticated": True,
        "binding_digest": "d" * 64, "source": "server_runtime",
    },)}

    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )

    assert report["smart_coverage"] == {
        "auth_states_tested": ["user1"],
        "principal_contexts_exercised": ["primary"],
        "principal_context_semantics": "server_observed_authenticated_target_traffic",
    }


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


def test_finalizer_projects_pinned_http_header_posture_findings():
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
            "pinned_address": "192.0.2.10",
        },
        "response": {
            "status": 200,
            "selected_headers": {
                "content-security-policy": "default-src 'self'",
                "referrer-policy": "",
                "permissions-policy": "",
                "strict-transport-security": "",
            },
        },
    },)}

    report = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )

    assert {item["title"] for item in report["findings"]} == {
        "Missing Referrer Policy header",
        "Missing Permissions Policy header",
        "Missing HTTP Strict Transport Security header",
    }
    assert all(item["verified"] is True for item in report["findings"])
    assert all(
        item["evidence"]["pinned_address"] == "192.0.2.10"
        for item in report["findings"]
    )


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
    result = report["result"]
    # Two axes. One proven high caps risk at the C band rather than denting a 100 down to a
    # still-passing 90; the suspected critical alongside it is real evidence but does not
    # cap as if it were confirmed.
    assert (result["risk_score"], result["risk_grade"]) == (70, "C")
    assert result["score_policy"] == "risk_and_assurance/v3"
    assert result["grade"] == "C*" and result["grade_reliable"] is False
    assert result["score"] == result["risk_score"], "compatibility alias is the risk axis"
    assert "proven_high:1" in result["score_reasons"]
    # This plan ran two actions over no candidate slices, so almost nothing was examined.
    # The old single number could not say that at all.
    assert result["assurance_score"] < 60
    assert result["assurance_band"] in {"none", "weak", "limited"}
    assert report["coverage"]["grade_reliability"]["reasons"] == [
        "unproven_critical_high"
    ]


def test_finalizer_marks_every_template_candidate_for_verification():
    templates = _action(
        "templates.passive", 0, capability_name="templates.passive_scan",
    )
    final = _action("finalize.report", 1, dependencies=(templates.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID,
        execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64,
        actions=(templates, final),
    )
    results = _results(plan)
    results[templates.action_id] = _result_with_observation_count(templates, 2)
    observations = {
        templates.action_id: (
            {
                "kind": "template_match",
                "template_id": "medium-candidate",
                "name": "Medium template candidate",
                "severity": "medium",
                "matched_at": "https://app.example.test/medium",
            },
            {
                "kind": "template_match",
                "template_id": "info-candidate",
                "name": "Informational template candidate",
                "severity": "info",
                "matched_at": "https://app.example.test/info",
            },
        ),
    }

    report = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )

    assert len(report["findings"]) == 2
    assert all(finding["suspected"] is True for finding in report["findings"])
    assert all(finding["verified"] is False for finding in report["findings"])
    assert all(
        finding["needs_verification"] is True
        for finding in report["findings"]
    )


def test_finalizer_retains_request_verifier_candidates_as_suspected_findings():
    request_xss = _action(
        "verify.request_xss.0", 0, capability_name="xss.request_verify",
    )
    request_sqli = _action(
        "verify.request_sqli.0", 1, dependencies=(request_xss.action_id,),
        capability_name="sqli.request_verify",
    )
    final = _action(
        "finalize.report", 2,
        dependencies=(request_xss.action_id, request_sqli.action_id),
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID,
        execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64,
        actions=(request_xss, request_sqli, final),
    )
    results = _results(plan)
    results[request_xss.action_id] = _result_with_observation_count(
        request_xss, 2,
    )
    results[request_sqli.action_id] = _result_with_observation_count(
        request_sqli, 1,
    )
    observations = {
        request_xss.action_id: (
            {
                "kind": "request_body_verification",
                "family": "xss",
                "candidate_id": "candidate-xss",
                "request_ref_id": "request-xss",
                "method": "POST",
                "origin": "https://app.example.test",
                "resolved_ips": ["192.0.2.10"],
                "field_path": "comment",
                "proof_contract": "xss_reflection_differential/v1",
                "proof_status": "reflected_candidate_only",
                "finding_verdict": "suspected",
            },
            {
                "kind": "request_body_verification",
                "family": "xss",
                "candidate_id": "safe-control",
                "proof_status": "not_proven",
                "finding_verdict": "not_proven",
            },
        ),
        request_sqli.action_id: ({
            "kind": "request_body_verification",
            "family": "sqli",
            "candidate_id": "candidate-sqli",
            "request_ref_id": "request-sqli",
            "method": "POST",
            "origin": "https://app.example.test",
            "resolved_ips": ["192.0.2.10"],
            "field_path": "id",
            "proof_contract": "sqli_error_differential/v1",
            "proof_status": "db_error_candidate_only",
            "finding_verdict": "suspected",
        },),
    }

    report = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )

    assert len(report["findings"]) == 2
    by_tool = {item["tool"]: item for item in report["findings"]}
    assert set(by_tool) == {
        "request_xss_differential", "request_sqli_differential",
    }
    assert report["runtime_destinations"] == [{
        "label": "verify.request_xss.0:0:0",
        "url": "https://app.example.test",
        "final_url": "https://app.example.test",
        "source": "xss.request_verify",
        "resolved_host": "app.example.test",
        "resolved_ips": ["192.0.2.10"],
    }, {
        "label": "verify.request_sqli.0:0:0",
        "url": "https://app.example.test",
        "final_url": "https://app.example.test",
        "source": "sqli.request_verify",
        "resolved_host": "app.example.test",
        "resolved_ips": ["192.0.2.10"],
    }]
    assert all(item["suspected"] is True for item in by_tool.values())
    assert all(item["verified"] is False for item in by_tool.values())
    assert by_tool["request_xss_differential"]["evidence"][
        "canonical_capability"
    ] == "xss.request_verify"
    assert by_tool["request_sqli_differential"]["evidence"][
        "canonical_capability"
    ] == "sqli.request_verify"


def test_finalizer_promotes_only_repeated_deterministic_sqli_proof():
    prove = _action(
        "prove.sqli.0", 0, capability_name="sqli.prove_batch",
    )
    final = _action("finalize.report", 1, dependencies=(prove.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID,
        execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64,
        actions=(prove, final),
    )
    results = {prove.action_id: _result_with_observation_count(prove, 1)}
    observations = {prove.action_id: ({
        "kind": "sqli_proof",
        "candidate_id": "candidate-sqli",
        "request_ref_id": "request-sqli",
        "method": "POST",
        "field_path": "email",
        "request_class": "safe_authentication",
        "proof_state": "verified",
        "finding_verdict": "verified",
        "proof_contract": "sqli_authentication_bypass/v1",
        "technique": "authentication_bypass_repeated",
        "repetitions": 2,
        "response_pairs": [{
            "control_response_sha256": "c" * 64,
            "payload_response_sha256": "d" * 64,
        }],
        "session_state_discarded": True,
    },)}

    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )

    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["tool"] == "shakerscan_sqli_proof"
    assert finding["severity"] == "critical"
    assert finding["verified"] is True
    assert finding["evidence"]["canonical_capability"] == "sqli.prove_batch"


def test_finalizer_promotes_only_structured_canonical_browser_xss_proof():
    prove = _action(
        "prove.xss", 0, capability_name="xss.browser_prove_batch",
    )
    final = _action("finalize.report", 1, dependencies=(prove.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(prove, final),
    )
    results = {prove.action_id: _result_with_observation_count(prove, 1)}
    observations = {prove.action_id: ({
        "kind": "xss_browser_proof", "candidate_id": "candidate-xss",
        "parameter_name": "q", "proof_state": "verified",
        "finding_verdict": "verified", "proof_producer": "shakerscan",
        "evidence_type": "dom_execution", "technique": "headless_xss_dom",
        "payload_sha256": "c" * 64, "marker_sha256": "d" * 64,
        "event_transcript": [{"signal": "console", "marker_match": True}],
        "dom_marker_executed": True,
        "sanitized_screenshot_sha256": "e" * 64,
        "browser_build": "Chromium test",
    },)}
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )
    finding = report["findings"][0]
    assert finding["tool"] == "shakerscan_browser_proof"
    assert finding["verified"] is True
    assert finding["evidence"]["proof_producer"] == "shakerscan"
    assert finding["evidence"]["sanitized_screenshot_sha256"] == "e" * 64


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


def test_anonymous_equals_authenticated_is_not_a_verified_authorization_break():
    """The differential proves the endpoint is public, not that a control broke.

    On a privileged function, identical anonymous and authenticated responses
    are broken access control. On a public one -- a product search, a list of
    security questions -- they are the intended behaviour, and nothing in the
    differential distinguishes the two. Claiming a verified break marked eight
    ordinary public endpoints of one application as high-severity findings.
    """
    import pathlib

    source = (
        pathlib.Path(__file__).resolve().parent.parent
        / "api" / "scan" / "finalizer.py"
    ).read_text(encoding="utf-8")
    block = source[source.index('kind == "authz_surface_proof"'):]
    block = block[:block.index('kind == "authz_differential"')]

    assert '"Verified broken function-level authorization"' not in block
    assert '"verified": False' in block
    assert '"suspected": True' in block
    assert '"needs_verification": True' in block
    assert '"severity="high"' not in block
