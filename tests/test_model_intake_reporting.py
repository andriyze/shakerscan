from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_reporting import (  # noqa: E402
    SHAKERSCAN_CHECK_CATALOG,
    CONTROL_STATUSES,
    apply_automatic_review_context,
    build_model_intake_report,
    model_intake_report_to_sarif,
    render_model_intake_html,
)


def test_authoritative_catalog_names_every_promised_model_intake_check():
    names = [item["check"] for item in SHAKERSCAN_CHECK_CATALOG]
    assert names == [
        "Source resolution and revision pinning", "Complete acquisition", "SHA-256 integrity",
        "Repository completeness", "Format identification", "Safetensors validation",
        "Pickle analysis", "Archive safety", "ModelScan", "Fickling", "Semgrep", "Trivy",
        "Inference dependency resolution", "OSV Scanner", "pip-audit",
        "Native Python AST analysis", "Dependency inventory", "SBOM and AIBOM generation",
        "License and governance metadata", "Signature and attestation verification",
        "Unsafe-format conversion", "Conversion equivalence", "Isolated model loading",
        "Warmup and inference", "Known-answer repeatability", "Network monitoring",
        "Resource enforcement", "Evidence integrity", "Deterministic policy decision",
        "Corporate-approval gap analysis",
    ]


NOW = datetime(2026, 7, 30, tzinfo=timezone.utc)
DIGESTS = {key: key * 64 for key in "abcdef"}


def _rows(*, artifact_uri: str = "hf://example/model/model.safetensors", active_admission: bool = True):
    submission_id = "11111111-1111-4111-8111-111111111111"
    manifest_sha = DIGESTS["d"]
    decision_sha = DIGESTS["e"]
    bundle_sha = DIGESTS["f"]
    evidence = []
    for index, evidence_type in enumerate((
        "static_analysis", "runtime_execution", "embedding_evaluation", "data_plane_evaluation",
    )):
        record = {
            "id": f"evidence-{index}",
            "evidence_type": evidence_type,
            "status": "PASS",
            "provenance_class": "GENERATED",
            "producer_id": f"producer-{index}",
            "builder_id": "builder://trusted",
            "payload_sha256": DIGESTS["c"],
            "subject_bindings": {"artifact": DIGESTS["a"]},
            "expires_at": NOW + timedelta(days=30),
        }
        if evidence_type == "static_analysis":
            record["payload_json"] = {
                "required_static_checks": {
                    "acquisition_complete": True,
                    "inspection_complete": True,
                    "repository_manifest_complete": True,
                },
                "checks": {"unsafe_serialization": True, "custom_code_review": True},
                "scanner_results": [{
                    "name": "semgrep",
                    "version": "1.172.0",
                    "status": "PASS",
                    "required": True,
                    "applicability": "repository_code",
                    "finding_count": 0,
                    "findings": [],
                    "coverage": {"files_scanned": 3},
                }],
                "license_compliance": {
                    "outcome": "NO LEGAL BLOCKER DETECTED",
                    "policy_status": "PASS",
                    "policy_version": "shakerscan-corporate-license-policy/1",
                    "legal_review_required": False,
                    "classification_counts": {"permissive": 2},
                    "reason_codes": [],
                    "evidence_sha256": DIGESTS["f"],
                },
            }
        evidence.append(record)
    phases = {
        name: {"status": "PASS", "duration_ms": index + 1}
        for index, name in enumerate(("import", "tokenizer", "model_load", "warmup", "inference", "teardown"))
    }
    runner_jobs = [{
        "id": "runner-1",
        "operation": "runtime",
        "state": "completed",
        "request_sha256": DIGESTS["b"],
        "result_json": {
            "payload": {
                "observations": {
                    "phases": phases,
                    "network_telemetry": {
                        "complete": True,
                        "attempt_count": 0,
                        "attempted_operations": [],
                        "attempts_by_phase": {},
                        "overflowed": False,
                        "lost_events": 0,
                        "guest_interfaces": ["lo"],
                        "host_interfaces": ["lo"],
                        "host_firewall_drop_count": 0,
                        "telemetry_sha256": DIGESTS["a"],
                    },
                    "resource_telemetry": {"complete": True, "limits_sha256": DIGESTS["b"]},
                },
            },
        },
    }]
    approvals = [{
        "id": f"approval-{index}",
        "decision": "approve",
        "approved_by_role": role,
        "approval_type": role,
        "approved_by_subject": f"operator:reviewer-{index}",
        "evidence_manifest_id": "manifest-1",
        "expires_at": NOW + timedelta(days=7),
    } for index, role in enumerate(("model_security_reviewer", "ml_platform_reviewer", "release_manager"))]
    admissions = []
    if active_admission:
        admissions.append({
            "id": "admission-1",
            "status": "active",
            "decision": "allow",
            "statement_sha256": DIGESTS["a"],
            "deployment_bundle_sha256": bundle_sha,
            "evidence_manifest_sha256": manifest_sha,
            "policy_decision_sha256": decision_sha,
            "expires_at": NOW + timedelta(days=2),
            "admission_package": {
                "statement": {
                    "predicate": {
                        "decision": "allow",
                        "deployment_bundle": {"bundle_sha256": bundle_sha},
                        "evidence_manifest_sha256": manifest_sha,
                        "policy_decision_sha256": decision_sha,
                    },
                },
            },
        })
    return {
        "submission": {
            "id": submission_id,
            "state": "admitted" if active_admission else "evidence_ready",
            "requested_environment": "production",
            "source_kind": "huggingface",
            "source_reference_hash": DIGESTS["a"],
            "created_at": NOW - timedelta(days=1),
            "updated_at": NOW,
        },
        "subjects": [
            {"id": "subject-artifact", "subject_kind": "artifact", "sha256": DIGESTS["a"], "immutable_uri": artifact_uri, "size_bytes": 100},
            {"id": "subject-repository", "subject_kind": "repository_snapshot", "sha256": DIGESTS["b"], "immutable_uri": "hf://example/model@revision"},
        ],
        "evidence": evidence,
        "manifests": [{"id": "manifest-1", "manifest_sha256": manifest_sha}],
        "approvals": approvals,
        "policy_decisions": [{"id": "decision-1", "evidence_manifest_id": "manifest-1", "decision": "allow", "decision_sha256": decision_sha}],
        "admissions": admissions,
        "events": [],
        "runner_jobs": runner_jobs,
        "agent_sessions": [],
    }


def _report(rows, *, generated_at=NOW):
    verification = (
        {"verified": True, "status": "PASS", "blockers": [], "trusted_key_fingerprints": [DIGESTS["a"]]}
        if rows["admissions"] else None
    )
    return build_model_intake_report(**rows, admission_verification=verification, generated_at=generated_at)


def _control(report, control_id):
    return next(item for item in report["controls"] if item["id"] == control_id)


def test_complete_exact_subject_report_allows_only_with_matching_active_admission():
    report = _report(_rows())

    assert report["outcome"] == "ALLOW"
    assert report["schema_version"] == "model-intake-corporate-report/v2"
    assert set(report["control_counts"]) == CONTROL_STATUSES
    assert report["executive_summary"]["deployable_under_configured_shakerscan_policy"] is True
    assert report["executive_summary"]["full_corporate_approval"] == "NOT_DETERMINED_BY_SHAKERSCAN"
    assert report["executive_summary"]["license_outcome"] == "NO LEGAL BLOCKER DETECTED"
    assert report["executive_summary"]["coverage"]["external_corporate_requirements"] >= 10
    assert report["presentation"]["headline"] == "Configured checks passed"
    assert report["presentation"]["counts"]["needs_attention"] == 0
    assert report["presentation"]["counts"]["deployment_follow_up"] == 4
    assert report["detailed_review"]["static_analysis_detail"]["scanner_results"][0]["name"] == "semgrep"
    catalog = report["detailed_review"]["shakerscan_check_catalog"]
    assert len(catalog) == 30
    assert all(item.get("execution_status") in {
        "PASS", "FAIL", "REVIEW", "INCOMPLETE", "ERROR", "NOT_RUN", "NOT_APPLICABLE",
    } for item in catalog)
    assert all(item.get("result_summary") for item in catalog)
    assert next(item for item in catalog if item["check"] == "Semgrep")["evidence_basis"] == "scanner_result"
    assert len(report["detailed_review"]["external_approval_requirements"]) >= 10
    assert _control(report, "firecracker_runtime")["status"] == "PASS"
    assert _control(report, "network_isolation")["status"] == "PASS"
    assert "No outbound or DNS connection attempt" in _control(report, "network_isolation")["detail"]
    assert _control(report, "conversion_equivalence")["status"] == "NOT_APPLICABLE"
    assert all(report["authority_bindings"]["admission_statement_parity"].values())


def test_license_review_is_prominent_and_requires_legal_reviewer_disposition():
    rows = _rows()
    static = next(item for item in rows["evidence"] if item["evidence_type"] == "static_analysis")
    static["payload_json"]["license_compliance"] = {
        "outcome": "LEGAL REVIEW REQUIRED",
        "policy_status": "REVIEW_REQUIRED",
        "policy_version": "shakerscan-corporate-license-policy/1",
        "legal_review_required": True,
        "classification_counts": {"reciprocal": 1},
        "reason_codes": ["reciprocal_terms"],
        "evidence_sha256": DIGESTS["f"],
    }

    pending = _report(rows)
    assert pending["outcome"] == "REVIEW"
    assert pending["executive_summary"]["legal_review_required"] is True
    assert pending["executive_summary"]["legal_disposition"] == "PENDING"
    assert _control(pending, "license_compliance")["status"] == "REVIEW"

    rows["approvals"].append({
        "id": "approval-legal",
        "decision": "approve",
        "approved_by_role": "legal_reviewer",
        "approval_type": "legal_reviewer",
        "approved_by_subject": "operator:legal-reviewer",
        "evidence_manifest_id": "manifest-1",
        "expires_at": NOW + timedelta(days=7),
    })
    approved = _report(rows)
    assert approved["outcome"] == "ALLOW"
    assert approved["executive_summary"]["legal_review_required"] is False
    assert approved["executive_summary"]["legal_disposition"] == "APPROVED"
    assert _control(approved, "license_compliance")["status"] == "PASS"


def test_missing_license_source_text_is_a_review_item_even_when_terms_pass_policy():
    rows = _rows()
    static = next(item for item in rows["evidence"] if item["evidence_type"] == "static_analysis")
    static["payload_json"]["license_compliance"] = {
        "policy_status": "PASS",
        "terms": [{"declared": "mit"}],
    }
    static["payload_json"]["scanner_results"].append({
        "name": "shakerscan-license-inventory",
        "status": "WARNING",
        "findings": [{"id": "license_file_missing"}],
    })

    report = _report(rows)
    control = _control(report, "license_compliance")

    assert control["status"] == "REVIEW"
    assert "authoritative license or NOTICE source text" in control["detail"]
    assert "preserve it with the pinned revision" in control["remediation"]
    assert "license/NOTICE source file is missing" not in _control(report, "static_analysis")["detail"]


def test_missing_runtime_and_required_conversion_are_plainly_incomplete():
    rows = _rows(artifact_uri="hf://example/model/pytorch_model.bin", active_admission=False)
    rows["runner_jobs"] = []
    rows["evidence"] = [item for item in rows["evidence"] if item["evidence_type"] != "runtime_execution"]
    report = _report(rows)

    assert report["outcome"] == "INCOMPLETE"
    assert _control(report, "runtime_execution")["status"] == "NOT_RUN"
    assert _control(report, "firecracker_runtime")["status"] == "NOT_RUN"
    assert _control(report, "conversion_equivalence")["status"] == "NOT_RUN"
    assert "firecracker_runtime" in report["assessment_scope"]["checks_not_completed"]


def test_automatic_report_explains_static_only_unsupported_runtime_profile():
    rows = _rows(artifact_uri="hf://example/model/model.gguf", active_admission=False)
    rows["runner_jobs"] = []
    report = apply_automatic_review_context(
        _report(rows),
        {
            "id": "review-1",
            "state": "attention_required",
            "current_step": "runtime_profile_unavailable",
            "progress": 100,
            "technical_outcome": "INCOMPLETE",
            "pending_controls": [{
                "control": "isolated_runtime",
                "status": "UNSUPPORTED",
                "action": "Use an approved runtime profile.",
                "detail": "no_loader_profile_for_format",
            }],
            "timeline_json": [{"event": "runtime_profile_unavailable"}],
        },
    )

    control = _control(report, "firecracker_runtime")
    assert report["outcome"] == "INCOMPLETE"
    assert report["automatic_review"]["technical_outcome"] == "INCOMPLETE"
    assert report["executive_summary"]["automatic_technical_review"]["current_step"] == "runtime_profile_unavailable"
    assert control["status"] == "INCOMPLETE"
    assert control["coverage"]["support_status"] == "UNSUPPORTED"
    assert control["remediation"] == "Use an approved runtime profile."
    assert len(report["report_sha256"]) == 64
    assert any(item["control_id"] == "firecracker_runtime" for item in report["executive_summary"]["required_actions"])


def test_automatic_report_keeps_deployment_follow_up_out_of_technical_result():
    rows = _rows(active_admission=False)
    rows["evidence"] = [
        item for item in rows["evidence"]
        if item["evidence_type"] != "data_plane_evaluation"
    ]
    report = apply_automatic_review_context(
        _report(rows),
        {
            "id": "review-technical",
            "state": "technical_review_complete",
            "current_step": "review_results",
            "progress": 100,
            "technical_outcome": "REVIEW_REQUIRED",
            "pending_controls": [{"control": "static_analysis", "status": "WARNING"}],
            "timeline_json": [],
        },
    )

    assert report["outcome"] == "REVIEW"
    assert report["plain_language"].startswith("Technical checks completed")
    assert report["presentation"]["headline"] == "Review findings before use"
    assert report["presentation"]["decision"] == "REVIEW_REQUIRED"
    assert report["executive_summary"]["deployable_under_configured_shakerscan_policy"] is False
    assert report["executive_summary"]["coverage"]["total_controls"] == 10
    assert all(
        item["control_id"] not in {"data_plane_evaluation", "human_approvals", "deterministic_policy", "signed_admission"}
        for item in report["executive_summary"]["key_results"]
    )
    assert all(
        item["control_id"] not in {"data_plane_evaluation", "human_approvals", "deterministic_policy", "signed_admission"}
        for item in report["executive_summary"]["required_actions"]
    )
    assert len(report["detailed_review"]["control_matrix"]) == 10
    sarif = model_intake_report_to_sarif(report)
    assert all(
        result["ruleId"] not in {
            "model-intake/data_plane_evaluation", "model-intake/human_approvals",
            "model-intake/deterministic_policy", "model-intake/signed_admission",
        }
        for result in sarif["runs"][0]["results"]
    )
    html = render_model_intake_html(report)
    assert "Technical checks completed" in html
    assert "Organization checklist" in html
    assert "No data plane evaluation evidence is attached" not in html.split("Detailed technical review", 1)[1]


def test_static_report_names_safe_finding_location_and_remediation():
    rows = _rows(active_admission=False)
    static = next(item for item in rows["evidence"] if item["evidence_type"] == "static_analysis")
    static["status"] = "WARNING"
    static["payload_json"]["scanner_results"] = [
        {
            "name": "python-ast-security", "status": "WARNING", "required": True,
            "finding_count": 1, "coverage": {"files_analyzed": 2},
            "findings": [{"id": "unsafe_torch_load", "call": "torch.load", "path": "modeling.py", "line": 42}],
        },
        {
            "name": "semgrep", "status": "WARNING", "required": True,
            "finding_count": 1, "coverage": {"files_analyzed": 2},
            "findings": [{
                "rule_id": "torch-load-version-dependent", "path": "modeling.py", "line": 42,
                "message": "torch.load should use weights_only=True", "severity": "medium",
            }],
        },
    ]
    static["payload_json"]["runtime_dependencies"] = {
        "status": "PASS",
        "profile": {"id": "shakerscan-firecracker-python312-cpu/v1"},
        "inferred_requirements": [{
            "import_name": "torch", "distribution": "torch", "version": "2.9.1+cpu",
            "required_for_fixed_loader": True, "resolution_status": "RESOLVED",
        }],
        "resolved_components": [{
            "name": "torch", "version": "2.9.1+cpu",
            "purl": "pkg:pypi/torch@2.9.1%2Bcpu", "source": "hash_locked_direct_wheel",
        }],
    }
    static["payload_json"]["vulnerability_summary"] = {"total": 1, "packages_affected": 1}
    static["payload_json"]["vulnerability_inventory"] = [{
        "id": "CVE-2026-12345", "package": "torch", "installed_version": "2.9.1",
        "severity": "high", "sources": ["osv-scanner", "pip-audit"],
        "fixed_versions": ["2.9.2"],
    }]
    report = apply_automatic_review_context(
        _report(rows),
        {
            "id": "review-finding", "state": "technical_review_complete",
            "current_step": "review_results", "progress": 100,
            "technical_outcome": "REVIEW_REQUIRED", "pending_controls": [], "timeline_json": [],
        },
    )

    static_control = _control(report, "static_analysis")
    assert "torch.load should use weights_only=True (modeling.py:42)" in static_control["detail"]
    assert "Resolve torch.load should use weights_only=True at modeling.py:42" in static_control["remediation"]
    assert "modeling.py:42" in next(
        item["action"] for item in report["executive_summary"]["required_actions"]
        if item["control_id"] == "static_analysis"
    )
    scanner = report["detailed_review"]["static_analysis_detail"]["scanner_results"][0]
    assert scanner["findings"][0]["path"] == "modeling.py"
    rendered = render_model_intake_html(report)
    assert "shakerscan-firecracker-python312-cpu/v1" in rendered
    assert "CVE-2026-12345" in rendered
    assert "osv-scanner, pip-audit" in rendered
    assert "torch</td><td>2.9.1+cpu" in rendered


def test_presentation_does_not_tell_engineers_to_repeat_passing_or_inapplicable_work():
    report = _report(_rows(active_admission=False))

    verified = report["presentation"]["groups"]["verified"]
    not_applicable = report["presentation"]["groups"]["not_applicable"]
    assert verified
    assert all(item["next_step"].startswith("Completed;") for item in verified)
    assert all(item["next_step"] == "No action is required for this revision." for item in not_applicable)


def test_calibration_digest_capture_is_not_presented_as_failed_inference():
    rows = _rows(active_admission=False)
    rows["runner_jobs"].insert(0, {
        "id": "calibration-1",
        "operation": "calibration",
        "state": "completed",
        "request_sha256": DIGESTS["b"],
        "result_json": {
            "payload": {
                "observations": {
                    "phases": {
                        "import": "PASS", "tokenizer": "PASS", "model_load": "PASS",
                        "warmup": "PASS", "inference": "FAIL", "teardown": "PASS",
                    },
                    "embedding_known_answers_status": "NOT_CONFIGURED",
                    "embedding_output_sha256": DIGESTS["c"],
                },
            },
        },
    })

    report = _report(rows)
    calibration = next(item for item in report["runner_timelines"] if item["operation"] == "calibration")
    inference = next(item for item in calibration["phases"] if item["phase"] == "inference")
    assert inference["status"] == "CALIBRATED"
    assert inference["raw_status"] == "FAIL"
    assert "repeat verification" in inference["detail"]
    assert "<td>CALIBRATED</td>" in render_model_intake_html(report)


def test_check_catalog_uses_direct_per_check_evidence_instead_of_aggregate_static_status():
    rows = _rows(active_admission=False)
    static = next(item for item in rows["evidence"] if item["evidence_type"] == "static_analysis")
    static["status"] = "WARNING"
    static["payload_json"]["checks"].update({
        "format_specific_inspection": True,
        "signature_verification": None,
        "sbom_dependencies": False,
    })
    static["payload_json"]["scanner_results"].extend([
        {"name": "python-pickletools", "status": "NOT_APPLICABLE", "finding_count": 0},
        {"name": "python-ast-security", "status": "REVIEW", "finding_count": 1},
        {"name": "shakerscan-sbom", "status": "PASS", "finding_count": 0},
    ])

    report = _report(rows)
    catalog = {item["id"]: item for item in report["detailed_review"]["shakerscan_check_catalog"]}
    assert catalog["MI-05"]["execution_status"] == "PASS"
    assert catalog["MI-06"]["execution_status"] == "PASS"
    assert catalog["MI-07"]["execution_status"] == "NOT_APPLICABLE"
    assert catalog["MI-13"]["execution_status"] == "REVIEW"
    assert catalog["MI-15"]["execution_status"] == "PASS"
    assert catalog["MI-17"]["execution_status"] == "NOT_RUN"


def test_network_attempt_is_a_blocking_control_failure():
    rows = _rows(active_admission=False)
    telemetry = rows["runner_jobs"][0]["result_json"]["payload"]["observations"]["network_telemetry"]
    telemetry["attempt_count"] = 1
    telemetry["attempted_operations"] = [{
        "operation": "connect", "phase": "model_load", "address_family": "AF_INET",
        "outbound_attempt": True,
    }]
    telemetry["observed_operations"] = list(telemetry["attempted_operations"])
    report = _report(rows)

    assert report["outcome"] == "BLOCK"
    assert _control(report, "runtime_execution")["status"] == "PASS"
    assert "containment is reported" in _control(report, "runtime_execution")["detail"]
    assert _control(report, "network_isolation")["status"] == "FAIL"
    network = report["runner_timelines"][0]["network"]
    assert network["attempt_sample"][0]["operation"] == "connect"
    assert network["outbound_attempt_count"] == 1
    assert network["attempts_by_operation"] == {"connect": 1}
    assert "attempted_operations" not in network


def test_successful_runtime_phases_do_not_upgrade_incomplete_signed_evidence():
    rows = _rows(active_admission=False)
    runtime = next(item for item in rows["evidence"] if item["evidence_type"] == "runtime_execution")
    runtime["status"] = "INCOMPLETE"
    report = _report(rows)

    runtime_control = _control(report, "runtime_execution")
    assert runtime_control["status"] == "INCOMPLETE"
    assert runtime_control["coverage"]["execution_status"] == "PASS"
    assert runtime_control["coverage"]["receipt_overall_status"] == "INCOMPLETE"
    assert "receipt trust and completeness" in runtime_control["detail"]
    assert _control(report, "firecracker_runtime")["status"] == "PASS"


def test_network_report_bounds_repetitive_syscall_evidence():
    rows = _rows(active_admission=False)
    telemetry = rows["runner_jobs"][0]["result_json"]["payload"]["observations"]["network_telemetry"]
    telemetry["attempt_count"] = 20
    telemetry["attempted_operations"] = [
        {"operation": "socket", "phase": "import", "address_family": "AF_UNIX"}
        for _ in range(20)
    ]
    report = _report(rows)
    network = report["runner_timelines"][0]["network"]

    assert network["local_ipc_event_count"] == 20
    assert network["ip_socket_event_count"] == 0
    assert network["outbound_attempt_count"] == 0
    assert network["attempt_sample"] == []
    assert network["attempt_sample_truncated"] is False
    assert _control(report, "network_isolation")["status"] == "PASS"


def test_embedding_control_distinguishes_behavior_from_runtime_containment():
    rows = _rows(active_admission=False)
    evaluation = next(item for item in rows["evidence"] if item["evidence_type"] == "embedding_evaluation")
    evaluation["payload_json"] = {
        "quality_status": "KNOWN_ANSWER_PASS",
        "containment_status": "FAIL",
        "embedding_shape": [2, 768],
        "benchmark_dataset_sha256": DIGESTS["a"],
        "thresholds_sha256": DIGESTS["b"],
        "embedding_output_sha256": DIGESTS["c"],
        "blockers": [],
        "containment_blockers": ["network_quiet"],
    }
    report = _report(rows)
    control = _control(report, "embedding_evaluation")

    assert control["status"] == "PASS"
    assert control["coverage"]["quality_status"] == "KNOWN_ANSWER_PASS"
    assert control["coverage"]["containment_status"] == "FAIL"
    assert "reported separately" in control["detail"]


def test_active_admission_mismatch_blocks_even_when_other_controls_pass():
    rows = _rows()
    rows["admissions"][0]["admission_package"]["statement"]["predicate"]["decision"] = "block"
    report = _report(rows)

    assert report["outcome"] == "BLOCK"
    assert report["authority_bindings"]["admission_statement_parity"]["decision_matches"] is False
    assert "does not match" in report["plain_language"]


def test_unverified_active_admission_cannot_allow():
    rows = _rows()
    report = build_model_intake_report(
        **rows,
        admission_verification={"verified": False, "status": "FAIL", "blockers": ["signature_invalid_or_untrusted"]},
        generated_at=NOW,
    )

    assert report["outcome"] == "BLOCK"
    assert report["authority_bindings"]["admission_statement_parity"]["cryptographic_signature_verified"] is False
    assert report["authority_bindings"]["admission_cryptographic_verification"]["blockers"] == ["signature_invalid_or_untrusted"]


def test_stale_approvals_and_policy_decision_do_not_bind_a_new_manifest():
    rows = _rows(active_admission=False)
    rows["manifests"].append({"id": "manifest-2", "manifest_sha256": "1" * 64})
    report = _report(rows)

    assert _control(report, "human_approvals")["status"] == "REVIEW"
    assert _control(report, "deterministic_policy")["status"] == "FAIL"
    assert report["outcome"] == "BLOCK"


def test_expired_generated_evidence_cannot_pass():
    rows = _rows(active_admission=False)
    rows["evidence"][0]["expires_at"] = NOW - timedelta(seconds=1)
    report = _report(rows)

    assert _control(report, "static_analysis")["status"] == "INCOMPLETE"
    assert report["outcome"] == "INCOMPLETE"


def test_report_digest_is_content_stable_across_render_times():
    rows = _rows()
    first = _report(rows, generated_at=NOW)
    second = _report(rows, generated_at=NOW + timedelta(seconds=1))

    assert first["generated_at"] != second["generated_at"]
    assert first["report_sha256"] == second["report_sha256"]


def test_html_is_escaped_printable_and_sarif_preserves_normalized_failures():
    rows = _rows(active_admission=False)
    rows["submission"]["state"] = "<script>alert(1)</script>"
    rows["runner_jobs"] = []
    report = _report(rows)
    rendered = render_model_intake_html(report)
    sarif = model_intake_report_to_sarif(report)

    assert "Print / Save PDF" in rendered
    assert "Model Intake review" in rendered
    assert "Deployment follow-up" in rendered
    assert "Organization checklist" in rendered
    assert "Detailed technical review" in rendered
    assert "Tool execution details" in rendered
    assert "What this tool tested" in rendered
    assert "No finding was reported by this tool." in rendered
    assert "NOT_DETERMINED_BY_SHAKERSCAN" not in rendered
    assert "Full corporate approval" not in rendered
    assert "Checks that need attention" in rendered
    assert "<script>alert(1)</script>" not in rendered
    assert "model-intake-corporate-report/v2" == sarif["runs"][0]["properties"]["schemaVersion"]
    assert sarif["runs"][0]["properties"]["reportSha256"] == report["report_sha256"]
    assert sarif["runs"][0]["results"]
    assert all(result["properties"]["status"] not in {"PASS", "NOT_APPLICABLE"} for result in sarif["runs"][0]["results"])


def test_html_reports_each_tool_scope_coverage_execution_and_findings_separately():
    rows = _rows(active_admission=False)
    static = next(item for item in rows["evidence"] if item["evidence_type"] == "static_analysis")
    static["payload_json"]["scanner_results"] = [{
        "name": "semgrep",
        "version": "1.172.0",
        "status": "WARNING",
        "required": True,
        "applicability": "repository_code",
        "target_scope": "repository",
        "duration_ms": 142,
        "timeout_seconds": 300,
        "exit_code": 1,
        "execution_contract": ["semgrep", "scan", "--config", "model-intake.yml", "{subject}"],
        "rules_sha256": "a" * 64,
        "finding_count": 1,
        "coverage": {"files_scanned": 4, "inventory_truncated": False},
        "summary": {"finding_count": 1, "error_count": 0},
        "findings": [{
            "rule_id": "model-intake.unsafe-torch-load",
            "severity": "medium",
            "message": "torch.load should use weights_only=True",
            "classification": "review_required",
            "path": "modeling.py",
            "line": 42,
        }],
    }, {
        "name": "modelscan",
        "version": "0.8.8",
        "status": "PASS",
        "required": True,
        "applicability": "serialized_model",
        "target_scope": "artifact",
        "finding_count": 0,
        "coverage": {"files_considered": 1},
        "findings": [],
    }]

    rendered = render_model_intake_html(_report(rows))

    assert rendered.count("class='tool-run'") == 2
    assert "<h4>semgrep</h4>" in rendered
    assert "<h4>modelscan</h4>" in rendered
    assert "Model-repository code and configuration" in rendered
    assert "Known unsafe or malicious operations in serialized model artifacts" in rendered
    assert "Coverage — Files scanned" in rendered
    assert "Observed — Error count" in rendered
    assert "model-intake.unsafe-torch-load" in rendered
    assert "modeling.py:42" in rendered
    assert "torch.load should use weights_only=True" in rendered
    assert "No finding was reported by this tool." in rendered
