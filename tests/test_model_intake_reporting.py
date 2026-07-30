from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_reporting import (  # noqa: E402
    CONTROL_STATUSES,
    build_model_intake_report,
    model_intake_report_to_sarif,
    render_model_intake_html,
)


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
        evidence.append({
            "id": f"evidence-{index}",
            "evidence_type": evidence_type,
            "status": "PASS",
            "provenance_class": "GENERATED",
            "producer_id": f"producer-{index}",
            "builder_id": "builder://trusted",
            "payload_sha256": DIGESTS["c"],
            "subject_bindings": {"artifact": DIGESTS["a"]},
            "expires_at": NOW + timedelta(days=30),
        })
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
    assert report["schema_version"] == "model-intake-corporate-report/v1"
    assert set(report["control_counts"]) == CONTROL_STATUSES
    assert _control(report, "firecracker_runtime")["status"] == "PASS"
    assert _control(report, "network_isolation")["status"] == "PASS"
    assert _control(report, "conversion_equivalence")["status"] == "NOT_APPLICABLE"
    assert all(report["authority_bindings"]["admission_statement_parity"].values())


def test_missing_runtime_and_required_conversion_are_plainly_incomplete():
    rows = _rows(artifact_uri="hf://example/model/pytorch_model.bin", active_admission=False)
    rows["runner_jobs"] = []
    rows["evidence"] = [item for item in rows["evidence"] if item["evidence_type"] != "runtime_execution"]
    report = _report(rows)

    assert report["outcome"] == "INCOMPLETE"
    assert _control(report, "runtime_execution")["status"] == "NOT_RUN"
    assert _control(report, "firecracker_runtime")["status"] == "NOT_RUN"
    assert _control(report, "conversion_equivalence")["status"] == "NOT_RUN"


def test_network_attempt_is_a_blocking_control_failure():
    rows = _rows(active_admission=False)
    telemetry = rows["runner_jobs"][0]["result_json"]["payload"]["observations"]["network_telemetry"]
    telemetry["attempt_count"] = 1
    telemetry["attempted_operations"] = [{"operation": "connect", "phase": "model_load"}]
    report = _report(rows)

    assert report["outcome"] == "BLOCK"
    assert _control(report, "network_isolation")["status"] == "FAIL"
    assert report["runner_timelines"][0]["network"]["attempted_operations"][0]["operation"] == "connect"


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
    assert "<script>alert(1)</script>" not in rendered
    assert "model-intake-corporate-report/v1" == sarif["runs"][0]["properties"]["schemaVersion"]
    assert sarif["runs"][0]["properties"]["reportSha256"] == report["report_sha256"]
    assert sarif["runs"][0]["results"]
    assert all(result["properties"]["status"] not in {"PASS", "NOT_APPLICABLE"} for result in sarif["runs"][0]["results"])
