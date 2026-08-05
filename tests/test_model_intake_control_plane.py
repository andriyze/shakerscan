import base64
import hashlib
import json
from datetime import timedelta
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_control_plane import (  # noqa: E402
    AdmissionContractError,
    LocalPemSigner,
    build_approval_receipt,
    build_deployment_bundle,
    digest_json,
    evaluate_policy,
    freeze_evidence_manifest,
    issue_admission_v2,
    policy_bundle_identity,
    utc_now,
    verify_admission_v2,
)
from model_intake_signer_service import IssueRequest  # noqa: E402


def test_embedded_policy_identity_is_source_bound_stable_and_pin_checked():
    first = policy_bundle_identity()
    second = policy_bundle_identity(first["bundle_sha256"])

    assert first == second
    assert first["schema_version"] == "model-intake-policy-bundle/v1"
    assert first["version"] == "shakerscan-embedded-model-admission-policy/v3"
    assert len(first["source_sha256"]) == 64
    assert len(first["bundle_sha256"]) == 64
    assert first["production_required_evidence"]["runtime_execution"] == "GENERATED_RUNTIME"

    with pytest.raises(AdmissionContractError, match="does not match shipped policy"):
        policy_bundle_identity("0" * 64)
    with pytest.raises(AdmissionContractError, match="digest is invalid"):
        policy_bundle_identity("not-a-digest")


def test_narrow_signer_accepts_only_server_derived_legacy_or_configured_operator_subjects():
    base = {
        "policy_decision_id": "00000000-0000-4000-8000-000000000001",
        "idempotency_key": "release-request-0001",
    }
    assert IssueRequest(**base, requested_by_subject="operator-token:" + "a" * 24)
    assert IssueRequest(**base, requested_by_subject="operator:corp:alice")

    for untrusted in ("alice", "operator:", "operator:corp alice", "submitter-peer:" + "a" * 24):
        with pytest.raises(ValidationError):
            IssueRequest(**base, requested_by_subject=untrusted)


def _keys():
    private = ed25519.Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def _bundle():
    return build_deployment_bundle({
        "model_artifact_sha256": "a" * 64,
        "repository_snapshot_sha256": "b" * 64,
        "custom_code_sha256": "c" * 64,
        "tokenizer_sha256": "d" * 64,
        "configuration_sha256": "e" * 64,
        "runtime_image_digest": "sha256:" + "f" * 64,
        "loader_profile_sha256": "1" * 64,
        "embedding_configuration": {
            "dimension": 768,
            "pooling": "mean",
            "normalization": True,
            "max_sequence_length": 8192,
            "precision": "bf16",
        },
        "retrieval_application_digest": "2" * 64,
        "index_schema_digest": "3" * 64,
        "target_environment": "production",
    })


def _evidence(bundle):
    provenances = {
        "static_analysis": "GENERATED_STATIC",
        "runtime_execution": "GENERATED_RUNTIME",
        "embedding_evaluation": "GENERATED_EVALUATION",
        "data_plane_evaluation": "GENERATED_DATA_PLANE",
    }
    records = []
    for index, (evidence_type, provenance) in enumerate(provenances.items(), start=1):
        binding_keys = {
            "static_analysis": (
                "model_artifact_sha256", "repository_snapshot_sha256", "custom_code_sha256",
                "tokenizer_sha256", "configuration_sha256",
            ),
            "runtime_execution": (
                "model_artifact_sha256", "repository_snapshot_sha256", "custom_code_sha256",
                "tokenizer_sha256", "configuration_sha256", "runtime_image_digest", "loader_profile_sha256",
            ),
            "embedding_evaluation": (
                "model_artifact_sha256", "repository_snapshot_sha256", "custom_code_sha256",
                "tokenizer_sha256", "configuration_sha256", "runtime_image_digest", "loader_profile_sha256",
            ),
            "data_plane_evaluation": (
                "model_artifact_sha256", "repository_snapshot_sha256",
                "retrieval_application_digest", "index_schema_digest",
            ),
        }[evidence_type]
        records.append({
            "id": f"00000000-0000-4000-8000-{index:012d}",
            "evidence_type": evidence_type,
            "schema_version": f"{evidence_type}/v1",
            "provenance_class": provenance,
            "producer_id": f"producer-{index}",
            "producer_version": "1",
            "builder_id": f"builder-{index}",
            "invocation_id": f"invocation-{index}",
            "subject_bindings": {
                "deployment_bundle_sha256": bundle["bundle_sha256"],
                **{key: bundle.get(key) for key in binding_keys},
            },
            "payload_sha256": str(index) * 64,
            "status": "PASS",
            "expires_at": (utc_now() + timedelta(days=7)).isoformat(),
        })
    return freeze_evidence_manifest(
        submission_id="00000000-0000-4000-8000-000000000010",
        subject_bundle_sha256=bundle["bundle_sha256"],
        version=1,
        evidence_records=records,
        frozen_by="control-plane:test",
    )


def test_policy_rejects_valid_evidence_bound_to_a_different_runtime_or_index():
    bundle = _bundle()
    evidence = _evidence(bundle)
    evidence["evidence"][1]["subject_bindings"]["runtime_image_digest"] = "sha256:" + "0" * 64
    evidence["evidence"][3]["subject_bindings"]["index_schema_digest"] = "9" * 64
    evidence["manifest_sha256"] = digest_json({key: value for key, value in evidence.items() if key != "manifest_sha256"})
    decision = evaluate_policy(
        deployment_bundle=bundle,
        evidence_manifest=evidence,
        approvals=[],
        submitter_subject="operator:submitter",
        policy_bundle_sha256="6" * 64,
    )

    assert "evidence_subject_mismatch:runtime_execution:runtime_image_digest" in decision["reasons"]
    assert "evidence_subject_mismatch:data_plane_evaluation:index_schema_digest" in decision["reasons"]


def test_warning_only_static_evidence_requires_and_accepts_bound_security_review():
    bundle = _bundle()
    evidence = _evidence(bundle)
    evidence["evidence"][0]["status"] = "WARNING"
    evidence["manifest_sha256"] = digest_json({key: value for key, value in evidence.items() if key != "manifest_sha256"})
    without_review = evaluate_policy(
        deployment_bundle=bundle,
        evidence_manifest=evidence,
        approvals=[],
        submitter_subject="operator:submitter",
        policy_bundle_sha256="6" * 64,
    )
    approvals = _approvals(bundle, evidence)
    with_review = evaluate_policy(
        deployment_bundle=bundle,
        evidence_manifest=evidence,
        approvals=approvals,
        submitter_subject="operator:submitter",
        policy_bundle_sha256="6" * 64,
    )

    assert "evidence_review_required:static_analysis" in without_review["reasons"]
    assert with_review["decision"] == "allow"
    assert with_review["reviewed_warning_evidence"] == ["static_analysis"]


def _approvals(bundle, evidence, policy_digest="6" * 64):
    return [
        build_approval_receipt(
            submission_id="00000000-0000-4000-8000-000000000010",
            subject_bundle_sha256=bundle["bundle_sha256"],
            evidence_manifest_sha256=evidence["manifest_sha256"],
            policy_bundle_sha256=policy_digest,
            environment="production",
            approval_type=role,
            decision="approve",
            approved_by_subject=f"subject:{role}",
            approved_by_role=role,
            reason="approved exact frozen evidence",
            expires_at=utc_now() + timedelta(days=7),
        )
        for role in ("model_security_reviewer", "ml_platform_reviewer", "release_manager")
    ]


def _issued():
    bundle = _bundle()
    evidence = _evidence(bundle)
    approvals = _approvals(bundle, evidence)
    policy = evaluate_policy(
        deployment_bundle=bundle,
        evidence_manifest=evidence,
        approvals=approvals,
        submitter_subject="subject:submitter",
        policy_bundle_sha256="6" * 64,
    )
    private_pem, public_pem = _keys()
    package = issue_admission_v2(
        deployment_bundle=bundle,
        evidence_manifest=evidence,
        policy_decision=policy,
        approvals=approvals,
        signer=LocalPemSigner(private_pem),
        admission_builder_id="https://shakerscan.dev/builders/model-admission/v2",
        idempotency_key="promotion-request-0001",
    )
    return bundle, evidence, approvals, policy, package, public_pem


def test_exact_bundle_v2_admission_verifies():
    bundle, _evidence_manifest, _approvals_list, policy, package, public_pem = _issued()

    assert policy["decision"] == "allow"
    result = verify_admission_v2(
        package,
        trusted_public_keys=[public_pem],
        trusted_builder_ids={"https://shakerscan.dev/builders/model-admission/v2"},
        expected_bundle_sha256=bundle["bundle_sha256"],
        expected_environment="production",
        expected_components={
            "model_artifact_sha256": "a" * 64,
            "runtime_image_digest": "sha256:" + "f" * 64,
            "tokenizer_sha256": "d" * 64,
            "loader_profile_sha256": "1" * 64,
        },
    )

    assert result["verified"] is True
    assert result["status"] == "PASS"


def test_policy_requires_generated_evidence_and_separated_approvals():
    bundle = _bundle()
    evidence = _evidence(bundle)
    evidence["evidence"][0]["provenance_class"] = "DECLARED"
    approvals = _approvals(bundle, evidence)
    approvals[0]["approved_by_subject"] = "subject:submitter"

    result = evaluate_policy(
        deployment_bundle=bundle,
        evidence_manifest=evidence,
        approvals=approvals,
        submitter_subject="subject:submitter",
        policy_bundle_sha256="6" * 64,
    )

    assert result["decision"] == "block"
    assert "deployment_bundle_digest_invalid" not in result["reasons"]
    assert "evidence_manifest_digest_invalid" in result["reasons"]
    assert "untrusted_provenance:static_analysis" in result["reasons"]
    assert "submitter_self_approval" in result["reasons"]


def test_narrow_signer_refuses_review_or_substituted_records():
    bundle = _bundle()
    evidence = _evidence(bundle)
    policy = evaluate_policy(
        deployment_bundle=bundle,
        evidence_manifest=evidence,
        approvals=[],
        submitter_subject="subject:submitter",
        policy_bundle_sha256="6" * 64,
    )
    private_pem, _public_pem = _keys()

    assert policy["decision"] == "review"
    with pytest.raises(AdmissionContractError, match="non-allow"):
        issue_admission_v2(
            deployment_bundle=bundle,
            evidence_manifest=evidence,
            policy_decision=policy,
            approvals=[],
            signer=LocalPemSigner(private_pem),
            admission_builder_id="builder",
            idempotency_key="promotion-request-0002",
        )


def test_one_byte_or_component_substitution_fails_verification():
    bundle, _evidence_manifest, _approvals_list, _policy, package, public_pem = _issued()
    statement = package["statement"]
    statement["predicate"]["deployment_bundle"]["tokenizer_sha256"] = "0" * 64
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    package["envelope"]["payload"] = base64.b64encode(payload).decode()
    package["statement_sha256"] = hashlib.sha256(payload).hexdigest()

    result = verify_admission_v2(
        package,
        trusted_public_keys=[public_pem],
        trusted_builder_ids={"https://shakerscan.dev/builders/model-admission/v2"},
        expected_bundle_sha256=bundle["bundle_sha256"],
        expected_environment="production",
        expected_components={"tokenizer_sha256": "d" * 64},
    )

    assert result["verified"] is False
    assert {
        "signature_invalid_or_untrusted",
        "component_mismatch:tokenizer_sha256",
        "deployment_bundle_digest_invalid",
    } <= set(result["blockers"])


def test_mutable_runtime_reference_is_rejected():
    data = _bundle()
    data.pop("bundle_sha256")
    data["runtime_image_digest"] = "registry.example/model:latest"

    with pytest.raises(AdmissionContractError, match="immutable"):
        build_deployment_bundle(data)


def test_embedding_contract_errors_name_the_field_bound_and_value():
    # The UI's own bundle template seeds zeros, so the first thing an operator
    # does in the runner stage used to fail with "embedding dimensions are
    # outside bounded limits" — one message covering four distinct failures,
    # naming neither the field nor what a valid value looks like.
    from model_intake_control_plane import (
        AdmissionContractError,
        build_deployment_bundle,
    )

    base = {
        "model_artifact_sha256": "a" * 64,
        "repository_snapshot_sha256": "b" * 64,
        "custom_code_sha256": None,
        "tokenizer_sha256": "c" * 64,
        "configuration_sha256": "d" * 64,
        "runtime_image_digest": "sha256:" + "e" * 64,
        "loader_profile_sha256": "f" * 64,
        "retrieval_application_digest": "1" * 64,
        "index_schema_digest": "2" * 64,
        "target_environment": "production",
    }

    def bundle(**overrides):
        embedding = {
            "dimension": 768,
            "pooling": "mean",
            "normalization": True,
            "max_sequence_length": 8192,
            "precision": "float32",
        }
        embedding.update(overrides)
        return {**base, "embedding_configuration": embedding}

    # A complete declaration is accepted and digested.
    accepted = build_deployment_bundle(bundle())
    assert accepted["embedding_configuration"]["dimension"] == 768
    assert accepted["bundle_sha256"]

    for overrides, expected in (
        ({"dimension": 0}, "embedding_configuration.dimension"),
        ({"dimension": 2_000_000}, "embedding_configuration.dimension"),
        ({"max_sequence_length": 0}, "embedding_configuration.max_sequence_length"),
        ({"pooling": "review-required"}, "embedding_configuration.pooling"),
        ({"precision": "unknown"}, "embedding_configuration.precision"),
    ):
        try:
            build_deployment_bundle(bundle(**overrides))
        except AdmissionContractError as exc:
            assert expected in str(exc), (overrides, str(exc))
            # The received value is echoed so the operator can see what was sent.
            assert "received" in str(exc)
        else:
            raise AssertionError(f"{overrides} should have been rejected")


def test_dimension_and_sequence_length_are_reported_separately():
    from model_intake_control_plane import AdmissionContractError, build_deployment_bundle

    base = {
        "model_artifact_sha256": "a" * 64,
        "repository_snapshot_sha256": "b" * 64,
        "custom_code_sha256": None,
        "tokenizer_sha256": "c" * 64,
        "configuration_sha256": "d" * 64,
        "runtime_image_digest": "sha256:" + "e" * 64,
        "loader_profile_sha256": "f" * 64,
        "retrieval_application_digest": "1" * 64,
        "index_schema_digest": "2" * 64,
        "target_environment": "production",
        "embedding_configuration": {
            "dimension": 768,
            "pooling": "mean",
            "normalization": True,
            "max_sequence_length": 0,
            "precision": "float32",
        },
    }
    try:
        build_deployment_bundle(base)
    except AdmissionContractError as exc:
        # A valid dimension must not be implicated by a bad sequence length.
        assert "max_sequence_length" in str(exc)
        assert "dimension must be" not in str(exc)
    else:
        raise AssertionError("a zero max_sequence_length should be rejected")


def test_a_runner_job_does_not_require_a_deployment_that_does_not_exist_yet():
    # retrieval_application_digest and index_schema_digest describe the serving
    # application and vector index. Only data_plane_evaluation consumes them —
    # the signed receipt verifier binds them for that evidence class alone — yet
    # the bundle demanded them for every job, so a Firecracker runtime or
    # calibration run could never be queued at all.
    from model_intake_control_plane import (
        EVIDENCE_BINDING_KEYS,
        AdmissionContractError,
        build_deployment_bundle,
    )

    assert "retrieval_application_digest" not in EVIDENCE_BINDING_KEYS["runtime_execution"]
    assert "index_schema_digest" in EVIDENCE_BINDING_KEYS["data_plane_evaluation"]

    data = {
        "model_artifact_sha256": "a" * 64,
        "repository_snapshot_sha256": "b" * 64,
        "custom_code_sha256": None,
        "tokenizer_sha256": "c" * 64,
        "configuration_sha256": "d" * 64,
        "runtime_image_digest": "sha256:" + "e" * 64,
        "loader_profile_sha256": "f" * 64,
        "target_environment": "production",
        "embedding_configuration": {
            "dimension": 768, "pooling": "mean", "normalization": True,
            "max_sequence_length": 8192, "precision": "float32",
        },
    }

    bundle = build_deployment_bundle(dict(data), require_data_plane=False)
    assert bundle["retrieval_application_digest"] is None
    assert bundle["index_schema_digest"] is None
    assert bundle["bundle_sha256"]

    # A supplied value is still validated rather than waved through.
    try:
        build_deployment_bundle({**data, "index_schema_digest": "not-a-digest"}, require_data_plane=False)
    except AdmissionContractError as exc:
        assert "index_schema_digest" in str(exc)
    else:
        raise AssertionError("a malformed data-plane digest must still be rejected")

    # The data-plane path keeps demanding them.
    try:
        build_deployment_bundle(dict(data))
    except AdmissionContractError as exc:
        assert "retrieval_application_digest" in str(exc)
    else:
        raise AssertionError("data-plane evaluation still requires its own subjects")
