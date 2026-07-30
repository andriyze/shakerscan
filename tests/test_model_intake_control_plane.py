import base64
import hashlib
import json
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from api.model_intake_control_plane import (
    AdmissionContractError,
    LocalPemSigner,
    build_approval_receipt,
    build_deployment_bundle,
    evaluate_policy,
    freeze_evidence_manifest,
    issue_admission_v2,
    utc_now,
    verify_admission_v2,
)


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
        records.append({
            "id": f"00000000-0000-4000-8000-{index:012d}",
            "evidence_type": evidence_type,
            "schema_version": f"{evidence_type}/v1",
            "provenance_class": provenance,
            "producer_id": f"producer-{index}",
            "producer_version": "1",
            "builder_id": f"builder-{index}",
            "invocation_id": f"invocation-{index}",
            "subject_bindings": {"deployment_bundle_sha256": bundle["bundle_sha256"]},
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
