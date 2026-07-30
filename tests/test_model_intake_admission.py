from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from scanner.scanner_tools.model_intake_admission import (
    TECHNICAL_CANDIDATE_SCHEMA_VERSION,
    build_statement,
    build_technical_candidate,
    sign_statement,
    trusted_public_keys_from_env,
    verify_package,
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


def _statement():
    return build_statement(
        subject_sha256="a" * 64,
        repository_snapshot_sha256="b" * 64,
        generated_evidence_sha256="c" * 64,
        sandbox_evidence_sha256="d" * 64,
        attestation_evidence_sha256="e" * 64,
        evaluation_evidence_sha256="1" * 64,
        policy_profile="production",
        policy_version="v1",
        decision="allow",
        decision_reason="all gates passed",
        findings_digest="f" * 64,
        expires_days=30,
    )


def test_signed_admission_verifies_exact_subjects():
    private_pem, public_pem = _keys()
    package = sign_statement(_statement(), private_pem)

    result = verify_package(
        package,
        trusted_public_keys=[public_pem],
        expected_artifact_sha256="a" * 64,
        expected_repository_snapshot_sha256="b" * 64,
        allow_legacy_v1=True,
    )

    assert package["status"] == "SIGNED"
    assert result["status"] == "PASS"
    assert result["verified"] is True


def test_legacy_v1_is_rejected_by_default_even_when_signature_and_subject_are_valid():
    private_pem, public_pem = _keys()
    package = sign_statement(_statement(), private_pem)

    result = verify_package(
        package,
        trusted_public_keys=[public_pem],
        expected_artifact_sha256="a" * 64,
        expected_repository_snapshot_sha256="b" * 64,
    )

    assert result["verified"] is False
    assert "legacy_admission_v1_reassessment_required" in result["blockers"]


def test_worker_technical_candidate_is_explicitly_non_deployable():
    candidate = build_technical_candidate(_statement())

    assert candidate["status"] == "TECHNICAL_CANDIDATE"
    assert candidate["deployable"] is False
    assert candidate["statement"]["_type"] == TECHNICAL_CANDIDATE_SCHEMA_VERSION
    assert "signature" not in candidate
    assert "not_signed_by_admission_signer" in candidate["limitations"]

    result = verify_package(candidate, trusted_public_keys=[])
    assert result["verified"] is False
    assert "unsupported_statement_type" in result["blockers"]


def test_legitimately_signed_block_decision_is_never_admitted():
    private_pem, public_pem = _keys()
    statement = _statement()
    statement["decision"] = {"outcome": "block", "reason": "critical unsafe serialization"}
    package = sign_statement(statement, private_pem)

    result = verify_package(
        package,
        trusted_public_keys=[public_pem],
        expected_artifact_sha256="a" * 64,
        expected_repository_snapshot_sha256="b" * 64,
    )

    assert package["status"] == "SIGNED"
    assert result["verified"] is False
    assert result["status"] == "FAIL"
    assert "admission_decision_not_allow" in result["blockers"]


def test_admission_rejects_tampering_drift_and_expiry():
    private_pem, public_pem = _keys()
    package = sign_statement(_statement(), private_pem)
    package["statement"]["decision"]["outcome"] = "block"

    result = verify_package(
        package,
        trusted_public_keys=[public_pem],
        expected_artifact_sha256="0" * 64,
        now=datetime.now(timezone.utc) + timedelta(days=31),
    )

    assert result["verified"] is False
    assert set(result["blockers"]) >= {
        "statement_digest_mismatch",
        "artifact_subject_mismatch",
        "admission_expired",
        "signature_invalid_or_untrusted",
    }


def test_signing_without_worker_key_is_explicitly_unsupported(monkeypatch):
    monkeypatch.delenv("MODEL_INTAKE_ADMISSION_SIGNING_KEY_PEM", raising=False)
    package = sign_statement(_statement())

    assert package["status"] == "UNSUPPORTED"
    assert package["error"] == "admission_signing_key_unavailable"


def test_admission_requires_complete_artifact_subject_and_trusted_keys():
    private_pem, _public_pem = _keys()
    statement = _statement()
    statement["subject"]["artifact_sha256"] = None
    package = sign_statement(statement, private_pem)

    result = verify_package(package, trusted_public_keys=[])

    assert result["verified"] is False
    assert "missing_or_invalid_artifact_subject" in result["blockers"]
    assert "no_trusted_admission_keys_configured" in result["blockers"]


def test_admission_trust_roots_parse_json_or_pem_bundle():
    _private_a, public_a = _keys()
    _private_b, public_b = _keys()

    assert trusted_public_keys_from_env(__import__("json").dumps([public_a, public_b])) == [public_a.strip(), public_b.strip()]
    assert trusted_public_keys_from_env(public_a + "\n" + public_b) == [public_a.strip(), public_b.strip()]
