import base64
import asyncio
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from scanner.scanner_tools.model_intake_attestation import _dsse_pae, _public_key_fingerprint, verify_dsse_in_toto
from scanner.scanner_tools.model_intake import run_model_intake_scan


PREDICATE = "https://slsa.dev/provenance/v1"


def _pem(key):
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _envelope(private_key, digest, *, builder="https://build.example/model", predicate=PREDICATE):
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "model", "digest": {"sha256": digest}}],
        "predicateType": predicate,
        "predicate": {"builder": {"id": builder}},
    }
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    payload_type = "application/vnd.in-toto+json"
    signature = private_key.sign(_dsse_pae(payload_type, payload))
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": "release", "sig": base64.b64encode(signature).decode()}],
    }


def test_dsse_in_toto_verification_binds_trusted_key_subject_and_builder():
    key = ed25519.Ed25519PrivateKey.generate()
    digest = hashlib.sha256(b"model").hexdigest()
    result = verify_dsse_in_toto(
        _envelope(key, digest),
        subject_sha256=digest,
        subject_complete=True,
        trusted_public_keys=[_pem(key.public_key())],
        allowed_predicate_types=[PREDICATE],
        required_builder_ids=["https://build.example/model"],
    )

    assert result["status"] == "PASS"
    assert result["verified"] is True
    assert result["subject_digest_match"] is True
    assert result["signature"]["algorithm"] == "ed25519"


def test_dsse_attestation_fails_closed_on_digest_identity_and_transparency():
    key = ed25519.Ed25519PrivateKey.generate()
    digest = hashlib.sha256(b"model").hexdigest()
    result = verify_dsse_in_toto(
        _envelope(key, "0" * 64, builder="https://evil.example/build"),
        subject_sha256=digest,
        subject_complete=True,
        trusted_public_keys=[_pem(key.public_key())],
        required_builder_ids=["https://build.example/model"],
        require_transparency_log=True,
    )

    assert result["verified"] is False
    assert set(result["blockers"]) == {
        "attestation_subject_digest_mismatch",
        "builder_identity_not_allowed",
        "transparency_log_proof_required",
    }


def test_dsse_attestation_requires_complete_subject_and_operator_key():
    key = ed25519.Ed25519PrivateKey.generate()
    digest = hashlib.sha256(b"model").hexdigest()
    envelope = _envelope(key, digest)

    assert verify_dsse_in_toto(
        envelope,
        subject_sha256=digest,
        subject_complete=False,
        trusted_public_keys=[_pem(key.public_key())],
    )["status"] == "INCOMPLETE"
    assert verify_dsse_in_toto(
        envelope,
        subject_sha256=digest,
        subject_complete=True,
        trusted_public_keys=None,
    )["error"] == "operator_trusted_attestation_key_required"


def test_dsse_attestation_pin_allowlist_cannot_be_widened_by_supplied_keys():
    pinned_key = ed25519.Ed25519PrivateKey.generate()
    unpinned_key = ed25519.Ed25519PrivateKey.generate()
    digest = hashlib.sha256(b"model").hexdigest()

    result = verify_dsse_in_toto(
        _envelope(unpinned_key, digest),
        subject_sha256=digest,
        subject_complete=True,
        trusted_public_keys=[_pem(pinned_key.public_key()), _pem(unpinned_key.public_key())],
        trusted_key_sha256=[_public_key_fingerprint(_pem(pinned_key.public_key()))],
    )

    assert result["status"] == "FAIL"
    assert result["signature"] is None
    assert "dsse_signature_invalid_or_untrusted" in result["blockers"]


def test_model_intake_uses_verified_dsse_attestation_as_generated_gate_evidence(tmp_path):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(b"model")
    digest = hashlib.sha256(b"model").hexdigest()
    key = ed25519.Ed25519PrivateKey.generate()

    result = asyncio.run(run_model_intake_scan(str(artifact), {
        "allow_local_files": True,
        "expected_sha256": digest,
        "attestation_bundle_json": _envelope(key, digest),
        "attestation_trusted_keys": [_pem(key.public_key())],
        "allowed_attestation_predicate_types": [PREDICATE],
        "required_attestation_builder_ids": ["https://build.example/model"],
        "require_attestation_verification": True,
        "require_signature": False,
        "require_model_governance": False,
        "require_deployment_approval": False,
    }))

    assert result["model_intake"]["summary"]["attestation_verified"] is True
    assert result["model_intake"]["attestation"]["provenance_class"] == "externally_attested"
    assert "model_intake:attestation_not_verified" not in {item["id"] for item in result["findings"]}
