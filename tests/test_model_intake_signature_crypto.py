"""R1: real cryptographic signature verification in Model Intake.

These prove that ShakerScan now performs ACTUAL detached-signature verification
(not metadata-trust): a valid signature verifies, a tampered one is rejected and
blocks, and a metadata-only claim under a crypto-strict policy is flagged.

Requires the `cryptography` library (present in the scanner runtime image; these
skip where it is absent, e.g. a minimal host interpreter).
"""

import asyncio
import base64
import hashlib
import json

import pytest

crypto = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa  # noqa: E402

from scanner.scanner_tools.model_intake import (  # noqa: E402
    _public_key_sha256,
    run_model_intake_scan,
)


def _safetensors_bytes(payload=b"\0\0\0\0"):
    header = {"__metadata__": {}, "weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, len(payload)]}}
    raw = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return len(raw).to_bytes(8, "little") + raw + payload


def _pub_pem(public_key):
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _run(artifact_path, options):
    return asyncio.run(run_model_intake_scan(str(artifact_path), {"allow_local_files": True, **options}))


def _base_opts(artifact_bytes, **extra):
    return {
        "expected_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "require_signature": False,
        "require_hash": False,
        "require_model_governance": False,
        **extra,
    }


def _finding_ids(result):
    return {f["id"] for f in result["findings"]}


def test_ed25519_detached_signature_verifies(tmp_path):
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes()
    artifact.write_bytes(data)

    priv = ed25519.Ed25519PrivateKey.generate()
    signature = priv.sign(data)  # signs the raw artifact bytes

    result = _run(artifact, _base_opts(
        data,
        signature_public_key=_pub_pem(priv.public_key()),
        signature_value=base64.b64encode(signature).decode(),
        signature_trusted_keys=[_pub_pem(priv.public_key())],  # configured trust anchor
        require_cryptographic_signature_verification=True,
    ))

    summary = result["model_intake"]["summary"]
    assert summary["signature_verification_status"] == "verified"
    assert summary["signature_cryptographically_verified"] is True
    assert summary["signature_trusted_root"] is True
    assert summary["signature_verifier"].startswith("cryptography:ed25519")
    assert summary["signature_attestation_subject_digest_match"] is True
    ids = _finding_ids(result)
    assert "model_intake:signature_not_verified" not in ids
    assert "model_intake:signature_invalid" not in ids


def test_rsa_pss_detached_signature_verifies(tmp_path):
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes()
    artifact.write_bytes(data)

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    result = _run(artifact, _base_opts(
        data,
        signature_public_key=_pub_pem(priv.public_key()),
        signature_value=base64.b64encode(signature).decode(),
        signature_rsa_padding="pss",
        signature_trusted_keys=[_pub_pem(priv.public_key())],  # configured trust anchor
        require_cryptographic_signature_verification=True,
    ))
    summary = result["model_intake"]["summary"]
    assert summary["signature_verification_status"] == "verified"
    assert summary["signature_cryptographically_verified"] is True
    assert summary["signature_verifier"].startswith("cryptography:rsa-pss")


def test_digest_hex_payload_signature_verifies(tmp_path):
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes()
    artifact.write_bytes(data)
    digest_hex = hashlib.sha256(data).hexdigest()

    priv = ed25519.Ed25519PrivateKey.generate()
    signature = priv.sign(digest_hex.encode())  # signs the hex digest string

    result = _run(artifact, _base_opts(
        data,
        signature_public_key=_pub_pem(priv.public_key()),
        signature_value=base64.b64encode(signature).decode(),
        signature_payload="digest_hex",
        signature_trusted_keys=[_pub_pem(priv.public_key())],  # configured trust anchor
        require_cryptographic_signature_verification=True,
    ))
    summary = result["model_intake"]["summary"]
    assert summary["signature_verification_status"] == "verified"
    assert summary["signature_cryptographically_verified"] is True


def test_raw_signature_cannot_verify_only_an_inspection_prefix(tmp_path):
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes(payload=b"x" * 4096)
    artifact.write_bytes(data)

    priv = ed25519.Ed25519PrivateKey.generate()
    prefix = data[:128]
    signature = priv.sign(prefix)

    result = _run(artifact, _base_opts(
        data,
        complete_artifact_download=True,
        max_download_bytes=128,
        max_artifact_bytes=10_000,
        quarantine_dir=str(tmp_path / "quarantine"),
        signature_public_key=_pub_pem(priv.public_key()),
        signature_value=base64.b64encode(signature).decode(),
        signature_trusted_keys=[_pub_pem(priv.public_key())],
        require_cryptographic_signature_verification=True,
    ))

    summary = result["model_intake"]["summary"]
    assert summary["signature_cryptographically_verified"] is False
    assert summary["signature_crypto_attempted"] is False
    assert "model_intake:signature_not_verified" in _finding_ids(result)


def test_tampered_signature_is_invalid_and_blocks(tmp_path):
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes()
    artifact.write_bytes(data)

    priv = ed25519.Ed25519PrivateKey.generate()
    signature = bytearray(priv.sign(data))
    signature[-1] ^= 0xFF  # corrupt the signature

    result = _run(artifact, _base_opts(
        data,
        signature_public_key=_pub_pem(priv.public_key()),
        signature_value=base64.b64encode(bytes(signature)).decode(),
    ))
    summary = result["model_intake"]["summary"]
    assert summary["signature_verification_status"] == "invalid"
    assert summary["signature_cryptographically_verified"] is False
    assert "model_intake:signature_invalid" in _finding_ids(result)


def test_wrong_key_does_not_verify(tmp_path):
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes()
    artifact.write_bytes(data)

    signer = ed25519.Ed25519PrivateKey.generate()
    other = ed25519.Ed25519PrivateKey.generate()  # unrelated key
    signature = signer.sign(data)

    result = _run(artifact, _base_opts(
        data,
        signature_public_key=_pub_pem(other.public_key()),
        signature_value=base64.b64encode(signature).decode(),
    ))
    assert result["model_intake"]["summary"]["signature_verification_status"] == "invalid"
    assert "model_intake:signature_invalid" in _finding_ids(result)


def test_valid_signature_without_trust_root_is_untrusted(tmp_path):
    # A self-signed artifact: the signature math passes, but no trust anchor is
    # configured, so provenance is NOT trusted and the status must not be "verified".
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes()
    artifact.write_bytes(data)

    priv = ed25519.Ed25519PrivateKey.generate()
    signature = priv.sign(data)

    result = _run(artifact, _base_opts(
        data,
        signature_public_key=_pub_pem(priv.public_key()),
        signature_value=base64.b64encode(signature).decode(),
        require_cryptographic_signature_verification=True,
    ))
    summary = result["model_intake"]["summary"]
    assert summary["signature_verification_status"] == "untrusted_root"
    assert summary["signature_valid"] is True
    assert summary["signature_cryptographically_verified"] is False
    assert summary["signature_trusted_root"] is None
    findings = {f["id"]: f for f in result["findings"]}
    assert "model_intake:signature_not_verified" in findings
    assert findings["model_intake:signature_not_verified"]["severity"] == "high"
    # The top-line "is this signature verified?" summary flag reflects the downgrade.
    assert summary["signature_verified"] is False


def test_valid_signature_with_untrusted_key_is_flagged(tmp_path):
    # The signing key is valid but a DIFFERENT key is the configured trust anchor.
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes()
    artifact.write_bytes(data)

    signer = ed25519.Ed25519PrivateKey.generate()
    trusted = ed25519.Ed25519PrivateKey.generate()  # the only anchor we trust
    signature = signer.sign(data)

    result = _run(artifact, _base_opts(
        data,
        signature_public_key=_pub_pem(signer.public_key()),
        signature_value=base64.b64encode(signature).decode(),
        signature_trusted_keys=[_pub_pem(trusted.public_key())],
        require_cryptographic_signature_verification=True,
    ))
    summary = result["model_intake"]["summary"]
    assert summary["signature_verification_status"] == "untrusted_key"
    assert summary["signature_valid"] is True
    assert summary["signature_cryptographically_verified"] is False
    assert summary["signature_trusted_root"] is False
    assert "model_intake:signature_not_verified" in _finding_ids(result)


def test_trusted_key_by_sha256_fingerprint_verifies(tmp_path):
    # Trust can be configured by fingerprint instead of full PEM.
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes()
    artifact.write_bytes(data)

    priv = ed25519.Ed25519PrivateKey.generate()
    signature = priv.sign(data)
    fingerprint = _public_key_sha256(_pub_pem(priv.public_key()))

    result = _run(artifact, _base_opts(
        data,
        signature_public_key=_pub_pem(priv.public_key()),
        signature_value=base64.b64encode(signature).decode(),
        signature_trusted_key_sha256=fingerprint,
        require_cryptographic_signature_verification=True,
    ))
    summary = result["model_intake"]["summary"]
    assert summary["signature_verification_status"] == "verified"
    assert summary["signature_cryptographically_verified"] is True
    assert summary["signature_trusted_root"] is True
    assert summary["signature_key_fingerprint"] == fingerprint
    assert "model_intake:signature_not_verified" not in _finding_ids(result)


def test_require_crypto_with_metadata_claim_only_is_flagged(tmp_path):
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes()
    artifact.write_bytes(data)

    # No public key / signature material — only a metadata boolean claim. Under a
    # crypto-strict policy this must NOT pass.
    result = _run(artifact, _base_opts(
        data,
        signature_url="https://example.test/model.safetensors.sig",
        require_cryptographic_signature_verification=True,
        metadata_json={"sigstore_verified": True, "signature_cryptographically_verified": True},
    ))
    summary = result["model_intake"]["summary"]
    assert summary["signature_verification_status"] == "claimed_verified"
    assert summary["signature_cryptographically_verified"] is False
    findings = {f["id"]: f for f in result["findings"]}
    assert "model_intake:signature_not_verified" in findings
    assert findings["model_intake:signature_not_verified"]["severity"] == "high"
