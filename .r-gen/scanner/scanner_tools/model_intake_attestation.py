"""Offline DSSE / in-toto attestation verification for Model Intake."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Iterable


IN_TOTO_PAYLOAD_TYPES = {
    "application/vnd.in-toto+json",
    "application/vnd.in-toto+json;version=1",
}


def _iter_values(raw: Any) -> Iterable[Any]:
    if raw is None:
        return
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            yield from _iter_values(item)
        return
    yield raw


def _public_key_fingerprint(pem: Any) -> str | None:
    try:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
        key = load_pem_public_key(pem if isinstance(pem, bytes) else str(pem).encode())
        return hashlib.sha256(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    except Exception:
        return None


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(type_bytes), type_bytes, len(payload), payload)


def _verify_with_key(public_key_pem: Any, signature: bytes, message: bytes) -> tuple[bool, str | None]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError:
        return False, None
    try:
        key = load_pem_public_key(public_key_pem if isinstance(public_key_pem, bytes) else str(public_key_pem).encode())
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
            return True, "ed25519"
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True, "rsa-pss-sha256"
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True, "ecdsa-sha256"
        return False, None
    except (InvalidSignature, ValueError, TypeError):
        return False, None


def verify_dsse_in_toto(
    envelope: Any,
    *,
    subject_sha256: str | None,
    subject_complete: bool,
    trusted_public_keys: Any,
    trusted_key_sha256: Any = None,
    allowed_predicate_types: Any = None,
    required_builder_ids: Any = None,
    require_transparency_log: bool = False,
) -> dict[str, Any]:
    """Verify an offline DSSE envelope and bind its in-toto subject to the artifact."""
    result: dict[str, Any] = {
        "schema_version": "model-intake-attestation/v1",
        "provenance_class": "declared",
        "status": "FAIL",
        "verified": False,
        "subject_digest_match": False,
        "transparency_log_verified": False,
    }
    if not subject_complete or not subject_sha256:
        return {**result, "status": "INCOMPLETE", "error": "complete_subject_digest_required"}
    if not isinstance(envelope, dict):
        return {**result, "error": "dsse_envelope_required"}
    payload_type = str(envelope.get("payloadType") or "")
    if payload_type not in IN_TOTO_PAYLOAD_TYPES:
        return {**result, "error": "unsupported_dsse_payload_type", "payload_type": payload_type}
    try:
        payload = base64.b64decode(str(envelope.get("payload") or ""), validate=True)
        statement = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        return {**result, "error": f"invalid_dsse_payload:{type(exc).__name__}"}
    if not isinstance(statement, dict) or statement.get("_type") not in {
        "https://in-toto.io/Statement/v0.1",
        "https://in-toto.io/Statement/v1",
    }:
        return {**result, "error": "in_toto_statement_required"}

    subjects = statement.get("subject") if isinstance(statement.get("subject"), list) else []
    subject_digests = {
        str(item.get("digest", {}).get("sha256") or "").lower()
        for item in subjects if isinstance(item, dict) and isinstance(item.get("digest"), dict)
    }
    subject_match = subject_sha256.lower() in subject_digests
    predicate_type = str(statement.get("predicateType") or "")
    allowed_predicates = {str(item) for item in _iter_values(allowed_predicate_types)}
    predicate_allowed = not allowed_predicates or predicate_type in allowed_predicates
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    builder = predicate.get("builder") if isinstance(predicate.get("builder"), dict) else {}
    builder_id = str(builder.get("id") or "") or None
    required_builders = {str(item) for item in _iter_values(required_builder_ids)}
    builder_allowed = not required_builders or builder_id in required_builders

    pinned_fingerprints = {
        str(item).strip().lower().replace(":", "") for item in _iter_values(trusted_key_sha256) if str(item).strip()
    }
    keys: list[tuple[Any, str]] = []
    for key in _iter_values(trusted_public_keys):
        fingerprint = _public_key_fingerprint(key)
        if fingerprint:
            keys.append((key, fingerprint))
    if not keys:
        return {**result, "error": "operator_trusted_attestation_key_required"}
    # Supplied keys are trust anchors when no separate pin set is configured.
    # Once pins are present, they are an additional allowlist and must never be
    # widened merely because a key was included in the request.
    trusted_fingerprints = pinned_fingerprints or {fingerprint for _, fingerprint in keys}

    message = _dsse_pae(payload_type, payload)
    verified_signature: dict[str, Any] | None = None
    for signature_entry in envelope.get("signatures") or []:
        if not isinstance(signature_entry, dict):
            continue
        try:
            signature = base64.b64decode(str(signature_entry.get("sig") or ""), validate=True)
        except Exception:
            continue
        for key, fingerprint in keys:
            if fingerprint not in trusted_fingerprints:
                continue
            valid, algorithm = _verify_with_key(key, signature, message)
            if valid:
                verified_signature = {
                    "key_fingerprint": fingerprint,
                    "keyid": signature_entry.get("keyid"),
                    "algorithm": algorithm,
                }
                break
        if verified_signature:
            break

    # A publisher-supplied boolean can never prove Rekor inclusion. Until a
    # trusted checkpoint/inclusion verifier produces evidence locally, the
    # transparency axis remains explicitly unsupported and fails closed when
    # policy requires it.
    transparency_verified = False
    blockers = []
    if not verified_signature:
        blockers.append("dsse_signature_invalid_or_untrusted")
    if not subject_match:
        blockers.append("attestation_subject_digest_mismatch")
    if not predicate_allowed:
        blockers.append("predicate_type_not_allowed")
    if not builder_allowed:
        blockers.append("builder_identity_not_allowed")
    if require_transparency_log and not transparency_verified:
        blockers.append("transparency_log_proof_required")

    verified = not blockers
    return {
        **result,
        "status": "PASS" if verified else "FAIL",
        "verified": verified,
        "provenance_class": "externally_attested" if verified else "declared",
        "payload_type": payload_type,
        "statement_type": statement.get("_type"),
        "predicate_type": predicate_type or None,
        "predicate_allowed": predicate_allowed,
        "builder_id": builder_id,
        "builder_allowed": builder_allowed,
        "subject_sha256": subject_sha256,
        "attested_subject_sha256": sorted(subject_digests),
        "subject_digest_match": subject_match,
        "signature": verified_signature,
        "transparency_log_verified": transparency_verified,
        "transparency_log_status": "UNSUPPORTED",
        "blockers": blockers,
        "statement_sha256": hashlib.sha256(payload).hexdigest(),
        "envelope_sha256": hashlib.sha256(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
