"""Canonical signed admission statements for Model Intake."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any


SCHEMA_VERSION = "model-intake-admission/v1"
_PEM_PUBLIC_KEY_RE = __import__("re").compile(
    r"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", __import__("re").DOTALL
)


def canonical_bytes(statement: dict[str, Any]) -> bytes:
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _public_key_fingerprint(key: Any) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return hashlib.sha256(key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def signing_available(private_key_pem: Any = None) -> bool:
    return bool(private_key_pem or os.getenv("MODEL_INTAKE_ADMISSION_SIGNING_KEY_PEM"))


def trusted_public_keys_from_env(value: Any = None) -> list[str]:
    """Read deployment trust roots without ever accepting them from an admission package."""
    raw = value if value is not None else os.getenv("MODEL_INTAKE_ADMISSION_TRUSTED_PUBLIC_KEYS", "")
    if isinstance(raw, (list, tuple, set)):
        return [str(item).strip() for item in raw if str(item).strip()]
    text = str(raw or "").strip()
    if not text:
        return []
    try:
        decoded = json.loads(text)
        if isinstance(decoded, list):
            return [str(item).strip() for item in decoded if str(item).strip()]
        if isinstance(decoded, str):
            text = decoded.strip()
    except json.JSONDecodeError:
        pass
    pem_blocks = _PEM_PUBLIC_KEY_RE.findall(text)
    return [block.strip() for block in pem_blocks] if pem_blocks else [text]


def build_statement(
    *,
    subject_sha256: str | None,
    repository_snapshot_sha256: str | None,
    generated_evidence_sha256: str | None,
    sandbox_evidence_sha256: str | None,
    attestation_evidence_sha256: str | None,
    evaluation_evidence_sha256: str | None,
    policy_profile: str | None,
    policy_version: str | None,
    decision: str,
    decision_reason: str,
    findings_digest: str,
    expires_days: int = 30,
) -> dict[str, Any]:
    issued = datetime.now(timezone.utc)
    return {
        "_type": SCHEMA_VERSION,
        "subject": {
            "artifact_sha256": subject_sha256,
            "repository_snapshot_sha256": repository_snapshot_sha256,
        },
        "evidence": {
            "generated_evidence_sha256": generated_evidence_sha256,
            "sandbox_evidence_sha256": sandbox_evidence_sha256,
            "attestation_evidence_sha256": attestation_evidence_sha256,
            "evaluation_evidence_sha256": evaluation_evidence_sha256,
            "findings_sha256": findings_digest,
        },
        "policy": {"profile": policy_profile, "version": policy_version},
        "decision": {"outcome": decision, "reason": decision_reason},
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(days=max(1, min(int(expires_days), 365)))).isoformat(),
    }


def sign_statement(statement: dict[str, Any], private_key_pem: Any = None) -> dict[str, Any]:
    pem = private_key_pem or os.getenv("MODEL_INTAKE_ADMISSION_SIGNING_KEY_PEM")
    if not pem:
        return {"status": "UNSUPPORTED", "error": "admission_signing_key_unavailable", "statement": statement}
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key = load_pem_private_key(pem if isinstance(pem, bytes) else str(pem).encode(), password=None)
        message = canonical_bytes(statement)
        if isinstance(key, ed25519.Ed25519PrivateKey):
            signature = key.sign(message)
            algorithm = "ed25519"
        elif isinstance(key, rsa.RSAPrivateKey):
            signature = key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            algorithm = "rsa-pss-sha256"
        else:
            return {"status": "UNSUPPORTED", "error": "unsupported_admission_key_type", "statement": statement}
        return {
            "status": "SIGNED",
            "statement": statement,
            "statement_sha256": hashlib.sha256(message).hexdigest(),
            "signature": base64.b64encode(signature).decode(),
            "algorithm": algorithm,
            "key_fingerprint": _public_key_fingerprint(key),
        }
    except Exception as exc:
        return {"status": "FAILED", "error": f"{type(exc).__name__}: {exc}", "statement": statement}


def verify_package(
    package: Any,
    *,
    trusted_public_keys: Any,
    expected_artifact_sha256: str | None = None,
    expected_repository_snapshot_sha256: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    result = {"verified": False, "status": "FAIL", "blockers": []}
    if not isinstance(package, dict) or not isinstance(package.get("statement"), dict):
        return {**result, "blockers": ["invalid_package"]}
    statement = package["statement"]
    if statement.get("_type") != SCHEMA_VERSION:
        result["blockers"].append("unsupported_statement_type")
    message = canonical_bytes(statement)
    if package.get("statement_sha256") != hashlib.sha256(message).hexdigest():
        result["blockers"].append("statement_digest_mismatch")
    subject = statement.get("subject") if isinstance(statement.get("subject"), dict) else {}
    artifact_subject = str(subject.get("artifact_sha256") or "").lower()
    snapshot_subject = str(subject.get("repository_snapshot_sha256") or "").lower()
    if not __import__("re").fullmatch(r"[0-9a-f]{64}", artifact_subject):
        result["blockers"].append("missing_or_invalid_artifact_subject")
    if expected_artifact_sha256 and subject.get("artifact_sha256") != expected_artifact_sha256:
        result["blockers"].append("artifact_subject_mismatch")
    if expected_repository_snapshot_sha256 and subject.get("repository_snapshot_sha256") != expected_repository_snapshot_sha256:
        result["blockers"].append("repository_snapshot_subject_mismatch")
    if snapshot_subject and not __import__("re").fullmatch(r"[0-9a-f]{64}", snapshot_subject):
        result["blockers"].append("invalid_repository_snapshot_subject")
    issued = None
    try:
        issued = datetime.fromisoformat(str(statement.get("issued_at") or "").replace("Z", "+00:00"))
        if issued.tzinfo is None:
            issued = issued.replace(tzinfo=timezone.utc)
    except ValueError:
        result["blockers"].append("invalid_issued_at")
    try:
        expires = datetime.fromisoformat(str(statement.get("expires_at") or "").replace("Z", "+00:00"))
        current = now or datetime.now(timezone.utc)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= current:
            result["blockers"].append("admission_expired")
        if issued and issued > current + timedelta(minutes=5):
            result["blockers"].append("admission_issued_in_future")
        if issued and expires <= issued:
            result["blockers"].append("invalid_validity_window")
    except ValueError:
        result["blockers"].append("invalid_expiry")
    try:
        signature = base64.b64decode(str(package.get("signature") or ""), validate=True)
    except Exception:
        signature = b""
    fingerprints = []
    signature_valid = False
    keys = trusted_public_keys if isinstance(trusted_public_keys, (list, tuple, set)) else [trusted_public_keys]
    if not any(keys):
        result["blockers"].append("no_trusted_admission_keys_configured")
    for pem in keys:
        if not pem:
            continue
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
            key = load_pem_public_key(pem if isinstance(pem, bytes) else str(pem).encode())
            fingerprint = hashlib.sha256(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
            fingerprints.append(fingerprint)
            if fingerprint != package.get("key_fingerprint"):
                continue
            if isinstance(key, ed25519.Ed25519PublicKey) and package.get("algorithm") == "ed25519":
                key.verify(signature, message)
            elif isinstance(key, rsa.RSAPublicKey) and package.get("algorithm") == "rsa-pss-sha256":
                key.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            else:
                continue
            signature_valid = True
            break
        except (InvalidSignature, ValueError, TypeError, ImportError):
            continue
    if not signature_valid:
        result["blockers"].append("signature_invalid_or_untrusted")
    result.update({
        "verified": not result["blockers"],
        "status": "PASS" if not result["blockers"] else "FAIL",
        "statement_sha256": hashlib.sha256(message).hexdigest(),
        "trusted_key_fingerprints": fingerprints,
    })
    return result


__all__ = [
    "SCHEMA_VERSION",
    "build_statement",
    "canonical_bytes",
    "sign_statement",
    "signing_available",
    "trusted_public_keys_from_env",
    "verify_package",
]
