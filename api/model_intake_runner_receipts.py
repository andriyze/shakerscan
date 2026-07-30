"""Signed, exact-subject evidence receipts from isolated Model Intake runners."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid
from typing import Any

try:
    from model_intake_control_plane import canonical_bytes
except ModuleNotFoundError:  # pragma: no cover - package import in tests
    from api.model_intake_control_plane import canonical_bytes


PAYLOAD_TYPE = "https://shakerscan.dev/attestation/model-evidence/v1"
SCHEMA = "model-intake-runner-receipt/v2"
EVIDENCE_POLICY = {
    "runtime_execution": ("GENERATED_RUNTIME", "runtime_runner"),
    "embedding_evaluation": ("GENERATED_EVALUATION", "evaluation_runner"),
    "data_plane_evaluation": ("GENERATED_DATA_PLANE", "data_plane_runner"),
    "conversion_equivalence": ("GENERATED_RUNTIME", "runtime_runner"),
}


class RunnerReceiptError(ValueError):
    pass


def issue_runner_envelope(payload: dict[str, Any], signer: Any) -> dict[str, Any]:
    """Sign one canonical, fully bound runner payload with a narrow signer."""
    if payload.get("schema_version") != SCHEMA:
        raise RunnerReceiptError("unsupported runner receipt schema")
    if payload.get("evidence_type") not in EVIDENCE_POLICY:
        raise RunnerReceiptError("unsupported runner evidence type")
    if payload.get("status") == "PASS":
        missing = _validate_pass_claim(payload)
        if missing:
            raise RunnerReceiptError(f"invalid PASS claim: {','.join(sorted(missing))}")
    body = canonical_bytes(payload)
    message = b"DSSEv1 %d %s %d %s" % (
        len(PAYLOAD_TYPE.encode()), PAYLOAD_TYPE.encode(), len(body), body
    )
    signed = signer.sign(message)
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(body).decode(),
        "signatures": [{
            "keyid": signed["key_id"],
            "sig": signed["signature"],
            "algorithm": signed["algorithm"],
            "provider": signed.get("provider"),
        }],
        "payload_sha256": hashlib.sha256(body).hexdigest(),
    }


def _parse_time(value: Any, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise RunnerReceiptError(f"invalid {field}") from exc
    if parsed.tzinfo is None:
        raise RunnerReceiptError(f"{field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _sha(value: Any, field: str) -> str:
    normalized = str(value or "").lower().removeprefix("sha256:")
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise RunnerReceiptError(f"invalid {field}")
    return normalized


def _validate_pass_claim(payload: dict[str, Any]) -> list[str]:
    observations = payload.get("observations") if isinstance(payload.get("observations"), dict) else {}
    kind = payload["evidence_type"]
    missing: list[str] = []
    if kind == "runtime_execution":
        network = observations.get("network_telemetry") if isinstance(observations.get("network_telemetry"), dict) else {}
        network_digest_input = {key: value for key, value in network.items() if key != "telemetry_sha256"}
        expected_network_digest = hashlib.sha256(canonical_bytes(network_digest_input)).hexdigest()
        required = {
            "artifact_loaded": observations.get("artifact_loaded") is True,
            "model_loaded": observations.get("model_loaded") is True,
            "known_answers": observations.get("embedding_known_answers_status") == "PASS",
            "no_egress": observations.get("network_egress_blocked") is True,
            "no_network_device": network.get("no_network_device") is True,
            "no_network_interface_config": network.get("network_interface_config_count") == 0,
            "no_tap_device": network.get("tap_device_count") == 0,
            "guest_interface_inventory": network.get("guest_interfaces") == ["lo"],
            "host_interface_inventory": network.get("host_interfaces") == ["lo"],
            "no_network_attempts": network.get("attempt_count") == 0 and network.get("attempted_operations") == [],
            "host_firewall_quiet": network.get("host_firewall_drop_count") == 0,
            "network_telemetry_complete": network.get("complete") is True,
            "network_telemetry_not_overflowed": network.get("overflowed") is False,
            "network_telemetry_no_loss": network.get("lost_events") == 0,
            "network_telemetry_digest": network.get("telemetry_sha256") == expected_network_digest,
            "network_raw_trace_digest": bool(network.get("raw_trace_sha256")),
            "syscall_telemetry": observations.get("syscall_telemetry_complete") is True,
            "resource_limits": observations.get("resource_limits_enforced") is True,
        }
    elif kind == "embedding_evaluation":
        required = {
            "generated": observations.get("observations_generated_by_runner") is True,
            "security": observations.get("security_status") == "PASS",
            "benchmark": bool(observations.get("benchmark_dataset_sha256")),
            "thresholds": bool(observations.get("thresholds_sha256")),
            "embedding_digest": bool(observations.get("embedding_output_sha256")),
        }
    elif kind == "data_plane_evaluation":
        required = {
            "security": observations.get("security_status") == "PASS",
            "connector": bool(observations.get("connector_id")),
            "index": bool(observations.get("index_id")),
            "principals": int(observations.get("principals_tested") or 0) >= 2,
            "cross_tenant": (
                isinstance(observations.get("cross_tenant_leaks"), int)
                and observations.get("cross_tenant_leaks") == 0
            ),
            "deletion": observations.get("deletion_verified") is True,
            "cache_auth": observations.get("cache_authorization_verified") is True,
        }
    else:
        required = {
            "source_digest": bool(observations.get("source_artifact_sha256")),
            "target_digest": observations.get("target_artifact_sha256") == payload.get("model_artifact_sha256"),
            "tensor_inventory": observations.get("tensor_inventory_equivalent") is True,
            "numeric": observations.get("numeric_equivalence_status") == "PASS",
            "embedding": observations.get("embedding_equivalence_status") == "PASS",
            "converter": bool(observations.get("converter_image_digest")),
        }
    for name, passed in required.items():
        if not passed:
            missing.append(name)
    return missing


def verify_runner_envelope(
    envelope: Any,
    *,
    expected_submission_id: str,
    expected_environment: str,
    trusted_public_keys: list[str],
    trusted_builder_ids: set[str],
    now: datetime | None = None,
) -> dict[str, Any]:
    blockers: list[str] = []
    if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
        return {"verified": False, "blockers": ["invalid_runner_payload_type"]}
    try:
        payload_bytes = base64.b64decode(str(envelope.get("payload") or ""), validate=True)
        payload = json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        return {"verified": False, "blockers": ["invalid_runner_payload"]}
    if canonical_bytes(payload) != payload_bytes:
        blockers.append("runner_payload_not_canonical")
    if payload.get("schema_version") != SCHEMA:
        blockers.append("unsupported_runner_receipt_schema")
    evidence_type = str(payload.get("evidence_type") or "")
    if evidence_type not in EVIDENCE_POLICY:
        blockers.append("unsupported_evidence_type")
    try:
        if str(uuid.UUID(str(payload.get("submission_id")))) != str(uuid.UUID(expected_submission_id)):
            blockers.append("submission_mismatch")
        _sha(payload.get("deployment_bundle_sha256"), "deployment_bundle_sha256")
        _sha(payload.get("model_artifact_sha256"), "model_artifact_sha256")
        _sha(payload.get("repository_snapshot_sha256"), "repository_snapshot_sha256")
        _sha(payload.get("loader_profile_sha256"), "loader_profile_sha256")
        image = str(payload.get("runtime_image_digest") or "")
        if not image.startswith("sha256:"):
            blockers.append("runtime_image_not_digest_pinned")
        else:
            _sha(image, "runtime_image_digest")
    except (ValueError, RunnerReceiptError):
        blockers.append("invalid_subject_binding")
    if payload.get("environment") != expected_environment:
        blockers.append("environment_mismatch")
    builder_id = str(payload.get("builder_id") or "")
    if not builder_id or builder_id not in trusted_builder_ids:
        blockers.append("runner_builder_untrusted")
    current = now or datetime.now(timezone.utc)
    try:
        started = _parse_time(payload.get("started_at"), "started_at")
        finished = _parse_time(payload.get("finished_at"), "finished_at")
        expires = _parse_time(payload.get("expires_at"), "expires_at")
        if not started <= finished <= current + timedelta(minutes=5):
            blockers.append("invalid_runner_execution_window")
        if expires <= current or expires <= finished:
            blockers.append("runner_receipt_expired")
    except RunnerReceiptError:
        blockers.append("invalid_runner_timestamps")
    if payload.get("status") == "PASS":
        blockers.extend(f"pass_claim_missing:{item}" for item in _validate_pass_claim(payload))
    elif payload.get("status") not in {"FAIL", "INCOMPLETE", "TIMEOUT", "CRASHED", "UNSUPPORTED"}:
        blockers.append("invalid_runner_status")

    signatures = envelope.get("signatures") if isinstance(envelope.get("signatures"), list) else []
    entry = signatures[0] if len(signatures) == 1 and isinstance(signatures[0], dict) else {}
    try:
        signature = base64.b64decode(str(entry.get("sig") or ""), validate=True)
    except ValueError:
        signature = b""
    message = b"DSSEv1 %d %s %d %s" % (
        len(PAYLOAD_TYPE.encode()), PAYLOAD_TYPE.encode(), len(payload_bytes), payload_bytes
    )
    signature_valid = False
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
        for pem in trusted_public_keys:
            try:
                key = load_pem_public_key(pem.encode())
                key_id = hashlib.sha256(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
                if key_id != entry.get("keyid"):
                    continue
                if isinstance(key, ed25519.Ed25519PublicKey) and entry.get("algorithm") == "ed25519":
                    key.verify(signature, message)
                elif isinstance(key, rsa.RSAPublicKey) and entry.get("algorithm") == "rsa-pss-sha256":
                    key.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size), hashes.SHA256())
                else:
                    continue
                signature_valid = True
                break
            except Exception:
                continue
    except ImportError:
        blockers.append("cryptography_runtime_unavailable")
    if not signature_valid:
        blockers.append("runner_signature_invalid_or_untrusted")
    return {
        "verified": not blockers,
        "status": "PASS" if not blockers else "FAIL",
        "blockers": sorted(set(blockers)),
        "payload": payload,
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "evidence_type": evidence_type,
        "provenance_class": EVIDENCE_POLICY.get(evidence_type, (None, None))[0],
        "required_anchor_purpose": EVIDENCE_POLICY.get(evidence_type, (None, None))[1],
    }


__all__ = ["EVIDENCE_POLICY", "PAYLOAD_TYPE", "SCHEMA", "issue_runner_envelope", "verify_runner_envelope"]
