import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_control_plane import LocalPemSigner, canonical_bytes  # noqa: E402
from model_intake_runner_receipts import PAYLOAD_TYPE, SCHEMA, issue_runner_envelope, verify_runner_envelope  # noqa: E402


def _envelope(evidence_type, observations):
    now = datetime.now(timezone.utc)
    payload = {
        "schema_version": SCHEMA,
        "receipt_id": str(uuid.uuid4()),
        "submission_id": str(uuid.uuid4()),
        "evidence_type": evidence_type,
        "environment": "production",
        "deployment_bundle_sha256": "1" * 64,
        "model_artifact_sha256": "2" * 64,
        "repository_snapshot_sha256": "3" * 64,
        "tokenizer_sha256": "6" * 64,
        "configuration_sha256": "7" * 64,
        "runtime_image_digest": "sha256:" + "4" * 64,
        "loader_profile_sha256": "5" * 64,
        "builder_id": "runner://prod-1",
        "runner_version": "1.0.0",
        "invocation_id": str(uuid.uuid4()),
        "status": "PASS",
        "observations": observations,
        "started_at": (now - timedelta(minutes=2)).isoformat(),
        "finished_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    private = ed25519.Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    public_pem = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    body = canonical_bytes(payload)
    message = b"DSSEv1 %d %s %d %s" % (len(PAYLOAD_TYPE.encode()), PAYLOAD_TYPE.encode(), len(body), body)
    signed = LocalPemSigner(private_pem).sign(message)
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(body).decode(),
        "signatures": [{"keyid": signed["key_id"], "sig": signed["signature"], "algorithm": signed["algorithm"]}],
    }
    return payload, envelope, public_pem


def _verify(payload, envelope, public_pem):
    return verify_runner_envelope(
        envelope,
        expected_submission_id=payload["submission_id"],
        expected_environment="production",
        trusted_public_keys=[public_pem],
        trusted_builder_ids={"runner://prod-1"},
    )


def _runtime_observations(**overrides):
    network = {
        "schema_version": "model-intake-network-telemetry/v1",
        "no_network_device": True,
        "network_interface_config_count": 0,
        "tap_device_count": 0,
        "guest_interfaces": ["lo"],
        "host_interfaces": ["lo"],
        "attempted_operations": [],
        "attempt_count": 0,
        "attempts_by_phase": {},
        "host_firewall_drop_count": 0,
        "raw_trace_sha256": "a" * 64,
        "complete": True,
        "overflowed": False,
        "lost_events": 0,
    }
    network["telemetry_sha256"] = __import__("hashlib").sha256(canonical_bytes(network)).hexdigest()
    observations = {
        "artifact_loaded": True,
        "model_loaded": True,
        "embedding_known_answers_status": "PASS",
        "network_egress_blocked": True,
        "network_telemetry": network,
        "syscall_telemetry_complete": True,
        "resource_limits_enforced": True,
    }
    observations.update(overrides)
    return observations


def test_runtime_pass_requires_real_generated_isolation_and_load_observations():
    payload, envelope, key = _envelope("runtime_execution", _runtime_observations())
    assert _verify(payload, envelope, key)["verified"] is True


def test_runner_receipt_requires_tokenizer_and_configuration_subject_bindings():
    payload, _envelope_value, key = _envelope("runtime_execution", _runtime_observations())
    del payload["tokenizer_sha256"]
    body = canonical_bytes(payload)
    private = ed25519.Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    message = b"DSSEv1 %d %s %d %s" % (len(PAYLOAD_TYPE.encode()), PAYLOAD_TYPE.encode(), len(body), body)
    signature = private.sign(message)
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(body).decode(),
        "signatures": [{
            "keyid": __import__("hashlib").sha256(private.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest(),
            "sig": base64.b64encode(signature).decode(),
            "algorithm": "ed25519",
        }],
    }

    result = verify_runner_envelope(
        envelope,
        expected_submission_id=payload["submission_id"],
        expected_environment="production",
        trusted_public_keys=[public_pem],
        trusted_builder_ids={"runner://prod-1"},
    )

    assert result["verified"] is False
    assert "invalid_subject_binding" in result["blockers"]


def test_runner_issuer_refuses_to_sign_incomplete_pass_claim():
    now = datetime.now(timezone.utc)
    payload = {
        "schema_version": SCHEMA,
        "evidence_type": "runtime_execution",
        "status": "PASS",
        "observations": {"artifact_loaded": True},
        "started_at": now.isoformat(),
        "finished_at": now.isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    private = ed25519.Ed25519PrivateKey.generate()
    signer = LocalPemSigner(private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())
    import pytest
    with pytest.raises(Exception, match="invalid PASS claim"):
        issue_runner_envelope(payload, signer)


def test_evaluation_and_data_plane_pass_claims_are_semantically_checked():
    eval_payload, eval_envelope, eval_key = _envelope("embedding_evaluation", {
        "observations_generated_by_runner": True,
        "security_status": "PASS",
        "benchmark_dataset_sha256": "a" * 64,
        "thresholds_sha256": "b" * 64,
        "embedding_output_sha256": "c" * 64,
    })
    assert _verify(eval_payload, eval_envelope, eval_key)["verified"] is True

    data_payload, data_envelope, data_key = _envelope("data_plane_evaluation", {
        "security_status": "PASS",
        "connector_id": "pgvector-prod",
        "index_id": "knowledge-graph-v1",
        "principals_tested": 2,
        "cross_tenant_leaks": 0,
        "deletion_verified": True,
        "cache_authorization_verified": True,
    })
    assert _verify(data_payload, data_envelope, data_key)["verified"] is True


def test_signed_pass_with_missing_runtime_observation_is_rejected():
    payload, envelope, key = _envelope("runtime_execution", {
        "artifact_loaded": True,
        "model_loaded": True,
    })
    result = _verify(payload, envelope, key)
    assert result["verified"] is False
    assert "pass_claim_missing:syscall_telemetry" in result["blockers"]


def test_signed_pass_with_network_attempt_or_tampered_telemetry_is_rejected():
    observations = _runtime_observations()
    observations["network_telemetry"]["attempt_count"] = 1
    observations["network_telemetry"]["attempted_operations"] = [{
        "operation": "connect", "phase": "load", "destination_digest": "b" * 64,
        "destination_port": 443, "dns_related": False,
    }]
    payload, envelope, key = _envelope("runtime_execution", observations)
    result = _verify(payload, envelope, key)
    assert result["verified"] is False
    assert "pass_claim_missing:no_network_attempts" in result["blockers"]
    assert "pass_claim_missing:network_telemetry_digest" in result["blockers"]


def test_conversion_receipt_requires_tensor_numeric_and_embedding_equivalence():
    observations = _runtime_observations()
    observations.update({
        "source_artifact_sha256": "f" * 64,
        "target_artifact_sha256": "2" * 64,
        "tensor_inventory_equivalent": True,
        "numeric_equivalence_status": "PASS",
        "embedding_equivalence_status": "PASS",
        "converter_image_digest": "sha256:" + "d" * 64,
    })
    payload, envelope, key = _envelope("conversion_equivalence", observations)
    assert _verify(payload, envelope, key)["verified"] is True
