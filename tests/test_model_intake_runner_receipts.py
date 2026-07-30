import base64
from datetime import datetime, timedelta, timezone
import json
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from api.model_intake_control_plane import LocalPemSigner, canonical_bytes
from api.model_intake_runner_receipts import PAYLOAD_TYPE, SCHEMA, verify_runner_envelope


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


def test_runtime_pass_requires_real_generated_isolation_and_load_observations():
    payload, envelope, key = _envelope("runtime_execution", {
        "artifact_loaded": True,
        "model_loaded": True,
        "embedding_known_answers_status": "PASS",
        "network_egress_blocked": True,
        "syscall_telemetry_complete": True,
        "resource_limits_enforced": True,
    })
    assert _verify(payload, envelope, key)["verified"] is True


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


def test_conversion_receipt_requires_tensor_numeric_and_embedding_equivalence():
    payload, envelope, key = _envelope("conversion_equivalence", {
        "source_artifact_sha256": "f" * 64,
        "target_artifact_sha256": "2" * 64,
        "tensor_inventory_equivalent": True,
        "numeric_equivalence_status": "PASS",
        "embedding_equivalence_status": "PASS",
        "converter_image_digest": "sha256:" + "d" * 64,
    })
    assert _verify(payload, envelope, key)["verified"] is True
