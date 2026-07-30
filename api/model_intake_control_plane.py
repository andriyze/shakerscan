"""Trusted Model Intake admission-v2 primitives.

This module accepts only already-resolved server records. It never downloads,
parses, or executes model content and intentionally has no scanner imports.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol


DEPLOYMENT_BUNDLE_SCHEMA = "model-deployment-bundle/v1"
EVIDENCE_MANIFEST_SCHEMA = "model-intake-evidence-manifest/v1"
APPROVAL_SCHEMA = "model-intake-approval/v1"
POLICY_FACTS_SCHEMA = "model-admission-facts/v1"
POLICY_DECISION_SCHEMA = "model-intake-policy-decision/v1"
ADMISSION_SCHEMA = "model-intake-admission/v2"
ADMISSION_PREDICATE_TYPE = "https://shakerscan.dev/attestation/model-admission/v2"
POLICY_BUNDLE_VERSION = "shakerscan-embedded-model-admission-policy/v3"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ALLOWED_ENVIRONMENTS = {"development", "test", "staging", "production"}
ALLOWED_PROVENANCE = {
    "DECLARED",
    "PROVIDER_RESOLVED",
    "GENERATED_STATIC",
    "GENERATED_RUNTIME",
    "GENERATED_EVALUATION",
    "GENERATED_DATA_PLANE",
    "HUMAN_APPROVAL",
    "POLICY_DECISION",
    "DEPLOYMENT_OBSERVED",
}

PRODUCTION_REQUIRED_EVIDENCE = {
    "static_analysis": "GENERATED_STATIC",
    "runtime_execution": "GENERATED_RUNTIME",
    "embedding_evaluation": "GENERATED_EVALUATION",
    "data_plane_evaluation": "GENERATED_DATA_PLANE",
}
PRODUCTION_REQUIRED_APPROVALS = {
    "model_security_reviewer",
    "ml_platform_reviewer",
    "release_manager",
}
EVIDENCE_BINDING_KEYS = {
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
}


class AdmissionContractError(ValueError):
    """Raised when trusted control-plane records violate the v2 contract."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def policy_bundle_identity(expected_sha256: str | None = None) -> dict[str, Any]:
    """Identify the exact shipped policy source and reject a mismatched operator pin."""
    try:
        source = Path(__file__).resolve().read_bytes()
    except OSError as exc:
        raise AdmissionContractError("embedded policy source is unavailable") from exc
    manifest = {
        "schema_version": "model-intake-policy-bundle/v1",
        "version": POLICY_BUNDLE_VERSION,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "policy_facts_schema": POLICY_FACTS_SCHEMA,
        "policy_decision_schema": POLICY_DECISION_SCHEMA,
        "production_required_evidence": dict(sorted(PRODUCTION_REQUIRED_EVIDENCE.items())),
        "production_required_approvals": sorted(PRODUCTION_REQUIRED_APPROVALS),
    }
    bundle_sha256 = digest_json(manifest)
    configured = str(expected_sha256 or "").strip().lower()
    if configured:
        if not SHA256_RE.fullmatch(configured):
            raise AdmissionContractError("configured policy bundle digest is invalid")
        if configured != bundle_sha256:
            raise AdmissionContractError("configured policy bundle digest does not match shipped policy")
    return {**manifest, "bundle_sha256": bundle_sha256}


def _self_digest_valid(value: dict[str, Any], field: str) -> bool:
    claimed = value.get(field)
    unsigned = {key: item for key, item in value.items() if key != field}
    return isinstance(claimed, str) and claimed == digest_json(unsigned)


def _sha256(value: Any, field: str, *, optional: bool = False) -> str | None:
    normalized = str(value or "").strip().lower().removeprefix("sha256:")
    if optional and not normalized:
        return None
    if not SHA256_RE.fullmatch(normalized):
        raise AdmissionContractError(f"{field} must be a lowercase SHA-256 digest")
    return normalized


def _oci_digest(value: Any, field: str) -> str:
    normalized = str(value or "").strip().lower()
    if not OCI_DIGEST_RE.fullmatch(normalized):
        raise AdmissionContractError(f"{field} must be an immutable sha256: OCI digest")
    return normalized


def _timestamp(value: Any, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise AdmissionContractError(f"{field} must be an ISO-8601 timestamp") from exc
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def build_deployment_bundle(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise AdmissionContractError("deployment bundle must be an object")
    environment = str(data.get("target_environment") or "").strip().lower()
    if environment not in ALLOWED_ENVIRONMENTS:
        raise AdmissionContractError("target_environment is invalid")
    embedding = data.get("embedding_configuration")
    if not isinstance(embedding, dict):
        raise AdmissionContractError("embedding_configuration is required")
    try:
        dimension = int(embedding.get("dimension"))
        max_sequence_length = int(embedding.get("max_sequence_length"))
    except (TypeError, ValueError) as exc:
        raise AdmissionContractError("embedding dimension and max_sequence_length are required integers") from exc
    if dimension <= 0 or dimension > 1_000_000 or max_sequence_length <= 0 or max_sequence_length > 10_000_000:
        raise AdmissionContractError("embedding dimensions are outside bounded limits")
    bundle = {
        "schema_version": DEPLOYMENT_BUNDLE_SCHEMA,
        "model_artifact_sha256": _sha256(data.get("model_artifact_sha256"), "model_artifact_sha256"),
        "repository_snapshot_sha256": _sha256(data.get("repository_snapshot_sha256"), "repository_snapshot_sha256"),
        "custom_code_sha256": _sha256(data.get("custom_code_sha256"), "custom_code_sha256", optional=True),
        "tokenizer_sha256": _sha256(data.get("tokenizer_sha256"), "tokenizer_sha256"),
        "configuration_sha256": _sha256(data.get("configuration_sha256"), "configuration_sha256"),
        "runtime_image_digest": _oci_digest(data.get("runtime_image_digest"), "runtime_image_digest"),
        "loader_profile_sha256": _sha256(data.get("loader_profile_sha256"), "loader_profile_sha256"),
        "embedding_configuration": {
            "dimension": dimension,
            "pooling": str(embedding.get("pooling") or "").strip(),
            "normalization": bool(embedding.get("normalization")),
            "max_sequence_length": max_sequence_length,
            "precision": str(embedding.get("precision") or "").strip().lower(),
        },
        "retrieval_application_digest": _sha256(
            data.get("retrieval_application_digest"), "retrieval_application_digest"
        ),
        "index_schema_digest": _sha256(data.get("index_schema_digest"), "index_schema_digest"),
        "target_environment": environment,
    }
    if not bundle["embedding_configuration"]["pooling"] or not bundle["embedding_configuration"]["precision"]:
        raise AdmissionContractError("embedding pooling and precision are required")
    bundle["bundle_sha256"] = digest_json(bundle)
    return bundle


def freeze_evidence_manifest(
    *,
    submission_id: str,
    subject_bundle_sha256: str,
    version: int,
    evidence_records: list[dict[str, Any]],
    frozen_by: str,
    frozen_at: datetime | None = None,
) -> dict[str, Any]:
    try:
        normalized_submission = str(uuid.UUID(str(submission_id)))
    except ValueError as exc:
        raise AdmissionContractError("submission_id must be a UUID") from exc
    if version < 1:
        raise AdmissionContractError("manifest version must be positive")
    if not evidence_records:
        raise AdmissionContractError("at least one evidence record is required")
    normalized_records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in evidence_records:
        record_id = str(uuid.UUID(str(record.get("id"))))
        if record_id in seen:
            raise AdmissionContractError("duplicate evidence record")
        seen.add(record_id)
        provenance = str(record.get("provenance_class") or "").strip().upper()
        if provenance not in ALLOWED_PROVENANCE:
            raise AdmissionContractError("unsupported evidence provenance")
        status = str(record.get("status") or "").strip().upper()
        if status not in {"PASS", "FAIL", "WARNING", "INCOMPLETE", "UNSUPPORTED", "TIMEOUT", "CRASHED"}:
            raise AdmissionContractError("unsupported evidence status")
        bindings = record.get("subject_bindings")
        if not isinstance(bindings, dict) or not bindings:
            raise AdmissionContractError("evidence subject bindings are required")
        normalized_records.append({
            "id": record_id,
            "evidence_type": str(record.get("evidence_type") or "").strip(),
            "schema_version": str(record.get("schema_version") or "").strip(),
            "provenance_class": provenance,
            "producer_id": str(record.get("producer_id") or "").strip(),
            "producer_version": str(record.get("producer_version") or "").strip(),
            "builder_id": str(record.get("builder_id") or "").strip(),
            "invocation_id": str(record.get("invocation_id") or "").strip(),
            "subject_bindings": bindings,
            "payload_sha256": _sha256(record.get("payload_sha256"), "payload_sha256"),
            "status": status,
            "expires_at": str(record.get("expires_at") or "") or None,
        })
        required = normalized_records[-1]
        if not all(required[key] for key in ("evidence_type", "schema_version", "producer_id", "builder_id", "invocation_id")):
            raise AdmissionContractError("evidence producer and invocation identity are required")
    manifest = {
        "schema_version": EVIDENCE_MANIFEST_SCHEMA,
        "submission_id": normalized_submission,
        "version": version,
        "subject_bundle_sha256": _sha256(subject_bundle_sha256, "subject_bundle_sha256"),
        "evidence": sorted(normalized_records, key=lambda item: item["id"]),
        "frozen_at": (frozen_at or utc_now()).isoformat(),
        "frozen_by": str(frozen_by or "").strip(),
    }
    if not manifest["frozen_by"]:
        raise AdmissionContractError("frozen_by authenticated identity is required")
    manifest["manifest_sha256"] = digest_json(manifest)
    return manifest


def build_approval_receipt(
    *,
    submission_id: str,
    subject_bundle_sha256: str,
    evidence_manifest_sha256: str,
    policy_bundle_sha256: str,
    environment: str,
    approval_type: str,
    decision: str,
    approved_by_subject: str,
    approved_by_role: str,
    reason: str,
    expires_at: datetime,
    restrictions: list[str] | None = None,
    approval_id: str | None = None,
    approved_at: datetime | None = None,
) -> dict[str, Any]:
    environment = str(environment).strip().lower()
    if environment not in ALLOWED_ENVIRONMENTS:
        raise AdmissionContractError("approval environment is invalid")
    decision = str(decision).strip().lower()
    if decision not in {"approve", "reject"}:
        raise AdmissionContractError("approval decision must be approve or reject")
    approved_at = approved_at or utc_now()
    expires_at = expires_at.astimezone(timezone.utc)
    if expires_at <= approved_at:
        raise AdmissionContractError("approval expiry must follow approval time")
    receipt = {
        "schema_version": APPROVAL_SCHEMA,
        "approval_id": str(uuid.UUID(approval_id)) if approval_id else str(uuid.uuid4()),
        "submission_id": str(uuid.UUID(str(submission_id))),
        "subject_bundle_sha256": _sha256(subject_bundle_sha256, "subject_bundle_sha256"),
        "evidence_manifest_sha256": _sha256(evidence_manifest_sha256, "evidence_manifest_sha256"),
        "policy_bundle_sha256": _sha256(policy_bundle_sha256, "policy_bundle_sha256"),
        "environment": environment,
        "approval_type": str(approval_type or "").strip(),
        "decision": decision,
        "restrictions": sorted(set(str(item).strip() for item in restrictions or [] if str(item).strip())),
        "approved_by_subject": str(approved_by_subject or "").strip(),
        "approved_by_role": str(approved_by_role or "").strip(),
        "approved_at": approved_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "reason": str(reason or "").strip(),
    }
    if not all(receipt[key] for key in ("approval_type", "approved_by_subject", "approved_by_role", "reason")):
        raise AdmissionContractError("approval identity, role, type, and reason are required")
    receipt["receipt_sha256"] = digest_json(receipt)
    return receipt


def evaluate_policy(
    *,
    deployment_bundle: dict[str, Any],
    evidence_manifest: dict[str, Any],
    approvals: list[dict[str, Any]],
    submitter_subject: str,
    policy_bundle_sha256: str,
    policy_provider: str = "shakerscan-embedded/v2",
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    blockers: list[str] = []
    missing_controls: list[str] = []
    bundle_digest = _sha256(deployment_bundle.get("bundle_sha256"), "bundle_sha256")
    manifest_digest = _sha256(evidence_manifest.get("manifest_sha256"), "manifest_sha256")
    if not _self_digest_valid(deployment_bundle, "bundle_sha256"):
        blockers.append("deployment_bundle_digest_invalid")
    if not _self_digest_valid(evidence_manifest, "manifest_sha256"):
        blockers.append("evidence_manifest_digest_invalid")
    if evidence_manifest.get("subject_bundle_sha256") != bundle_digest:
        blockers.append("evidence_manifest_subject_mismatch")
    environment = str(deployment_bundle.get("target_environment") or "")
    evidence = evidence_manifest.get("evidence") if isinstance(evidence_manifest.get("evidence"), list) else []
    evidence_by_type = {str(item.get("evidence_type")): item for item in evidence if isinstance(item, dict)}
    reviewable_evidence: list[str] = []
    required_evidence = PRODUCTION_REQUIRED_EVIDENCE if environment == "production" else {
        "static_analysis": "GENERATED_STATIC"
    }
    for evidence_type, provenance in required_evidence.items():
        item = evidence_by_type.get(evidence_type)
        if not item:
            missing_controls.append(f"evidence:{evidence_type}")
        elif item.get("provenance_class") != provenance:
            blockers.append(f"untrusted_provenance:{evidence_type}")
        else:
            if item.get("status") == "WARNING" and evidence_type == "static_analysis":
                reviewable_evidence.append(evidence_type)
            elif item.get("status") != "PASS":
                blockers.append(f"evidence_non_pass:{evidence_type}:{str(item.get('status')).lower()}")
            if item.get("expires_at") and _timestamp(item["expires_at"], "evidence expires_at") <= now:
                blockers.append(f"evidence_expired:{evidence_type}")
            bindings = item.get("subject_bindings") if isinstance(item.get("subject_bindings"), dict) else {}
            mismatches = [
                key for key in EVIDENCE_BINDING_KEYS[evidence_type]
                if bindings.get(key) != deployment_bundle.get(key)
            ]
            blockers.extend(f"evidence_subject_mismatch:{evidence_type}:{key}" for key in mismatches)
    required_approvals = PRODUCTION_REQUIRED_APPROVALS if environment == "production" else set()
    approved_roles: set[str] = set()
    required_role_subjects: dict[str, str] = {}
    approval_digests: list[str] = []
    for approval in approvals:
        approval_digests.append(_sha256(approval.get("receipt_sha256"), "approval receipt_sha256") or "")
        if not _self_digest_valid(approval, "receipt_sha256"):
            blockers.append("approval_receipt_digest_invalid")
        if approval.get("subject_bundle_sha256") != bundle_digest:
            blockers.append("approval_subject_mismatch")
        if approval.get("evidence_manifest_sha256") != manifest_digest:
            blockers.append("approval_evidence_manifest_mismatch")
        if approval.get("policy_bundle_sha256") != policy_bundle_sha256:
            blockers.append("approval_policy_mismatch")
        if approval.get("environment") != environment:
            blockers.append("approval_environment_mismatch")
        if approval.get("decision") != "approve":
            blockers.append("approval_rejected")
        if _timestamp(approval.get("expires_at"), "approval expires_at") <= now:
            blockers.append("approval_expired")
        if approval.get("approved_by_subject") == submitter_subject:
            blockers.append("submitter_self_approval")
        approved_roles.add(str(approval.get("approved_by_role") or ""))
        role = str(approval.get("approved_by_role") or "")
        if role in required_approvals:
            required_role_subjects[role] = str(approval.get("approved_by_subject") or "")
    if reviewable_evidence and "model_security_reviewer" not in approved_roles:
        blockers.extend(f"evidence_review_required:{item}" for item in reviewable_evidence)
    for role in sorted(required_approvals - approved_roles):
        missing_controls.append(f"approval:{role}")
    if len(set(required_role_subjects.values())) < len(required_role_subjects):
        blockers.append("approval_separation_of_duties_violation")
    decision = "block" if blockers else "review" if missing_controls else "allow"
    facts = {
        "schema_version": POLICY_FACTS_SCHEMA,
        "subject": deployment_bundle,
        "environment": environment,
        "evidence_manifest_sha256": manifest_digest,
        "evidence": evidence,
        "approvals": sorted(approval_digests),
        "submitter_subject_sha256": hashlib.sha256(submitter_subject.encode()).hexdigest(),
    }
    result = {
        "schema_version": POLICY_DECISION_SCHEMA,
        "decision_id": str(uuid.uuid4()),
        "decision": decision,
        "reasons": sorted(set(blockers + missing_controls)),
        "missing_controls": sorted(set(missing_controls)),
        "restrictions": sorted({item for approval in approvals for item in approval.get("restrictions", [])}),
        "maximum_expiry": min(
            (_timestamp(item["expires_at"], "approval expires_at") for item in approvals),
            default=now + timedelta(days=1),
        ).isoformat(),
        "reassessment_triggers": [
            "artifact_digest",
            "runtime_change",
            "loader_change",
            "policy_change",
            "policy_bundle_change",
            "trust_anchor_change",
            "signer_key_change",
            "approval_change",
            "approval_expiry",
            "scanner_update",
            "scanner_data_stale",
            "cve_update",
            "authorization_incident",
        ],
        "policy_provider": policy_provider,
        "reviewed_warning_evidence": (
            sorted(reviewable_evidence) if "model_security_reviewer" in approved_roles else []
        ),
        "policy_bundle_sha256": _sha256(policy_bundle_sha256, "policy_bundle_sha256"),
        "input_sha256": digest_json(facts),
        "facts": facts,
        "created_at": now.isoformat(),
    }
    result["decision_sha256"] = digest_json(result)
    return result


class SignerProvider(Protocol):
    provider_id: str

    def sign(self, message: bytes) -> dict[str, str]: ...


class LocalPemSigner:
    """Development-only signer kept outside worker environments."""

    provider_id = "local-pem-development"

    def __init__(self, private_key_pem: str | bytes):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        self._key = load_pem_private_key(
            private_key_pem if isinstance(private_key_pem, bytes) else private_key_pem.encode(),
            password=None,
        )

    def sign(self, message: bytes) -> dict[str, str]:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        if isinstance(self._key, ed25519.Ed25519PrivateKey):
            signature = self._key.sign(message)
            algorithm = "ed25519"
        elif isinstance(self._key, rsa.RSAPrivateKey):
            signature = self._key.sign(
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            algorithm = "rsa-pss-sha256"
        else:
            raise AdmissionContractError("unsupported local signer key type")
        public_der = self._key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return {
            "signature": base64.b64encode(signature).decode(),
            "algorithm": algorithm,
            "key_id": hashlib.sha256(public_der).hexdigest(),
            "provider": self.provider_id,
        }


class AwsKmsSigner:
    """Narrow AWS KMS provider; the service still decides the exact payload."""

    def __init__(self, key_id: str, *, region: str | None = None, client: Any = None):
        if not str(key_id or "").strip():
            raise AdmissionContractError("AWS KMS key id is required")
        if client is None:
            try:
                import boto3  # type: ignore
            except ImportError as exc:
                raise AdmissionContractError("AWS KMS signer requires the optional boto3 runtime") from exc
            client = boto3.client("kms", region_name=region)
        self._client = client
        self._key_id = key_id
        self.provider_id = f"aws-kms:{key_id}"

    def sign(self, message: bytes) -> dict[str, str]:
        public = self._client.get_public_key(KeyId=self._key_id)
        algorithms = set(public.get("SigningAlgorithms") or [])
        algorithm = "RSASSA_PSS_SHA_256"
        if algorithm not in algorithms:
            raise AdmissionContractError("AWS KMS key does not support RSASSA_PSS_SHA_256")
        response = self._client.sign(
            KeyId=self._key_id,
            Message=hashlib.sha256(message).digest(),
            MessageType="DIGEST",
            SigningAlgorithm=algorithm,
        )
        public_der = bytes(public.get("PublicKey") or b"")
        signature = bytes(response.get("Signature") or b"")
        if not public_der or not signature:
            raise AdmissionContractError("AWS KMS returned incomplete signing material")
        return {
            "signature": base64.b64encode(signature).decode(),
            "algorithm": "rsa-pss-sha256",
            "key_id": hashlib.sha256(public_der).hexdigest(),
            "provider": self.provider_id,
        }


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(type_bytes), type_bytes, len(payload), payload)


def issue_admission_v2(
    *,
    deployment_bundle: dict[str, Any],
    evidence_manifest: dict[str, Any],
    policy_decision: dict[str, Any],
    approvals: list[dict[str, Any]],
    signer: SignerProvider,
    admission_builder_id: str,
    idempotency_key: str,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    if policy_decision.get("decision") != "allow":
        raise AdmissionContractError("narrow signer refuses a non-allow policy decision")
    if not _self_digest_valid(deployment_bundle, "bundle_sha256"):
        raise AdmissionContractError("deployment bundle digest is invalid")
    if not _self_digest_valid(evidence_manifest, "manifest_sha256"):
        raise AdmissionContractError("evidence manifest digest is invalid")
    if not _self_digest_valid(policy_decision, "decision_sha256"):
        raise AdmissionContractError("policy decision digest is invalid")
    if any(not _self_digest_valid(item, "receipt_sha256") for item in approvals):
        raise AdmissionContractError("approval receipt digest is invalid")
    if evidence_manifest.get("subject_bundle_sha256") != deployment_bundle.get("bundle_sha256"):
        raise AdmissionContractError("evidence manifest does not bind the deployment bundle")
    facts = policy_decision.get("facts") if isinstance(policy_decision.get("facts"), dict) else {}
    if facts.get("subject") != deployment_bundle or facts.get("evidence_manifest_sha256") != evidence_manifest.get("manifest_sha256"):
        raise AdmissionContractError("policy decision does not bind the exact bundle and evidence manifest")
    if policy_decision.get("input_sha256") != digest_json(facts):
        raise AdmissionContractError("policy input digest is invalid")
    approval_digests = sorted(item["receipt_sha256"] for item in approvals)
    if sorted(facts.get("approvals") or []) != approval_digests:
        raise AdmissionContractError("policy decision approval set does not match")
    if len(str(idempotency_key or "")) < 16:
        raise AdmissionContractError("idempotency_key must contain at least 16 characters")
    issued_at = issued_at or utc_now()
    maximum_expiry = _timestamp(policy_decision.get("maximum_expiry"), "maximum_expiry")
    if maximum_expiry <= issued_at:
        raise AdmissionContractError("policy decision is already expired")
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": ADMISSION_PREDICATE_TYPE,
        "schema_version": ADMISSION_SCHEMA,
        "subject": [
            {"name": "model-deployment-bundle", "digest": {"sha256": deployment_bundle["bundle_sha256"]}},
            {"name": "model-artifact", "digest": {"sha256": deployment_bundle["model_artifact_sha256"]}},
            {"name": "repository-snapshot", "digest": {"sha256": deployment_bundle["repository_snapshot_sha256"]}},
            {"name": "runtime-image", "digest": {"sha256": deployment_bundle["runtime_image_digest"].removeprefix("sha256:")}},
        ],
        "predicate": {
            "decision": "allow",
            "deployment_bundle": deployment_bundle,
            "evidence_manifest_sha256": evidence_manifest["manifest_sha256"],
            "policy_decision_sha256": policy_decision["decision_sha256"],
            "policy_bundle_sha256": policy_decision["policy_bundle_sha256"],
            "approval_receipt_sha256": approval_digests,
            "restrictions": policy_decision.get("restrictions", []),
            "reassessment_triggers": policy_decision.get("reassessment_triggers", []),
            "target_environment": deployment_bundle["target_environment"],
            "admission_builder_id": str(admission_builder_id or "").strip(),
            "issued_at": issued_at.isoformat(),
            "expires_at": maximum_expiry.isoformat(),
        },
    }
    if not statement["predicate"]["admission_builder_id"]:
        raise AdmissionContractError("admission_builder_id is required")
    payload = canonical_bytes(statement)
    signature = signer.sign(_dsse_pae(ADMISSION_PREDICATE_TYPE, payload))
    envelope = {
        "payloadType": ADMISSION_PREDICATE_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{
            "keyid": signature["key_id"],
            "sig": signature["signature"],
            "algorithm": signature["algorithm"],
            "provider": signature["provider"],
        }],
    }
    return {
        "status": "SIGNED",
        "deployable": True,
        "schema_version": ADMISSION_SCHEMA,
        "statement": statement,
        "statement_sha256": hashlib.sha256(payload).hexdigest(),
        "envelope": envelope,
        "idempotency_key_sha256": hashlib.sha256(idempotency_key.encode()).hexdigest(),
    }


def verify_admission_v2(
    package: Any,
    *,
    trusted_public_keys: list[str],
    trusted_builder_ids: set[str],
    expected_bundle_sha256: str,
    expected_environment: str,
    expected_components: dict[str, str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    blockers: list[str] = []
    if not isinstance(package, dict) or package.get("schema_version") != ADMISSION_SCHEMA:
        return {"verified": False, "status": "FAIL", "blockers": ["unsupported_admission_schema"]}
    envelope = package.get("envelope") if isinstance(package.get("envelope"), dict) else {}
    if envelope.get("payloadType") != ADMISSION_PREDICATE_TYPE:
        blockers.append("invalid_payload_type")
    try:
        payload = base64.b64decode(str(envelope.get("payload") or ""), validate=True)
        statement = json.loads(payload)
    except (ValueError, json.JSONDecodeError):
        return {"verified": False, "status": "FAIL", "blockers": ["invalid_dsse_payload"]}
    if canonical_bytes(statement) != payload or statement != package.get("statement"):
        blockers.append("noncanonical_or_mismatched_statement")
    if hashlib.sha256(payload).hexdigest() != package.get("statement_sha256"):
        blockers.append("statement_digest_mismatch")
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    bundle = predicate.get("deployment_bundle") if isinstance(predicate.get("deployment_bundle"), dict) else {}
    if statement.get("schema_version") != ADMISSION_SCHEMA or statement.get("predicateType") != ADMISSION_PREDICATE_TYPE:
        blockers.append("unsupported_statement_schema")
    if predicate.get("decision") != "allow":
        blockers.append("admission_decision_not_allow")
    if not _self_digest_valid(bundle, "bundle_sha256"):
        blockers.append("deployment_bundle_digest_invalid")
    expected_bundle = _sha256(expected_bundle_sha256, "expected_bundle_sha256")
    if bundle.get("bundle_sha256") != expected_bundle:
        blockers.append("deployment_bundle_mismatch")
    if predicate.get("target_environment") != expected_environment or bundle.get("target_environment") != expected_environment:
        blockers.append("target_environment_mismatch")
    if predicate.get("admission_builder_id") not in trusted_builder_ids:
        blockers.append("admission_builder_untrusted")
    for field, expected in (expected_components or {}).items():
        if bundle.get(field) != expected:
            blockers.append(f"component_mismatch:{field}")
    current = now or utc_now()
    try:
        issued_at = _timestamp(predicate.get("issued_at"), "issued_at")
        expires_at = _timestamp(predicate.get("expires_at"), "expires_at")
        if issued_at > current + timedelta(minutes=5):
            blockers.append("admission_issued_in_future")
        if expires_at <= current:
            blockers.append("admission_expired")
        if expires_at <= issued_at:
            blockers.append("invalid_validity_window")
    except AdmissionContractError:
        blockers.append("invalid_admission_time")
    signatures = envelope.get("signatures") if isinstance(envelope.get("signatures"), list) else []
    signature_entry = signatures[0] if len(signatures) == 1 and isinstance(signatures[0], dict) else {}
    try:
        signature = base64.b64decode(str(signature_entry.get("sig") or ""), validate=True)
    except ValueError:
        signature = b""
    signature_valid = False
    fingerprints: list[str] = []
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
    except ImportError:
        blockers.append("cryptography_runtime_unavailable")
    else:
        for public_pem in trusted_public_keys:
            try:
                key = load_pem_public_key(public_pem.encode())
                fingerprint = hashlib.sha256(
                    key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
                ).hexdigest()
                fingerprints.append(fingerprint)
                if fingerprint != signature_entry.get("keyid"):
                    continue
                message = _dsse_pae(ADMISSION_PREDICATE_TYPE, payload)
                if isinstance(key, ed25519.Ed25519PublicKey) and signature_entry.get("algorithm") == "ed25519":
                    key.verify(signature, message)
                elif isinstance(key, rsa.RSAPublicKey) and signature_entry.get("algorithm") == "rsa-pss-sha256":
                    key.verify(
                        signature,
                        message,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256(),
                    )
                else:
                    continue
                signature_valid = True
                break
            except (InvalidSignature, TypeError, ValueError):
                continue
    if not trusted_public_keys:
        blockers.append("no_trusted_admission_keys_configured")
    if not signature_valid:
        blockers.append("signature_invalid_or_untrusted")
    return {
        "verified": not blockers,
        "status": "PASS" if not blockers else "FAIL",
        "blockers": sorted(set(blockers)),
        "statement_sha256": hashlib.sha256(payload).hexdigest(),
        "deployment_bundle_sha256": bundle.get("bundle_sha256"),
        "target_environment": predicate.get("target_environment"),
        "trusted_key_fingerprints": fingerprints,
    }


__all__ = [
    "ADMISSION_SCHEMA",
    "AdmissionContractError",
    "AwsKmsSigner",
    "LocalPemSigner",
    "build_approval_receipt",
    "build_deployment_bundle",
    "digest_json",
    "evaluate_policy",
    "freeze_evidence_manifest",
    "issue_admission_v2",
    "verify_admission_v2",
]
