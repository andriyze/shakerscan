import inspect
from pathlib import Path
import re
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import api  # noqa: E402
import model_intake_signer_service as signer_service  # noqa: E402
from model_intake_control_plane import AdmissionContractError  # noqa: E402


def test_legacy_scan_is_preflight_by_default_and_submission_cannot_carry_authority():
    assert api.ModelIntakeScanRequest(artifact_url="https://models.example/model.safetensors").intake_mode == "preflight"

    with pytest.raises(Exception):
        api.ModelSubmissionRequest(
            source="hf://acme/model@revision/model.safetensors",
            intended_environment="production",
            trust_anchor_ids=["requester-selected"],
        )


def test_approval_dto_has_no_identity_or_role_claim_fields():
    fields = set(api.ModelApprovalCreateRequest.model_fields)
    assert "approved_by_subject" not in fields
    assert "approved_by_role" not in fields
    assert "approver" not in fields


def test_scoped_trust_anchor_routes_attestation_and_publisher_keys_separately():
    request = api.ModelIntakeScanRequest(
        artifact_url="https://models.example/model.safetensors",
        intake_mode="admission",
    )
    merged = api._merge_model_intake_trust_anchor_material(request, [
        {
            "id": "publisher",
            "name": "publisher",
            "purpose": "publisher_signature",
            "environment": "production",
            "version": "1",
            "public_key_pem": "publisher-pem",
        },
        {
            "id": "attestation",
            "name": "attestation",
            "purpose": "upstream_attestation",
            "environment": "production",
            "version": "2",
            "public_key_pem": "attestation-pem",
            "builder_id_constraint": "https://builder.example/model",
        },
    ])

    assert merged.signature_trusted_keys == ["publisher-pem"]
    assert merged.attestation_trusted_keys == ["attestation-pem"]
    assert merged.required_attestation_builder_ids == ["https://builder.example/model"]


def test_signer_has_no_generic_signing_endpoint_and_requires_internal_auth(monkeypatch):
    routes = {route.path for route in signer_service.app.routes}
    assert "/internal/model-intake/admissions/issue" in routes
    assert all("/sign" not in route for route in routes)

    monkeypatch.setenv("MODEL_INTAKE_SIGNER_INTERNAL_TOKEN", "x" * 32)
    with pytest.raises(signer_service.HTTPException):
        signer_service._authorize_internal("wrong")


def test_local_pem_signer_cannot_issue_production(monkeypatch):
    monkeypatch.setenv("MODEL_INTAKE_SIGNER_BACKEND", "local-pem")
    monkeypatch.setenv("MODEL_INTAKE_SIGNER_ALLOW_LOCAL_PEM", "true")
    monkeypatch.setenv("MODEL_INTAKE_CONTROL_PLANE_SIGNING_KEY_PEM", "not-used")

    with pytest.raises(AdmissionContractError, match="prohibited for production"):
        signer_service._signer_provider("production")


def test_compose_keeps_signer_authority_out_of_workers():
    root = Path(__file__).resolve().parents[1]
    for compose_name in ("docker-compose.yml", "docker-compose.release.yml"):
        source = (root / compose_name).read_text()
        signer_block = re.search(
            r"(?ms)^  model-intake-signer:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)", source
        ).group(0)
        assert "MODEL_INTAKE_CONTROL_PLANE_SIGNING_KEY_PEM" in signer_block
        worker_block = re.search(
            r"(?ms)^  worker:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)", source
        ).group(0)
        assert "MODEL_INTAKE_CONTROL_PLANE_SIGNING_KEY_PEM" not in worker_block
        assert "MODEL_INTAKE_SIGNER_AWS_KMS_KEY_ID" not in worker_block


def test_promotion_api_sends_only_stored_decision_id_and_idempotency_key():
    source = inspect.getsource(api._call_model_intake_signer)
    assert '"policy_decision_id"' in source
    assert '"idempotency_key"' in source
    for forbidden in ("deployment_bundle", "evidence_manifest", "approval", "private_key"):
        assert f'"{forbidden}"' not in source
