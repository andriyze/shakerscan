import asyncio
import inspect
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
import api  # noqa: E402


def test_legacy_scan_is_preflight_by_default_and_submission_cannot_carry_authority():
    assert api.ModelIntakeScanRequest(artifact_url="https://models.example/model.safetensors").intake_mode == "preflight"

    with pytest.raises(Exception):
        api.ModelSubmissionRequest(
            source="hf://acme/model@revision/model.safetensors",
            intended_environment="production",
            trust_anchor_ids=["requester-selected"],
        )

    request = api.ModelIntakeScanRequest(
        artifact_url="https://models.example/model.safetensors",
        intake_mode="admission",
        metadata_json={"deployment_approved": True},
    )
    with pytest.raises(api.HTTPException, match="server-owned"):
        api._validate_model_intake_admission_request_authority(request)


def test_legacy_scan_rejects_admission_before_enrichment_or_queueing():
    request = api.ModelIntakeScanRequest(
        artifact_url="https://models.example/model.safetensors",
        intake_mode="admission",
        metadata_json={
            "repository_manifest": {
                "complete": True,
                "files": [{"path": "model.safetensors", "size": 1}],
            },
            "python_files": [],
            "custom_code_required": False,
        },
    )

    with pytest.raises(api.HTTPException) as caught:
        asyncio.run(api.scan_model_intake(request))

    assert caught.value.status_code == 409
    assert caught.value.detail == {
        "code": "legacy_model_intake_admission_mode_removed",
        "message": (
            "POST /model-intake/scan is preflight-only and cannot create an admission candidate. "
            "Use /model-intake/submissions and the controlled evidence, approval, policy, and "
            "promotion workflow for deployment authorization."
        ),
        "required_intake_mode": "preflight",
        "authoritative_workflow": "/model-intake/submissions",
    }


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


def test_signer_has_narrow_route_auth_and_no_production_local_key():
    code = """
import os
import model_intake_signer_service as service
routes = {route.path for route in service.app.routes}
assert '/internal/model-intake/admissions/issue' in routes
assert all('/sign' not in route for route in routes)
os.environ['MODEL_INTAKE_SIGNER_INTERNAL_TOKEN'] = 'x' * 32
try:
    service._authorize_internal('wrong')
except service.HTTPException:
    pass
else:
    raise AssertionError('wrong internal token accepted')
os.environ['MODEL_INTAKE_SIGNER_BACKEND'] = 'local-pem'
os.environ['MODEL_INTAKE_SIGNER_ALLOW_LOCAL_PEM'] = 'true'
os.environ['MODEL_INTAKE_CONTROL_PLANE_SIGNING_KEY_PEM'] = 'not-used'
try:
    service._signer_provider('production')
except Exception as exc:
    assert 'prohibited for production' in str(exc)
else:
    raise AssertionError('production local PEM signer accepted')
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "api")
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


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


def test_partial_or_scanner_omitting_scan_cannot_become_pass_static_evidence():
    apparently_clean = {
        "acquisition_complete": True,
        "inspection_complete": True,
        "checksum_status": "verified",
    }
    checks = api._model_intake_required_static_checks(apparently_clean)
    assert checks["repository_snapshot_complete"] is False
    assert checks["generated_evidence_pass"] is False
    assert not all(checks.values())
