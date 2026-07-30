import asyncio
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
import api  # noqa: E402


def _operator_request(token: str):
    return api.Request({
        "type": "http",
        "method": "POST",
        "path": "/model-intake/submissions",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
        "client": ("127.0.0.1", 40123),
        "server": ("127.0.0.1", 8080),
        "scheme": "http",
        "query_string": b"",
    })


def test_submission_and_approval_use_one_authenticated_subject(monkeypatch):
    token = "model-intake-operator-token-that-is-long-enough"
    monkeypatch.setenv("MODEL_INTAKE_OPERATOR_TOKEN", token)
    request = _operator_request(token)

    submitter = api._model_intake_submission_subject(request)
    approver = api._model_intake_authenticated_subject(request)

    assert submitter == approver
    assert submitter.startswith("operator-token:")


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


def test_runner_job_dto_has_no_path_profile_or_command_authority():
    fields = set(api.ModelRunnerJobCreateRequest.model_fields)
    assert fields == {
        "operation", "deployment_bundle", "known_answer_inputs",
        "known_answer_embedding_sha256", "vcpu_count", "memory_mib", "timeout_seconds",
    }
    with pytest.raises(Exception):
        api.ModelRunnerJobCreateRequest(
            operation="runtime",
            deployment_bundle={},
            command=["/bin/sh"],
        )


def test_keyless_model_intake_agent_dtos_have_no_authority_or_provider_fields():
    assert set(api.ModelIntakeAgentSessionRequest.model_fields) == {
        "objective", "max_iterations", "action_budget",
    }
    assert set(api.ModelIntakeAgentReplyRequest.model_fields) == {"reply"}
    source = inspect.getsource(api._execute_model_intake_agent_action)
    for forbidden in ("subprocess", "shell=True", "model_intake_admissions", "model_intake_approval_receipts"):
        assert forbidden not in source


def test_runner_materialization_reconstructs_exact_content_addressed_snapshot(tmp_path, monkeypatch):
    results = tmp_path / "results"
    content = b"bounded safetensors fixture"
    artifact_sha = hashlib.sha256(content).hexdigest()
    object_path = results / "model-intake-quarantine" / "sha256" / artifact_sha[:2] / artifact_sha
    object_path.parent.mkdir(parents=True)
    object_path.write_bytes(content)
    canonical = {
        "provider": "huggingface",
        "repository": "acme/model",
        "revision": "1" * 40,
        "files": [{"path": "model.safetensors", "size_bytes": len(content), "sha256": artifact_sha}],
    }
    snapshot_sha = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    scan_result = {"model_intake": {
        "metadata": {"library_name": "transformers"},
        "repository_snapshot": {
            "complete": True,
            "snapshot_sha256": snapshot_sha,
            "repository": "acme/model",
            "revision": "1" * 40,
            "repository_manifest": {"provider": "huggingface"},
            "files": [{
                "path": "model.safetensors",
                "size_bytes": len(content),
                "sha256": artifact_sha,
                "quarantine_object": f"sha256:{artifact_sha}",
            }],
        },
    }}
    monkeypatch.setattr(api, "RESULTS_DIR", results)
    monkeypatch.setenv("MODEL_INTAKE_RUNNER_HOST_RESULTS_ROOT", "/srv/shakerscan/results")

    materialized = api._model_intake_snapshot_materialization(
        scan_result,
        artifact_sha256=artifact_sha,
        repository_snapshot_sha256=snapshot_sha,
    )

    assert materialized["subject_path"] == f"/srv/shakerscan/results/model-intake-runner-subjects/{snapshot_sha}"
    assert materialized["artifact_path"] == "model.safetensors"
    assert materialized["profile_manifest"]["custom_code_required"] is False
    assert (results / "model-intake-runner-subjects" / snapshot_sha / "model.safetensors").read_bytes() == content

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


def test_preflight_trust_is_selected_from_durable_server_state(monkeypatch):
    class Conn:
        def __init__(self):
            self.query = ""
            self.args = ()

        async def fetch(self, query, *args):
            self.query = query
            self.args = args
            return [{
                "id": uuid.uuid4(),
                "name": "publisher",
                "purpose": "publisher_signature",
                "environment": "production",
                "policy_profile": "production",
                "version": "1",
                "public_key_pem": "server-owned-publisher-pem",
                "public_key_sha256": None,
                "builder_id_constraint": None,
            }]

    class Acquire:
        def __init__(self, conn):
            self.conn = conn

        async def __aenter__(self):
            return self.conn

        async def __aexit__(self, *_args):
            return False

    class Pool:
        def __init__(self, conn):
            self.conn = conn

        def acquire(self):
            return Acquire(self.conn)

    conn = Conn()
    monkeypatch.setattr(api, "db_pool", Pool(conn))
    request = api.ModelIntakeScanRequest(
        artifact_url="https://models.example/model.safetensors",
        intake_mode="preflight",
        policy_profile="production",
    )

    merged = asyncio.run(api._expand_model_intake_saved_trust_anchors(request))

    assert merged.signature_trusted_keys == ["server-owned-publisher-pem"]
    assert merged.metadata_json["selected_trust_anchors"][0]["name"] == "publisher"
    assert conn.args == ("production",)
    assert "id = ANY" not in conn.query
    assert "valid_until IS NULL OR valid_until > NOW()" in conn.query


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
        assert "postgresql://model_intake_signer:" in signer_block
        assert "- signer-control" in signer_block
        assert "- default" not in signer_block
        worker_block = re.search(
            r"(?ms)^  worker:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)", source
        ).group(0)
        assert "MODEL_INTAKE_CONTROL_PLANE_SIGNING_KEY_PEM" not in worker_block
        assert "MODEL_INTAKE_SIGNER_AWS_KMS_KEY_ID" not in worker_block
        assert "signer-control" not in worker_block


def test_signer_image_and_database_role_are_narrow_and_releasable():
    dockerfile = (ROOT / "api" / "model_intake_signer.Dockerfile").read_text()
    role_script = (ROOT / "db" / "configure-model-intake-signer-role.sh").read_text()
    publisher = (ROOT / "scripts" / "publish-images.sh").read_text()
    release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()

    assert "scanner/Dockerfile" not in dockerfile
    assert "worker.py" not in dockerfile
    assert "model_intake_signer_service.py" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "boto3==" in (ROOT / "api" / "model_intake_signer.requirements.lock").read_text()
    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE" in role_script
    assert "UPDATE (state, updated_at)" in role_script
    assert "REVOKE CREATE ON SCHEMA public" in role_script
    assert "shakerscan-model-intake-signer" in publisher
    assert "file: api/model_intake_signer.Dockerfile" in release_workflow
    assert "Create Model Intake signer manifest list" in release_workflow


def test_signer_request_preserves_only_server_derived_operator_identity():
    fields = api.ModelPromotionRequest.model_fields
    assert "requested_by_subject" not in fields
    source = inspect.getsource(api.promote_model_intake_submission)
    assert "requested_by_subject = _model_intake_authenticated_subject" in source
    signer_source = (ROOT / "api" / "model_intake_signer_service.py").read_text()
    assert r'^operator-token:[0-9a-f]{24}$' in signer_source
    assert '"issued_by_service": "model-intake-signer"' in signer_source


def test_fresh_and_upgrade_schemas_share_deployment_binding_admission_fk():
    root = Path(__file__).resolve().parents[1]
    init_sql = (root / "db" / "init.sql").read_text()
    migrations = (root / "api" / "retest_contract.py").read_text()
    constraint = "model_intake_deployment_bindings_admission_id_fkey"

    for source in (init_sql, migrations):
        assert constraint in source
        assert "FOREIGN KEY (admission_id) REFERENCES model_intake_admissions(id) ON DELETE SET NULL" in source

    assert "SET admission_id = NULL" in migrations


def test_runtime_evaluation_payload_is_durable_and_not_confused_with_data_plane_evidence():
    init_sql = (ROOT / "db" / "init.sql").read_text()
    migrations = (ROOT / "api" / "retest_contract.py").read_text()
    persist_source = inspect.getsource(api._persist_model_intake_runner_evidence)
    for source in (init_sql, migrations):
        assert "payload_json JSONB" in source
    assert "derive_model_runner_embedding_evaluation" in persist_source
    assert "'embedding_evaluation'" in persist_source
    assert "data_plane_evaluation" not in persist_source


def test_submission_state_machine_rejects_authority_skips():
    assert api._model_intake_transition_is_allowed("submitted", "evidence_ready") is True
    assert api._model_intake_transition_is_allowed("evidence_ready", "awaiting_approval") is True
    assert api._model_intake_transition_is_allowed("awaiting_approval", "policy_decided") is True
    assert api._model_intake_transition_is_allowed("policy_decided", "admitted") is True
    assert api._model_intake_transition_is_allowed("submitted", "admitted") is False
    assert api._model_intake_transition_is_allowed("evidence_ready", "policy_decided") is False
    assert api._model_intake_transition_is_allowed("cancelled", "evidence_ready") is False


def test_new_authoritative_evidence_invalidates_active_deployment_authority():
    class Conn:
        def __init__(self):
            self.state = "admitted"
            self.executions = []
            self.fetches = []

        async def fetch(self, query, *_args):
            assert "UPDATE model_intake_admissions" in query
            self.fetches.append(query)
            return [{"id": uuid.UUID("11111111-1111-4111-8111-111111111111"), "statement_sha256": "a" * 64}]

        async def fetchrow(self, query, *_args):
            assert "SELECT state FROM model_intake_submissions" in query
            return {"state": self.state}

        async def execute(self, query, *args):
            self.executions.append((query, args))
            if "UPDATE model_intake_deployment_bindings" in query:
                return "UPDATE 1"
            if "UPDATE model_intake_submissions SET state" in query:
                self.state = args[1]
                return "UPDATE 1"
            return "INSERT 0 1"

    conn = Conn()
    result = asyncio.run(api._reset_model_intake_for_new_evidence(
        conn,
        uuid.UUID("22222222-2222-4222-8222-222222222222"),
        actor="operator-token:test",
        evidence_type="runtime_execution",
        evidence_id="33333333-3333-4333-8333-333333333333",
    ))

    assert result == {"admissions_invalidated": 1, "deployment_bindings_staled": 1}
    assert conn.state == "evidence_ready"
    sql = "\n".join(conn.fetches + [query for query, _args in conn.executions])
    assert "status='reassessment_required'" in sql
    assert "verifier_status='STALE'" in sql
    assert "authoritative_evidence_changed" in sql
    assert any("authoritative_evidence_attached" in args for _query, args in conn.executions)


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
