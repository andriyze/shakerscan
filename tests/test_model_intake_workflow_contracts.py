import asyncio
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
import api  # noqa: E402


def test_automatic_review_payload_decodes_jsonb_for_browser_contract():
    review_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)
    payload = api._model_intake_automatic_review_payload({
        "id": review_id,
        "scan_id": scan_id,
        "timeline_json": json.dumps([{"event": "static_scan_queued", "state": "static_scan_pending"}]),
        "pending_controls": json.dumps([{"control": "publisher_trust", "status": "PENDING"}]),
        "error_json": json.dumps({"code": "runner_not_ready"}),
        "deployment_bundle_json": json.dumps({"model_artifact_sha256": "a" * 64}),
        "created_at": created_at,
    })

    assert payload["id"] == str(review_id)
    assert payload["scan_id"] == str(scan_id)
    assert payload["created_at"] == created_at.isoformat()
    assert payload["timeline_json"] == [{"event": "static_scan_queued", "state": "static_scan_pending"}]
    assert payload["pending_controls"] == [{"control": "publisher_trust", "status": "PENDING"}]
    assert payload["error_json"] == {"code": "runner_not_ready"}
    assert payload["deployment_bundle_json"] == {"model_artifact_sha256": "a" * 64}


def test_automatic_review_payload_tracks_live_static_scan_progress():
    payload = api._model_intake_automatic_review_payload({
        "id": "review-1",
        "scan_id": "scan-1",
        "state": "static_scan_pending",
        "current_step": "static_scan",
        "progress": 5,
        "static_scan_status": "running",
        "static_scan_progress": 35,
        "static_scan_phase": "artifact_acquisition",
        "timeline_json": [],
        "pending_controls": [],
    })

    assert payload["effective_progress"] == 18
    assert payload["effective_current_step"] == "artifact_acquisition"


def test_automatic_review_payload_fails_safe_for_malformed_jsonb():
    payload = api._model_intake_automatic_review_payload({
        "timeline_json": '{not-json',
        "pending_controls": '{"not":"a-list"}',
        "error_json": '[]',
        "deployment_bundle_json": '[]',
    })

    assert payload["timeline_json"] == []
    assert payload["pending_controls"] == []
    assert payload["error_json"] is None
    assert payload["deployment_bundle_json"] is None


def test_complete_artifact_size_uses_generated_observation_not_declared_metadata():
    digest = "a" * 64
    model_intake = {
        "artifact": {
            "fetch": {
                "complete": True,
                "truncated": False,
                "bytes_total": 2_627_013_817,
            }
        },
        "metadata": {"artifact_size_bytes": 1},
    }

    assert api._model_intake_artifact_size_bytes(
        model_intake,
        {"sha256": digest},
    ) == 2_627_013_817
    assert api._model_intake_artifact_size_bytes(
        {"artifact": {"fetch": {"complete": False, "bytes_total": 2_627_013_817}}},
        {"artifact_size_bytes": None},
    ) is None


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


def test_configured_model_intake_operators_have_distinct_server_owned_identities_and_roles(monkeypatch):
    security_token = "security-reviewer-credential-that-is-long-enough"
    platform_token = "platform-reviewer-credential-that-is-long-enough"
    monkeypatch.delenv("MODEL_INTAKE_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("FLEET_OPERATOR_TOKEN", raising=False)
    monkeypatch.setenv("MODEL_INTAKE_OPERATOR_CREDENTIALS_JSON", json.dumps([
        {
            "token_sha256": hashlib.sha256(security_token.encode()).hexdigest(),
            "subject": "corp:alice",
            "roles": ["model_security_reviewer"],
        },
        {
            "token_sha256": hashlib.sha256(platform_token.encode()).hexdigest(),
            "subject": "corp:bob",
            "roles": ["ml_platform_reviewer"],
        },
    ]))

    security = _operator_request(security_token)
    platform = _operator_request(platform_token)

    assert api._model_intake_authenticated_subject(security) == "operator:corp:alice"
    assert api._model_intake_authenticated_subject(platform) == "operator:corp:bob"
    assert api._model_intake_operator_roles(security) == {"model_security_reviewer"}
    assert api._model_intake_operator_roles(platform) == {"ml_platform_reviewer"}
    assert api._model_intake_submission_subject(security) != api._model_intake_authenticated_subject(platform)


def test_invalid_model_intake_operator_credential_map_fails_closed(monkeypatch):
    token = "model-intake-operator-token-that-is-long-enough"
    monkeypatch.setenv("MODEL_INTAKE_OPERATOR_TOKEN", token)
    monkeypatch.setenv("MODEL_INTAKE_OPERATOR_CREDENTIALS_JSON", '{"subject":"caller"}')

    with pytest.raises(api.HTTPException) as caught:
        api._model_intake_authenticated_subject(_operator_request(token))

    assert caught.value.status_code == 503


def test_submission_listing_and_detail_require_operator_authentication(monkeypatch):
    # Make the service configuration explicit so this test cannot depend on a
    # developer .env loaded by an earlier test or by python-dotenv discovery.
    monkeypatch.setenv("MODEL_INTAKE_OPERATOR_TOKEN", "configured-model-intake-token-that-is-long-enough")
    unauthenticated = api.Request({
        "type": "http",
        "method": "GET",
        "path": "/model-intake/submissions",
        "headers": [],
        "client": ("127.0.0.1", 40123),
        "server": ("127.0.0.1", 8080),
        "scheme": "http",
        "query_string": b"",
    })

    with pytest.raises(api.HTTPException) as listed:
        asyncio.run(api.list_model_intake_submissions(unauthenticated))
    with pytest.raises(api.HTTPException) as detailed:
        asyncio.run(api.get_model_intake_submission(str(uuid.uuid4()), unauthenticated))
    with pytest.raises(api.HTTPException) as reported:
        asyncio.run(api.get_model_intake_submission_report(str(uuid.uuid4()), unauthenticated))

    assert listed.value.status_code == 401
    assert detailed.value.status_code == 401
    assert reported.value.status_code == 401


def test_normalized_report_route_reads_authoritative_records_only(monkeypatch):
    submission_id = uuid.uuid4()

    class _Connection:
        async def fetchrow(self, query, *_args):
            assert "model_intake_submissions" in query
            return {
                "id": submission_id,
                "scan_id": None,
                "requested_by": "operator:submitter",
                "requested_environment": "production",
                "source_kind": "huggingface",
                "source_reference_hash": "a" * 64,
                "state": "submitted",
                "created_at": api.utc_now(),
                "updated_at": api.utc_now(),
            }

        async def fetch(self, _query, *_args):
            return []

    class _Acquire:
        async def __aenter__(self):
            return _Connection()

        async def __aexit__(self, *_args):
            return False

    class _Pool:
        def acquire(self):
            return _Acquire()

    monkeypatch.setattr(api, "db_pool", _Pool())
    monkeypatch.setattr(api, "_model_intake_authenticated_subject", lambda _request: "operator:reviewer")

    report = asyncio.run(api.get_model_intake_submission_report(str(submission_id), object(), "json"))

    assert report["outcome"] == "INCOMPLETE"
    assert report["submission"]["id"] == str(submission_id)
    assert "source" not in report["submission"]
    assert report["authority_bindings"]["admission_cryptographic_verification"]["verified"] is None


def test_agent_session_cancel_is_durable_and_idempotent(monkeypatch):
    session_id = uuid.uuid4()
    state = {
        "id": session_id,
        "submission_id": uuid.uuid4(),
        "objective": "review evidence",
        "status": "awaiting_planner",
        "max_iterations": 10,
        "iteration": 1,
        "action_budget": 20,
        "actions_used": 1,
        "transcript_json": [{"role": "system", "content": "bounded"}],
        "final_assessment_json": None,
        "created_by": "operator:corp:alice",
    }

    class _Transaction:
        async def __aenter__(self):
            return None

        async def __aexit__(self, *_args):
            return False

    class _Connection:
        def transaction(self):
            return _Transaction()

        async def fetchrow(self, query, *args):
            if query.lstrip().startswith("SELECT"):
                return dict(state)
            state["status"] = "cancelled"
            state["transcript_json"] = json.loads(args[1])
            return dict(state)

    class _Acquire:
        async def __aenter__(self):
            return _Connection()

        async def __aexit__(self, *_args):
            return False

    class _Pool:
        def acquire(self):
            return _Acquire()

    monkeypatch.setattr(api, "db_pool", _Pool())
    monkeypatch.setattr(api, "_model_intake_authenticated_subject", lambda _request: "operator:corp:alice")

    first = asyncio.run(api.cancel_model_intake_agent_session(str(session_id), object()))
    second = asyncio.run(api.cancel_model_intake_agent_session(str(session_id), object()))

    assert first["cancelled"] is True
    assert first["idempotent"] is False
    assert second["idempotent"] is True
    assert state["transcript_json"][-1]["content"]["authority"] == "advisory_only"


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


def test_keyless_runner_plan_uses_authoritative_static_artifact_subject_name():
    source = inspect.getsource(api._execute_model_intake_agent_action)
    assert '("artifact", bundle["model_artifact_sha256"]) not in subject_pairs' in source
    assert '("repository_snapshot", bundle["repository_snapshot_sha256"]) not in subject_pairs' in source
    assert "_model_intake_converted_snapshot_materialization" in source


def test_runner_submission_rejects_bundle_profile_that_differs_from_server_resolution():
    source = inspect.getsource(api.create_model_intake_runner_job)
    assert 'bundle["loader_profile_sha256"] != profile["profile_sha256"]' in source
    assert "authoritative server resolution" in source


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
    assert materialized["custom_code_sha256"] is None
    assert materialized["profile_manifest"]["custom_code_required"] is False
    assert (results / "model-intake-runner-subjects" / snapshot_sha / "model.safetensors").read_bytes() == content


def test_runner_materialization_derives_exact_custom_code_identity(tmp_path, monkeypatch):
    results = tmp_path / "results"
    files = {
        "model.safetensors": b"weights",
        "modeling_custom.py": b"class ReviewedModel:\n    pass\n",
        "nested/helper.py": b"VALUE = 1\n",
    }
    entries = []
    for name, content in files.items():
        digest = hashlib.sha256(content).hexdigest()
        object_path = results / "model-intake-quarantine" / "sha256" / digest[:2] / digest
        object_path.parent.mkdir(parents=True, exist_ok=True)
        object_path.write_bytes(content)
        entries.append({"path": name, "size_bytes": len(content), "sha256": digest})
    canonical = {
        "provider": "huggingface",
        "repository": "acme/custom-model",
        "revision": "2" * 40,
        "files": sorted(entries, key=lambda item: item["path"]),
    }
    snapshot_sha = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    artifact_sha = next(item["sha256"] for item in entries if item["path"] == "model.safetensors")
    scan_result = {"model_intake": {
        "metadata": {"library_name": "transformers"},
        "repository_snapshot": {
            "complete": True,
            "snapshot_sha256": snapshot_sha,
            "repository": canonical["repository"],
            "revision": canonical["revision"],
            "repository_manifest": {"provider": "huggingface"},
            "files": entries,
        },
    }}
    expected_entries = [
        {"path": item["path"], "sha256": item["sha256"]}
        for item in sorted(entries, key=lambda item: item["path"])
        if item["path"].endswith(".py")
    ]
    expected = hashlib.sha256(json.dumps(expected_entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    monkeypatch.setattr(api, "RESULTS_DIR", results)
    monkeypatch.setenv("MODEL_INTAKE_RUNNER_HOST_RESULTS_ROOT", "/srv/shakerscan/results")

    materialized = api._model_intake_snapshot_materialization(
        scan_result,
        artifact_sha256=artifact_sha,
        repository_snapshot_sha256=snapshot_sha,
    )

    assert materialized["custom_code_sha256"] == expected
    assert materialized["profile_manifest"]["custom_code_required"] is True
    assert api._model_intake_snapshot_custom_code_sha256(scan_result["model_intake"]) == expected


def test_custom_code_identity_rejects_duplicate_or_unsafe_snapshot_paths():
    for paths in (["modeling.py", "modeling.py"], ["../modeling.py"]):
        model_intake = {"repository_snapshot": {
            "complete": True,
            "files": [{"path": path, "sha256": "a" * 64} for path in paths],
        }}
        with pytest.raises(api.HTTPException, match="custom-code path is unsafe"):
            api._model_intake_snapshot_custom_code_sha256(model_intake)

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
    assert r'operator-token:[0-9a-f]{24}|operator:[A-Za-z0-9]' in signer_source
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


def test_trust_or_policy_change_invalidates_scoped_active_authority_and_bindings():
    class Conn:
        def __init__(self):
            self.fetch_args = None
            self.executions = []

        async def fetch(self, query, *args):
            assert "status='reassessment_required'" in query
            assert "target_environment" in query
            assert "policy_profile" in query
            self.fetch_args = args
            return [
                {"id": uuid.UUID("11111111-1111-4111-8111-111111111111"), "statement_sha256": "a" * 64},
                {"id": uuid.UUID("22222222-2222-4222-8222-222222222222"), "statement_sha256": "b" * 64},
            ]

        async def execute(self, query, *args):
            self.executions.append((query, args))
            return "UPDATE 2" if "UPDATE model_intake_deployment_bindings" in query else "INSERT 0 1"

    conn = Conn()
    result = asyncio.run(api._invalidate_model_intake_authority_change(
        conn,
        actor="operator:corp:alice",
        trigger_type="trust_anchor_change",
        reason="rotated runner trust",
        environments=["Production", "production"],
        policy_profiles=["corp-strict", "corp-strict"],
    ))

    assert result == {"admissions_invalidated": 2, "deployment_bindings_staled": 2}
    assert conn.fetch_args == (["production"], ["corp-strict"])
    sql = "\n".join(query for query, _args in conn.executions)
    assert sql.count("authority_changed") == 2
    assert "verifier_status='STALE'" in sql
    assert all("operator:corp:alice" in args for query, args in conn.executions if "authority_changed" in query)


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


def test_warning_only_required_scanner_evidence_stays_reviewable_not_pass_or_incomplete():
    summary = {
        "acquisition_complete": True,
        "inspection_complete": True,
        "repository_manifest_complete": True,
        "repository_snapshot_complete": True,
        "generated_evidence_status": "REVIEW_REQUIRED",
        "checksum_status": "verified",
    }
    model_intake = {"generated_evidence": {
        "required_non_pass": ["semgrep"],
        "results": [{
            "scanner": {"name": "semgrep"},
            "execution": {"status": "WARNING", "required": True},
        }],
    }}
    checks = api._model_intake_required_static_checks(summary)

    assert api._model_intake_static_evidence_status(model_intake, summary, [], checks) == "WARNING"
    assert api._model_intake_static_evidence_status(
        model_intake, summary, [{"severity": "high"}], checks,
    ) == "FAIL"
    assert not all(checks.values())


def test_license_policy_review_and_block_survive_static_evidence_binding():
    summary = {
        "acquisition_complete": True,
        "inspection_complete": True,
        "repository_manifest_complete": True,
        "repository_snapshot_complete": True,
        "generated_evidence_status": "PASS",
        "checksum_status": "verified",
    }
    checks = api._model_intake_required_static_checks(summary)
    review = {"supply_chain": {"license_compliance": {"policy_status": "REVIEW_REQUIRED"}}}
    blocked = {"supply_chain": {"license_compliance": {"policy_status": "BLOCK"}}}

    assert all(checks.values())
    assert api._model_intake_static_evidence_status(review, summary, [], checks) == "WARNING"
    assert api._model_intake_static_evidence_status(blocked, summary, [], checks) == "FAIL"


def test_complete_large_safetensors_is_not_incomplete_only_because_memory_prefix_is_bounded():
    summary = {
        "acquisition_complete": True,
        "inspection_complete": False,
        "repository_manifest_complete": True,
        "repository_snapshot_complete": True,
        "generated_evidence_status": "REVIEW_REQUIRED",
        "checksum_status": "verified",
    }
    model_intake = {
        "supply_chain": {
            "format_inspection": {
                "extension": ".safetensors",
                "safetensors_header": {
                    "valid": True,
                    "validation_complete": True,
                    "payload_bounds_checked": True,
                    "payload_coverage_complete": True,
                },
            },
        },
        "generated_evidence": {
            "required_non_pass": ["python-ast-security"],
            "results": [{
                "scanner": {"name": "python-ast-security"},
                "execution": {"status": "WARNING", "required": True},
            }],
        },
    }

    checks = api._model_intake_required_static_checks(summary, model_intake)

    assert checks["inspection_complete"] is True
    assert api._model_intake_static_evidence_status(
        model_intake, summary, [], checks,
    ) == "WARNING"


def test_bounded_unknown_or_onnx_payload_remains_incomplete_without_full_parser_evidence():
    summary = {"acquisition_complete": True, "inspection_complete": False}
    model_intake = {
        "supply_chain": {
            "format_inspection": {
                "extension": ".onnx",
                "onnx": {"parser_status": "not_executed_in_worker"},
            },
        },
    }

    checks = api._model_intake_required_static_checks(summary, model_intake)

    assert checks["inspection_complete"] is False


def test_static_report_coverage_is_content_free():
    digest = "a" * 64
    assert api._model_intake_content_free_coverage({
        "files_analyzed": 12,
        "inventory_truncated": False,
        "rules_sha256": digest,
        "first_path": "modeling_secret.py",
        "source_url": "https://example.invalid/private",
        "parse_errors": ["sensitive detail"],
    }) == {
        "files_analyzed": 12,
        "inventory_truncated": False,
        "rules_sha256": digest,
    }


def test_automatic_review_system_principal_is_server_scoped_and_not_a_bearer_shortcut():
    request = api._model_intake_automatic_system_request()

    assert request.headers.get("authorization") is None
    assert api._model_intake_authenticated_subject(request) == "system:model-intake-auto"
    assert request.scope["shakerscan.model_intake_system_actor"] == "system:model-intake-auto"

    ordinary = api.Request({
        "type": "http", "method": "POST", "path": "/", "headers": [],
        "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8080),
        "scheme": "http", "query_string": b"",
    })
    with pytest.raises(api.HTTPException):
        api._model_intake_authenticated_subject(ordinary)


def test_automatic_review_requires_fingerprint_current_workers():
    source = inspect.getsource(api.create_model_intake_automatic_review)
    schema = (ROOT / "api" / "retest_contract.py").read_text()

    assert '"require_current_workers": True' in source
    assert 'policy_profile = "research"' in source
    assert '"require_dynamic_sandbox": request.intended_environment' not in source
    assert "source_label" in source
    assert "source_label TEXT NOT NULL DEFAULT 'Model review'" in schema
    fields = api.ModelIntakeScanRequest.model_fields
    assert fields["require_current_workers"].default is False


def test_automatic_review_reports_unsupported_runtime_as_expected_incomplete():
    source = inspect.getsource(api._advance_model_intake_automatic_review)

    assert 'event="runtime_profile_unavailable"' in source
    assert '"status": "UNSUPPORTED"' in source
    assert "Static reports and bills of materials remain useful" in source


def test_automatic_review_progress_never_moves_backward_after_conversion():
    source = inspect.getsource(api._advance_model_intake_automatic_review)
    checkpoints = {
        event: int(progress)
        for progress, event in re.findall(r'progress=(\d+), event="([^"]+)"', source)
    }

    assert checkpoints["conversion_registered_and_rescanned"] < checkpoints["calibration_queued"]
    assert checkpoints["calibration_queued"] < checkpoints["calibration_digest_recorded"]


def test_model_intake_scan_fails_closed_on_stale_workers_before_database_access(monkeypatch):
    monkeypatch.setattr(api, "_worker_freshness_snapshot", lambda: {
        "available": True,
        "expected_build_fingerprint": "a" * 16,
        "fleet_size": 2,
        "stale_count": 1,
        "pending_count": 0,
        "stale_names": ["worker-2"],
        "pending_names": [],
    })

    request = api.ModelIntakeScanRequest(
        artifact_url="https://huggingface.co/example/model/resolve/main/model.safetensors",
        require_current_workers=True,
    )
    with pytest.raises(api.HTTPException) as caught:
        asyncio.run(api.scan_model_intake(request))

    assert caught.value.status_code == 409
    assert caught.value.detail["error"] == "workers_not_confirmed_current"


def test_automatic_review_bundle_records_the_fixed_guest_embedding_contract():
    authoritative = {"deployment_bundle": {
        "model_artifact_sha256": "a" * 64,
        "repository_snapshot_sha256": "b" * 64,
        "tokenizer_sha256": "c" * 64,
        "configuration_sha256": "d" * 64,
        "runtime_image_digest": "sha256:" + "e" * 64,
        "loader_profile_sha256": "f" * 64,
        "target_environment": "production",
    }}
    bundle = api._model_intake_auto_embedding_bundle(
        authoritative,
        {"dimension": 768, "max_sequence_length": 8192, "pooling": "cls"},
    )

    assert bundle["embedding_configuration"] == {
        "dimension": 768,
        "pooling": "attention-mask-mean",
        "normalization": False,
        "max_sequence_length": 8192,
        "precision": "float32",
    }
    assert bundle["retrieval_application_digest"] is None
    assert bundle["index_schema_digest"] is None


def test_automatic_review_never_guesses_missing_embedding_dimensions():
    with pytest.raises(ValueError, match="embedding dimension"):
        api._model_intake_auto_embedding_bundle(
            {"deployment_bundle": {}}, {"max_sequence_length": 512}
        )


def test_failed_security_receipt_can_register_proven_equivalent_conversion_output():
    payload = {
        "evidence_type": "conversion_equivalence",
        # Network attempts or a non-production signer can fail the overall
        # security receipt without invalidating the separately proven target.
        "status": "FAIL",
        "observations": {
            "target_artifact_sha256": "a" * 64,
            "target_repository_snapshot_sha256": "b" * 64,
            "target_tokenizer_sha256": "c" * 64,
            "target_configuration_sha256": "d" * 64,
            "tensor_inventory_equivalent": True,
            "numeric_equivalence_status": "PASS",
            "embedding_equivalence_status": "PASS",
            "phases": {
                phase: "PASS" for phase in (
                    "import", "deserialize_convert", "tensor_equivalence",
                    "embedding_equivalence", "teardown",
                )
            },
        },
    }

    assert api._model_intake_conversion_output_usable(payload) is True
    payload["observations"]["phases"]["tensor_equivalence"] = "FAIL"
    assert api._model_intake_conversion_output_usable(payload) is False


def test_automatic_summary_names_containment_failure_without_falsely_failing_operations():
    conversion = {
        "evidence_type": "conversion_equivalence",
        "status": "FAIL",
        "observations": {
            "status": "PASS",
            "target_artifact_sha256": "a" * 64,
            "target_repository_snapshot_sha256": "b" * 64,
            "target_tokenizer_sha256": "c" * 64,
            "target_configuration_sha256": "d" * 64,
            "tensor_inventory_equivalent": True,
            "numeric_equivalence_status": "PASS",
            "embedding_equivalence_status": "PASS",
            "phases": {phase: "PASS" for phase in (
                "import", "deserialize_convert", "tensor_equivalence",
                "embedding_equivalence", "teardown",
            )},
            "network_telemetry": {
                "complete": True,
                "no_network_device": True,
                "attempt_count": 2,
                "overflowed": False,
                "lost_events": 0,
                "host_firewall_drop_count": 0,
            },
            "resource_telemetry": {"complete": True},
        },
    }
    runtime = {
        "evidence_type": "runtime_execution",
        "status": "FAIL",
        "observations": {
            "status": "PASS",
            "phases": {phase: "PASS" for phase in (
                "import", "tokenizer", "model_load", "warmup", "inference", "teardown",
            )},
            "network_telemetry": {
                "complete": True,
                "no_network_device": True,
                "attempt_count": 0,
                "overflowed": False,
                "lost_events": 0,
                "host_firewall_drop_count": 0,
            },
            "resource_telemetry": {"complete": True},
        },
    }

    def row(payload):
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        return {
            "evidence_type": payload["evidence_type"],
            "status": payload["status"],
            "signature_envelope": {"payload": encoded},
        }

    controls = api._model_intake_automatic_control_statuses([
        row(conversion), row(runtime),
    ])

    assert controls["conversion_equivalence"] == "PASS"
    assert controls["runtime_execution"] == "PASS"
    assert controls["resource_envelope"] == "PASS"
    assert controls["network_isolation"] == "FAIL"


def test_conversion_evidence_freeze_binds_target_identity_not_source_loader():
    bundle = {
        "bundle_sha256": "0" * 64,
        "model_artifact_sha256": "a" * 64,
        "repository_snapshot_sha256": "b" * 64,
        "custom_code_sha256": None,
        "tokenizer_sha256": "c" * 64,
        "configuration_sha256": "d" * 64,
        "runtime_image_digest": "sha256:" + "e" * 64,
        "loader_profile_sha256": "f" * 64,
    }
    conversion_bindings = {
        **{key: bundle[key] for key in (
            "model_artifact_sha256", "repository_snapshot_sha256", "custom_code_sha256",
            "tokenizer_sha256", "configuration_sha256", "runtime_image_digest",
        )},
        "deployment_bundle_sha256": "1" * 64,
        "loader_profile_sha256": "2" * 64,
        "source_model_artifact_sha256": "3" * 64,
        "source_repository_snapshot_sha256": "4" * 64,
    }

    assert api._model_intake_evidence_matches_bundle(
        "conversion_equivalence", conversion_bindings, bundle
    ) is True
    conversion_bindings["model_artifact_sha256"] = "9" * 64
    assert api._model_intake_evidence_matches_bundle(
        "conversion_equivalence", conversion_bindings, bundle
    ) is False


def test_converted_snapshot_materialization_rehashes_every_member_and_derives_components(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "RESULTS_DIR", tmp_path)
    monkeypatch.setenv("MODEL_INTAKE_RUNNER_HOST_RESULTS_ROOT", "/host/results")
    root = tmp_path / "model-intake-conversions"
    files = {
        "model.safetensors": b"safe-weights",
        "config.json": b'{"model_type":"bert"}',
        "tokenizer.json": b'{"version":"1"}',
        "modeling_custom.py": b"class SafeModel: pass\n",
    }
    entries = [
        {"path": name, "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        for name, content in sorted(files.items())
    ]
    artifact_sha = next(item["sha256"] for item in entries if item["path"] == "model.safetensors")
    manifest = {
        "provider": "shakerscan-conversion",
        "repository": "example/model",
        "revision": artifact_sha,
        "files": entries,
    }
    snapshot_sha = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    subject = root / snapshot_sha
    subject.mkdir(parents=True)
    for name, content in files.items():
        (subject / name).write_bytes(content)
    (root / f"{snapshot_sha}.manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    )

    materialized = api._model_intake_converted_snapshot_materialization(
        artifact_sha256=artifact_sha,
        repository_snapshot_sha256=snapshot_sha,
    )

    assert materialized["artifact_path"] == "model.safetensors"
    assert materialized["subject_path"] == f"/host/results/model-intake-conversions/{snapshot_sha}"
    assert re.fullmatch(r"[0-9a-f]{64}", materialized["custom_code_sha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", materialized["tokenizer_sha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", materialized["configuration_sha256"])

    (subject / "config.json").write_bytes(b"tampered")
    with pytest.raises(api.HTTPException, match="invalid|digest mismatch"):
        api._model_intake_converted_snapshot_materialization(
            artifact_sha256=artifact_sha,
            repository_snapshot_sha256=snapshot_sha,
        )
