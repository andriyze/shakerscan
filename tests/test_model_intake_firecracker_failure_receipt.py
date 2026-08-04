from pathlib import Path
import sys
import uuid


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import model_intake_firecracker_runner as firecracker_runner_module  # noqa: E402
from model_intake_firecracker_runner import FirecrackerRunner  # noqa: E402


def test_failed_conversion_receipt_binds_source_without_target_key_error(tmp_path, monkeypatch):
    key_file = tmp_path / "runner-key.pem"
    key_file.write_text("test-only-key")
    monkeypatch.setattr(firecracker_runner_module, "LocalPemSigner", lambda _key: object())
    monkeypatch.setattr(
        firecracker_runner_module,
        "issue_runner_envelope",
        lambda payload, _signer: {"test_payload": payload},
    )
    runner = FirecrackerRunner({
        "MODEL_INTAKE_RUNNER_SIGNER_BACKEND": "local-pem",
        "MODEL_INTAKE_RUNNER_ALLOW_LOCAL_PEM": "true",
        "MODEL_INTAKE_RUNNER_SIGNING_KEY_PEM_FILE": str(key_file),
        "MODEL_INTAKE_RUNNER_BUILDER_ID": "test-builder",
    })
    monkeypatch.setattr(runner, "execute", lambda _request: {
        "status": "FAIL",
        "source_artifact_sha256": "1" * 64,
        "target_artifact_sha256": "9" * 64,
        "errors": [{"phase": "embedding_equivalence", "type": "ImportError"}],
    })
    request = {
        "submission_id": str(uuid.uuid4()),
        "mode": "conversion",
        "environment": "test",
        "deployment_bundle_sha256": "2" * 64,
        "model_artifact_sha256": "1" * 64,
        "repository_snapshot_sha256": "3" * 64,
        "reviewed_custom_code_sha256": "4" * 64,
        "tokenizer_sha256": "5" * 64,
        "configuration_sha256": "6" * 64,
        "runtime_image_digest": "sha256:" + "7" * 64,
        "loader_profile_sha256": "8" * 64,
    }

    payload = runner.execute_and_sign(request)["payload"]

    assert payload["status"] == "FAIL"
    assert payload["model_artifact_sha256"] == request["model_artifact_sha256"]
    assert payload["repository_snapshot_sha256"] == request["repository_snapshot_sha256"]
    assert payload["source_model_artifact_sha256"] == request["model_artifact_sha256"]
