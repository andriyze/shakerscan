import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "model_intake_runner_cli",
    ROOT / "scripts" / "model_intake_runner_cli.py",
)
assert SPEC and SPEC.loader
runner_cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner_cli)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_stage(runtime: Path, kernel: bytes, rootfs: bytes) -> Path:
    stage = runtime / ".shakerscan-model-intake-runner-stage"
    stage.mkdir()
    (stage / "vmlinux").write_bytes(kernel)
    (stage / "rootfs.ext4").write_bytes(rootfs)
    manifest = {
        "schema_version": "model-intake-runner-stage/v1",
        "artifacts": {
            "kernel": {"bytes": len(kernel), "sha256": _digest(kernel)},
            "rootfs": {"bytes": len(rootfs), "sha256": _digest(rootfs)},
        },
    }
    (stage / "stage-manifest.json").write_text(json.dumps(manifest))
    return stage


def test_staged_inputs_require_manifest_and_both_exact_digests(tmp_path, monkeypatch):
    kernel = b"kernel"
    rootfs = b"rootfs"
    monkeypatch.setattr(runner_cli, "DEFAULT_KERNEL_SHA256", _digest(kernel))
    stage = _write_stage(tmp_path, kernel, rootfs)

    verified = runner_cli._staged_inputs(tmp_path)
    assert verified["integrity_verified"] is True
    assert verified["rootfs"]["sha256"] == _digest(rootfs)

    (stage / "rootfs.ext4").write_bytes(b"tampered")
    rejected = runner_cli._staged_inputs(tmp_path)
    assert rejected["integrity_verified"] is False
    assert rejected["error"] == "rootfs_digest_mismatch"


def test_staged_inputs_reject_symlink_substitution(tmp_path, monkeypatch):
    kernel = b"kernel"
    rootfs = b"rootfs"
    monkeypatch.setattr(runner_cli, "DEFAULT_KERNEL_SHA256", _digest(kernel))
    stage = _write_stage(tmp_path, kernel, rootfs)
    outside = tmp_path / "outside.ext4"
    outside.write_bytes(rootfs)
    (stage / "rootfs.ext4").unlink()
    (stage / "rootfs.ext4").symlink_to(outside)

    rejected = runner_cli._staged_inputs(tmp_path)
    assert rejected["integrity_verified"] is False
    assert rejected["error"] == "symlink_rejected"


def test_upsert_runner_env_replaces_values_without_duplicates(tmp_path):
    path = tmp_path / "runner.env"
    path.write_text("TOKEN=keep\nMODEL_INTAKE_RUNNER_BUILDER_ID=old\n")
    runner_cli._upsert_env_file(path, {
        "MODEL_INTAKE_RUNNER_BUILDER_ID": "new",
        "MODEL_INTAKE_RUNNER_SIGNER_BACKEND": "aws-kms",
    })

    lines = path.read_text().splitlines()
    assert "TOKEN=keep" in lines
    assert lines.count("MODEL_INTAKE_RUNNER_BUILDER_ID=new") == 1
    assert "MODEL_INTAKE_RUNNER_BUILDER_ID=old" not in lines
    assert "MODEL_INTAKE_RUNNER_SIGNER_BACKEND=aws-kms" in lines


def test_hardened_service_mounts_only_results_and_conversion_output():
    provisioner = (ROOT / "scripts" / "provision-model-intake-firecracker.sh").read_text()
    assert "ProtectHome=tmpfs" in provisioner
    assert 'BindReadOnlyPaths="$SHARED_RESULTS_ROOT"' in provisioner
    assert 'BindPaths="$SHARED_RESULTS_ROOT/model-intake-conversions"' in provisioner
    assert "MODEL_INTAKE_RUNNER_QUARANTINE_ROOT=$SHARED_RESULTS_ROOT" in provisioner
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK" in provisioner


def test_installer_selects_runnable_release_binaries_not_debug_objects():
    provisioner = (ROOT / "scripts" / "provision-model-intake-firecracker.sh").read_text()
    assert 'firecracker-${FIRECRACKER_VERSION}-${arch}"' in provisioner
    assert 'jailer-${FIRECRACKER_VERSION}-${arch}"' in provisioner
    assert "-name 'firecracker-*'" not in provisioner
    assert "-name 'jailer-*'" not in provisioner
    assert '"$INSTALL_ROOT/bin/firecracker" --version' in provisioner
    assert '"$INSTALL_ROOT/bin/jailer" --version' in provisioner


def test_installer_registers_purpose_scoped_environment_anchors(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(
        "MODEL_INTAKE_OPERATOR_TOKEN=" + "t" * 48 + "\n"
        "SHAKERSCAN_BIND_HOST=127.0.0.1\n"
    )
    calls = []

    def fake_api(url, token, method="GET", payload=None):
        calls.append((url, method, payload))
        if url.endswith("/model-intake/trust-anchors?active_only=true"):
            return {"trust_anchors": []}
        if url.endswith("/model-intake/runners/readiness"):
            return {"status": "READY", "ready": True}
        return {"status": "ok"}

    monkeypatch.setattr(runner_cli, "_api_request", fake_api)
    monkeypatch.setattr(runner_cli, "_runner_public_key_pem", lambda signer: "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n")

    runner_cli._register_runner_trust_anchors(tmp_path, "local-pem", "builder-1")
    posts = [payload for _, method, payload in calls if method == "POST"]
    assert {item["environment"] for item in posts} == {"development", "test", "staging", "production"}
    assert all(item["purpose"] == "runtime_runner" for item in posts)
    assert all(item["builder_id_constraint"] == "builder-1" for item in posts)
    assert all(item["policy_profile"] == "local-pem-evidence" for item in posts)
    assert all("not valid for production admission" in item["description"] for item in posts)

    calls.clear()
    runner_cli._register_runner_trust_anchors(tmp_path, "kms:key-1", "builder-1")
    posts = [payload for _, method, payload in calls if method == "POST"]
    assert len(posts) == 1
    assert posts[0]["environment"] == "production"
