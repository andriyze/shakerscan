from pathlib import Path

from api.model_intake_loader_profiles import resolve_loader_profile
from api.model_intake_runner_controller import build_firecracker_config, firecracker_readiness


def test_loader_selection_is_capability_based_and_supports_unseen_models():
    result = resolve_loader_profile(
        {"library_name": "transformers", "custom_code_required": False, "architectures": ["NovelEncoder"]},
        artifact_path="unseen-vendor/new-model.safetensors",
        runtime_image_digest="sha256:" + "a" * 64,
    )
    assert result["status"] == "READY"
    assert result["profile"]["trust_remote_code"] is False
    assert result["profile"]["allow_pickle"] is False
    assert len(result["profile"]["profile_sha256"]) == 64


def test_custom_code_and_pickle_require_review_or_conversion():
    custom = resolve_loader_profile(
        {"library_name": "transformers", "custom_code_required": True},
        artifact_path="model.safetensors",
        runtime_image_digest="sha256:" + "a" * 64,
    )
    assert custom == {"status": "BLOCKED", "reason": "reviewed_custom_code_digest_required", "profile": None}
    pickle = resolve_loader_profile(
        {"library_name": "transformers"},
        artifact_path="pytorch_model.bin",
        runtime_image_digest="sha256:" + "a" * 64,
    )
    assert pickle["status"] == "BLOCKED"
    assert pickle["conversion_target"] == "safetensors"


def test_firecracker_contract_has_no_network_and_read_only_subject_drives():
    config = build_firecracker_config({
        "vm_id": "run-1",
        "kernel_image": "/runner/kernel",
        "rootfs_image": "/runner/rootfs",
        "input_drive": "/runner/input.ext4",
        "output_drive": "/runner/output.ext4",
        "vcpu_count": 2,
        "memory_mib": 4096,
        "timeout_seconds": 600,
    })
    assert config["network-interfaces"] == []
    assert config["drives"][0]["is_read_only"] is True
    assert config["drives"][1]["is_read_only"] is True
    assert config["metadata"]["seccomp_level"] == 2
    assert config["metadata"]["receipt_required"] is True


def test_firecracker_readiness_has_no_local_container_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr("api.model_intake_runner_controller.platform.system", lambda: "Linux")
    readiness = firecracker_readiness({})
    assert readiness["status"] == "NOT_READY"
    assert readiness["fallback_execution"] is False
