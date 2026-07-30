from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_loader_profiles import resolve_conversion_profile, resolve_loader_profile  # noqa: E402
from model_intake_control_plane import canonical_bytes  # noqa: E402
from model_intake_runner_controller import build_firecracker_config, firecracker_readiness  # noqa: E402
from model_intake_firecracker_runner import FirecrackerRunner, parse_network_telemetry  # noqa: E402


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


def test_conversion_profile_is_narrow_digest_bound_and_model_agnostic():
    blocked = resolve_conversion_profile(
        {"library_name": "transformers", "custom_code_required": True},
        artifact_path="unseen/model.bin",
        runtime_image_digest="sha256:" + "a" * 64,
    )
    assert blocked["status"] == "BLOCKED"
    ready = resolve_conversion_profile(
        {"library_name": "transformers", "custom_code_required": True, "architectures": ["NovelEncoder"]},
        artifact_path="unseen/model.bin",
        runtime_image_digest="sha256:" + "a" * 64,
        reviewed_custom_code_sha256="b" * 64,
    )
    assert ready["status"] == "READY"
    profile = ready["profile"]
    assert profile["source_deserializer"] == "torch.load(weights_only=True,map_location=cpu)"
    assert profile["allow_pickle_scope"] == "single-reviewed-source-artifact-inside-firecracker"
    assert profile["network"] == "none"
    assert len(profile["profile_sha256"]) == 64


def test_api_exposes_conversion_profile_without_turning_runtime_pickle_on():
    source = (Path(__file__).resolve().parents[1] / "api" / "api.py").read_text()
    assert '@app.post("/model-intake/conversion-profiles/resolve")' in source
    assert "_resolve_model_conversion_profile" in source
    runtime = resolve_loader_profile(
        {"library_name": "transformers"},
        artifact_path="converted/model.safetensors",
        runtime_image_digest="sha256:" + "a" * 64,
    )
    assert runtime["profile"]["allow_pickle"] is False


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
    monkeypatch.setattr("model_intake_runner_controller.platform.system", lambda: "Linux")
    readiness = firecracker_readiness({})
    assert readiness["status"] == "NOT_READY"
    assert readiness["fallback_execution"] is False


def test_network_trace_parser_records_attempt_phase_destination_and_overflow_state(tmp_path):
    traces = tmp_path / "traces"
    traces.mkdir()
    (traces / "trace.load.42").write_text(
        '12:00:00 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(443), '
        'sin_addr=inet_addr("203.0.113.5")}, 16) = -1 ENETUNREACH\n'
        '12:00:01 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3\n'
    )
    telemetry = parse_network_telemetry(
        traces,
        ["lo"],
        {
            "complete": True, "interfaces": ["lo"], "drop_count": 0,
            "no_network_device": True, "network_interface_config_count": 0, "tap_device_count": 0,
        },
    )
    assert telemetry["attempt_count"] == 2
    assert telemetry["attempts_by_phase"] == {"load": 2}
    assert telemetry["attempted_operations"][0]["destination_port"] == 443
    assert telemetry["attempted_operations"][0]["address_family"] == "AF_INET"
    assert telemetry["attempted_operations"][0]["result"] == "-1 ENETUNREACH"
    assert telemetry["attempted_operations"][0]["destination_digest"] != "203.0.113.5"
    assert len(telemetry["destination_salt_sha256"]) == 64
    assert telemetry["complete"] is True
    assert telemetry["overflowed"] is False
    assert len(telemetry["telemetry_sha256"]) == 64


def test_real_input_drive_builder_copies_bounded_subject_and_fixed_job(tmp_path):
    quarantine = tmp_path / "quarantine"
    subject = quarantine / "snapshot"
    subject.mkdir(parents=True)
    (subject / "config.json").write_text('{"model_type":"bert"}')
    (subject / "model.safetensors").write_bytes(b"safe-model-bytes")
    work = tmp_path / "work"
    work.mkdir()
    runner = FirecrackerRunner({
        "MODEL_INTAKE_RUNNER_QUARANTINE_ROOT": str(quarantine),
        "MODEL_INTAKE_RUNNER_WORK_ROOT": str(tmp_path / "runs"),
    })
    input_drive, output_drive = runner._prepare_drives(work, subject, {
        "trust_remote_code": False,
        "allow_pickle": False,
        "known_answer_inputs": ["bounded input"],
        "output_bytes": 64 * 1024**2,
    })
    assert input_drive.is_file() and input_drive.stat().st_size >= 256 * 1024**2
    assert output_drive.is_file() and output_drive.stat().st_size == 64 * 1024**2
    import subprocess
    listing = subprocess.run(
        ["debugfs", "-R", "ls -l /model", str(input_drive)],
        capture_output=True, text=True, check=False,
    )
    assert listing.returncode == 0
    assert "config.json" in listing.stdout
    assert "model.safetensors" in listing.stdout


def test_runner_rejects_subject_outside_quarantine(tmp_path):
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x")
    runner = FirecrackerRunner({"MODEL_INTAKE_RUNNER_QUARANTINE_ROOT": str(quarantine)})
    import pytest
    with pytest.raises(Exception, match="escapes"):
        runner._validated_subject(str(outside))


def test_runner_rebinds_manifest_runtime_profile_and_reviewed_custom_code(tmp_path):
    import hashlib
    import json
    import pytest

    quarantine = tmp_path / "quarantine"
    subject = quarantine / "snapshot"
    subject.mkdir(parents=True)
    model = subject / "model.safetensors"
    code = subject / "modeling_custom.py"
    model.write_bytes(b"model")
    code.write_text("class SafeModel: pass\n")
    files = []
    for path in (code, model):
        files.append({
            "path": path.relative_to(subject).as_posix(),
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    manifest = {"files": files, "complete": True}
    manifest_path = quarantine / "manifest.json"
    manifest_path.write_bytes(canonical_bytes(manifest))
    rootfs = tmp_path / "rootfs.ext4"
    rootfs.write_bytes(b"rootfs")
    profile = {"trust_remote_code": True, "allow_pickle": False, "entrypoint": "transformers"}
    custom_entries = [{"path": "modeling_custom.py", "sha256": hashlib.sha256(code.read_bytes()).hexdigest()}]
    request = {
        "mode": "runtime",
        "environment": "test",
        "repository_manifest_path": str(manifest_path),
        "repository_snapshot_sha256": hashlib.sha256(canonical_bytes(manifest)).hexdigest(),
        "model_artifact_sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
        "runtime_image_digest": "sha256:" + hashlib.sha256(rootfs.read_bytes()).hexdigest(),
        "loader_profile": profile,
        "loader_profile_sha256": hashlib.sha256(canonical_bytes(profile)).hexdigest(),
        "reviewed_custom_code_sha256": hashlib.sha256(canonical_bytes(custom_entries)).hexdigest(),
    }
    runner = FirecrackerRunner({
        "MODEL_INTAKE_RUNNER_QUARANTINE_ROOT": str(quarantine),
        "MODEL_INTAKE_ROOTFS_IMAGE": str(rootfs),
    })
    normalized = runner._validate_job(subject, request)
    assert normalized["trust_remote_code"] is True
    assert normalized["allow_pickle"] is False

    weakened = dict(request)
    weakened["loader_profile"] = {**profile, "allow_pickle": True}
    weakened["loader_profile_sha256"] = hashlib.sha256(canonical_bytes(weakened["loader_profile"])).hexdigest()
    with pytest.raises(Exception, match="never permits pickle"):
        runner._validate_job(subject, weakened)

    tampered = dict(request)
    tampered["reviewed_custom_code_sha256"] = "0" * 64
    with pytest.raises(Exception, match="custom-code digest mismatch"):
        runner._validate_job(subject, tampered)


def test_conversion_export_creates_new_content_addressed_identity_and_complete_manifest(tmp_path):
    import hashlib
    import json
    extracted = tmp_path / "extracted"
    converted = extracted / "work" / "converted"
    converted.mkdir(parents=True)
    artifact = converted / "model.safetensors"
    artifact.write_bytes(b"converted-safe-weights")
    (converted / "config.json").write_text('{"model_type":"bert"}')
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    root = tmp_path / "conversion-root"
    runner = FirecrackerRunner({
        "MODEL_INTAKE_RUNNER_QUARANTINE_ROOT": str(tmp_path),
        "MODEL_INTAKE_RUNNER_CONVERSION_ROOT": str(root),
    })
    result = runner._export_conversion(extracted, {"target_artifact_sha256": digest})
    assert result["target_artifact_sha256"] == digest
    destination = Path(result["converted_snapshot_path"])
    manifest_path = Path(result["target_repository_manifest_path"])
    assert destination.name == digest
    assert (destination / "model.safetensors").read_bytes() == b"converted-safe-weights"
    manifest = json.loads(manifest_path.read_text())
    assert manifest["complete"] is True
    assert {item["path"] for item in manifest["files"]} == {"config.json", "model.safetensors"}
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == result["target_repository_snapshot_sha256"]
