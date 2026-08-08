from pathlib import Path
import hashlib
import inspect
import os
import sys
import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_loader_profiles import resolve_conversion_profile, resolve_loader_profile  # noqa: E402
import model_intake_firecracker_runner as firecracker_runner_module  # noqa: E402
import model_intake_runner_controller as runner_controller  # noqa: E402
import model_intake_runner_service as runner_service  # noqa: E402
from model_intake_control_plane import canonical_bytes  # noqa: E402
from model_intake_runner_controller import build_firecracker_config, firecracker_readiness  # noqa: E402
from model_intake_firecracker_runner import (  # noqa: E402
    DENY_ALL_NFT_RULES,
    FirecrackerExecutionError,
    FirecrackerRunner,
    _unix_http,
    _copy_tree,
    _wait_for_jailed_pid,
    parse_network_telemetry,
)
from model_intake_components import component_identities  # noqa: E402


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


def test_firecracker_provisioner_installs_every_first_party_runner_module():
    root = Path(__file__).resolve().parents[1]
    provisioner = (root / "scripts/provision-model-intake-firecracker.sh").read_text()
    required = {
        "model_intake_control_plane.py",
        "model_intake_components.py",
        "model_intake_loader_profiles.py",
        "model_intake_runner_controller.py",
        "model_intake_runner_inputs.py",
        "model_intake_runner_receipts.py",
        "model_intake_firecracker_runner.py",
        "model_intake_runner_service.py",
    }
    assert all(f'api/{name}' in provisioner for name in required)


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


def test_reviewed_sentence_transformers_custom_code_uses_fixed_safe_loader():
    result = resolve_loader_profile(
        {"library_name": "sentence-transformers", "custom_code_required": True},
        artifact_path="model.safetensors",
        runtime_image_digest="sha256:" + "a" * 64,
        reviewed_custom_code_sha256="b" * 64,
    )
    assert result["status"] == "READY"
    assert result["profile"]["entrypoint"] == "transformers.AutoModel.from_pretrained"
    assert result["profile"]["trust_remote_code"] is True
    assert result["profile"]["allow_pickle"] is False
    assert result["profile"]["network"] == "none"


def test_onnx_profile_uses_hash_locked_cpu_runtime_for_hugging_face_families():
    result = resolve_loader_profile(
        {"library_name": "transformers", "custom_code_required": False},
        artifact_path="model.onnx",
        runtime_image_digest="sha256:" + "a" * 64,
    )

    assert result["status"] == "READY"
    assert result["profile"]["profile_id"] == "onnx-embedding"
    assert result["profile"]["entrypoint"] == "onnxruntime.InferenceSession"
    assert result["profile"]["trust_remote_code"] is False
    assert result["profile"]["allow_pickle"] is False


def test_firecracker_guest_packages_and_executes_the_declared_onnx_profile():
    root = Path(__file__).resolve().parents[1]
    requirements = (root / "runner" / "guest" / "requirements.lock").read_text()
    guest = (root / "runner" / "guest" / "guest_worker.py").read_text()
    runner = (root / "api" / "model_intake_firecracker_runner.py").read_text()

    assert "onnxruntime==1.23.2" in requirements
    assert 'profile_id == "onnx-embedding"' in guest
    assert "ort.InferenceSession" in guest
    assert 'providers=["CPUExecutionProvider"]' in guest
    assert '"profile_id": loader_profile.get("profile_id")' in runner
    assert '"artifact_path": loader_profile.get("artifact_path")' in runner


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


def test_jailer_file_limit_tracks_the_bounded_output_drive():
    source = (Path(__file__).resolve().parents[1] / "api" / "model_intake_firecracker_runner.py").read_text()

    assert 'f"fsize={output_drive.stat().st_size}"' in source
    assert '"fsize=1073741824"' not in source


def test_deny_all_firewall_uses_explicit_counter_rules():
    assert "policy drop;" in DENY_ALL_NFT_RULES
    assert "policy drop; counter" not in DENY_ALL_NFT_RULES
    assert DENY_ALL_NFT_RULES.count("\n  counter\n") == 2


def test_firecracker_api_client_does_not_wait_for_keep_alive_close(monkeypatch):
    class KeepAliveSocket:
        recv_calls = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def connect(self, _path):
            pass

        def sendall(self, _request):
            pass

        def recv(self, _size):
            self.recv_calls += 1
            if self.recv_calls == 1:
                return b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
            raise TimeoutError("client incorrectly waited for connection close")

    client = KeepAliveSocket()
    monkeypatch.setattr(firecracker_runner_module.socket, "socket", lambda *_args: client)
    _unix_http(Path("/run/firecracker.socket"), "PUT", "/boot-source", {"kernel_image_path": "/kernel"})
    assert client.recv_calls == 1


def test_runner_waits_for_pid_namespace_child_not_jailer_wrapper(monkeypatch):
    observations = iter([("R", "42"), ("S", "42"), ("Z", "42")])
    monkeypatch.setattr(firecracker_runner_module, "_process_identity", lambda _pid: next(observations))
    monkeypatch.setattr(firecracker_runner_module.time, "sleep", lambda _seconds: None)

    assert _wait_for_jailed_pid(1234, "42", 1) is True


def test_runner_rejects_pid_reuse_while_waiting(monkeypatch):
    monkeypatch.setattr(firecracker_runner_module, "_process_identity", lambda _pid: ("R", "reused"))
    import pytest

    with pytest.raises(FirecrackerExecutionError, match="identity changed"):
        _wait_for_jailed_pid(1234, "original", 1)


def test_runner_subject_root_is_traversable_despite_service_umask(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.json").write_text('{"model_type":"example"}')
    nested = source / "1_Pooling"
    nested.mkdir()
    (nested / "config.json").write_text('{"pooling_mode_mean_tokens":true}')
    destination = tmp_path / "input-tree" / "model"
    previous = os.umask(0o077)
    try:
        _copy_tree(source, destination)
    finally:
        os.umask(previous)

    assert destination.stat().st_mode & 0o777 == 0o755
    assert (destination / "config.json").stat().st_mode & 0o777 == 0o644
    assert (destination / "1_Pooling").stat().st_mode & 0o777 == 0o755
    assert (destination / "1_Pooling" / "config.json").stat().st_mode & 0o777 == 0o644


def test_guest_installs_only_the_canonical_legacy_conv1d_alias(monkeypatch):
    guest_root = Path(__file__).resolve().parents[1] / "runner" / "guest"
    monkeypatch.syspath_prepend(str(guest_root))
    import guest_worker

    canonical = object()
    package = types.ModuleType("transformers")
    package.__path__ = []
    modeling_utils = types.ModuleType("transformers.modeling_utils")
    pytorch_utils = types.ModuleType("transformers.pytorch_utils")
    pytorch_utils.Conv1D = canonical
    monkeypatch.setitem(sys.modules, "transformers", package)
    monkeypatch.setitem(sys.modules, "transformers.modeling_utils", modeling_utils)
    monkeypatch.setitem(sys.modules, "transformers.pytorch_utils", pytorch_utils)

    guest_worker._install_transformers_compatibility()

    assert modeling_utils.Conv1D is canonical


def test_guest_embedding_equivalence_uses_deterministic_cpu_execution():
    source = (
        Path(__file__).resolve().parents[1] / "runner" / "guest" / "guest_worker.py"
    ).read_text()

    assert "torch.set_num_threads(1)" in source
    assert "torch.manual_seed(0)" in source
    assert "torch.use_deterministic_algorithms(True)" in source
    assert 'os.environ[_thread_env] = "1"' in source
    assert source.count("_configure_deterministic_torch(torch)") >= 3


def test_guest_deterministic_torch_thread_setup_is_process_idempotent(monkeypatch):
    guest_root = Path(__file__).resolve().parents[1] / "runner" / "guest"
    monkeypatch.syspath_prepend(str(guest_root))
    import guest_worker

    calls = {"threads": 0, "interop": 0, "seed": 0, "deterministic": 0}

    class FakeTorch:
        def set_num_threads(self, value):
            assert value == 1
            calls["threads"] += 1

        def set_num_interop_threads(self, value):
            assert value == 1
            calls["interop"] += 1

        def manual_seed(self, value):
            assert value == 0
            calls["seed"] += 1

        def use_deterministic_algorithms(self, value):
            assert value is True
            calls["deterministic"] += 1

    monkeypatch.setattr(guest_worker, "_TORCH_THREAD_LIMITS_CONFIGURED", False)
    fake = FakeTorch()
    guest_worker._configure_deterministic_torch(fake)
    guest_worker._configure_deterministic_torch(fake)

    assert calls == {"threads": 1, "interop": 1, "seed": 2, "deterministic": 2}


def test_firecracker_readiness_has_no_local_container_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr("model_intake_runner_controller.platform.system", lambda: "Linux")
    # Pin the CPU probe. Left to the ambient /proc/cpuinfo this asserted
    # NOT_READY on a host with vmx/svm and UNSUPPORTED_HOST on one without,
    # so the result depended on which machine ran the suite.
    virt_capable = tmp_path / "cpuinfo-virt"
    virt_capable.write_text("processor\t: 0\nflags\t\t: fpu vme de vmx lm\n")
    no_virt = tmp_path / "cpuinfo-plain"
    no_virt.write_text("processor\t: 0\nflags\t\t: fpu vme de lm\n")

    # A Linux host whose prerequisites are incomplete is a fixable deployment.
    incomplete = firecracker_readiness({}, cpuinfo_path=virt_capable)
    assert incomplete["status"] == "NOT_READY"

    # A host with no virtualization extension is an unavailable tier instead.
    unsupported = firecracker_readiness({}, cpuinfo_path=no_virt)
    assert unsupported["status"] == "UNSUPPORTED_HOST"
    assert unsupported["unsupported_reason"] == "no_hardware_virtualization"

    # Neither branch may ever admit a local fallback executor.
    for readiness in (incomplete, unsupported):
        assert readiness["ready"] is False
        assert readiness["fallback_execution"] is False


def test_runner_component_digest_cache_rehashes_when_file_identity_changes(tmp_path, monkeypatch):
    component = tmp_path / "rootfs.ext4"
    component.write_bytes(b"a" * (2 * 1024 * 1024))
    original_sha256 = hashlib.sha256
    calls = 0

    def counted_sha256():
        nonlocal calls
        calls += 1
        return original_sha256()

    runner_controller._SHA256_CACHE.clear()
    monkeypatch.setattr(runner_controller.hashlib, "sha256", counted_sha256)
    first = runner_controller._sha256(component)
    second = runner_controller._sha256(component)

    assert first == second
    assert calls == 1

    component.write_bytes(b"b" * (2 * 1024 * 1024))
    third = runner_controller._sha256(component)

    assert third != first
    assert calls == 2


def test_runner_health_digest_work_does_not_block_the_service_event_loop():
    assert inspect.iscoroutinefunction(runner_service.health) is False


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
    assert telemetry["event_count"] == 2
    assert telemetry["attempt_count"] == 1
    assert telemetry["attempts_by_phase"] == {"load": 2}
    assert telemetry["attempted_operations"][0]["destination_port"] == 443
    assert telemetry["attempted_operations"][0]["destination_address"] == "203.0.113.5"
    assert telemetry["attempted_operations"][0]["address_family"] == "AF_INET"
    assert telemetry["attempted_operations"][0]["result"] == "-1 ENETUNREACH"
    assert telemetry["attempted_operations"][0]["destination_digest"] != "203.0.113.5"
    assert len(telemetry["destination_salt_sha256"]) == 64
    assert telemetry["complete"] is True
    assert telemetry["overflowed"] is False
    assert len(telemetry["telemetry_sha256"]) == 64


def test_network_trace_parser_does_not_call_local_ipc_or_socket_creation_egress(tmp_path):
    traces = tmp_path / "traces"
    traces.mkdir()
    (traces / "trace.import.42").write_text(
        'socket(AF_UNIX, SOCK_STREAM, 0) = 3<UNIX-STREAM:[1154]>\n'
        'connect(3<UNIX-STREAM:[1154]>, {sa_family=AF_UNIX, sun_path="/tmp/torch"}, 110) = -1 ENOENT\n'
        'socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP) = 3<TCPv6:[1160]>\n'
        'bind(3<TCPv6:[1160]>, {sa_family=AF_INET6, sin6_port=htons(0)}, 28) = -1 EADDRNOTAVAIL\n'
    )
    telemetry = parse_network_telemetry(
        traces, ["lo"], {
            "complete": True, "interfaces": ["lo"], "drop_count_before": 0,
            "drop_count_after": 0, "no_network_device": True,
            "network_interface_config_count": 0, "tap_device_count": 0,
        },
    )

    assert telemetry["event_count"] == 4
    assert telemetry["attempt_count"] == 0
    assert telemetry["attempted_operations"] == []
    assert telemetry["local_ipc_event_count"] == 2
    assert telemetry["ip_socket_event_count"] == 2
    assert all(item["destination_digest"] is None for item in telemetry["observed_operations"])


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
    config = subject / "config.json"
    tokenizer = subject / "tokenizer.json"
    model.write_bytes(b"model")
    code.write_text("class SafeModel: pass\n")
    config.write_text('{"model_type":"bert"}')
    tokenizer.write_text('{"version":"1"}')
    files = []
    for path in (code, config, model, tokenizer):
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
    components = component_identities(files)
    request = {
        "mode": "runtime",
        "environment": "test",
        "repository_manifest_path": str(manifest_path),
        "repository_snapshot_sha256": hashlib.sha256(canonical_bytes(manifest)).hexdigest(),
        "model_artifact_sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
        "tokenizer_sha256": components["tokenizer_sha256"],
        "configuration_sha256": components["configuration_sha256"],
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

    wrong_tokenizer = dict(request)
    wrong_tokenizer["tokenizer_sha256"] = "0" * 64
    with pytest.raises(Exception, match="tokenizer component digest mismatch"):
        runner._validate_job(subject, wrong_tokenizer)


def test_conversion_export_creates_new_content_addressed_identity_and_complete_manifest(tmp_path):
    import hashlib
    import json
    extracted = tmp_path / "extracted"
    converted = extracted / "work" / "converted"
    converted.mkdir(parents=True)
    artifact = converted / "model.safetensors"
    artifact.write_bytes(b"converted-safe-weights")
    (converted / "config.json").write_text('{"model_type":"bert"}')
    (converted / "tokenizer.json").write_text('{"version":"1"}')
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    source_weight = b"legacy-weights"
    source_manifest = {
        "provider": "huggingface",
        "repository": "example/model",
        "revision": "source-revision",
        "files": [
            {"path": "config.json", "size_bytes": (converted / "config.json").stat().st_size,
             "sha256": hashlib.sha256((converted / "config.json").read_bytes()).hexdigest()},
            {"path": "tokenizer.json", "size_bytes": (converted / "tokenizer.json").stat().st_size,
             "sha256": hashlib.sha256((converted / "tokenizer.json").read_bytes()).hexdigest()},
            {"path": "pytorch_model.bin", "size_bytes": len(source_weight),
             "sha256": hashlib.sha256(source_weight).hexdigest()},
        ],
    }
    root = tmp_path / "conversion-root"
    runner = FirecrackerRunner({
        "MODEL_INTAKE_RUNNER_QUARANTINE_ROOT": str(tmp_path),
        "MODEL_INTAKE_RUNNER_CONVERSION_ROOT": str(root),
    })
    result = runner._export_conversion(
        extracted,
        {"target_artifact_sha256": digest},
        source_manifest,
        hashlib.sha256(source_weight).hexdigest(),
    )
    assert result["target_artifact_sha256"] == digest
    destination = Path(result["converted_snapshot_path"])
    manifest_path = Path(result["target_repository_manifest_path"])
    assert destination.name == result["target_repository_snapshot_sha256"]
    assert (destination / "model.safetensors").read_bytes() == b"converted-safe-weights"
    manifest = json.loads(manifest_path.read_text())
    assert manifest["provider"] == "shakerscan-conversion"
    assert {item["path"] for item in manifest["files"]} == {
        "config.json", "model.safetensors", "tokenizer.json",
    }
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == result["target_repository_snapshot_sha256"]
    assert result["non_weight_members_preserved"] is True


def test_conversion_export_rejects_changed_non_weight_member(tmp_path):
    import hashlib
    import pytest
    extracted = tmp_path / "extracted"
    converted = extracted / "work" / "converted"
    converted.mkdir(parents=True)
    (converted / "model.safetensors").write_bytes(b"converted")
    (converted / "config.json").write_text('{"tampered":true}')
    source_weight_sha = hashlib.sha256(b"legacy").hexdigest()
    manifest = {"provider": "huggingface", "repository": "example/model", "revision": "source", "files": [
        {"path": "pytorch_model.bin", "size_bytes": 6, "sha256": source_weight_sha},
        {"path": "config.json", "size_bytes": 2, "sha256": hashlib.sha256(b"{}").hexdigest()},
    ]}
    runner = FirecrackerRunner({
        "MODEL_INTAKE_RUNNER_QUARANTINE_ROOT": str(tmp_path),
        "MODEL_INTAKE_RUNNER_CONVERSION_ROOT": str(tmp_path / "conversions"),
    })

    with pytest.raises(Exception, match="changed or omitted"):
        runner._export_conversion(
            extracted,
            {"target_artifact_sha256": hashlib.sha256(b"converted").hexdigest()},
            manifest,
            source_weight_sha,
        )


def test_macos_host_reports_an_unavailable_runner_tier_not_a_broken_one():
    # The API runs in a Linux container even on Docker Desktop, so the host
    # platform recorded by scanner.sh is the only signal that a microVM can
    # never run here. Reporting NOT_READY on a Mac reads as a deployment the
    # operator should go repair, which is wrong and unactionable.
    from model_intake_runner_controller import firecracker_readiness

    macos = firecracker_readiness({"SHAKERSCAN_HOST_PLATFORM": "macos"})
    assert macos["status"] == "UNSUPPORTED_HOST"
    assert macos["supported_host"] is False
    assert macos["host_platform"] == "macos"
    assert "Linux host with KVM" in macos["reason"]
    # Fail-closed behavior is unchanged: no job may be queued, no fallback runs.
    assert macos["ready"] is False
    assert macos["fallback_execution"] is False


def _cpuinfo(tmp_path, flags: str):
    path = tmp_path / "cpuinfo"
    path.write_text(f"processor\t: 0\nmodel name\t: Test CPU\nflags\t\t: {flags}\n")
    return path


def test_linux_host_with_incomplete_prerequisites_still_reports_not_ready(tmp_path):
    from model_intake_runner_controller import firecracker_readiness

    # Pin the CPU signal so the verdict does not depend on whether the machine
    # running the suite happens to expose virtualization extensions.
    capable = _cpuinfo(tmp_path, "fpu vme de pse vmx smep")
    linux = firecracker_readiness({"SHAKERSCAN_HOST_PLATFORM": "linux"}, cpuinfo_path=capable)
    assert linux["status"] == "NOT_READY"
    assert linux["supported_host"] is True
    assert linux["ready"] is False

    # An unrecorded host stays eligible, matching how the fleet feature gates.
    unknown = firecracker_readiness({}, cpuinfo_path=capable)
    assert unknown["status"] == "NOT_READY"
    assert unknown["supported_host"] is True


def test_linux_host_without_nested_virtualization_reports_unsupported_host(tmp_path):
    # A c8i-style cloud instance is Linux, but with nested virtualization off it
    # is a guest with no vmx or svm flag, so /dev/kvm cannot appear. Reporting
    # NOT_READY there sends the operator to install Firecracker prerequisites
    # that cannot help, because nothing on the host is the problem.
    from model_intake_runner_controller import firecracker_readiness

    guest = _cpuinfo(tmp_path, "fpu vme de pse hypervisor lahf_lm smep")
    result = firecracker_readiness({"SHAKERSCAN_HOST_PLATFORM": "linux"}, cpuinfo_path=guest)
    assert result["status"] == "UNSUPPORTED_HOST"
    assert result["supported_host"] is False
    assert result["checks"]["kvm"] is False
    assert result["unsupported_reason"] == "no_hardware_virtualization"
    # The remedy is off-host but real, so the reason must point at it rather
    # than claiming the machine can never run a microVM.
    assert "nested-virtualization CPU option" in result["reason"]
    assert "cannot be enabled here" not in result["reason"]
    # Fail-closed behavior is unchanged: no job may be queued, no fallback runs.
    assert result["ready"] is False
    assert result["fallback_execution"] is False


def test_unreadable_cpuinfo_leaves_a_linux_host_eligible(tmp_path):
    # Without a positive "this CPU cannot virtualize" signal, stay in the
    # repairable NOT_READY state rather than declaring the host hopeless.
    from model_intake_runner_controller import firecracker_readiness

    missing = tmp_path / "absent-cpuinfo"
    result = firecracker_readiness({"SHAKERSCAN_HOST_PLATFORM": "linux"}, cpuinfo_path=missing)
    assert result["status"] == "NOT_READY"
    assert result["supported_host"] is True


def test_runner_memory_admission_reserves_capacity_for_host_services():
    from model_intake_runner_controller import runner_memory_admission

    readiness = {"resources": {
        "host_memory_total_bytes": 16 * 1024**3,
        "host_memory_available_bytes": 14 * 1024**3,
    }}
    codesage = runner_memory_admission(readiness, 13_312)
    oversized = runner_memory_admission(readiness, 15_000)
    busy_host = runner_memory_admission({"resources": {
        "host_memory_total_bytes": 16 * 1024**3,
        "host_memory_available_bytes": 12 * 1024**3,
    }}, 13_312)
    jittering_host = runner_memory_admission({"resources": {
        "host_memory_total_bytes": 16 * 1024**3,
        "host_memory_available_bytes": 13_240 * 1024**2,
    }}, 13_312)

    assert codesage["sufficient"] is True
    assert codesage["host_reserve_mib"] >= 2048
    assert oversized["sufficient"] is False
    assert "exceeds" in oversized["reason"]
    assert busy_host["sufficient"] is False
    assert "currently available" in busy_host["reason"]
    assert jittering_host["sufficient"] is True
    assert jittering_host["available_sample_tolerance_mib"] == 512


def test_locally_derived_loader_profiles_diverge_from_the_authoritative_one():
    """Why the UI must not recompute the runner bundle.

    profile_sha256 hashes selection_facts, and the authoritative manifest the
    queue validates against hardcodes library_name and an empty architectures
    list. A caller that passes the model's declared architectures — which most
    Hugging Face repositories publish — computes a different digest, so the
    queue rejected the job the UI had just enabled.
    """
    import sys
    from pathlib import Path as _Path

    sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "api"))
    from model_intake_loader_profiles import resolve_loader_profile

    authoritative_manifest = {
        "library_name": "transformers",
        "custom_code_required": False,
        "architectures": [],
    }
    ui_style_manifest = {
        "library_name": "transformers",
        "custom_code_required": False,
        # What a Hugging Face model actually declares.
        "architectures": ["NomicBertModel"],
    }
    common = {
        "artifact_path": "model.safetensors",
        "runtime_image_digest": "sha256:" + "e" * 64,
        "reviewed_custom_code_sha256": None,
    }

    authoritative = resolve_loader_profile(authoritative_manifest, **common)
    diverged = resolve_loader_profile(ui_style_manifest, **common)

    assert authoritative["status"] == "READY"
    assert diverged["status"] == "READY"
    assert (
        authoritative["profile"]["profile_sha256"] != diverged["profile"]["profile_sha256"]
    ), "declared architectures must change the digest, which is why only the server may derive it"


def test_a_custom_code_embedding_model_resolves_a_runnable_profile():
    """The nomic-bert / CodeRankEmbed shape: safetensors plus reviewed custom code.

    This is the decisive question for whether a Firecracker run is possible at
    all, so pin it: the profile must resolve READY, permit the remote code the
    architecture requires, and still give the guest no network.
    """
    import sys
    from pathlib import Path as _Path

    sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "api"))
    from model_intake_loader_profiles import resolve_conversion_profile, resolve_loader_profile

    def manifest(python_files):
        # Exactly what the server materializes: library fixed, architectures empty.
        return {
            "library_name": "transformers",
            "custom_code_required": bool(python_files),
            "python_files": python_files,
            "architectures": [],
        }

    image = "sha256:" + "e" * 64
    reviewed = "a" * 64

    ready = resolve_loader_profile(
        manifest(["modeling_hf_nomic_bert.py"]),
        artifact_path="model.safetensors",
        runtime_image_digest=image,
        reviewed_custom_code_sha256=reviewed,
    )
    assert ready["status"] == "READY"
    assert ready["profile"]["profile_id"] == "transformers-embedding-reviewed-custom-code"
    assert ready["profile"]["trust_remote_code"] is True
    assert ready["profile"]["network"] == "none"

    # A plain safetensors model needs no remote code at all.
    plain = resolve_loader_profile(
        manifest([]), artifact_path="model.safetensors", runtime_image_digest=image
    )
    assert plain["profile"]["trust_remote_code"] is False

    # A pickle-serialized artifact cannot be loaded directly; conversion first.
    blocked = resolve_loader_profile(
        manifest(["m.py"]),
        artifact_path="pytorch_model.bin",
        runtime_image_digest=image,
        reviewed_custom_code_sha256=reviewed,
    )
    assert blocked["status"] == "BLOCKED"
    assert blocked["reason"] == "executable_serialization_requires_controlled_conversion"
    # And that conversion is itself a supported operation, so the path is not a
    # dead end for a .bin-only repository.
    conversion = resolve_conversion_profile(
        manifest(["m.py"]),
        artifact_path="pytorch_model.bin",
        runtime_image_digest=image,
        reviewed_custom_code_sha256=reviewed,
    )
    assert conversion["status"] == "READY"
