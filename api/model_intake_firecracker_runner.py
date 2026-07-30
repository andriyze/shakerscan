"""Physical Firecracker/KVM executor for Model Intake.

This module is intentionally a fixed-function runner, not a command runner. It
accepts only a validated model job, starts one jailed microVM without a virtual
NIC, and derives telemetry from bounded guest output plus independent host
namespace/firewall state.
"""

from __future__ import annotations

import hashlib
import hmac
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import subprocess
import time
from typing import Any
import uuid

try:
    from model_intake_control_plane import canonical_bytes
    from model_intake_control_plane import AwsKmsSigner, LocalPemSigner
    from model_intake_runner_controller import build_firecracker_config, firecracker_readiness
    from model_intake_runner_receipts import SCHEMA, issue_runner_envelope
    from model_intake_loader_profiles import CONVERSION_PROFILE_ID
    from model_intake_runner_inputs import suite_identity
except ModuleNotFoundError:  # pragma: no cover
    from api.model_intake_control_plane import canonical_bytes
    from api.model_intake_control_plane import AwsKmsSigner, LocalPemSigner
    from api.model_intake_runner_controller import build_firecracker_config, firecracker_readiness
    from api.model_intake_runner_receipts import SCHEMA, issue_runner_envelope
    from api.model_intake_loader_profiles import CONVERSION_PROFILE_ID
    from api.model_intake_runner_inputs import suite_identity


class FirecrackerExecutionError(RuntimeError):
    pass


NETWORK_CALL = re.compile(
    r"\b(socket|socketpair|connect|bind|listen|accept|accept4|sendto|sendmsg|recvfrom|recvmsg|"
    r"getsockname|getpeername|setsockopt|getsockopt|shutdown)\("
)
PORT = re.compile(r"(?:sin_port=htons\((\d+)\)|port=(\d+))")
ADDRESS = re.compile(r'(?:inet_addr\("([^"]+)"\)|sin6_addr=inet_pton\([^,]+, "([^"]+)"\))')
FAMILY = re.compile(r"\b(AF_[A-Z0-9_]+)\b")
RESULT = re.compile(r"\)\s+=\s+([^\s]+)(?:\s+([A-Z][A-Z0-9_]+))?")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file() and not item.is_symlink())


def _digest(value: Any, field: str, *, prefixed: bool = False) -> str:
    text = str(value or "").lower()
    if prefixed:
        if not text.startswith("sha256:"):
            raise FirecrackerExecutionError(f"{field} must be digest pinned")
        text = text.removeprefix("sha256:")
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise FirecrackerExecutionError(f"invalid {field}")
    return text


def _custom_code_sha256(subject: Path) -> str | None:
    entries = []
    for path in sorted(subject.rglob("*.py")) if subject.is_dir() else []:
        if path.is_symlink() or not path.is_file():
            raise FirecrackerExecutionError("invalid custom-code member")
        entries.append({"path": path.relative_to(subject).as_posix(), "sha256": _sha256(path)})
    return hashlib.sha256(canonical_bytes(entries)).hexdigest() if entries else None


def _copy_tree(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    if source.is_file():
        target = destination / source.name
        shutil.copyfile(source, target)
        target.chmod(0o644)
        return
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        target = destination / relative
        if item.is_symlink():
            raise FirecrackerExecutionError("symbolic links are prohibited in runner subjects")
        if item.is_dir():
            target.mkdir(mode=0o755)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, target)
            target.chmod(0o644)
        else:
            raise FirecrackerExecutionError("non-regular runner subject member")


def _run(argv: list[str], *, input_text: str | None = None, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )


def _require_ok(completed: subprocess.CompletedProcess[str], action: str) -> None:
    if completed.returncode:
        detail = (completed.stderr or completed.stdout)[-2000:]
        raise FirecrackerExecutionError(f"{action} failed: {detail}")


def _unix_http(socket_path: Path, method: str, path: str, payload: dict[str, Any]) -> None:
    body = canonical_bytes(payload)
    request = (
        f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(str(socket_path))
        client.sendall(request)
        response = b""
        while len(response) <= 1_000_000:
            chunk = client.recv(65536)
            if not chunk:
                break
            response += chunk
    status_line = response.split(b"\r\n", 1)[0]
    if not re.match(rb"HTTP/1\.[01] 2\d\d\b", status_line):
        raise FirecrackerExecutionError(f"Firecracker API rejected {path}: {response[-2000:]!r}")


def parse_network_telemetry(
    trace_dir: Path,
    guest_interfaces: list[str],
    host_state: dict[str, Any],
    *,
    destination_salt: bytes | None = None,
) -> dict[str, Any]:
    salt = destination_salt or os.urandom(32)
    events: list[dict[str, Any]] = []
    raw_digest = hashlib.sha256()
    trace_files = sorted(trace_dir.glob("trace.*")) if trace_dir.is_dir() else []
    overflowed = False
    for path in trace_files:
        phase_parts = path.name.split(".")
        phase = phase_parts[1] if len(phase_parts) > 2 else "unknown"
        with path.open("rb") as raw:
            for line_bytes in raw:
                raw_digest.update(line_bytes)
                line = line_bytes.decode("utf-8", "replace")
                match = NETWORK_CALL.search(line)
                if not match:
                    continue
                if len(events) >= 10_000:
                    overflowed = True
                    continue
                address_match = ADDRESS.search(line)
                port_match = PORT.search(line)
                family_match = FAMILY.search(line)
                result_match = RESULT.search(line)
                address = next((item for item in (address_match.groups() if address_match else ()) if item), None)
                port = next((int(item) for item in (port_match.groups() if port_match else ()) if item), None)
                destination = f"{address or 'unresolved'}:{port if port is not None else 'unknown'}"
                events.append({
                    "operation": match.group(1),
                    "phase": phase,
                    "address_family": family_match.group(1) if family_match else None,
                    "destination_digest": hmac.new(salt, destination.encode(), hashlib.sha256).hexdigest(),
                    "destination_port": port,
                    "dns_related": port == 53,
                    "result": " ".join(item for item in (result_match.groups() if result_match else ()) if item) or None,
                })
    phases: dict[str, int] = {}
    for event in events:
        phases[event["phase"]] = phases.get(event["phase"], 0) + 1
    telemetry = {
        "schema_version": "model-intake-network-telemetry/v1",
        "no_network_device": host_state.get("no_network_device") is True,
        "network_interface_config_count": int(host_state.get("network_interface_config_count") or 0),
        "tap_device_count": int(host_state.get("tap_device_count") or 0),
        "guest_interfaces": sorted(set(guest_interfaces)),
        "host_interfaces": sorted(set(host_state.get("interfaces") or [])),
        "attempted_operations": events,
        "attempt_count": len(events),
        "attempts_by_phase": phases,
        "host_firewall_before": int(host_state.get("drop_count_before") or 0),
        "host_firewall_after": int(host_state.get("drop_count_after") or 0),
        "host_firewall_drop_count": max(0, int(host_state.get("drop_count_after") or 0) - int(host_state.get("drop_count_before") or 0)),
        "raw_trace_sha256": raw_digest.hexdigest() if trace_files else None,
        "destination_salt_sha256": hashlib.sha256(salt).hexdigest(),
        "complete": bool(trace_files) and bool(host_state.get("complete")),
        "overflowed": overflowed,
        "lost_events": 0,
    }
    telemetry["telemetry_sha256"] = hashlib.sha256(canonical_bytes(telemetry)).hexdigest()
    return telemetry


class FirecrackerRunner:
    def __init__(self, environment: dict[str, str] | None = None):
        self.env = dict(environment or os.environ)
        self.quarantine_root = Path(self.env.get("MODEL_INTAKE_RUNNER_QUARANTINE_ROOT", "/var/lib/shakerscan/model-intake-quarantine")).resolve()
        self.work_root = Path(self.env.get("MODEL_INTAKE_RUNNER_WORK_ROOT", "/var/lib/shakerscan/model-intake-runner")).resolve()
        self.jailer_root = Path(self.env.get("MODEL_INTAKE_JAILER_ROOT", "/srv/jailer")).resolve()
        self.conversion_root = Path(self.env.get("MODEL_INTAKE_RUNNER_CONVERSION_ROOT", str(self.quarantine_root / "conversions"))).resolve()

    def _validated_subject(self, value: str) -> Path:
        path = Path(value).resolve(strict=True)
        if path != self.quarantine_root and self.quarantine_root not in path.parents:
            raise FirecrackerExecutionError("subject path escapes the configured quarantine root")
        return path

    def _validate_subject_manifest(self, subject: Path, request: dict[str, Any]) -> dict[str, Any]:
        manifest_path = self._validated_subject(str(request.get("repository_manifest_path") or ""))
        if manifest_path.is_dir() or manifest_path.stat().st_size > 20_000_000:
            raise FirecrackerExecutionError("repository manifest is invalid")
        manifest = json.loads(manifest_path.read_text())
        if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
            raise FirecrackerExecutionError("repository manifest schema is invalid")
        expected_manifest = _digest(request.get("repository_snapshot_sha256"), "repository_snapshot_sha256")
        if hashlib.sha256(canonical_bytes(manifest)).hexdigest() != expected_manifest:
            raise FirecrackerExecutionError("repository manifest digest mismatch")
        declared: dict[str, dict[str, Any]] = {}
        for entry in manifest["files"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                raise FirecrackerExecutionError("repository manifest entry is invalid")
            relative = Path(entry["path"])
            if relative.is_absolute() or ".." in relative.parts or relative.as_posix() in declared:
                raise FirecrackerExecutionError("repository manifest path is unsafe or duplicated")
            declared[relative.as_posix()] = entry
        observed = {
            path.relative_to(subject).as_posix(): path
            for path in subject.rglob("*") if path.is_file() and not path.is_symlink()
        } if subject.is_dir() else {subject.name: subject}
        if set(observed) != set(declared):
            raise FirecrackerExecutionError("repository manifest is not complete for the runner subject")
        model_digest = _digest(request.get("model_artifact_sha256"), "model_artifact_sha256")
        model_found = False
        for relative, path in observed.items():
            entry = declared[relative]
            actual = _sha256(path)
            if _digest(entry.get("sha256"), f"manifest sha256 for {relative}") != actual:
                raise FirecrackerExecutionError(f"repository member digest mismatch: {relative}")
            if int(entry.get("size") if entry.get("size") is not None else entry.get("size_bytes", -1)) != path.stat().st_size:
                raise FirecrackerExecutionError(f"repository member size mismatch: {relative}")
            model_found = model_found or actual == model_digest
        if not model_found:
            raise FirecrackerExecutionError("model artifact is absent from the exact repository manifest")
        return manifest

    def _validate_job(self, subject: Path, request: dict[str, Any]) -> dict[str, Any]:
        mode = request.get("mode", "runtime")
        if mode not in {"runtime", "conversion"}:
            raise FirecrackerExecutionError("unsupported fixed runner mode")
        if request.get("environment") not in {"development", "test", "staging", "production"}:
            raise FirecrackerExecutionError("invalid target environment")
        self._validate_subject_manifest(subject, request)
        rootfs_digest = _sha256(Path(self.env["MODEL_INTAKE_ROOTFS_IMAGE"]))
        if _digest(request.get("runtime_image_digest"), "runtime_image_digest", prefixed=True) != rootfs_digest:
            raise FirecrackerExecutionError("runtime image digest does not match the verified guest rootfs")
        profile = request.get("loader_profile")
        if not isinstance(profile, dict):
            raise FirecrackerExecutionError("loader profile is required")
        profile_body = {key: value for key, value in profile.items() if key != "profile_sha256"}
        profile_sha = hashlib.sha256(canonical_bytes(profile_body)).hexdigest()
        if _digest(request.get("loader_profile_sha256"), "loader_profile_sha256") != profile_sha:
            raise FirecrackerExecutionError("loader profile digest mismatch")
        if profile.get("profile_sha256") not in {None, profile_sha}:
            raise FirecrackerExecutionError("embedded loader profile digest mismatch")
        if mode == "runtime" and profile.get("allow_pickle") is not False:
            raise FirecrackerExecutionError("runtime admission never permits pickle-capable loading")
        if mode == "conversion" and (
            profile.get("profile_id") != CONVERSION_PROFILE_ID
            or profile.get("allow_pickle") is not True
            or profile.get("allow_pickle_scope") != "single-reviewed-source-artifact-inside-firecracker"
        ):
            raise FirecrackerExecutionError("conversion requires the exact server-owned restricted profile")
        trust_remote_code = profile.get("trust_remote_code") is True
        reviewed = _custom_code_sha256(subject)
        if trust_remote_code and _digest(request.get("reviewed_custom_code_sha256"), "reviewed_custom_code_sha256") != reviewed:
            raise FirecrackerExecutionError("reviewed custom-code digest mismatch")
        normalized = dict(request)
        normalized["trust_remote_code"] = trust_remote_code
        normalized["allow_pickle"] = mode == "conversion"
        normalized["observed_custom_code_sha256"] = reviewed
        return normalized

    def _namespace_setup(self, name: str) -> None:
        _require_ok(_run(["ip", "netns", "add", name]), "network namespace creation")
        rules = """table inet shakerscan {
 chain input { type filter hook input priority 0; policy drop; counter }
 chain output { type filter hook output priority 0; policy drop; counter }
}
"""
        _require_ok(_run(["ip", "netns", "exec", name, "nft", "-f", "-"], input_text=rules), "deny-all firewall setup")

    def _namespace_state(self, name: str) -> dict[str, Any]:
        links = _run(["ip", "netns", "exec", name, "ip", "-j", "link", "show"])
        nft = _run(["ip", "netns", "exec", name, "nft", "-j", "list", "ruleset"])
        if links.returncode or nft.returncode:
            return {"complete": False, "interfaces": [], "drop_count": 0}
        interfaces = sorted(item.get("ifname") for item in json.loads(links.stdout) if item.get("ifname"))
        drop_count = 0
        def counters(value: Any):
            if isinstance(value, dict):
                if isinstance(value.get("counter"), dict):
                    yield value["counter"]
                for child in value.values():
                    yield from counters(child)
            elif isinstance(value, list):
                for child in value:
                    yield from counters(child)
        for counter in counters(json.loads(nft.stdout)):
            drop_count += int(counter.get("packets") or 0)
        return {"complete": True, "interfaces": interfaces, "drop_count": drop_count}

    @staticmethod
    def _cgroup_state(vm_id: str, memory_mib: int, vcpu_count: int) -> dict[str, Any]:
        root = Path("/sys/fs/cgroup/shakerscan-model-intake") / vm_id
        expected = {
            "memory.max": str(memory_mib * 1024 * 1024),
            "pids.max": "64",
            "cpu.max": f"{vcpu_count * 100000} 100000",
        }
        observed: dict[str, Any] = {}
        complete = True
        for name, wanted in expected.items():
            try:
                value = (root / name).read_text().strip()
            except OSError:
                complete = False
                value = None
            observed[name] = value
            complete = complete and value == wanted
        for name in ("memory.peak", "pids.peak", "cpu.stat"):
            try:
                observed[name] = (root / name).read_text().strip()[:20_000]
            except OSError:
                observed[name] = None
                complete = False
        observed["complete"] = complete
        observed["limits_sha256"] = hashlib.sha256(canonical_bytes({
            key: value for key, value in observed.items() if key not in {"complete", "limits_sha256"}
        })).hexdigest()
        return observed

    def _prepare_drives(self, work: Path, subject: Path, request: dict[str, Any]) -> tuple[Path, Path]:
        staging = work / "input-tree"
        model = staging / "model"
        staging.mkdir(mode=0o700)
        _copy_tree(subject, model)
        try:
            known_answer_suite = suite_identity(request.get("known_answer_inputs") or [])
        except ValueError as exc:
            raise FirecrackerExecutionError(str(exc)) from exc
        job = {
            "schema_version": "model-intake-firecracker-job/v1",
            "mode": request.get("mode", "runtime"),
            "trust_remote_code": bool(request.get("trust_remote_code")),
            "allow_pickle": bool(request.get("allow_pickle")),
            "known_answer_inputs": known_answer_suite["inputs"],
            "known_answer_suite_version": known_answer_suite["suite_version"],
            "known_answer_inputs_sha256": known_answer_suite["inputs_sha256"],
            "known_answer_embedding_sha256": request.get("known_answer_embedding_sha256"),
        }
        job_path = staging / "job.json"
        job_path.write_bytes(canonical_bytes(job))
        job_path.chmod(0o644)
        size = _tree_size(staging)
        max_input = int(self.env.get("MODEL_INTAKE_RUNNER_MAX_INPUT_BYTES", str(20 * 1024**3)))
        if size > max_input:
            raise FirecrackerExecutionError("runner subject exceeds the configured input quota")
        image_size = max(256 * 1024**2, ((size * 13 // 10 + 128 * 1024**2 + 4095) // 4096) * 4096)
        input_drive = work / "input.ext4"
        with input_drive.open("wb") as handle:
            handle.truncate(image_size)
        _require_ok(_run(["mkfs.ext4", "-q", "-F", "-d", str(staging), str(input_drive)], timeout=600), "input drive creation")
        default_output = 512 * 1024**2 if request.get("mode", "runtime") == "runtime" else max(1024**3, size * 13 // 10)
        output_limit = int(self.env.get("MODEL_INTAKE_RUNNER_MAX_OUTPUT_BYTES", str(5 * 1024**3)))
        output_bytes = min(max(int(request.get("output_bytes") or default_output), 64 * 1024**2), output_limit)
        output_drive = work / "output.ext4"
        with output_drive.open("wb") as handle:
            handle.truncate(output_bytes)
        _require_ok(_run(["mkfs.ext4", "-q", "-F", str(output_drive)], timeout=120), "output drive creation")
        return input_drive, output_drive

    def _export_conversion(self, extracted: Path, result: dict[str, Any]) -> dict[str, Any]:
        source = extracted / "work" / "converted"
        target_artifact = source / "model.safetensors"
        if not source.is_dir() or not target_artifact.is_file() or target_artifact.is_symlink():
            raise FirecrackerExecutionError("converted snapshot is missing")
        expected = _digest(result.get("target_artifact_sha256"), "target_artifact_sha256")
        if _sha256(target_artifact) != expected:
            raise FirecrackerExecutionError("converted artifact digest mismatch after guest export")
        files = []
        for path in sorted(source.rglob("*")):
            if path.is_symlink() or (not path.is_dir() and not path.is_file()):
                raise FirecrackerExecutionError("converted snapshot contains an unsafe member")
            if path.is_file():
                files.append({
                    "path": path.relative_to(source).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": _sha256(path),
                })
        manifest = {
            "schema_version": "model-intake-converted-snapshot/v1",
            "complete": True,
            "files": files,
            "target_artifact_sha256": expected,
        }
        manifest_sha = hashlib.sha256(canonical_bytes(manifest)).hexdigest()
        self.conversion_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        destination = (self.conversion_root / expected).resolve()
        manifest_path = (self.conversion_root / f"{expected}.manifest.json").resolve()
        if self.conversion_root != destination.parent:
            raise FirecrackerExecutionError("conversion destination escapes its content-addressed root")
        if destination.exists():
            if not manifest_path.is_file() or hashlib.sha256(manifest_path.read_bytes()).hexdigest() != manifest_sha:
                raise FirecrackerExecutionError("content-addressed conversion destination conflicts")
        else:
            temporary = self.conversion_root / f".{expected}.{uuid.uuid4().hex}.tmp"
            shutil.copytree(source, temporary)
            os.replace(temporary, destination)
            temporary_manifest = self.conversion_root / f".{expected}.{uuid.uuid4().hex}.manifest.tmp"
            temporary_manifest.write_bytes(canonical_bytes(manifest))
            os.replace(temporary_manifest, manifest_path)
        return {
            "target_artifact_sha256": expected,
            "target_repository_snapshot_sha256": manifest_sha,
            "target_repository_manifest_path": str(manifest_path),
            "converted_snapshot_path": str(destination),
        }

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        readiness = firecracker_readiness(self.env)
        if not readiness["ready"]:
            raise FirecrackerExecutionError(f"runner is not ready: {readiness['checks']}")
        subject = self._validated_subject(str(request.get("subject_path") or ""))
        request = self._validate_job(subject, request)
        vm_id = f"mi-{uuid.uuid4().hex[:24]}"
        namespace = vm_id
        work = self.work_root / vm_id
        work.mkdir(parents=True, mode=0o700)
        input_drive, output_drive = self._prepare_drives(work, subject, request)
        config = build_firecracker_config({
            "vm_id": vm_id,
            "kernel_image": self.env["MODEL_INTAKE_KERNEL_IMAGE"],
            "rootfs_image": self.env["MODEL_INTAKE_ROOTFS_IMAGE"],
            "input_drive": str(input_drive),
            "output_drive": str(output_drive),
            "vcpu_count": request.get("vcpu_count", 2),
            "memory_mib": request.get("memory_mib", 4096),
            "timeout_seconds": request.get("timeout_seconds", 600),
        })
        firecracker = Path(self.env["MODEL_INTAKE_FIRECRACKER_BIN"])
        jailer = self.env["MODEL_INTAKE_JAILER_BIN"]
        jail_uid = int(self.env.get("MODEL_INTAKE_JAILER_UID", "65532"))
        jail_gid = int(self.env.get("MODEL_INTAKE_JAILER_GID", "65532"))
        process: subprocess.Popen[bytes] | None = None
        log_handle = None
        jail: Path | None = None
        started = time.monotonic()
        try:
            self._namespace_setup(namespace)
            firewall_before = self._namespace_state(namespace)
            argv = [
                jailer, "--id", vm_id, "--exec-file", str(firecracker),
                "--uid", str(jail_uid), "--gid", str(jail_gid),
                "--chroot-base-dir", str(self.jailer_root),
                "--netns", f"/var/run/netns/{namespace}", "--new-pid-ns",
                "--cgroup-version", "2", "--parent-cgroup", "shakerscan-model-intake",
                "--cgroup", f"memory.max={int(request.get('memory_mib', 4096)) * 1024 * 1024}",
                "--cgroup", "pids.max=64",
                "--cgroup", f"cpu.max={int(request.get('vcpu_count', 2)) * 100000} 100000",
                "--resource-limit", "no-file=1024", "--resource-limit", "fsize=1073741824",
                "--", "--api-sock", "/run/firecracker.socket",
            ]
            log_handle = (work / "jailer.log").open("wb")
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log_handle, stderr=subprocess.STDOUT, start_new_session=True)
            jail = self.jailer_root / firecracker.name / vm_id / "root"
            api_socket = jail / "run" / "firecracker.socket"
            deadline = time.monotonic() + 15
            while not api_socket.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if not api_socket.exists():
                raise FirecrackerExecutionError("Firecracker API socket did not become ready")
            resources = {
                "kernel": Path(config["boot-source"]["kernel_image_path"]),
                "rootfs.ext4": Path(config["drives"][0]["path_on_host"]),
                "input.ext4": input_drive,
                "output.ext4": output_drive,
            }
            for name, source in resources.items():
                target = jail / name
                shutil.copyfile(source, target)
                os.chown(target, jail_uid, jail_gid)
                target.chmod(0o600)
            _unix_http(api_socket, "PUT", "/boot-source", {
                "kernel_image_path": "/kernel",
                "boot_args": config["boot-source"]["boot_args"] + " init=/opt/shakerscan/guest-init",
            })
            for drive in (
                {"drive_id": "rootfs", "path_on_host": "/rootfs.ext4", "is_root_device": True, "is_read_only": True},
                {"drive_id": "input", "path_on_host": "/input.ext4", "is_root_device": False, "is_read_only": True},
                {"drive_id": "output", "path_on_host": "/output.ext4", "is_root_device": False, "is_read_only": False},
            ):
                _unix_http(api_socket, "PUT", f"/drives/{drive['drive_id']}", drive)
            _unix_http(api_socket, "PUT", "/machine-config", config["machine-config"])
            _unix_http(api_socket, "PUT", "/actions", {"action_type": "InstanceStart"})
            timeout = min(int(request.get("timeout_seconds") or 600), 3600)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
                raise FirecrackerExecutionError("microVM execution timed out") from exc
            jailed_output = jail / "output.ext4"
            shutil.copyfile(jailed_output, output_drive)
            extracted = work / "output"
            extracted.mkdir(mode=0o700)
            dump = _run(["debugfs", "-R", f"rdump / {extracted}", str(output_drive)], timeout=120)
            _require_ok(dump, "output evidence extraction")
            result_path = extracted / "result.json"
            if not result_path.is_file() or result_path.stat().st_size > 2_000_000:
                raise FirecrackerExecutionError("guest result is missing or oversized")
            result = json.loads(result_path.read_text())
            guest_interfaces = result.get("guest_interfaces") if isinstance(result.get("guest_interfaces"), list) else []
            firewall_after = self._namespace_state(namespace)
            network = parse_network_telemetry(extracted / "traces", guest_interfaces, {
                "complete": firewall_before.get("complete") is True and firewall_after.get("complete") is True,
                "interfaces": firewall_after.get("interfaces") or [],
                "drop_count_before": firewall_before.get("drop_count") or 0,
                "drop_count_after": firewall_after.get("drop_count") or 0,
                "no_network_device": config.get("network-interfaces") == []
                and firewall_after.get("interfaces") == ["lo"],
                "network_interface_config_count": len(config.get("network-interfaces") or []),
                "tap_device_count": sum(
                    1 for name in (firewall_after.get("interfaces") or []) if str(name).startswith("tap")
                ),
            }, destination_salt=os.urandom(32))
            required_phases = (
                {"import", "tokenizer", "model_load", "warmup", "inference", "teardown"}
                if request.get("mode", "runtime") == "runtime"
                else {"import", "deserialize_convert", "tensor_equivalence", "embedding_equivalence", "teardown"}
            )
            if set(result.get("phases") or {}) != required_phases:
                network["complete"] = False
                network["telemetry_sha256"] = hashlib.sha256(canonical_bytes({
                    key: value for key, value in network.items() if key != "telemetry_sha256"
                })).hexdigest()
            result["network_telemetry"] = network
            result["network_egress_blocked"] = (
                network["complete"] and not network["overflowed"] and network["lost_events"] == 0
                and network["attempt_count"] == 0 and network["host_firewall_drop_count"] == 0
                and network["guest_interfaces"] == ["lo"] and network["host_interfaces"] == ["lo"]
            )
            result["syscall_telemetry_complete"] = network["complete"] and not network["overflowed"]
            cgroup = self._cgroup_state(vm_id, int(request.get("memory_mib", 4096)), int(request.get("vcpu_count", 2)))
            result["resource_telemetry"] = cgroup
            result["resource_limits_enforced"] = cgroup["complete"]
            result["reviewed_custom_code_sha256"] = request.get("observed_custom_code_sha256")
            result["observations_generated_by_runner"] = True
            known_answer_suite = suite_identity(request.get("known_answer_inputs") or [])
            result["benchmark_suite_version"] = known_answer_suite["suite_version"]
            result["benchmark_dataset_sha256"] = known_answer_suite["inputs_sha256"]
            result["benchmark_input_count"] = known_answer_suite["input_count"]
            result["thresholds_sha256"] = hashlib.sha256(canonical_bytes({
                "known_answer_embedding_sha256": request.get("known_answer_embedding_sha256"),
                "vcpu_count": int(request.get("vcpu_count") or 2),
                "memory_mib": int(request.get("memory_mib") or 4096),
                "timeout_seconds": min(int(request.get("timeout_seconds") or 600), 3600),
                "network_attempts_allowed": 0,
            })).hexdigest()
            if request.get("mode") == "conversion" and result.get("status") == "PASS":
                if result.get("source_artifact_sha256") != request.get("model_artifact_sha256"):
                    raise FirecrackerExecutionError("conversion source digest does not match the requested artifact")
                result.update(self._export_conversion(extracted, result))
                result["converter_image_digest"] = "sha256:" + _sha256(Path(self.env["MODEL_INTAKE_ROOTFS_IMAGE"]))
            result["runner_duration_seconds"] = round(time.monotonic() - started, 3)
            result["firecracker_component_sha256"] = readiness["verified_component_sha256"]
            result["firecracker_config_sha256"] = hashlib.sha256(canonical_bytes(config)).hexdigest()
            (work / "observations.json").write_bytes(canonical_bytes(result))
            # Raw traces can contain destination addresses and model paths. The
            # signed observation retains their digest plus a salted normalized
            # event stream, then destroys the transient drives and raw output.
            shutil.rmtree(work / "input-tree", ignore_errors=True)
            shutil.rmtree(extracted, ignore_errors=True)
            for transient in (input_drive, output_drive):
                try:
                    transient.unlink()
                except OSError:
                    pass
            return result
        finally:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            if log_handle is not None:
                log_handle.close()
            _run(["ip", "netns", "delete", namespace])
            cgroup = Path("/sys/fs/cgroup/shakerscan-model-intake") / vm_id
            try:
                cgroup.rmdir()
            except OSError:
                pass
            if jail is not None and jail.parent.name == vm_id and jail.parent.parent.parent == self.jailer_root:
                shutil.rmtree(jail.parent, ignore_errors=True)

    def execute_and_sign(self, request: dict[str, Any]) -> dict[str, Any]:
        started_at = datetime.now(timezone.utc)
        observations = self.execute(request)
        finished_at = datetime.now(timezone.utc)
        status = str(observations.get("status") or "INCOMPLETE")
        if status == "PASS" and not observations.get("network_egress_blocked"):
            status = "FAIL"
        payload = {
            "schema_version": SCHEMA,
            "receipt_id": str(uuid.uuid4()),
            "submission_id": str(uuid.UUID(str(request["submission_id"]))),
            "evidence_type": "conversion_equivalence" if request.get("mode") == "conversion" else "runtime_execution",
            "environment": str(request["environment"]),
            "deployment_bundle_sha256": str(request["deployment_bundle_sha256"]).lower(),
            "model_artifact_sha256": (
                str(observations["target_artifact_sha256"]).lower()
                if request.get("mode") == "conversion"
                else str(request["model_artifact_sha256"]).lower()
            ),
            "repository_snapshot_sha256": str(request["repository_snapshot_sha256"]).lower(),
            "runtime_image_digest": str(request["runtime_image_digest"]).lower(),
            "loader_profile_sha256": str(request["loader_profile_sha256"]).lower(),
            "builder_id": self.env.get("MODEL_INTAKE_RUNNER_BUILDER_ID", ""),
            "runner_version": self.env.get("MODEL_INTAKE_RUNNER_VERSION", "unknown"),
            "invocation_id": str(uuid.uuid4()),
            "status": status,
            "observations": observations,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "expires_at": (finished_at + timedelta(days=int(self.env.get("MODEL_INTAKE_RUNNER_RECEIPT_DAYS", "7")))).isoformat(),
        }
        backend = self.env.get("MODEL_INTAKE_RUNNER_SIGNER_BACKEND", "").lower()
        if backend == "aws-kms":
            signer = AwsKmsSigner(
                self.env.get("MODEL_INTAKE_RUNNER_SIGNER_KEY_ID", ""),
                region=self.env.get("MODEL_INTAKE_RUNNER_AWS_REGION") or None,
            )
        elif backend == "local-pem" and request.get("environment") != "production" and self.env.get("MODEL_INTAKE_RUNNER_ALLOW_LOCAL_PEM") == "true":
            signer = LocalPemSigner(self.env.get("MODEL_INTAKE_RUNNER_SIGNING_KEY_PEM", ""))
        else:
            raise FirecrackerExecutionError("no permitted runner receipt signer is configured")
        return {"receipt": issue_runner_envelope(payload, signer), "payload": payload}


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute one fixed Model Intake Firecracker job")
    parser.add_argument("--request", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    request_path = Path(args.request).resolve(strict=True)
    if request_path.stat().st_size > 1_000_000:
        raise FirecrackerExecutionError("request is oversized")
    request = json.loads(request_path.read_text())
    result = FirecrackerRunner().execute_and_sign(request)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_bytes(canonical_bytes(result))
    temporary.chmod(0o600)
    os.replace(temporary, output)
    return 0


__all__ = ["FirecrackerExecutionError", "FirecrackerRunner", "parse_network_telemetry"]


if __name__ == "__main__":
    raise SystemExit(main())
