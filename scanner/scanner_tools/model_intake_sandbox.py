"""File-queue client and no-egress service for dynamic model artifact inspection."""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import os
import resource
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "model-intake-sandbox/v1"
HEARTBEAT_MAX_AGE_SECONDS = 15
ALLOWED_DIGEST = set("0123456789abcdef")
RISKY_EXTENSIONS = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt", ".bin", ".mar"}
MAX_REQUEST_TIMEOUT_SECONDS = 600
DEFAULT_CHILD_MEMORY_BYTES = 1_500_000_000
DEFAULT_CHILD_FILE_BYTES = 64_000_000
DEFAULT_CHILD_OPEN_FILES = 256
DEFAULT_CHILD_PROCESSES = 32
MAX_RUNTIME_REPORT_BYTES = 2_000_000
MAX_RUNTIME_STDERR_BYTES = 32_000


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _attach_evidence_digest(payload: dict[str, Any]) -> dict[str, Any]:
    payload["evidence_sha256"] = _sha256_json(payload)
    return payload


def _request_binding(request_id: str, request_nonce: str) -> dict[str, str]:
    return {
        "request_id": request_id,
        "request_nonce_sha256": hashlib.sha256(request_nonce.encode("utf-8")).hexdigest(),
    }


def _safe_digest(value: Any) -> str:
    digest = str(value or "").lower().removeprefix("sha256:")
    if len(digest) != 64 or any(char not in ALLOWED_DIGEST for char in digest):
        raise ValueError("request requires a lowercase SHA-256 digest")
    return digest


def _network_probe() -> dict[str, Any]:
    observations = []
    for address in (("169.254.169.254", 80), ("1.1.1.1", 53)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        try:
            code = sock.connect_ex(address)
        except OSError as exc:
            code = f"{type(exc).__name__}:{exc}"
        finally:
            sock.close()
        observations.append({"destination": f"{address[0]}:{address[1]}", "connect_result": code})
    return {
        "network_mode": os.getenv("MODEL_INTAKE_SANDBOX_NETWORK_MODE") or "unknown",
        "outbound_probes": observations,
        "blocked": all(item["connect_result"] != 0 for item in observations),
    }


def _seccomp_mode() -> int | None:
    try:
        for line in Path("/proc/self/status").read_text("utf-8").splitlines():
            if line.startswith("Seccomp:"):
                return int(line.split(":", 1)[1].strip())
    except (OSError, ValueError):
        pass
    return None


def _runtime_adapter(extension: str) -> tuple[dict[str, Any] | None, str | None]:
    raw = os.getenv("MODEL_INTAKE_SANDBOX_RUNTIME_ADAPTERS_JSON")
    if not raw:
        if extension == ".safetensors":
            return {
                "name": "shakerscan-safetensors-weights",
                "version": "1",
                "required_load_level": "weights",
                "argv": [
                    sys.executable,
                    "/app/scanner_tools/model_intake_runtime.py",
                    "{artifact}",
                    "{digest}",
                ],
            }, None
        return None, None
    try:
        configuration = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        return None, f"runtime_adapter_configuration_invalid:{type(exc).__name__}"
    if not isinstance(configuration, dict):
        return None, "runtime_adapter_configuration_invalid:not_object"
    adapter = configuration.get(extension) or configuration.get(extension.lstrip("."))
    if adapter is None:
        return None, None
    if not isinstance(adapter, dict) or not isinstance(adapter.get("argv"), list):
        return None, "runtime_adapter_configuration_invalid:argv_required"
    argv = adapter["argv"]
    if not argv or len(argv) > 100 or not all(isinstance(item, str) and item for item in argv):
        return None, "runtime_adapter_configuration_invalid:argv_invalid"
    return adapter, None


def _runtime_environment() -> dict[str, str]:
    allowed = {
        "PATH", "LANG", "LC_ALL", "HOME", "TMPDIR", "LD_LIBRARY_PATH",
        "PYTHONPATH", "CUDA_VISIBLE_DEVICES", "HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update({
        "NO_PROXY": "*",
        "no_proxy": "*",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
        "MODEL_INTAKE_RUNTIME_NO_NETWORK": "1",
    })
    return environment


def _run_runtime_adapter(
    adapter: dict[str, Any],
    *,
    path: Path,
    filename: str,
    digest: str,
) -> dict[str, Any]:
    replacements = {
        "{artifact}": str(path),
        "{filename}": Path(filename).name,
        "{digest}": digest,
    }
    argv = [
        replacements.get(argument, argument)
        for argument in adapter["argv"]
    ]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_runtime_environment(),
            cwd="/tmp",
            check=False,
            timeout=_bounded_env_int("MODEL_INTAKE_SANDBOX_RUNTIME_TIMEOUT_SECONDS", 90, 1, 590),
        )
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "error": "runtime_adapter_timeout", "adapter": adapter.get("name")}
    except OSError as exc:
        return {"status": "CRASHED", "error": f"runtime_adapter_launch_failed:{type(exc).__name__}:{exc}"}
    stderr = completed.stderr[:MAX_RUNTIME_STDERR_BYTES].decode("utf-8", "replace")
    if len(completed.stdout) > MAX_RUNTIME_REPORT_BYTES:
        return {
            "status": "FAIL",
            "error": "runtime_adapter_report_too_large",
            "exit_code": completed.returncode,
            "stderr": stderr,
        }
    try:
        report = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "status": "FAIL",
            "error": f"runtime_adapter_report_invalid:{type(exc).__name__}",
            "exit_code": completed.returncode,
            "stderr": stderr,
        }
    if not isinstance(report, dict):
        return {"status": "FAIL", "error": "runtime_adapter_report_not_object", "exit_code": completed.returncode}
    known_answers = report.get("known_answer_tests") if isinstance(report.get("known_answer_tests"), list) else []
    blockers = []
    if completed.returncode != 0:
        blockers.append("runtime_adapter_nonzero_exit")
    if report.get("status") != "PASS":
        blockers.append("runtime_adapter_report_non_pass")
    if report.get("artifact_sha256") != digest:
        blockers.append("runtime_artifact_digest_mismatch")
    required_load_level = str(adapter.get("required_load_level") or "model")
    if required_load_level == "weights":
        if report.get("artifact_loaded") is not True or report.get("load_level") != "weights":
            blockers.append("weights_load_not_proven")
    elif report.get("model_loaded") is not True or report.get("load_level") not in {None, "model"}:
        blockers.append("model_load_not_proven")
    if not known_answers:
        blockers.append("known_answer_tests_missing")
    elif any(not isinstance(item, dict) or item.get("status") != "PASS" for item in known_answers):
        blockers.append("known_answer_test_non_pass")
    if report.get("network_attempts") not in (None, []):
        blockers.append("runtime_network_attempt_reported")
    try:
        spawned_processes = int(report.get("spawned_processes") or 0)
    except (TypeError, ValueError):
        spawned_processes = -1
    allowed_processes = int(adapter.get("max_spawned_processes") or 0)
    if spawned_processes < 0 or spawned_processes > allowed_processes:
        blockers.append("runtime_process_budget_exceeded")
    return {
        "status": "FAIL" if blockers else "PASS",
        "adapter": {
            "name": str(adapter.get("name") or Path(argv[0]).name),
            "version": str(adapter.get("version") or "") or None,
            "argv_sha256": _sha256_json(adapter["argv"]),
        },
        "exit_code": completed.returncode,
        "duration_seconds": round(time.monotonic() - started, 6),
        "model_loaded": report.get("model_loaded") is True,
        "artifact_loaded": report.get("artifact_loaded") is True,
        "load_level": report.get("load_level"),
        "artifact_sha256": report.get("artifact_sha256"),
        "known_answer_tests": known_answers[:100],
        "imports": report.get("imports", [])[:100] if isinstance(report.get("imports"), list) else [],
        "spawned_processes": spawned_processes,
        "network_attempts": report.get("network_attempts", []),
        "limitations": report.get("limitations", [])[:100] if isinstance(report.get("limitations"), list) else [],
        "blockers": blockers,
        "stderr": stderr,
        "report_sha256": _sha256_json(report),
    }


def _inspect_safetensors(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        length_raw = handle.read(8)
        if len(length_raw) != 8:
            return {"status": "FAIL", "error": "truncated_header_length"}
        header_length = int.from_bytes(length_raw, "little")
        if header_length <= 0 or header_length > 100_000_000:
            return {"status": "FAIL", "error": "invalid_header_length", "header_length": header_length}
        header = json.loads(handle.read(header_length).decode("utf-8"))
    if not isinstance(header, dict):
        return {"status": "FAIL", "error": "header_not_object"}
    payload_size = path.stat().st_size - 8 - header_length
    invalid = []
    for name, tensor in header.items():
        if name == "__metadata__":
            continue
        offsets = tensor.get("data_offsets") if isinstance(tensor, dict) else None
        if not isinstance(offsets, list) or len(offsets) != 2 or not all(isinstance(item, int) for item in offsets):
            invalid.append({"tensor": name, "reason": "invalid_offsets"})
        elif offsets[0] < 0 or offsets[1] < offsets[0] or offsets[1] > payload_size:
            invalid.append({"tensor": name, "reason": "out_of_bounds"})
    return {
        "status": "FAIL" if invalid else "PASS",
        "format": "safetensors",
        "tensor_count": len([name for name in header if name != "__metadata__"]),
        "invalid_tensors": invalid[:100],
        "payload_size": payload_size,
    }


def _inspect_onnx(path: Path) -> dict[str, Any]:
    try:
        import onnx  # type: ignore
        model = onnx.load(str(path), load_external_data=False)
        onnx.checker.check_model(model, full_check=False)
    except ImportError:
        return {"status": "UNSUPPORTED", "format": "onnx", "error": "onnx_runtime_unavailable"}
    except Exception as exc:
        return {"status": "FAIL", "format": "onnx", "error": f"{type(exc).__name__}: {exc}"}
    external = []
    domains = []
    for initializer in getattr(model.graph, "initializer", []) or []:
        for item in getattr(initializer, "external_data", []) or []:
            if getattr(item, "key", "") == "location":
                external.append(str(getattr(item, "value", "")))
    for node in getattr(model.graph, "node", []) or []:
        domain = str(getattr(node, "domain", "") or "")
        if domain and domain not in {"ai.onnx", "ai.onnx.ml"}:
            domains.append(domain)
    return {
        "status": "FAIL" if external or domains else "PASS",
        "format": "onnx",
        "graph_name": getattr(model.graph, "name", None),
        "external_data_locations": sorted(set(external))[:100],
        "custom_operator_domains": sorted(set(domains))[:100],
    }


def inspect_quarantine_object(
    path: Path,
    filename: str,
    *,
    expected_digest: str,
    request_id: str | None = None,
    request_nonce: str | None = None,
) -> dict[str, Any]:
    started = _utc_iso()
    before = resource.getrusage(resource.RUSAGE_SELF)
    observed_digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            observed_digest.update(chunk)
            size += len(chunk)
    digest = observed_digest.hexdigest()
    extension = Path(filename).suffix.lower()
    if digest != expected_digest:
        inspection = {"status": "FAIL", "error": "quarantine_digest_mismatch"}
    elif extension in RISKY_EXTENSIONS:
        inspection = {
            "status": "BLOCKED_BY_POLICY",
            "format": extension.lstrip("."),
            "error": "executable_serialization_load_prohibited",
        }
    elif extension == ".safetensors":
        try:
            inspection = _inspect_safetensors(path)
        except Exception as exc:
            inspection = {"status": "FAIL", "format": "safetensors", "error": f"{type(exc).__name__}: {exc}"}
    elif extension == ".onnx":
        inspection = _inspect_onnx(path)
    elif extension == ".gguf":
        with path.open("rb") as handle:
            magic = handle.read(4)
        inspection = {"status": "PASS" if magic == b"GGUF" else "FAIL", "format": "gguf", "magic_valid": magic == b"GGUF"}
    else:
        inspection = {"status": "UNSUPPORTED", "format": extension.lstrip(".") or "unknown", "error": "dynamic_format_not_supported"}
    static_inspection = inspection
    if inspection["status"] not in {"FAIL", "BLOCKED_BY_POLICY"}:
        adapter, adapter_error = _runtime_adapter(extension)
        if adapter_error:
            inspection = {
                "status": "FAIL",
                "format": extension.lstrip(".") or "unknown",
                "error": adapter_error,
                "static_inspection": static_inspection,
            }
        elif adapter:
            runtime = _run_runtime_adapter(
                adapter,
                path=path,
                filename=filename,
                digest=digest,
            )
            inspection = {
                "status": runtime["status"],
                "format": extension.lstrip(".") or "unknown",
                "static_inspection": static_inspection,
                "runtime": runtime,
            }
        else:
            inspection = {
                "status": "UNSUPPORTED",
                "format": extension.lstrip(".") or "unknown",
                "error": "runtime_adapter_not_configured",
                "static_inspection": static_inspection,
            }
    after = resource.getrusage(resource.RUSAGE_SELF)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "provenance_class": "shakerscan_generated",
        "status": inspection["status"],
        "subject": {"digest": f"sha256:{digest}", "filename": Path(filename).name, "size_bytes": size},
        "inspection": inspection,
        "isolation": {
            "network": _network_probe(),
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "read_only_rootfs_declared": os.getenv("MODEL_INTAKE_SANDBOX_READ_ONLY") == "1",
            "no_new_privileges_declared": os.getenv("MODEL_INTAKE_SANDBOX_NO_NEW_PRIVILEGES") == "1",
            "seccomp_mode": _seccomp_mode(),
            "credentials_present": any(
                key.lower().endswith(("token", "password", "secret", "api_key"))
                for key, value in os.environ.items() if value
            ),
        },
        "resources": {
            "user_cpu_seconds": max(0.0, after.ru_utime - before.ru_utime),
            "system_cpu_seconds": max(0.0, after.ru_stime - before.ru_stime),
            "max_rss": after.ru_maxrss,
        },
        "started_at": started,
        "finished_at": _utc_iso(),
    }
    if request_id and request_nonce:
        payload["request_binding"] = _request_binding(request_id, request_nonce)
    return _attach_evidence_digest(payload)


def _safe_request_identity(request: dict[str, Any], request_path: Path) -> tuple[str, str]:
    request_id = str(request.get("request_id") or "")
    request_nonce = str(request.get("request_nonce") or "")
    if request_id != request_path.stem or not request_id:
        raise ValueError("request identifier does not match queue filename")
    if len(request_nonce) < 32 or len(request_nonce) > 256:
        raise ValueError("request nonce must contain 32 through 256 characters")
    return request_id, request_nonce


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(int(os.getenv(name) or default), maximum))
    except (TypeError, ValueError):
        return default


def _apply_child_resource_limits(timeout_seconds: int) -> None:
    limits = [
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_CPU, max(1, timeout_seconds)),
        (resource.RLIMIT_FSIZE, _bounded_env_int(
            "MODEL_INTAKE_SANDBOX_MAX_FILE_BYTES", DEFAULT_CHILD_FILE_BYTES, 1_000_000, 1_000_000_000,
        )),
        (resource.RLIMIT_NOFILE, _bounded_env_int(
            "MODEL_INTAKE_SANDBOX_MAX_OPEN_FILES", DEFAULT_CHILD_OPEN_FILES, 32, 4_096,
        )),
    ]
    if hasattr(resource, "RLIMIT_NPROC"):
        limits.append((resource.RLIMIT_NPROC, _bounded_env_int(
            "MODEL_INTAKE_SANDBOX_MAX_PROCESSES", DEFAULT_CHILD_PROCESSES, 1, 256,
        )))
    # RLIMIT_AS is reliable in the Linux service container. On macOS it can be
    # lower than the interpreter's existing virtual mapping and cause spurious
    # local-test failures before inspection begins.
    if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_AS"):
        limits.append((resource.RLIMIT_AS, _bounded_env_int(
            "MODEL_INTAKE_SANDBOX_MAX_MEMORY_BYTES", DEFAULT_CHILD_MEMORY_BYTES,
            256_000_000, 8_000_000_000,
        )))
    for limit_kind, value in limits:
        resource.setrlimit(limit_kind, (value, value))


def _inspection_child(
    connection: Any,
    subject_path: Path,
    filename: str,
    digest: str,
    request_id: str,
    request_nonce: str,
    timeout_seconds: int,
) -> None:
    try:
        _apply_child_resource_limits(timeout_seconds)
        result = inspect_quarantine_object(
            subject_path,
            filename,
            expected_digest=digest,
            request_id=request_id,
            request_nonce=request_nonce,
        )
    except BaseException as exc:
        result = _attach_evidence_digest({
            "schema_version": SCHEMA_VERSION,
            "provenance_class": "shakerscan_generated",
            "status": "CRASHED",
            "error": f"{type(exc).__name__}: {exc}",
            "request_binding": _request_binding(request_id, request_nonce),
            "finished_at": _utc_iso(),
        })
    try:
        connection.send(result)
    finally:
        connection.close()


def _run_bounded_inspection(
    subject_path: Path,
    filename: str,
    digest: str,
    request_id: str,
    request_nonce: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    context = multiprocessing.get_context("fork") if hasattr(os, "fork") else multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_inspection_child,
        args=(sender, subject_path, filename, digest, request_id, request_nonce, timeout_seconds),
        daemon=True,
    )
    process.start()
    sender.close()
    try:
        if receiver.poll(timeout_seconds):
            try:
                return receiver.recv()
            except EOFError:
                pass
        if process.is_alive():
            process.terminate()
        process.join(timeout=2)
        return _attach_evidence_digest({
            "schema_version": SCHEMA_VERSION,
            "provenance_class": "shakerscan_generated",
            "status": "TIMEOUT" if process.exitcode is None or process.exitcode == -15 else "CRASHED",
            "error": "sandbox_child_timeout" if process.exitcode is None or process.exitcode == -15 else f"sandbox_child_exit:{process.exitcode}",
            "request_binding": _request_binding(request_id, request_nonce),
            "finished_at": _utc_iso(),
        })
    finally:
        receiver.close()
        if process.is_alive():
            process.kill()
        process.join(timeout=2)


def process_pending_once(queue_root: Path, quarantine_root: Path) -> int:
    requests = queue_root / "requests"
    responses = queue_root / "responses"
    requests.mkdir(parents=True, exist_ok=True)
    responses.mkdir(parents=True, exist_ok=True)
    processed = 0
    for request_path in sorted(requests.glob("*.json")):
        response_path = responses / request_path.name
        if response_path.exists():
            continue
        request_id = request_path.stem
        request_nonce = "unbound"
        try:
            request = json.loads(request_path.read_text("utf-8"))
            if not isinstance(request, dict):
                raise ValueError("sandbox request must be an object")
            request_id, request_nonce = _safe_request_identity(request, request_path)
            digest = _safe_digest(request.get("digest"))
            subject_path = quarantine_root / "sha256" / digest[:2] / digest
            if not subject_path.is_file() or subject_path.is_symlink():
                raise FileNotFoundError("quarantine object missing")
            timeout_seconds = max(1, min(int(request.get("timeout_seconds") or 120), MAX_REQUEST_TIMEOUT_SECONDS))
            result = _run_bounded_inspection(
                subject_path,
                str(request.get("filename") or "artifact"),
                digest,
                request_id,
                request_nonce,
                timeout_seconds,
            )
        except Exception as exc:
            result = _attach_evidence_digest({
                "schema_version": SCHEMA_VERSION,
                "provenance_class": "shakerscan_generated",
                "status": "CRASHED",
                "error": f"{type(exc).__name__}: {exc}",
                "request_binding": _request_binding(request_id, request_nonce),
                "finished_at": _utc_iso(),
            })
        temporary = response_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
        os.replace(temporary, response_path)
        processed += 1
    return processed


def _rejected_sandbox_response(errors: list[str], response: Any = None) -> dict[str, Any]:
    rejected = {
        "schema_version": SCHEMA_VERSION,
        "provenance_class": "shakerscan_generated",
        "status": "CRASHED",
        "error": "sandbox_response_validation_failed",
        "validation_errors": errors,
    }
    if isinstance(response, dict) and response.get("evidence_sha256"):
        rejected["rejected_evidence_sha256"] = str(response["evidence_sha256"])
    return rejected


def _validate_sandbox_response(
    response: Any,
    *,
    request_id: str,
    request_nonce: str,
    digest: str,
    filename: str,
) -> dict[str, Any]:
    if not isinstance(response, dict):
        return _rejected_sandbox_response(["response_not_object"])
    errors: list[str] = []
    if response.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version_mismatch")
    if response.get("provenance_class") != "shakerscan_generated":
        errors.append("provenance_class_invalid")
    evidence_sha256 = str(response.get("evidence_sha256") or "")
    evidence_body = dict(response)
    evidence_body.pop("evidence_sha256", None)
    if evidence_sha256 != _sha256_json(evidence_body):
        errors.append("evidence_digest_mismatch")
    if response.get("request_binding") != _request_binding(request_id, request_nonce):
        errors.append("request_binding_mismatch")
    status = str(response.get("status") or "")
    if status not in {"PASS", "FAIL", "UNSUPPORTED", "BLOCKED_BY_POLICY", "TIMEOUT", "CRASHED", "INCOMPLETE"}:
        errors.append("status_invalid")
    if status in {"PASS", "FAIL", "UNSUPPORTED", "BLOCKED_BY_POLICY", "INCOMPLETE"}:
        subject = response.get("subject") if isinstance(response.get("subject"), dict) else {}
        if subject.get("digest") != f"sha256:{digest}":
            errors.append("subject_digest_mismatch")
        if subject.get("filename") != Path(filename).name:
            errors.append("subject_filename_mismatch")
    if status == "PASS":
        isolation = response.get("isolation") if isinstance(response.get("isolation"), dict) else {}
        network = isolation.get("network") if isinstance(isolation.get("network"), dict) else {}
        if network.get("blocked") is not True or network.get("network_mode") != "none":
            errors.append("no_egress_not_proven")
        if isolation.get("uid") in {None, 0}:
            errors.append("non_root_not_proven")
        if isolation.get("read_only_rootfs_declared") is not True:
            errors.append("read_only_rootfs_not_proven")
        if isolation.get("no_new_privileges_declared") is not True:
            errors.append("no_new_privileges_not_proven")
        if isolation.get("seccomp_mode") != 2:
            errors.append("seccomp_filter_not_proven")
        if isolation.get("credentials_present") is not False:
            errors.append("credential_free_environment_not_proven")
    return _rejected_sandbox_response(errors, response) if errors else response


def request_sandbox_analysis(
    digest: str,
    filename: str,
    *,
    queue_root: Path,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    normalized = _safe_digest(digest)
    heartbeat = queue_root / "heartbeat.json"
    try:
        heartbeat_age = time.time() - heartbeat.stat().st_mtime
    except OSError:
        heartbeat_age = HEARTBEAT_MAX_AGE_SECONDS + 1
    if heartbeat_age > HEARTBEAT_MAX_AGE_SECONDS:
        return {
            "schema_version": SCHEMA_VERSION,
            "provenance_class": "shakerscan_generated",
            "status": "UNSUPPORTED",
            "error": "sandbox_service_unavailable",
        }
    request_id = str(uuid.uuid4())
    request_nonce = uuid.uuid4().hex + uuid.uuid4().hex
    requests = queue_root / "requests"
    responses = queue_root / "responses"
    requests.mkdir(parents=True, exist_ok=True)
    responses.mkdir(parents=True, exist_ok=True)
    request_path = requests / f"{request_id}.json"
    temporary = request_path.with_suffix(".tmp")
    temporary.write_text(json.dumps({
        "request_id": request_id,
        "request_nonce": request_nonce,
        "digest": normalized,
        "filename": Path(filename).name,
        "timeout_seconds": max(1, min(int(timeout_seconds), MAX_REQUEST_TIMEOUT_SECONDS)),
        "requested_at": _utc_iso(),
    }), encoding="utf-8")
    os.replace(temporary, request_path)
    response_path = responses / request_path.name
    deadline = time.monotonic() + max(1, min(int(timeout_seconds), 600))
    while time.monotonic() < deadline:
        if response_path.exists():
            try:
                response = json.loads(response_path.read_text("utf-8"))
                return _validate_sandbox_response(
                    response,
                    request_id=request_id,
                    request_nonce=request_nonce,
                    digest=normalized,
                    filename=filename,
                )
            except (OSError, json.JSONDecodeError) as exc:
                return {"schema_version": SCHEMA_VERSION, "status": "CRASHED", "error": f"invalid_sandbox_response:{exc}"}
        time.sleep(0.1)
    return {"schema_version": SCHEMA_VERSION, "provenance_class": "shakerscan_generated", "status": "TIMEOUT", "error": "sandbox_response_timeout"}


def serve(queue_root: Path, quarantine_root: Path) -> None:
    queue_root.mkdir(parents=True, exist_ok=True)
    while True:
        heartbeat = queue_root / "heartbeat.json"
        temporary = heartbeat.with_suffix(".tmp")
        temporary.write_text(json.dumps({"at": _utc_iso(), "pid": os.getpid()}), encoding="utf-8")
        os.replace(temporary, heartbeat)
        process_pending_once(queue_root, quarantine_root)
        time.sleep(0.25)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--queue-root", default="/results/model-intake-sandbox")
    parser.add_argument("--quarantine-root", default="/results/model-intake-quarantine")
    args = parser.parse_args()
    if args.serve:
        serve(Path(args.queue_root), Path(args.quarantine_root))
        return 0
    parser.error("--serve is required")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
