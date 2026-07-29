"""File-queue client and no-egress service for dynamic model artifact inspection."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "model-intake-sandbox/v1"
HEARTBEAT_MAX_AGE_SECONDS = 15
ALLOWED_DIGEST = set("0123456789abcdef")
RISKY_EXTENSIONS = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt", ".bin", ".mar"}


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


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


def inspect_quarantine_object(path: Path, filename: str, *, expected_digest: str) -> dict[str, Any]:
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
    payload["evidence_sha256"] = _sha256_json(payload)
    return payload


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
        try:
            request = json.loads(request_path.read_text("utf-8"))
            digest = _safe_digest(request.get("digest"))
            subject_path = quarantine_root / "sha256" / digest[:2] / digest
            if not subject_path.is_file() or subject_path.is_symlink():
                raise FileNotFoundError("quarantine object missing")
            result = inspect_quarantine_object(subject_path, str(request.get("filename") or "artifact"), expected_digest=digest)
        except Exception as exc:
            result = {
                "schema_version": SCHEMA_VERSION,
                "provenance_class": "shakerscan_generated",
                "status": "CRASHED",
                "error": f"{type(exc).__name__}: {exc}",
                "finished_at": _utc_iso(),
            }
            result["evidence_sha256"] = _sha256_json(result)
        temporary = response_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
        os.replace(temporary, response_path)
        processed += 1
    return processed


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
    requests = queue_root / "requests"
    responses = queue_root / "responses"
    requests.mkdir(parents=True, exist_ok=True)
    responses.mkdir(parents=True, exist_ok=True)
    request_path = requests / f"{request_id}.json"
    temporary = request_path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"digest": normalized, "filename": Path(filename).name}), encoding="utf-8")
    os.replace(temporary, request_path)
    response_path = responses / request_path.name
    deadline = time.monotonic() + max(1, min(int(timeout_seconds), 600))
    while time.monotonic() < deadline:
        if response_path.exists():
            try:
                return json.loads(response_path.read_text("utf-8"))
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
