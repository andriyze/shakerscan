"""Single source manifest for API, worker, and scanner build fingerprints."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

# logical name, source-checkout relative path, container-runtime relative path
FINGERPRINT_SOURCE_FILES: tuple[tuple[str, str, str], ...] = (
    ("scanner.py", "scanner/scanner.py", "scanner.py"),
    ("active_checks.py", "scanner/scanner_tools/active_checks.py", "scanner_tools/active_checks.py"),
    ("parallel_scan.py", "api/parallel_scan.py", "parallel_scan.py"),
    ("finding_validator.py", "scanner/scanner_tools/finding_validator.py", "scanner_tools/finding_validator.py"),
    ("worker.py", "api/worker.py", "worker.py"),
    ("constants.py", "scanner/constants.py", "constants.py"),
    ("findings.py", "scanner/findings.py", "findings.py"),
    ("grading.py", "scanner/grading.py", "grading.py"),
    ("reporting.py", "scanner/reporting.py", "reporting.py"),
    ("data_exposure.py", "scanner/scanner_tools/data_exposure.py", "scanner_tools/data_exposure.py"),
    ("webhook_checks.py", "scanner/scanner_tools/webhook_checks.py", "scanner_tools/webhook_checks.py"),
    ("approval_checks.py", "scanner/scanner_tools/approval_checks.py", "scanner_tools/approval_checks.py"),
    ("access_control_checks.py", "scanner/scanner_tools/access_control_checks.py", "scanner_tools/access_control_checks.py"),
    ("attempt_telemetry.py", "scanner/scanner_tools/attempt_telemetry.py", "scanner_tools/attempt_telemetry.py"),
    ("request_meter.py", "scanner/scanner_tools/request_meter.py", "scanner_tools/request_meter.py"),
    ("auth_session.py", "scanner/scanner_tools/auth_session.py", "scanner_tools/auth_session.py"),
    ("oauth_auth.py", "scanner/scanner_tools/oauth_auth.py", "scanner_tools/oauth_auth.py"),
    ("infrastructure_checks.py", "scanner/scanner_tools/infrastructure_checks.py", "scanner_tools/infrastructure_checks.py"),
    ("model_intake.py", "scanner/scanner_tools/model_intake.py", "scanner_tools/model_intake.py"),
    ("redaction.py", "scanner/redaction.py", "redaction.py"),
    ("ai_gate_scan.py", "api/ai_gate_scan.py", "ai_gate_scan.py"),
    ("build_fingerprint.py", "scanner/scanner_tools/build_fingerprint.py", "scanner_tools/build_fingerprint.py"),
)

# These packages define the canonical V2 authority and executable capability surface. A worker
# running stale code in any one of them must never advertise the same build fingerprint.
V2_API_RUNTIME_PACKAGES: tuple[str, ...] = (
    "capabilities",
    "exposure",
    "finding_exceptions",
    "hunt",
    "interactive",
    "policy_profiles",
    "runtime",
    "scan",
    "worker_handlers",
)
_NATIVE_V2_FINGERPRINT_MARKER = "_shakerscan_v2_package_fingerprint"


def _is_runtime_source(path: Path) -> bool:
    return "__pycache__" not in path.parts and path.suffix != ".pyc" and path.is_file()


def _add_tree(files: dict[str, str], root: Path, logical_root: str) -> None:
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if _is_runtime_source(path):
            files[f"{logical_root}/{path.relative_to(root).as_posix()}"] = str(path)


def _add_v2_api_packages(files: dict[str, str], api_root: Path) -> None:
    for package in V2_API_RUNTIME_PACKAGES:
        _add_tree(files, api_root / package, package)


def source_file_map(workspace_root: str = "/workspace") -> dict[str, str]:
    """Map deterministic source/config copied into the API/worker image.

    Freshness must change for security rules, corpora, wordlists, dependency locks, the
    canonical V2 authority packages, and the fixed Firecracker runtime as well as Python.
    Otherwise a worker can report current source while executing stale policy or adapters.
    """
    root = Path(workspace_root)
    files: dict[str, str] = {}
    scanner_root = root / "scanner"
    api_root = root / "api"
    # The curl installer deliberately packages a small host-side api/ support
    # directory under /workspace, but it is not a source checkout. Treating any
    # api/*.py file as proof of a checkout produces a partial checksum that can
    # never match the worker image. Require both execution anchors before
    # enumerating a workspace; otherwise return the complete legacy manifest so
    # require_all=True fails and callers correctly fall back to /app.
    if not (scanner_root / "scanner.py").is_file() or not (api_root / "worker.py").is_file():
        return {
            name: os.path.join(workspace_root, source_relative)
            for name, source_relative, _ in FINGERPRINT_SOURCE_FILES
        }
    if scanner_root.is_dir():
        for path in sorted(scanner_root.glob("*.py")):
            files[path.name] = str(path)
    if api_root.is_dir():
        for path in sorted(api_root.glob("*.py")):
            files[path.name] = str(path)
    for package_root, logical_root in (
        (scanner_root / "scanner_tools", "scanner_tools"),
        (api_root / "ai_gate", "ai_gate"),
        (scanner_root / "wordlists", "wordlists"),
        (scanner_root / "payloads", "payloads"),
    ):
        _add_tree(files, package_root, logical_root)
    _add_v2_api_packages(files, api_root)
    _add_tree(files, scanner_root / "model_intake_tools", "model_intake_locks")
    auxiliary = (
        ("runtime/requirements.lock", scanner_root / "requirements.lock"),
        ("runtime/entrypoint.sh", scanner_root / "entrypoint.sh"),
        ("runtime/scanner.Dockerfile", scanner_root / "Dockerfile"),
        ("model_intake_locks/firecracker-runtime.lock", root / "runner" / "guest" / "requirements.lock"),
        ("model_intake_locks/firecracker-guest-worker.py", root / "runner" / "guest" / "guest_worker.py"),
        ("model_intake_locks/firecracker-guest-init", root / "runner" / "guest" / "guest-init"),
        ("model_intake_locks/firecracker-guest.Dockerfile", root / "runner" / "guest" / "Dockerfile"),
    )
    for logical_name, path in auxiliary:
        if path.is_file():
            files[logical_name] = str(path)
    return files


def runtime_file_map(
    runtime_root: str = "/app",
    model_intake_lock_root: str = "/opt/model-intake-locks",
    build_input_root: str = "/opt/build-inputs",
) -> dict[str, str]:
    """Map the image runtime layout using the same logical keys as source_file_map."""
    root = Path(runtime_root)
    files: dict[str, str] = {}
    if root.is_dir():
        for path in sorted(root.glob("*.py")):
            files[path.name] = str(path)
        for logical_root in ("scanner_tools", "ai_gate", "wordlists", "payloads"):
            package_root = root / logical_root
            _add_tree(files, package_root, logical_root)
        _add_v2_api_packages(files, root)
        lock_root = Path(model_intake_lock_root)
        _add_tree(files, lock_root, "model_intake_locks")
        auxiliary = (
            ("runtime/requirements.lock", root / "requirements.lock"),
            ("runtime/entrypoint.sh", root / "entrypoint.sh"),
            ("runtime/scanner.Dockerfile", Path(build_input_root) / "scanner.Dockerfile"),
            ("model_intake_locks/firecracker-runtime.lock", lock_root / "firecracker-runtime.lock"),
            ("model_intake_locks/firecracker-guest-worker.py", lock_root / "firecracker-guest-worker.py"),
            ("model_intake_locks/firecracker-guest-init", lock_root / "firecracker-guest-init"),
            ("model_intake_locks/firecracker-guest.Dockerfile", lock_root / "firecracker-guest.Dockerfile"),
        )
        for logical_name, path in auxiliary:
            if path.is_file():
                files[logical_name] = str(path)
    if files:
        return files
    return {
        name: os.path.join(runtime_root, runtime_relative)
        for name, _, runtime_relative in FINGERPRINT_SOURCE_FILES
    }


def hash_source_files(file_map: dict[str, str], *, require_all: bool = False) -> str | None:
    if require_all and not all(os.path.exists(path) for path in file_map.values()):
        return None
    digest = hashlib.sha256()
    hashed = 0
    for name in sorted(file_map):
        try:
            with open(file_map[name], "rb") as handle:
                digest.update(name.encode())
                digest.update(b"\0")
                digest.update(handle.read())
            hashed += 1
        except OSError:
            if require_all:
                return None
    return digest.hexdigest()[:16] if hashed else None


# Mixed-version images still import the former compatibility shim. Mark the native functions so
# that shim becomes a no-op rather than wrapping the same behavior twice.
setattr(source_file_map, _NATIVE_V2_FINGERPRINT_MARKER, True)
setattr(runtime_file_map, _NATIVE_V2_FINGERPRINT_MARKER, True)
