"""Single source manifest for API, worker, and scanner build fingerprints."""

from __future__ import annotations

import hashlib
import os
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


def source_file_map(workspace_root: str = "/workspace") -> dict[str, str]:
    return {
        name: os.path.join(workspace_root, source_relative)
        for name, source_relative, _ in FINGERPRINT_SOURCE_FILES
    }


def runtime_file_map(runtime_root: str = "/app") -> dict[str, str]:
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
