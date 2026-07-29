"""Generated Model Intake scanner evidence and bounded plug-in execution."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import os
import pickletools
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCANNER_RESULT_SCHEMA = "model-intake-scanner-result/v1"
NORMALIZED_STATUSES = {
    "PASS",
    "FAIL",
    "WARNING",
    "NOT_APPLICABLE",
    "UNSUPPORTED",
    "TIMEOUT",
    "CRASHED",
    "INCOMPLETE",
    "SKIPPED_BY_POLICY",
    "REVIEW_REQUIRED",
    "NOT_RUN",
}
NON_PASS_STATUSES = {"FAIL", "UNSUPPORTED", "TIMEOUT", "CRASHED", "INCOMPLETE", "REVIEW_REQUIRED", "NOT_RUN"}
REQUIRED_NON_PASS_STATUSES = NON_PASS_STATUSES | {"SKIPPED_BY_POLICY"}
MAX_SCANNER_OUTPUT_BYTES = 20_000_000
MAX_SOURCE_FILE_BYTES = 2_000_000
MAX_PICKLE_MEMBER_BYTES = 100_000_000
MAX_PICKLE_ARCHIVE_MEMBERS = 5_000
MAX_SOURCE_FILES = 10_000
MAX_SUBJECT_FILES = 10_000
ADAPTER_SELF_TEST_PATH = os.getenv(
    "SHAKERSCAN_MODEL_INTAKE_ADAPTER_SELF_TEST",
    "/opt/model-intake-tools/self-test.json",
)


@dataclass(frozen=True)
class ScannerSpec:
    name: str
    executable: str
    args: tuple[str, ...]
    version_args: tuple[str, ...] = ("--version",)
    timeout_seconds: int = 300
    required: bool = False
    parser: Callable[[str, str, int], tuple[str, list[dict[str, Any]], dict[str, Any]]] | None = None
    result_file: str | None = None
    adapter_kind: str = "evidence_scanner"
    applicability: str = "always"
    target_scope: str = "repository"
    enabled_by_default: bool = False
    required_profiles: tuple[str, ...] = ()
    rules_path: str | None = None
    database_path: str | None = None


EXTERNAL_SCANNERS: tuple[ScannerSpec, ...] = (
    ScannerSpec(
        "modelscan", "modelscan",
        ("-p", "{subject}", "-r", "json", "-o", "{scratch}/modelscan.json"),
        applicability="serialized_model", target_scope="artifact", enabled_by_default=True,
        required_profiles=("strict",),
        result_file="modelscan.json",
    ),
    ScannerSpec(
        "semgrep", "semgrep",
        ("scan", "--config", "/app/scanner_tools/model_intake_semgrep.yml", "--json", "--metrics", "off", "--disable-version-check", "{subject}"),
        applicability="repository_code", enabled_by_default=True, required_profiles=("strict",),
        rules_path="/app/scanner_tools/model_intake_semgrep.yml",
    ),
    ScannerSpec(
        "fickling", "fickling", ("--check-safety", "-p", "{subject}"),
        applicability="pickle_model", target_scope="artifact", enabled_by_default=True,
        required_profiles=("strict",),
    ),
    ScannerSpec(
        "trivy", "trivy",
        (
            "fs", "--scanners", "vuln,secret,misconfig,license", "--format", "json",
            "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
            "--offline-scan", "--disable-telemetry", "--skip-version-check",
            "--cache-dir", "/opt/trivy-cache", "{subject}",
        ),
        applicability="dependency_repository", enabled_by_default=True, required_profiles=("strict",),
        database_path="/opt/trivy-cache/db/metadata.json",
    ),
    ScannerSpec("clamav", "clamscan", ("--recursive=yes", "--infected", "{subject}"), applicability="always"),
    ScannerSpec("gitleaks", "gitleaks", ("detect", "--no-git", "--source", "{subject}", "--report-format", "json", "--report-path", "{scratch}/gitleaks.json"), applicability="repository_code", result_file="gitleaks.json"),
    ScannerSpec("syft", "syft", ("dir:{subject}", "-o", "cyclonedx-json"), applicability="dependency_repository"),
    ScannerSpec("osv-scanner", "osv-scanner", ("scan", "source", "-r", "{subject}", "--format", "json"), applicability="dependency_repository"),
    ScannerSpec("pip-audit", "pip-audit", ("--path", "{subject}", "--format=json"), applicability="python_dependency_repository"),
)
BUILTIN_SCANNER_NAMES = {
    "python-pickletools",
    "python-ast-security",
    "shakerscan-secret-rules",
    "shakerscan-malware-rules",
    "shakerscan-sbom",
    "shakerscan-native-binary-inventory",
    "shakerscan-license-inventory",
}

SERIALIZED_MODEL_EXTENSIONS = {
    ".bin", ".ckpt", ".h5", ".hdf5", ".joblib", ".keras", ".mar", ".pb",
    ".pickle", ".pkl", ".pt", ".pth",
}
PICKLE_MODEL_EXTENSIONS = {".bin", ".ckpt", ".joblib", ".mar", ".pickle", ".pkl", ".pt", ".pth"}
CODE_AND_CONFIG_EXTENSIONS = {
    ".bash", ".cfg", ".ini", ".js", ".json", ".jsx", ".py", ".sh", ".toml",
    ".ts", ".tsx", ".yaml", ".yml",
}
DEPENDENCY_FILENAMES = {
    "cargo.lock", "cargo.toml", "composer.lock", "composer.json", "environment.yml",
    "gemfile", "gemfile.lock", "go.mod", "go.sum", "package-lock.json", "package.json",
    "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml", "requirements.txt",
    "setup.cfg", "setup.py", "uv.lock", "yarn.lock",
}
PYTHON_DEPENDENCY_FILENAMES = {
    "environment.yml", "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml",
    "requirements.txt", "setup.cfg", "setup.py", "uv.lock",
}


def _candidate_files(subject_path: Path) -> list[Path]:
    if subject_path.is_file():
        return [subject_path]
    files, _, _ = _subject_file_inventory(subject_path)
    return files


def scanner_applicability(spec: ScannerSpec, subject_path: Path) -> dict[str, Any]:
    """Resolve applicability from immutable subject facts, never a model/repository name."""
    files = _candidate_files(subject_path)
    names = {path.name.lower() for path in files}
    suffixes = {path.suffix.lower() for path in files}
    reason = "applicable_to_all_complete_subjects"
    applicable = True
    if spec.applicability == "serialized_model":
        applicable = bool(suffixes & SERIALIZED_MODEL_EXTENSIONS)
        reason = "serialized_model_artifact_present" if applicable else "no_supported_serialized_model_artifact"
    elif spec.applicability == "pickle_model":
        applicable = bool(suffixes & PICKLE_MODEL_EXTENSIONS)
        reason = "pickle_backed_artifact_present" if applicable else "no_pickle_backed_artifact"
    elif spec.applicability == "repository_code":
        applicable = subject_path.is_dir() and any(
            path.suffix.lower() in CODE_AND_CONFIG_EXTENSIONS or path.name.lower() in {"dockerfile", "containerfile"}
            for path in files
        )
        reason = "repository_code_or_configuration_present" if applicable else "no_repository_code_or_configuration"
    elif spec.applicability == "dependency_repository":
        applicable = subject_path.is_dir() and bool(names & DEPENDENCY_FILENAMES)
        reason = "dependency_manifest_present" if applicable else "no_dependency_manifest"
    elif spec.applicability == "python_dependency_repository":
        applicable = subject_path.is_dir() and bool(names & PYTHON_DEPENDENCY_FILENAMES)
        reason = "python_dependency_manifest_present" if applicable else "no_python_dependency_manifest"
    return {
        "applicable": applicable,
        "reason": reason,
        "files_considered": len(files),
        "applicability": spec.applicability,
    }


def resolve_scanner_plan(
    subject_path: Path,
    *,
    requested_names: set[str] | None = None,
    profile: str = "baseline",
) -> list[dict[str, Any]]:
    """Build a non-weakenable, applicability-aware external scanner plan."""
    strict = profile == "strict"
    plan: list[dict[str, Any]] = []
    for spec in EXTERNAL_SCANNERS:
        applicability = scanner_applicability(spec, subject_path)
        requested = requested_names is not None and spec.name in requested_names
        required = requested or (
            strict and profile in spec.required_profiles and bool(applicability["applicable"])
        )
        selected = requested or (requested_names is None and spec.enabled_by_default) or required
        if not selected and not required:
            continue
        plan.append({
            "spec": dataclasses.replace(spec, required=required),
            "selected": selected,
            "requested": requested,
            "required": required,
            **applicability,
        })
    return plan


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _scanner_result(
    *,
    name: str,
    version: str | None,
    status: str,
    subject: dict[str, Any],
    started_at: str,
    finished_at: str,
    findings: list[dict[str, Any]] | None = None,
    coverage: dict[str, Any] | None = None,
    execution: dict[str, Any] | None = None,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if status not in NORMALIZED_STATUSES:
        raise ValueError(f"invalid normalized scanner status: {status}")
    payload = {
        "schema_version": SCANNER_RESULT_SCHEMA,
        "provenance_class": "shakerscan_generated",
        "scanner": {
            "name": name,
            "version": version,
            "worker_image_digest": os.getenv("SHAKERSCAN_WORKER_IMAGE_DIGEST") or None,
        },
        "subject": subject,
        "execution": {
            "status": status,
            "started_at": started_at,
            "finished_at": finished_at,
            "network_policy": "credentials_removed_egress_not_isolated",
            **(execution or {}),
        },
        "coverage": coverage or {},
        "findings": findings or [],
        "summary": summary or {},
    }
    payload["evidence_sha256"] = _sha256_json(payload)
    return payload


def _bounded_command(executable: str, args: tuple[str, ...] | list[str]) -> list[str]:
    launcher = Path(__file__).with_name("bounded_exec.py")
    options = ["--no-address-space-limit"] if Path(executable).name in {"semgrep", "trivy"} else []
    return [sys.executable, str(launcher), *options, "--", executable, *args]


def _safe_environment(scratch: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(scratch),
        "TMPDIR": str(scratch),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_PROXY": "*",
        "no_proxy": "*",
    }


def _prepare_unprivileged_scratch(scratch: Path) -> None:
    """Make a temporary working directory writable after the scanner UID drop."""
    if os.geteuid() != 0:
        return
    try:
        account = pwd.getpwnam("scanner")
    except KeyError:
        return
    os.chown(scratch, account.pw_uid, account.pw_gid)
    os.chmod(scratch, 0o700)


def _prepare_unprivileged_paths(subject_path: Path, scratch: Path) -> None:
    """Make the disposable scan view readable and scratch writable after UID drop."""
    _prepare_unprivileged_scratch(scratch)
    if os.geteuid() != 0:
        return
    try:
        pwd.getpwnam("scanner")
    except KeyError:
        return
    # TemporaryDirectory creates its root as 0700. The scanner only needs
    # traversal to the copied, read-only subject view beneath it.
    os.chmod(subject_path.parent, 0o711)
    if subject_path.is_dir():
        for root, directories, filenames in os.walk(subject_path):
            os.chmod(root, 0o555)
            for directory in directories:
                os.chmod(Path(root) / directory, 0o555)
            for filename in filenames:
                os.chmod(Path(root) / filename, 0o444)
    else:
        os.chmod(subject_path, 0o444)


def _read_bounded(path: Path, limit: int = MAX_SCANNER_OUTPUT_BYTES) -> tuple[str, bool]:
    size = path.stat().st_size if path.exists() else 0
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    return raw[:limit].decode("utf-8", "replace"), size > limit or len(raw) > limit


def _output_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for index, path in enumerate(paths):
        if index:
            digest.update(b"\0")
        if not path.is_file():
            continue
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def _tool_version(executable: str, args: tuple[str, ...], env: dict[str, str], cwd: Path) -> str | None:
    try:
        completed = subprocess.run(
            _bounded_command(executable, args),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (completed.stdout or completed.stderr or "").strip().splitlines()
    return output[0][:300] if output else None


def _default_external_parser(stdout: str, stderr: str, exit_code: int) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    return "INCOMPLETE", [], {
        "error": "scanner_parser_contract_missing",
        "exit_code": exit_code,
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
    }


def _json_output(stdout: str) -> Any:
    if not stdout.strip():
        raise ValueError("empty scanner output")
    return json.loads(stdout)


def _modelscan_json_output(stdout: str) -> Any:
    """Parse ModelScan's JSON after its documented human-readable preamble."""
    offsets = [offset for marker in ("{", "[") if (offset := stdout.find(marker)) >= 0]
    if not offsets:
        raise ValueError("modelscan JSON payload missing")
    offset = min(offsets)
    preamble = stdout[:offset].strip()
    if preamble and any(
        not line.startswith(("No settings file detected", "Scanning "))
        for line in preamble.splitlines()
        if line.strip()
    ):
        raise ValueError("unexpected modelscan output preamble")
    parsed, end = json.JSONDecoder().raw_decode(stdout[offset:])
    if stdout[offset + end:].strip():
        raise ValueError("unexpected modelscan output trailer")
    return parsed


def _external_finding(scanner: str, item: Any, severity: str = "high") -> dict[str, Any]:
    return {
        "id": f"{scanner}_finding",
        "severity": severity,
        "evidence_sha256": _sha256_json(item),
    }


def _parse_external_scanner(
    scanner: str, stdout: str, stderr: str, exit_code: int
) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    """Validate each tool's output contract; exit zero alone is never PASS."""
    if scanner in {"modelscan", "semgrep", "gitleaks", "syft", "trivy", "osv-scanner", "pip-audit"}:
        try:
            parsed = _modelscan_json_output(stdout) if scanner == "modelscan" else _json_output(stdout)
        except (ValueError, json.JSONDecodeError) as exc:
            return "INCOMPLETE" if exit_code in {0, 1} else "CRASHED", [], {"error": f"invalid_json_output:{exc}"}
        findings: list[dict[str, Any]] = []
        summary: dict[str, Any] = {"output_schema": type(parsed).__name__}
        if scanner == "modelscan":
            if not isinstance(parsed, (dict, list)):
                return "INCOMPLETE", [], {"error": "modelscan_output_shape_invalid"}
            if isinstance(parsed, dict) and not any(key in parsed for key in ("issues", "findings", "errors")):
                return "INCOMPLETE", [], {"error": "modelscan_findings_key_missing"}
            candidates = (
                parsed if isinstance(parsed, list)
                else parsed.get("issues") or parsed.get("findings") or parsed.get("errors") or []
            )
            if not isinstance(candidates, list):
                return "INCOMPLETE", [], {"error": "modelscan_findings_shape_invalid"}
            findings = [_external_finding(scanner, item, "critical") for item in candidates[:1000]]
            summary["finding_count"] = len(candidates)
        elif scanner == "semgrep":
            if not isinstance(parsed, dict) or not isinstance(parsed.get("results"), list):
                return "INCOMPLETE", [], {"error": "semgrep_results_missing"}
            errors = parsed.get("errors") if isinstance(parsed.get("errors"), list) else []
            candidates = parsed["results"]
            findings = [
                _external_finding(
                    scanner,
                    item,
                    str((item.get("extra") or {}).get("severity") or "high").lower()
                    if isinstance(item, dict) else "high",
                )
                for item in candidates[:1000]
            ]
            blocking_count = sum(
                1 for item in candidates
                if isinstance(item, dict) and str((item.get("extra") or {}).get("severity") or "ERROR").upper() == "ERROR"
            )
            summary.update({
                "finding_count": len(candidates),
                "blocking_finding_count": blocking_count,
                "error_count": len(errors),
                "warning_only": bool(candidates) and blocking_count == 0,
            })
            if errors:
                return "INCOMPLETE", findings, {**summary, "errors_sha256": _sha256_json(errors)}
        elif scanner == "gitleaks":
            if not isinstance(parsed, list):
                return "INCOMPLETE", [], {"error": "gitleaks_output_shape_invalid"}
            findings = [_external_finding(scanner, item, "critical") for item in parsed[:1000]]
            summary["finding_count"] = len(parsed)
        elif scanner == "syft":
            if not isinstance(parsed, dict) or not isinstance(parsed.get("components"), list):
                return "INCOMPLETE", [], {"error": "cyclonedx_components_missing"}
            summary.update({"bom_format": parsed.get("bomFormat"), "component_count": len(parsed["components"])})
        elif scanner == "trivy":
            results = parsed.get("Results") if isinstance(parsed, dict) else None
            if not isinstance(results, list):
                return "INCOMPLETE", [], {"error": "trivy_results_missing"}
            counts = {"vulnerabilities": 0, "secrets": 0, "misconfigurations": 0}
            warning = False
            for result in results:
                if not isinstance(result, dict):
                    continue
                for key, label in (("Vulnerabilities", "vulnerabilities"), ("Secrets", "secrets"), ("Misconfigurations", "misconfigurations")):
                    items = result.get(key) if isinstance(result.get(key), list) else []
                    counts[label] += len(items)
                    for item in items[:1000 - len(findings)]:
                        severity = str(item.get("Severity") or "high").lower() if isinstance(item, dict) else "high"
                        if key == "Secrets" or severity in {"critical", "high"}:
                            findings.append(_external_finding(scanner, item, "critical" if severity == "critical" else "high"))
                        elif severity in {"medium", "low", "unknown"}:
                            warning = True
            summary.update(counts)
            summary["warning_only"] = warning and not findings
        elif scanner == "osv-scanner":
            results = parsed.get("results") if isinstance(parsed, dict) else None
            if not isinstance(results, list):
                return "INCOMPLETE", [], {"error": "osv_results_missing"}
            vulnerabilities = []
            for result in results:
                packages = result.get("packages") if isinstance(result, dict) else []
                for package in packages if isinstance(packages, list) else []:
                    vulnerabilities.extend(package.get("vulnerabilities") or [] if isinstance(package, dict) else [])
            findings = [_external_finding(scanner, item) for item in vulnerabilities[:1000]]
            summary["vulnerability_count"] = len(vulnerabilities)
        elif scanner == "pip-audit":
            dependencies = parsed.get("dependencies") if isinstance(parsed, dict) else parsed if isinstance(parsed, list) else None
            if not isinstance(dependencies, list):
                return "INCOMPLETE", [], {"error": "pip_audit_dependencies_missing"}
            vulnerabilities = [
                vulnerability
                for dependency in dependencies if isinstance(dependency, dict)
                for vulnerability in (dependency.get("vulns") or [])
            ]
            findings = [_external_finding(scanner, item) for item in vulnerabilities[:1000]]
            summary["vulnerability_count"] = len(vulnerabilities)
        if exit_code not in {0, 1}:
            return "CRASHED", findings, {**summary, "error": (stderr or "unexpected exit code")[:1000]}
        if summary.get("warning_only"):
            return "WARNING", findings, summary
        if findings:
            return "FAIL", findings, summary
        return "PASS", [], summary

    text = f"{stdout}\n{stderr}".strip()
    if scanner == "clamav":
        if "SCAN SUMMARY" not in text or "Infected files:" not in text:
            return "INCOMPLETE" if exit_code in {0, 1} else "CRASHED", [], {"error": "clamav_summary_missing"}
        match = re.search(r"Infected files:\s*(\d+)", text)
        infected = int(match.group(1)) if match else 0
        findings = [_external_finding(scanner, {"infected_files": infected}, "critical")] if infected else []
        if exit_code not in {0, 1}:
            return "CRASHED", findings, {"infected_files": infected, "error": "clamav_engine_error"}
        return ("FAIL" if infected else "PASS"), findings, {"infected_files": infected}
    if scanner == "fickling":
        if not text:
            return "INCOMPLETE", [], {"error": "fickling_output_empty"}
        unsafe = exit_code != 0 or any(marker in text.lower() for marker in ("unsafe", "malicious", "overtly bad"))
        findings = [_external_finding(scanner, {"output_sha256": hashlib.sha256(text.encode()).hexdigest()}, "critical")] if unsafe else []
        return ("FAIL" if unsafe else "PASS"), findings, {"output_sha256": hashlib.sha256(text.encode()).hexdigest()}
    return _default_external_parser(stdout, stderr, exit_code)


def run_external_scanner(spec: ScannerSpec, subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    executable = shutil.which(spec.executable)
    if not executable:
        return _scanner_result(
            name=spec.name,
            version=None,
            status="UNSUPPORTED",
            subject=subject,
            started_at=started_at,
            finished_at=_utc_iso(),
            execution={"error": "executable_not_installed", "required": spec.required},
        )
    with tempfile.TemporaryDirectory(prefix=f"model-intake-{spec.name}-") as scratch_raw:
        scratch = Path(scratch_raw)
        _prepare_unprivileged_paths(subject_path, scratch)
        env = _safe_environment(scratch)
        version = _tool_version(executable, spec.version_args, env, scratch)
        argv = [
            executable,
            *(
                value.replace("{subject}", str(subject_path)).replace("{scratch}", str(scratch))
                for value in spec.args
            ),
        ]
        stdout_path = scratch / "stdout"
        stderr_path = scratch / "stderr"
        start = time.monotonic()
        try:
            with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
                completed = subprocess.run(
                    _bounded_command(executable, argv[1:]),
                    cwd=scratch,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    timeout=spec.timeout_seconds,
                    check=False,
                )
        except subprocess.TimeoutExpired:
            return _scanner_result(
                name=spec.name,
                version=version,
                status="TIMEOUT",
                subject=subject,
                started_at=started_at,
                finished_at=_utc_iso(),
                execution={"timeout_seconds": spec.timeout_seconds, "required": spec.required},
            )
        except OSError as exc:
            return _scanner_result(
                name=spec.name,
                version=version,
                status="CRASHED",
                subject=subject,
                started_at=started_at,
                finished_at=_utc_iso(),
                execution={"error": f"{type(exc).__name__}: {exc}", "required": spec.required},
            )
        stdout, stdout_truncated = _read_bounded(stdout_path)
        stderr, stderr_truncated = _read_bounded(stderr_path)
        result_path = scratch / spec.result_file if spec.result_file else None
        result_output = stdout
        result_truncated = False
        if result_path is not None:
            if result_path.is_file():
                result_output, result_truncated = _read_bounded(result_path)
            else:
                result_output = ""
                result_truncated = True
        raw_digest = _output_digest(
            [stdout_path, stderr_path, *([result_path] if result_path is not None else [])]
        )
        if stdout_truncated or stderr_truncated or result_truncated:
            status, findings, summary = "INCOMPLETE", [], {"error": "scanner_output_limit_exceeded"}
        else:
            parser = spec.parser
            try:
                status, findings, summary = (
                    parser(result_output, stderr, completed.returncode)
                    if parser
                    else _parse_external_scanner(spec.name, result_output, stderr, completed.returncode)
                )
            except Exception as exc:
                status, findings, summary = "CRASHED", [], {"error": f"parser_{type(exc).__name__}: {exc}"}
        return _scanner_result(
            name=spec.name,
            version=version,
            status=status,
            subject=subject,
            started_at=started_at,
            finished_at=_utc_iso(),
            findings=findings,
            execution={
                "exit_code": completed.returncode,
                "duration_ms": int((time.monotonic() - start) * 1000),
                "timeout_seconds": spec.timeout_seconds,
                "raw_result_digest": raw_digest,
                "required": spec.required,
                "argv_contract": [spec.executable, *spec.args],
                "adapter_kind": spec.adapter_kind,
                "applicability": spec.applicability,
                "target_scope": spec.target_scope,
            },
            summary=summary,
        )


def scanner_adapter_catalog() -> list[dict[str, Any]]:
    return [
        {
            "name": spec.name,
            "adapter_kind": spec.adapter_kind,
            "executable": spec.executable,
            "applicability": spec.applicability,
            "target_scope": spec.target_scope,
            "enabled_by_default": spec.enabled_by_default,
            "required_profiles": list(spec.required_profiles),
            "rules_path": spec.rules_path,
            "database_path": spec.database_path,
        }
        for spec in EXTERNAL_SCANNERS
    ]


def scanner_adapter_readiness() -> dict[str, Any]:
    """Return content-free runtime readiness for operators and policy diagnostics."""
    self_test_checks: dict[str, dict[str, Any]] = {}
    self_test_path = Path(ADAPTER_SELF_TEST_PATH)
    self_test_receipt: dict[str, Any] | None = None
    if self_test_path.is_file():
        try:
            parsed_receipt = json.loads(self_test_path.read_text("utf-8"))
            if isinstance(parsed_receipt, dict):
                self_test_receipt = parsed_receipt
                self_test_checks = {
                    str(item.get("name")): item
                    for item in parsed_receipt.get("checks") or []
                    if isinstance(item, dict) and item.get("name")
                }
        except (OSError, ValueError):
            self_test_receipt = {"status": "INVALID"}
    adapters: list[dict[str, Any]] = []
    for spec in EXTERNAL_SCANNERS:
        executable = shutil.which(spec.executable)
        rules_digest = None
        if spec.rules_path and Path(spec.rules_path).is_file():
            rules_digest = _hash_path(Path(spec.rules_path))
        database: dict[str, Any] | None = None
        if spec.database_path:
            database_path = Path(spec.database_path)
            database = {"present": database_path.is_file(), "path": spec.database_path}
            if database_path.is_file():
                database["sha256"] = _hash_path(database_path)
                try:
                    metadata = json.loads(database_path.read_text("utf-8"))
                    database["updated_at"] = metadata.get("UpdatedAt") or metadata.get("updated_at")
                    database["next_update"] = metadata.get("NextUpdate") or metadata.get("next_update")
                except (OSError, ValueError):
                    database["metadata_status"] = "unparseable"
        version = None
        if executable:
            with tempfile.TemporaryDirectory(prefix=f"model-intake-readiness-{spec.name}-") as scratch_raw:
                scratch = Path(scratch_raw)
                _prepare_unprivileged_scratch(scratch)
                version = _tool_version(executable, spec.version_args, _safe_environment(scratch), scratch)
        self_test = self_test_checks.get(spec.name)
        self_test_required = spec.enabled_by_default or bool(spec.required_profiles)
        ready = bool(
            executable
            and (not spec.rules_path or rules_digest)
            and (not database or database.get("present"))
            and (not self_test_required or (self_test and self_test.get("passed") is True))
        )
        adapters.append({
            **next(item for item in scanner_adapter_catalog() if item["name"] == spec.name),
            "ready": ready,
            "installed": bool(executable),
            "version": version,
            "rules_sha256": rules_digest,
            "database": database,
            "last_self_test": self_test,
            "status": "READY" if ready else "UNAVAILABLE",
        })
    required = [item for item in adapters if item["required_profiles"]]
    return {
        "schema_version": "model-intake-adapter-readiness/v1",
        "status": "READY" if all(item["ready"] for item in required) else "DEGRADED",
        "required_ready": sum(1 for item in required if item["ready"]),
        "required_total": len(required),
        "self_test": {
            "status": (self_test_receipt or {}).get("status") or "MISSING",
            "tested_at": (self_test_receipt or {}).get("tested_at"),
            "receipt_sha256": (self_test_receipt or {}).get("receipt_sha256"),
        },
        "adapters": adapters,
    }


DANGEROUS_PICKLE_OPCODES = {
    "GLOBAL", "STACK_GLOBAL", "REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX",
    "EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID",
}


def _pickle_streams(path: Path) -> tuple[list[tuple[str, bytes]], int]:
    if zipfile.is_zipfile(path):
        streams: list[tuple[str, bytes]] = []
        with zipfile.ZipFile(path) as archive:
            candidates = [
                info for info in archive.infolist()
                if info.filename.lower().endswith((".pkl", ".pickle", "data.pkl"))
            ]
            for info in candidates[:MAX_PICKLE_ARCHIVE_MEMBERS]:
                name = info.filename
                if info.file_size > MAX_PICKLE_MEMBER_BYTES:
                    continue
                streams.append((name, archive.read(info)))
        return streams, len(candidates)
    if path.suffix.lower() in {".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin", ".joblib"}:
        if path.stat().st_size > MAX_PICKLE_MEMBER_BYTES:
            return [], 1
        return [(path.name, path.read_bytes())], 1
    return [], 0


def run_builtin_pickle_scan(subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    inventory_truncated = False
    if subject_path.is_dir():
        files, files_discovered, inventory_truncated = _subject_file_inventory(subject_path)
        streams = []
        discovered = 0
        for path in files:
            path_streams, path_discovered = _pickle_streams(path)
            relative = path.relative_to(subject_path).as_posix()
            streams.extend((f"{relative}!/{name}" if name != path.name else relative, raw) for name, raw in path_streams)
            discovered += path_discovered
    else:
        streams, discovered = _pickle_streams(subject_path)
        files_discovered = 1
    if discovered == 0:
        return _scanner_result(
            name="python-pickletools",
            version=None,
            status="INCOMPLETE" if inventory_truncated else "NOT_APPLICABLE",
            subject=subject,
            started_at=started_at,
            finished_at=_utc_iso(),
            coverage={
                "files_discovered": files_discovered,
                "files_enumerated": min(files_discovered, MAX_SUBJECT_FILES),
                "inventory_truncated": inventory_truncated,
                "pickle_streams_discovered": 0,
                "pickle_streams_analyzed": 0,
            },
            execution={"required": True},
        )
    findings: list[dict[str, Any]] = []
    analyzed = 0
    parse_errors: list[dict[str, str]] = []
    for name, raw in streams:
        try:
            opcodes = []
            for opcode, argument, position in pickletools.genops(raw):
                if opcode.name in DANGEROUS_PICKLE_OPCODES:
                    opcodes.append({"opcode": opcode.name, "argument": str(argument)[:300], "position": position})
            analyzed += 1
            if opcodes:
                findings.append({
                    "id": "dangerous_pickle_opcodes",
                    "severity": "critical",
                    "path": name,
                    "opcodes": opcodes[:100],
                })
        except Exception as exc:
            parse_errors.append({"path": name, "error": f"{type(exc).__name__}: {exc}"})
    if analyzed < discovered or parse_errors or inventory_truncated:
        status = "INCOMPLETE"
    elif findings:
        status = "FAIL"
    else:
        status = "PASS"
    return _scanner_result(
        name="python-pickletools",
        version=None,
        status=status,
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=findings,
        coverage={
            "files_discovered": files_discovered,
            "files_enumerated": min(files_discovered, MAX_SUBJECT_FILES),
            "inventory_truncated": inventory_truncated,
            "pickle_streams_discovered": discovered,
            "pickle_streams_analyzed": analyzed,
        },
        execution={"required": True},
        summary={"parse_errors": parse_errors[:20]},
    )


DANGEROUS_CALL_NAMES = {
    "eval", "exec", "compile", "__import__", "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",
    "pickle.load", "pickle.loads", "torch.load", "requests.get", "requests.post",
    "urllib.request.urlopen", "socket.socket",
}


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def run_builtin_source_scan(snapshot_root: Path | None, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    if not snapshot_root or not snapshot_root.is_dir():
        return _scanner_result(
            name="python-ast-security",
            version=None,
            status="NOT_APPLICABLE",
            subject=subject,
            started_at=started_at,
            finished_at=_utc_iso(),
            coverage={"python_files_discovered": 0, "python_files_analyzed": 0},
            execution={"required": True},
        )
    all_paths = sorted(snapshot_root.rglob("*.py"))
    paths = all_paths[:MAX_SOURCE_FILES]
    findings: list[dict[str, Any]] = []
    analyzed = 0
    incomplete = len(all_paths) > len(paths)
    for path in paths:
        relative = path.relative_to(snapshot_root).as_posix()
        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            findings.append({"id": "source_file_too_large", "severity": "high", "path": relative})
            incomplete = True
            continue
        try:
            tree = ast.parse(path.read_text("utf-8", errors="replace"), filename=relative)
        except (OSError, SyntaxError) as exc:
            findings.append({"id": "source_parse_failed", "severity": "high", "path": relative, "error": str(exc)[:500]})
            incomplete = True
            continue
        analyzed += 1
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call = _call_name(node.func)
            if call in DANGEROUS_CALL_NAMES:
                findings.append({
                    "id": "dangerous_python_call",
                    "severity": "high" if call != "torch.load" else "medium",
                    "path": relative,
                    "line": getattr(node, "lineno", None),
                    "call": call,
                })
    status = "INCOMPLETE" if incomplete else "WARNING" if findings else "PASS"
    return _scanner_result(
        name="python-ast-security",
        version=None,
        status=status,
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=findings[:1000],
        coverage={
            "python_files_discovered": len(all_paths),
            "python_files_enumerated": len(paths),
            "python_files_analyzed": analyzed,
            "inventory_truncated": len(all_paths) > len(paths),
        },
        execution={"required": True},
    )


def _subject_file_inventory(subject_path: Path, *, limit: int | None = None) -> tuple[list[Path], int, bool]:
    if subject_path.is_file():
        return [subject_path], 1, False
    limit = MAX_SUBJECT_FILES if limit is None else limit
    all_files = [path for path in sorted(subject_path.rglob("*")) if path.is_file()]
    return all_files[:limit], len(all_files), len(all_files) > limit


def _subject_files(subject_path: Path, *, limit: int | None = None) -> list[Path]:
    return _subject_file_inventory(subject_path, limit=limit)[0]


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


SECRET_RULES = {
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github_token": re.compile(rb"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{30,255}\b"),
    "generic_secret_assignment": re.compile(
        rb"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_./+\-=]{16,}"
    ),
}
SECRET_RULESET_SHA256 = _sha256_json(sorted(SECRET_RULES))
SECRET_TEXT_EXTENSIONS = {
    ".cfg", ".conf", ".ini", ".json", ".md", ".py", ".rst", ".sh",
    ".toml", ".txt", ".yaml", ".yml", ".ps1", ".xml",
}
OPAQUE_MODEL_EXTENSIONS = {
    ".bin", ".ckpt", ".gguf", ".joblib", ".mar", ".onnx", ".pickle",
    ".pkl", ".pt", ".pth", ".safetensors", ".tflite",
}


def run_builtin_secret_scan(subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    files, files_discovered, inventory_truncated = _subject_file_inventory(subject_path)
    findings: list[dict[str, Any]] = []
    analyzed = 0
    skipped_large = 0
    excluded_by_type = 0
    root = subject_path if subject_path.is_dir() else subject_path.parent
    for path in files:
        extension = path.suffix.lower()
        if extension in OPAQUE_MODEL_EXTENSIONS:
            excluded_by_type += 1
            continue
        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            if extension in SECRET_TEXT_EXTENSIONS or path.name.lower().startswith(("license", "readme", "requirements")):
                skipped_large += 1
            else:
                excluded_by_type += 1
            continue
        raw = path.read_bytes()
        if b"\0" in raw[:4096] and extension not in SECRET_TEXT_EXTENSIONS:
            excluded_by_type += 1
            continue
        analyzed += 1
        for rule_id, pattern in SECRET_RULES.items():
            for match in list(pattern.finditer(raw))[:20]:
                value = match.group(0)
                findings.append({
                    "id": rule_id,
                    "severity": "critical" if rule_id == "private_key" else "high",
                    "path": path.relative_to(root).as_posix(),
                    "offset": match.start(),
                    "match_sha256": hashlib.sha256(value).hexdigest(),
                    "match_length": len(value),
                })
    status = "INCOMPLETE" if skipped_large or inventory_truncated else "FAIL" if findings else "PASS"
    return _scanner_result(
        name="shakerscan-secret-rules",
        version="1",
        status=status,
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=findings[:1000],
        coverage={
            "files_discovered": files_discovered,
            "files_enumerated": len(files),
            "files_analyzed": analyzed,
            "files_skipped_large": skipped_large,
            "files_excluded_by_type": excluded_by_type,
            "inventory_truncated": inventory_truncated,
        },
        execution={"required": True, "rules_sha256": SECRET_RULESET_SHA256},
    )


MALWARE_MARKERS = {
    "eicar_test_file": b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
    "shell_download_execute": b"curl | sh",
    "powershell_encoded_command": b"powershell -enc",
    "python_reverse_shell": b"socket.socket();os.dup2",
}
MALWARE_RULESET_SHA256 = _sha256_json({key: value.hex() for key, value in MALWARE_MARKERS.items()})


def _stream_marker_matches(path: Path, markers: dict[str, bytes]) -> set[str]:
    matches: set[str] = set()
    lowered_markers = {key: value.lower() for key, value in markers.items()}
    overlap = max((len(value) for value in lowered_markers.values()), default=1) - 1
    carry = b""
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            window = (carry + chunk).lower()
            for rule_id, marker in lowered_markers.items():
                if rule_id not in matches and marker in window:
                    matches.add(rule_id)
            carry = window[-overlap:] if overlap > 0 else b""
    return matches


def run_builtin_malware_scan(subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    files, files_discovered, inventory_truncated = _subject_file_inventory(subject_path)
    findings: list[dict[str, Any]] = []
    analyzed = 0
    root = subject_path if subject_path.is_dir() else subject_path.parent
    for path in files:
        analyzed += 1
        for rule_id in sorted(_stream_marker_matches(path, MALWARE_MARKERS)):
            findings.append({
                "id": rule_id,
                "severity": "critical" if rule_id == "eicar_test_file" else "high",
                "path": path.relative_to(root).as_posix(),
                "file_sha256": _hash_path(path),
            })
    status = "INCOMPLETE" if inventory_truncated else "FAIL" if findings else "PASS"
    return _scanner_result(
        name="shakerscan-malware-rules",
        version="1",
        status=status,
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=findings[:1000],
        coverage={
            "files_discovered": files_discovered,
            "files_enumerated": len(files),
            "files_analyzed": analyzed,
            "inventory_truncated": inventory_truncated,
        },
        execution={"required": True, "rules_sha256": MALWARE_RULESET_SHA256},
    )


DEPENDENCY_FILES = {"requirements.txt", "requirements-dev.txt", "pyproject.toml", "package-lock.json"}


def _requirement_components(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    components: list[dict[str, Any]] = []
    unpinned: list[str] = []
    if path.name.startswith("requirements"):
        for raw_line in path.read_text("utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            match = re.match(r"([A-Za-z0-9_.-]+)\s*==\s*([^\s;]+)", line)
            if match:
                name, version = match.groups()
                components.append({"type": "library", "name": name, "version": version, "purl": f"pkg:pypi/{name}@{version}"})
            else:
                unpinned.append(line[:300])
    elif path.name == "package-lock.json":
        try:
            payload = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return [], ["package-lock.json:parse_error"]
        packages = payload.get("packages") if isinstance(payload, dict) else {}
        for package_path, value in (packages.items() if isinstance(packages, dict) else []):
            if not package_path or not isinstance(value, dict):
                continue
            name = str(value.get("name") or Path(package_path).name)
            version = str(value.get("version") or "")
            if name and version:
                components.append({"type": "library", "name": name, "version": version, "purl": f"pkg:npm/{name}@{version}"})
    return components, unpinned


def run_builtin_sbom_scan(subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    root = subject_path if subject_path.is_dir() else subject_path.parent
    files, files_discovered, inventory_truncated = _subject_file_inventory(subject_path)
    dependency_paths = [path for path in files if path.name.lower() in DEPENDENCY_FILES]
    components: list[dict[str, Any]] = []
    unpinned: list[dict[str, str]] = []
    for path in dependency_paths:
        parsed, path_unpinned = _requirement_components(path)
        components.extend(parsed)
        unpinned.extend({"path": path.relative_to(root).as_posix(), "requirement": item} for item in path_unpinned)
    unique = {
        (item.get("purl") or f"{item.get('name')}@{item.get('version')}"): item for item in components
    }
    normalized_components = [unique[key] for key in sorted(unique)]
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "provenance_class": "shakerscan_generated",
        "subject_digest": subject.get("digest"),
        "components": normalized_components,
    }
    sbom["serialNumber"] = f"urn:uuid:{_sha256_json(sbom)[:32]}"
    status = "INCOMPLETE" if inventory_truncated else "WARNING" if unpinned else "PASS"
    return _scanner_result(
        name="shakerscan-sbom",
        version="1",
        status=status,
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=[{"id": "unpinned_dependency", "severity": "medium", **item} for item in unpinned[:1000]],
        coverage={
            "files_discovered": files_discovered,
            "files_enumerated": len(files),
            "inventory_truncated": inventory_truncated,
            "dependency_files_discovered": len(dependency_paths),
            "components_generated": len(normalized_components),
        },
        execution={"required": True},
        summary={"sbom": sbom, "sbom_sha256": _sha256_json(sbom)},
    )


BINARY_MAGIC = {
    b"\x7fELF": "elf",
    b"MZ": "portable_executable",
    b"\xcf\xfa\xed\xfe": "mach_o_64",
    b"\xfe\xed\xfa\xcf": "mach_o_64_be",
}


def run_builtin_binary_inventory(subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    root = subject_path if subject_path.is_dir() else subject_path.parent
    files, files_discovered, inventory_truncated = _subject_file_inventory(subject_path)
    binaries: list[dict[str, Any]] = []
    for path in files:
        with path.open("rb") as handle:
            prefix = handle.read(8)
        binary_format = next((kind for magic, kind in BINARY_MAGIC.items() if prefix.startswith(magic)), None)
        if binary_format:
            binaries.append({
                "id": "native_binary_present",
                "severity": "high",
                "path": path.relative_to(root).as_posix(),
                "format": binary_format,
                "sha256": _hash_path(path),
            })
    return _scanner_result(
        name="shakerscan-binary-inventory",
        version="1",
        status="INCOMPLETE" if inventory_truncated else "WARNING" if binaries else "PASS",
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=binaries[:1000],
        coverage={
            "files_discovered": files_discovered,
            "files_enumerated": len(files),
            "inventory_truncated": inventory_truncated,
            "native_binaries": len(binaries),
        },
        execution={"required": True},
    )


LICENSE_MARKERS = {
    "Apache-2.0": ("apache license", "version 2.0"),
    "MIT": ("permission is hereby granted, free of charge",),
    "BSD-3-Clause": ("redistribution and use in source and binary forms", "neither the name"),
    "BSD-2-Clause": ("redistribution and use in source and binary forms",),
}


def run_builtin_license_inventory(subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    if not subject_path.is_dir():
        return _scanner_result(
            name="shakerscan-license-inventory",
            version="1",
            status="NOT_APPLICABLE",
            subject=subject,
            started_at=started_at,
            finished_at=_utc_iso(),
            coverage={"license_files_discovered": 0, "license_files_analyzed": 0},
            execution={"required": True},
        )
    files, files_discovered, inventory_truncated = _subject_file_inventory(subject_path)
    candidates = [
        path for path in files
        if path.name.lower().startswith(("license", "licence", "copying", "notice"))
    ]
    inventory: list[dict[str, Any]] = []
    for path in candidates:
        text = path.read_text("utf-8", errors="replace")[:1_000_000].lower()
        matches = [
            spdx for spdx, markers in LICENSE_MARKERS.items()
            if all(marker in text for marker in markers)
        ]
        inventory.append({
            "path": path.relative_to(subject_path).as_posix(),
            "sha256": _hash_path(path),
            "spdx_candidates": matches,
            "requires_legal_review": len(matches) != 1,
        })
    findings = [
        {"id": "license_unidentified", "severity": "medium", "path": item["path"]}
        for item in inventory if item["requires_legal_review"]
    ]
    if not candidates:
        findings.append({"id": "license_file_missing", "severity": "medium"})
    return _scanner_result(
        name="shakerscan-license-inventory",
        version="1",
        status="INCOMPLETE" if inventory_truncated else "WARNING" if findings else "PASS",
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=findings,
        coverage={
            "files_discovered": files_discovered,
            "files_enumerated": len(files),
            "inventory_truncated": inventory_truncated,
            "license_files_discovered": len(candidates),
            "license_files_analyzed": len(inventory),
        },
        execution={"required": True, "rules_sha256": _sha256_json(LICENSE_MARKERS)},
        summary={"licenses": inventory},
    )


def materialize_snapshot_tree(snapshot: dict[str, Any], quarantine_dir: Path, destination: Path) -> Path:
    """Create a path-preserving disposable view over content-addressed objects."""
    destination.mkdir(parents=True, exist_ok=False)
    seen_casefold: set[str] = set()
    for item in snapshot.get("files") or []:
        path = str(item.get("path") or "")
        parts = path.split("/")
        if not path or any(part in {"", ".", ".."} for part in parts) or "\\" in path:
            raise ValueError("snapshot contains an unsafe path")
        folded = path.casefold()
        if folded in seen_casefold:
            raise ValueError("snapshot contains a case-colliding path")
        seen_casefold.add(folded)
        digest = str(item.get("sha256") or "")
        if len(digest) != 64:
            raise ValueError("snapshot file is missing a SHA-256 digest")
        source = quarantine_dir / "sha256" / digest[:2] / digest
        if not source.is_file() or source.is_symlink():
            raise FileNotFoundError("snapshot quarantine object is missing")
        target = destination.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Do not hard-link: later read-only permission changes for an
        # unprivileged scanner must never mutate the quarantine inode.
        shutil.copyfile(source, target)
        os.chmod(target, 0o444)
    return destination


def generated_evidence_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = {
        str(item.get("scanner", {}).get("name") or "unknown"): str(item.get("execution", {}).get("status") or "CRASHED")
        for item in results
    }
    return {
        "schema_version": "model-intake-generated-evidence/v1",
        "provenance_class": "shakerscan_generated",
        "results": results,
        "statuses": statuses,
        "required_non_pass": [
            name
            for name, status in statuses.items()
            if status in REQUIRED_NON_PASS_STATUSES
            and next(
                (bool(item.get("execution", {}).get("required")) for item in results if item.get("scanner", {}).get("name") == name),
                False,
            )
        ],
        "evidence_sha256": _sha256_json(results),
    }
