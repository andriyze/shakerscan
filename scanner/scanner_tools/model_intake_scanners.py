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
NON_PASS_STATUSES = {
    "FAIL", "WARNING", "UNSUPPORTED", "TIMEOUT", "CRASHED", "INCOMPLETE",
    "REVIEW_REQUIRED", "NOT_RUN",
}
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
DEFAULT_MAX_RULE_AGE_DAYS = 90
DEFAULT_MAX_DATABASE_AGE_DAYS = 14


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
        if applicable and spec.name == "fickling" and any(
            path.suffix.lower() in PICKLE_MODEL_EXTENSIONS and zipfile.is_zipfile(path)
            for path in files
        ):
            applicable = False
            reason = "pytorch_zip_not_supported_by_fickling"
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
        required = bool(applicability["applicable"]) and (requested or (
            strict and profile in spec.required_profiles and bool(applicability["applicable"])
        ))
        selected = requested or (requested_names is None and spec.enabled_by_default) or required
        if not selected and not required:
            continue
        plan.append({
            "spec": dataclasses.replace(spec, required=required),
            "selected": selected,
            "requested": requested,
            "required": required,
            "requirement_source": (
                "caller_requested" if requested and applicability["applicable"]
                else "strict_profile" if required
                else "not_applicable" if not applicability["applicable"]
                else "default_optional"
            ),
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
            "network_policy": "seccomp_external_socket_domains_and_io_uring_denied",
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
    # Selected artifacts can live at
    # /tmp/model-intake-subject-*/snapshot/model.bin. Make every directory
    # inside that disposable view traversable; changing only the immediate
    # parent leaves the outer TemporaryDirectory at 0700.
    disposable_parents: list[Path] = []
    disposable_root_found = False
    for parent in subject_path.parents:
        disposable_parents.append(parent)
        if parent.name.startswith("model-intake-subject-"):
            disposable_root_found = True
            break
    for parent in disposable_parents if disposable_root_found else [subject_path.parent]:
        os.chmod(parent, 0o711)
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


def _semgrep_finding(item: Any) -> dict[str, Any]:
    """Keep actionable, content-free Semgrep coordinates in normalized evidence."""
    if not isinstance(item, dict):
        return _external_finding("semgrep", item)
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    start = item.get("start") if isinstance(item.get("start"), dict) else {}
    semgrep_severity = str(extra.get("severity") or "ERROR").upper()
    severity = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(semgrep_severity, "high")
    path = str(item.get("path") or "")
    normalized = _external_finding("semgrep", item, severity)
    normalized.update({
        "rule_id": str(item.get("check_id") or "unknown"),
        "path": Path(path).name if path else None,
        "line": int(start["line"]) if isinstance(start.get("line"), int) else None,
        "message": str(extra.get("message") or "Semgrep rule matched")[:500],
        "tool_severity": semgrep_severity,
        "classification": (
            "prohibited_capability" if semgrep_severity == "ERROR"
            else "review_required" if semgrep_severity == "WARNING"
            else "informational"
        ),
    })
    return {key: value for key, value in normalized.items() if value is not None}


def _parse_external_scanner(
    scanner: str, stdout: str, stderr: str, exit_code: int
) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    """Validate each tool's output contract; exit zero alone is never PASS."""
    if scanner in {"modelscan", "semgrep", "trivy"}:
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
            findings = [_semgrep_finding(item) for item in candidates[:1000]]
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
        if exit_code not in {0, 1}:
            return "CRASHED", findings, {**summary, "error": (stderr or "unexpected exit code")[:1000]}
        if summary.get("warning_only"):
            return "WARNING", findings, summary
        if findings:
            return "FAIL", findings, summary
        return "PASS", [], summary

    text = f"{stdout}\n{stderr}".strip()
    if scanner == "fickling":
        output_sha256 = hashlib.sha256(text.encode()).hexdigest()
        if exit_code == 0:
            return "PASS", [], {"output_sha256": output_sha256}
        unsafe = exit_code == 1 and any(
            marker in text.lower() for marker in ("may be unsafe", "malicious pickle", "is suspicious")
        )
        if unsafe:
            return "FAIL", [_external_finding(scanner, {"output_sha256": output_sha256}, "critical")], {
                "output_sha256": output_sha256,
            }
        return "INCOMPLETE" if exit_code in {1, 2} else "CRASHED", [], {
            "error": "fickling_analysis_failed",
            "exit_code": exit_code,
            "output_sha256": output_sha256,
        }
    return _default_external_parser(stdout, stderr, exit_code)


def _configured_max_age(name: str, default: int) -> tuple[int | None, str | None]:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return None, f"{name}_invalid"
    if value < 1 or value > 3650:
        return None, f"{name}_out_of_range"
    return value, None


def _material_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _freshness(
    *,
    updated_at: datetime | None,
    max_age_days: int | None,
    configuration_error: str | None,
    now: datetime,
) -> dict[str, Any]:
    age_seconds = (now - updated_at).total_seconds() if updated_at else None
    fresh = bool(
        updated_at
        and max_age_days is not None
        and age_seconds is not None
        and age_seconds >= -300
        and age_seconds <= max_age_days * 86400
    )
    if configuration_error:
        reason = configuration_error
    elif updated_at is None:
        reason = "timestamp_missing_or_invalid"
    elif age_seconds is not None and age_seconds < -300:
        reason = "timestamp_in_future"
    elif not fresh:
        reason = "material_stale"
    else:
        reason = None
    return {
        "fresh": fresh,
        "status": "FRESH" if fresh else "STALE",
        "updated_at": updated_at.isoformat() if updated_at else None,
        "age_days": round(max(0.0, age_seconds or 0.0) / 86400, 3) if updated_at else None,
        "max_age_days": max_age_days,
        "reason": reason,
    }


def _scanner_material_state(spec: ScannerSpec, *, now: datetime | None = None) -> dict[str, Any]:
    """Measure rules/database freshness from shipped material, never caller declarations."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    rule_max_age, rule_error = _configured_max_age(
        "MODEL_INTAKE_SCANNER_MAX_RULE_AGE_DAYS", DEFAULT_MAX_RULE_AGE_DAYS,
    )
    database_max_age, database_error = _configured_max_age(
        "MODEL_INTAKE_SCANNER_MAX_DATABASE_AGE_DAYS", DEFAULT_MAX_DATABASE_AGE_DAYS,
    )
    rules: dict[str, Any] | None = None
    if spec.rules_path:
        path = Path(spec.rules_path)
        updated_at = None
        if path.is_file():
            try:
                updated_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            except OSError:
                pass
        rules = {
            "present": path.is_file(),
            "sha256": _hash_path(path) if path.is_file() else None,
            **_freshness(
                updated_at=updated_at,
                max_age_days=rule_max_age,
                configuration_error=rule_error,
                now=current,
            ),
        }
    database: dict[str, Any] | None = None
    if spec.database_path:
        path = Path(spec.database_path)
        metadata: dict[str, Any] = {}
        if path.is_file():
            try:
                parsed = json.loads(path.read_text("utf-8"))
                metadata = parsed if isinstance(parsed, dict) else {}
            except (OSError, ValueError):
                pass
        updated_value = metadata.get("UpdatedAt") or metadata.get("updated_at")
        database = {
            "present": path.is_file(),
            "sha256": _hash_path(path) if path.is_file() else None,
            "next_update": metadata.get("NextUpdate") or metadata.get("next_update"),
            **_freshness(
                updated_at=_material_timestamp(updated_value),
                max_age_days=database_max_age,
                configuration_error=database_error,
                now=current,
            ),
        }
    required_materials = [item for item in (rules, database) if item is not None]
    return {
        "ready": all(item.get("present") is True and item.get("fresh") is True for item in required_materials),
        "rules": rules,
        "database": database,
    }


def run_external_scanner(spec: ScannerSpec, subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    materials = _scanner_material_state(spec)
    if not materials["ready"]:
        return _scanner_result(
            name=spec.name,
            version=None,
            status="INCOMPLETE",
            subject=subject,
            started_at=started_at,
            finished_at=_utc_iso(),
            execution={
                "error": "scanner_material_missing_or_stale",
                "required": spec.required,
                "reassessment_trigger": "scanner_data_stale",
            },
            summary={"materials": materials},
        )
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
        result_missing = False
        if result_path is not None:
            if result_path.is_file():
                result_output, result_truncated = _read_bounded(result_path)
            else:
                result_output = ""
                result_missing = True
        raw_digest = _output_digest(
            [stdout_path, stderr_path, *([result_path] if result_path is not None else [])]
        )
        if result_missing:
            status, findings, summary = "INCOMPLETE", [], {
                "error": "scanner_result_file_missing",
                "exit_code": completed.returncode,
                "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
            }
        elif stdout_truncated or stderr_truncated or result_truncated:
            status, findings, summary = "INCOMPLETE", [], {
                "error": "scanner_output_limit_exceeded",
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "result_truncated": result_truncated,
            }
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
        materials = _scanner_material_state(spec)
        rules = materials["rules"]
        database = materials["database"]
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
            and materials["ready"]
            and (not self_test_required or (self_test and self_test.get("passed") is True))
        )
        adapters.append({
            **next(item for item in scanner_adapter_catalog() if item["name"] == spec.name),
            "ready": ready,
            "installed": bool(executable),
            "version": version,
            "rules_sha256": rules.get("sha256") if rules else None,
            "rules": rules,
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
        "reassessment_required": any(
            not item.get("ready")
            and (
                (item.get("rules") and not item["rules"].get("fresh"))
                or (item.get("database") and not item["database"].get("fresh"))
            )
            for item in required
        ),
        "reassessment_trigger": "scanner_data_stale",
        "self_test": {
            "status": (self_test_receipt or {}).get("status") or "MISSING",
            "tested_at": (self_test_receipt or {}).get("tested_at"),
            "receipt_sha256": (self_test_receipt or {}).get("receipt_sha256"),
        },
        "adapters": adapters,
    }


DANGEROUS_PICKLE_GLOBALS = {
    "builtins.__import__", "builtins.compile", "builtins.eval", "builtins.exec", "builtins.open",
    "importlib.import_module", "nt.system", "os.popen", "os.system", "posix.system",
    "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
    "subprocess.run",
}
DANGEROUS_PICKLE_MODULE_PREFIXES = (
    "importlib", "multiprocessing", "nt", "os", "pathlib", "posix", "requests", "shutil",
    "socket", "subprocess", "urllib",
)
EXPECTED_PICKLE_GLOBALS = {
    "builtins.bytearray", "builtins.complex", "builtins.frozenset", "builtins.set",
    "builtins.slice", "collections.OrderedDict", "copyreg._reconstructor",
    "numpy.core.multiarray._reconstruct", "numpy.dtype", "numpy.ndarray",
    "torch._utils._rebuild_device_tensor_from_numpy", "torch._utils._rebuild_parameter",
    "torch._utils._rebuild_parameter_with_state", "torch._utils._rebuild_qtensor",
    "torch._utils._rebuild_sparse_tensor", "torch._utils._rebuild_tensor",
    "torch._utils._rebuild_tensor_v2", "torch._utils._rebuild_tensor_v3",
}
EXPECTED_PICKLE_GLOBAL_PREFIXES = (
    "torch.BFloat16Storage", "torch.BoolStorage", "torch.ByteStorage", "torch.CharStorage",
    "torch.ComplexDoubleStorage", "torch.ComplexFloatStorage", "torch.DoubleStorage",
    "torch.FloatStorage", "torch.HalfStorage", "torch.IntStorage", "torch.LongStorage",
    "torch.QInt32Storage", "torch.QInt8Storage", "torch.QUInt4x2Storage",
    "torch.QUInt8Storage", "torch.ShortStorage",
)
PICKLE_UNRESOLVED_GLOBAL_OPCODES = {"INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "EXT1", "EXT2", "EXT4"}


def _normalize_pickle_global(argument: Any) -> str:
    parts = str(argument or "").replace("\n", " ").split()
    return f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else str(argument or "").strip()


def _pickle_global_classification(global_name: str) -> str:
    if global_name in DANGEROUS_PICKLE_GLOBALS:
        return "dangerous"
    module = global_name.rsplit(".", 1)[0] if "." in global_name else global_name
    if any(module == prefix or module.startswith(f"{prefix}.") for prefix in DANGEROUS_PICKLE_MODULE_PREFIXES):
        return "dangerous"
    if global_name in EXPECTED_PICKLE_GLOBALS or global_name in EXPECTED_PICKLE_GLOBAL_PREFIXES:
        return "expected_framework"
    return "review"


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
            dangerous_globals: list[dict[str, Any]] = []
            review_globals: list[dict[str, Any]] = []
            expected_globals: list[str] = []
            unresolved_globals: list[dict[str, Any]] = []
            executable_constructs: dict[str, int] = {}
            recent_strings: list[str] = []
            for opcode, argument, position in pickletools.genops(raw):
                if opcode.name in {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE"}:
                    recent_strings.append(str(argument))
                    recent_strings = recent_strings[-2:]
                global_name = ""
                if opcode.name == "GLOBAL":
                    global_name = _normalize_pickle_global(argument)
                elif opcode.name == "STACK_GLOBAL":
                    if len(recent_strings) >= 2:
                        global_name = f"{recent_strings[-2]}.{recent_strings[-1]}"
                    else:
                        unresolved_globals.append({"opcode": opcode.name, "position": position})
                if global_name:
                    item = {"global": global_name[:300], "opcode": opcode.name, "position": position}
                    classification = _pickle_global_classification(global_name)
                    if classification == "dangerous":
                        dangerous_globals.append(item)
                    elif classification == "expected_framework":
                        expected_globals.append(global_name)
                    else:
                        review_globals.append(item)
                if opcode.name in {"REDUCE", "PERSID", "BINPERSID", *PICKLE_UNRESOLVED_GLOBAL_OPCODES}:
                    executable_constructs[opcode.name] = executable_constructs.get(opcode.name, 0) + 1
                if opcode.name in PICKLE_UNRESOLVED_GLOBAL_OPCODES:
                    unresolved_globals.append({"opcode": opcode.name, "position": position})
            analyzed += 1
            if dangerous_globals:
                findings.append({
                    "id": "dangerous_pickle_global",
                    "severity": "critical",
                    "path": name,
                    "classification": "proven_dangerous_callable",
                    "globals": dangerous_globals[:100],
                })
            if unresolved_globals:
                findings.append({
                    "id": "unresolved_pickle_callable",
                    "severity": "high",
                    "path": name,
                    "classification": "indeterminate_callable",
                    "opcodes": unresolved_globals[:100],
                })
            if review_globals:
                findings.append({
                    "id": "unrecognized_pickle_global",
                    "severity": "medium",
                    "path": name,
                    "classification": "manual_review_required",
                    "globals": review_globals[:100],
                })
            if not dangerous_globals and not unresolved_globals and not review_globals:
                expected_globals = sorted(set(expected_globals))
            else:
                expected_globals = sorted(set(expected_globals))[:100]
            # Per-stream detail stays content-free while making an ordinary
            # framework pickle distinguishable from a proven exploit primitive.
            if expected_globals or executable_constructs:
                findings.append({
                    "id": "pickle_execution_capability",
                    "severity": "info",
                    "path": name,
                    "classification": "expected_framework_pickle" if expected_globals and not (dangerous_globals or unresolved_globals or review_globals) else "mixed",
                    "expected_globals": expected_globals[:100],
                    "executable_constructs": executable_constructs,
                })
        except Exception as exc:
            parse_errors.append({"path": name, "error": f"{type(exc).__name__}: {exc}"})
    blocking_findings = [item for item in findings if item.get("severity") in {"critical", "high"}]
    review_findings = [item for item in findings if item.get("severity") == "medium"]
    if analyzed < discovered or parse_errors or inventory_truncated:
        status = "INCOMPLETE"
    elif blocking_findings:
        status = "FAIL"
    elif review_findings:
        status = "WARNING"
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
        summary={
            "parse_errors": parse_errors[:20],
            "semantic_classification": (
                "dangerous_callable_detected" if any(item.get("severity") == "critical" for item in findings)
                else "indeterminate_callable" if blocking_findings
                else "manual_review_required" if review_findings
                else "expected_framework_pickle"
            ),
            "capability_only": not blocking_findings and not review_findings,
        },
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


def _stream_secret_matches(path: Path) -> list[tuple[str, int, bytes]]:
    """Scan arbitrary-size text files with bounded memory and boundary overlap."""
    matches: list[tuple[str, int, bytes]] = []
    carry = b""
    offset = 0
    overlap = 4096
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            window = carry + chunk
            window_offset = offset - len(carry)
            for rule_id, pattern in SECRET_RULES.items():
                remaining = 20 - sum(1 for existing, _, _ in matches if existing == rule_id)
                if remaining <= 0:
                    continue
                for match in pattern.finditer(window):
                    absolute = window_offset + match.start()
                    # Matches wholly inside carry were already reported.
                    if match.end() <= len(carry):
                        continue
                    matches.append((rule_id, absolute, match.group(0)))
                    remaining -= 1
                    if remaining == 0:
                        break
            offset += len(chunk)
            carry = window[-overlap:]
    return matches


def run_builtin_secret_scan(subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    files, files_discovered, inventory_truncated = _subject_file_inventory(subject_path)
    findings: list[dict[str, Any]] = []
    analyzed = 0
    streamed_large = 0
    excluded_by_type = 0
    root = subject_path if subject_path.is_dir() else subject_path.parent
    for path in files:
        extension = path.suffix.lower()
        if extension in OPAQUE_MODEL_EXTENSIONS:
            excluded_by_type += 1
            continue
        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            if extension in SECRET_TEXT_EXTENSIONS or path.name.lower().startswith(("license", "readme", "requirements")):
                streamed_large += 1
            else:
                excluded_by_type += 1
                continue
        with path.open("rb") as handle:
            prefix = handle.read(4096)
        if b"\0" in prefix and extension not in SECRET_TEXT_EXTENSIONS:
            excluded_by_type += 1
            continue
        analyzed += 1
        for rule_id, match_offset, value in _stream_secret_matches(path):
            findings.append({
                "id": rule_id,
                "severity": "critical" if rule_id == "private_key" else "high",
                "path": path.relative_to(root).as_posix(),
                "offset": match_offset,
                "match_sha256": hashlib.sha256(value).hexdigest(),
                "match_length": len(value),
            })
    status = "INCOMPLETE" if inventory_truncated else "FAIL" if findings else "PASS"
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
            "files_skipped_large": 0,
            "files_streamed_large": streamed_large,
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
    expectations = []
    for item in results:
        scanner = item.get("scanner") if isinstance(item.get("scanner"), dict) else {}
        execution = item.get("execution") if isinstance(item.get("execution"), dict) else {}
        name = str(scanner.get("name") or "unknown")
        status = str(execution.get("status") or "CRASHED")
        required = bool(execution.get("required"))
        acceptable = ["PASS", "NOT_APPLICABLE"] if required else ["PASS", "WARNING", "NOT_APPLICABLE"]
        expectations.append({
            "scanner": name,
            "required": required,
            "applicability": execution.get("applicability") or "built_in",
            "reason": execution.get("reason"),
            "acceptable_statuses": acceptable,
            "actual_status": status,
            "satisfied": status in acceptable,
        })
    return {
        "schema_version": "model-intake-generated-evidence/v1",
        "provenance_class": "shakerscan_generated",
        "results": results,
        "statuses": statuses,
        "expectation_matrix": expectations,
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


def scan_materialized_snapshot(
    snapshot_root: Path,
    *,
    artifact_relative_path: str,
    snapshot_sha256: str,
    profile: str = "strict",
) -> dict[str, Any]:
    """Rescan one already materialized, immutable repository snapshot.

    This is used for Firecracker conversion outputs. It intentionally accepts no
    URL, command, scanner override, or caller-authored manifest.
    """
    root = snapshot_root.resolve(strict=True)
    relative = Path(artifact_relative_path)
    if not root.is_dir() or relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("materialized model snapshot or artifact path is invalid")
    artifact = (root / relative).resolve(strict=True)
    if root not in artifact.parents or not artifact.is_file() or artifact.is_symlink():
        raise ValueError("materialized model artifact escapes the snapshot")
    if not re.fullmatch(r"[0-9a-f]{64}", snapshot_sha256):
        raise ValueError("materialized model snapshot digest is invalid")
    subject = {
        "kind": "repository_snapshot",
        "filename": artifact.name,
        "digest": f"sha256:{snapshot_sha256}",
        "complete": True,
    }
    results = [
        run_builtin_pickle_scan(artifact, subject),
        run_builtin_source_scan(root, subject),
        run_builtin_secret_scan(root, subject),
        run_builtin_malware_scan(root, subject),
        run_builtin_sbom_scan(root, subject),
        run_builtin_binary_inventory(root, subject),
        run_builtin_license_inventory(root, subject),
    ]
    for planned in resolve_scanner_plan(root, profile=profile):
        spec = planned["spec"]
        if not planned["applicable"]:
            now = datetime.now(timezone.utc).isoformat()
            results.append(_scanner_result(
                name=spec.name,
                version=None,
                status="NOT_APPLICABLE",
                subject=subject,
                started_at=now,
                finished_at=now,
                coverage={"files_considered": planned["files_considered"]},
                execution={
                    "required": False,
                    "reason": planned["reason"],
                    "adapter_kind": spec.adapter_kind,
                    "applicability": spec.applicability,
                    "target_scope": spec.target_scope,
                },
            ))
            continue
        results.append(run_external_scanner(
            spec,
            artifact if spec.target_scope == "artifact" else root,
            subject,
        ))
    summary = generated_evidence_summary(results)
    severity = {
        str(finding.get("severity") or "").lower()
        for scanner_result in results
        for finding in scanner_result.get("findings") or [] if isinstance(finding, dict)
    }
    required_non_pass = [
        item for item in results
        if item.get("execution", {}).get("status") in REQUIRED_NON_PASS_STATUSES
        and bool(item.get("execution", {}).get("required"))
    ]
    status = (
        "FAIL" if severity.intersection({"critical", "high"})
        else "PASS" if not required_non_pass
        else "REVIEW_REQUIRED" if all(
            item.get("execution", {}).get("status") == "WARNING" for item in required_non_pass
        )
        else "FAIL"
    )
    return {**summary, "status": status}
