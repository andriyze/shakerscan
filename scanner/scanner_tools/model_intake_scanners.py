"""Generated Model Intake scanner evidence and bounded plug-in execution."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import pickletools
import pwd
import re
import resource
import shutil
import subprocess
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
}
NON_PASS_STATUSES = {"FAIL", "UNSUPPORTED", "TIMEOUT", "CRASHED", "INCOMPLETE"}
MAX_SCANNER_OUTPUT_BYTES = 20_000_000
MAX_SOURCE_FILE_BYTES = 2_000_000
MAX_PICKLE_MEMBER_BYTES = 100_000_000


@dataclass(frozen=True)
class ScannerSpec:
    name: str
    executable: str
    args: tuple[str, ...]
    version_args: tuple[str, ...] = ("--version",)
    timeout_seconds: int = 300
    required: bool = False
    parser: Callable[[str, str, int], tuple[str, list[dict[str, Any]], dict[str, Any]]] | None = None


EXTERNAL_SCANNERS: tuple[ScannerSpec, ...] = (
    ScannerSpec("modelscan", "modelscan", ("-p", "{subject}", "-r", "json"), required=True),
    ScannerSpec("fickling", "fickling", ("--check-safety", "{subject}"), required=True),
    ScannerSpec("clamav", "clamscan", ("--recursive=yes", "--infected", "{subject}"), required=True),
    ScannerSpec("gitleaks", "gitleaks", ("detect", "--no-git", "--source", "{subject}", "--report-format", "json", "--report-path", "{scratch}/gitleaks.json"), required=True),
    ScannerSpec("syft", "syft", ("dir:{subject}", "-o", "cyclonedx-json"), required=True),
    ScannerSpec("trivy", "trivy", ("fs", "--scanners", "vuln,secret,misconfig,license", "--format", "json", "--skip-db-update", "{subject}"), required=True),
    ScannerSpec("osv-scanner", "osv-scanner", ("scan", "source", "-r", "{subject}", "--format", "json"), required=True),
    ScannerSpec("pip-audit", "pip-audit", ("--path", "{subject}", "--format=json"), required=False),
)


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


def _bounded_preexec() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (100 * 1024**2, 100 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (128, 128))
    except (ValueError, OSError):
        pass
    if os.geteuid() == 0:
        try:
            account = pwd.getpwnam("scanner")
        except KeyError:
            return
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)


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


def _prepare_unprivileged_paths(subject_path: Path, scratch: Path) -> None:
    """Make the disposable scan view readable and scratch writable after UID drop."""
    if os.geteuid() != 0:
        return
    try:
        account = pwd.getpwnam("scanner")
    except KeyError:
        return
    os.chown(scratch, account.pw_uid, account.pw_gid)
    os.chmod(scratch, 0o700)
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


def _tool_version(executable: str, args: tuple[str, ...], env: dict[str, str], cwd: Path) -> str | None:
    try:
        completed = subprocess.run(
            [executable, *args],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            preexec_fn=_bounded_preexec,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (completed.stdout or completed.stderr or "").strip().splitlines()
    return output[0][:300] if output else None


def _default_external_parser(stdout: str, stderr: str, exit_code: int) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    parsed: Any = None
    try:
        parsed = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError:
        parsed = None
    if exit_code == 0:
        status = "PASS"
    elif exit_code == 1:
        status = "FAIL"
    else:
        status = "CRASHED"
    findings: list[dict[str, Any]] = []
    if status == "FAIL":
        findings.append({
            "id": "scanner_reported_issue",
            "severity": "high",
            "message": (stderr or stdout or "Scanner reported a policy-relevant issue")[:2000],
        })
    summary = {
        "json_output": parsed is not None,
        "top_level_type": type(parsed).__name__ if parsed is not None else None,
    }
    return status, findings, summary


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
                    argv,
                    cwd=scratch,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    timeout=spec.timeout_seconds,
                    check=False,
                    preexec_fn=_bounded_preexec,
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
        raw_digest = hashlib.sha256(stdout_path.read_bytes() + b"\0" + stderr_path.read_bytes()).hexdigest()
        if stdout_truncated or stderr_truncated:
            status, findings, summary = "INCOMPLETE", [], {"error": "scanner_output_limit_exceeded"}
        else:
            parser = spec.parser or _default_external_parser
            try:
                status, findings, summary = parser(stdout, stderr, completed.returncode)
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
            },
            summary=summary,
        )


DANGEROUS_PICKLE_OPCODES = {
    "GLOBAL", "STACK_GLOBAL", "REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX",
    "EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID",
}


def _pickle_streams(path: Path) -> tuple[list[tuple[str, bytes]], int]:
    if zipfile.is_zipfile(path):
        streams: list[tuple[str, bytes]] = []
        discovered = 0
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist()[:5000]:
                name = info.filename
                if not name.lower().endswith((".pkl", ".pickle", "data.pkl")):
                    continue
                discovered += 1
                if info.file_size > MAX_PICKLE_MEMBER_BYTES:
                    continue
                streams.append((name, archive.read(info)))
        return streams, discovered
    if path.suffix.lower() in {".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin", ".joblib"}:
        if path.stat().st_size > MAX_PICKLE_MEMBER_BYTES:
            return [], 1
        return [(path.name, path.read_bytes())], 1
    return [], 0


def run_builtin_pickle_scan(subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    streams, discovered = _pickle_streams(subject_path)
    if discovered == 0:
        return _scanner_result(
            name="python-pickletools",
            version=None,
            status="NOT_APPLICABLE",
            subject=subject,
            started_at=started_at,
            finished_at=_utc_iso(),
            coverage={"pickle_streams_discovered": 0, "pickle_streams_analyzed": 0},
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
    if analyzed < discovered or parse_errors:
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
        coverage={"pickle_streams_discovered": discovered, "pickle_streams_analyzed": analyzed},
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
        )
    paths = sorted(snapshot_root.rglob("*.py"))[:10_000]
    findings: list[dict[str, Any]] = []
    analyzed = 0
    incomplete = False
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
        coverage={"python_files_discovered": len(paths), "python_files_analyzed": analyzed},
    )


def _subject_files(subject_path: Path, *, limit: int = 10_000) -> list[Path]:
    if subject_path.is_file():
        return [subject_path]
    return [path for path in sorted(subject_path.rglob("*")) if path.is_file()][:limit]


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


def run_builtin_secret_scan(subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    files = _subject_files(subject_path)
    findings: list[dict[str, Any]] = []
    analyzed = 0
    skipped_large = 0
    root = subject_path if subject_path.is_dir() else subject_path.parent
    for path in files:
        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            skipped_large += 1
            continue
        raw = path.read_bytes()
        if b"\0" in raw[:4096] and path.suffix.lower() not in {".json", ".txt", ".md", ".yaml", ".yml"}:
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
    status = "INCOMPLETE" if skipped_large else "FAIL" if findings else "PASS"
    return _scanner_result(
        name="shakerscan-secret-rules",
        version="1",
        status=status,
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=findings[:1000],
        coverage={"files_discovered": len(files), "files_analyzed": analyzed, "files_skipped_large": skipped_large},
        execution={"required": True, "rules_sha256": SECRET_RULESET_SHA256},
    )


MALWARE_MARKERS = {
    "eicar_test_file": b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
    "shell_download_execute": b"curl | sh",
    "powershell_encoded_command": b"powershell -enc",
    "python_reverse_shell": b"socket.socket();os.dup2",
}
MALWARE_RULESET_SHA256 = _sha256_json({key: value.hex() for key, value in MALWARE_MARKERS.items()})


def run_builtin_malware_scan(subject_path: Path, subject: dict[str, Any]) -> dict[str, Any]:
    started_at = _utc_iso()
    files = _subject_files(subject_path)
    findings: list[dict[str, Any]] = []
    analyzed = 0
    skipped_large = 0
    root = subject_path if subject_path.is_dir() else subject_path.parent
    for path in files:
        if path.stat().st_size > MAX_PICKLE_MEMBER_BYTES:
            skipped_large += 1
            continue
        raw = path.read_bytes()
        analyzed += 1
        lowered = raw.lower()
        for rule_id, marker in MALWARE_MARKERS.items():
            if marker.lower() in lowered:
                findings.append({
                    "id": rule_id,
                    "severity": "critical" if rule_id == "eicar_test_file" else "high",
                    "path": path.relative_to(root).as_posix(),
                    "file_sha256": hashlib.sha256(raw).hexdigest(),
                })
    status = "INCOMPLETE" if skipped_large else "FAIL" if findings else "PASS"
    return _scanner_result(
        name="shakerscan-malware-rules",
        version="1",
        status=status,
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=findings[:1000],
        coverage={"files_discovered": len(files), "files_analyzed": analyzed, "files_skipped_large": skipped_large},
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
    dependency_paths = [path for path in _subject_files(subject_path) if path.name.lower() in DEPENDENCY_FILES]
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
    status = "WARNING" if unpinned else "PASS"
    return _scanner_result(
        name="shakerscan-sbom",
        version="1",
        status=status,
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=[{"id": "unpinned_dependency", "severity": "medium", **item} for item in unpinned[:1000]],
        coverage={"dependency_files_discovered": len(dependency_paths), "components_generated": len(normalized_components)},
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
    files = _subject_files(subject_path)
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
        status="WARNING" if binaries else "PASS",
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=binaries[:1000],
        coverage={"files_discovered": len(files), "native_binaries": len(binaries)},
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
        )
    candidates = [
        path for path in _subject_files(subject_path)
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
        status="WARNING" if findings else "PASS",
        subject=subject,
        started_at=started_at,
        finished_at=_utc_iso(),
        findings=findings,
        coverage={"license_files_discovered": len(candidates), "license_files_analyzed": len(inventory)},
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
            if status in NON_PASS_STATUSES
            and next(
                (bool(item.get("execution", {}).get("required")) for item in results if item.get("scanner", {}).get("name") == name),
                False,
            )
        ],
        "evidence_sha256": _sha256_json(results),
    }
