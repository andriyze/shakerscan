"""Generated Model Intake scanner evidence and bounded plug-in execution."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import pickletools
import pwd
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


def materialize_snapshot_tree(snapshot: dict[str, Any], quarantine_dir: Path, destination: Path) -> Path:
    """Create a path-preserving, hard-linked view over content-addressed objects."""
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
        os.link(source, target)
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
