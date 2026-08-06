"""
Model intake security checks.

This module inspects model artifacts without importing or executing them. It is
intended for pre-deployment intake checks: provenance, unsafe serialization,
artifact integrity/signing, malware-risk signals, and approval metadata.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import pickletools
import re
import shutil
import struct
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any

from .model_intake_acquisition import (
    acquisition_policy as _acquisition_policy,
    download_http as _safe_download_http,
    download_http_to_quarantine as _safe_download_http_to_quarantine,
    quarantine_local_file as _quarantine_local_file,
)
from . import model_intake_scanners as _model_intake_scanners
from .model_intake_admission import (
    build_statement as _build_admission_statement,
    build_technical_candidate as _build_admission_candidate,
)
from .model_intake_archives import inspect_archive as _inspect_complete_archive
from .model_intake_attestation import verify_dsse_in_toto as _verify_dsse_in_toto
from .model_intake_evaluation import evaluate as _evaluate_model_intake
from .model_intake_evaluation import verify_report as _verify_model_intake_evaluation
from .model_intake_registry import adapter_capabilities as _adapter_capabilities
from .model_intake_runtime import DTYPE_SIZES as _SAFETENSORS_DTYPE_SIZES
from .model_intake_sandbox import request_sandbox_analysis as _request_sandbox_analysis

if __package__ == "scanner_tools":
    from redaction import (
        SENSITIVE_KEYS,
        SENSITIVE_KEY_FRAGMENTS,
        is_sensitive_key,
        redact_sensitive,
        redact_url_credentials,
    )
else:
    from ..redaction import (
        SENSITIVE_KEYS,
        SENSITIVE_KEY_FRAGMENTS,
        is_sensitive_key,
        redact_sensitive,
        redact_url_credentials,
    )


RISKY_EXTENSIONS = {
    ".pkl",
    ".pickle",
    ".joblib",
    ".pt",
    ".pth",
    ".ckpt",
    ".bin",
    ".mar",
}

SAFER_MODEL_EXTENSIONS = {
    ".safetensors",
    ".onnx",
    ".tflite",
    ".gguf",
}

MODEL_ARTIFACT_FILENAMES = {
    "model.safetensors",
    "pytorch_model.bin",
    "tf_model.h5",
    "model.onnx",
    "model.tflite",
    "model.gguf",
    "adapter_model.safetensors",
    "adapter_model.bin",
}

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".sh",
    ".bash",
    ".ps1",
    ".bat",
    ".cmd",
}

PICKLE_MAGIC_PREFIXES = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")
PICKLE_OPCODE_MARKERS = (b"__reduce__", b"cposix\nsystem", b"cos\nsystem")

MAX_INSPECTION_BYTES = 100_000_000
MAX_ARTIFACT_BYTES = 100_000_000_000
MAX_REPOSITORY_BYTES = 500_000_000_000
MAX_REPOSITORY_FILES = 10_000

# Metadata documents and artifact-side metadata are publisher declarations,
# never corporate approval or policy authority. Server-owned approval travels
# only through typed options/control-plane records.
UNTRUSTED_GOVERNANCE_METADATA_KEYS = {
    "deployment_approved",
    "approved_by",
    "approver",
    "approved_at",
    "approval_timestamp",
    "approval_date",
    "approval_policy_version",
    "policy_version",
    "approved_environment",
    "deployment_environment",
    "legal_approved",
    "privacy_approved",
    "security_approved",
    "risk_accepted",
}


def _strip_untrusted_governance_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_untrusted_governance_metadata(child)
            for key, child in value.items()
            if str(key).strip().lower() not in UNTRUSTED_GOVERNANCE_METADATA_KEYS
        }
    if isinstance(value, list):
        return [_strip_untrusted_governance_metadata(child) for child in value]
    return value
MAX_TIMEOUT_SECONDS = 120

SUSPICIOUS_LOADER_MARKERS = {
    b"os.system": "python_os_system",
    b"subprocess": "python_subprocess",
    b"eval(": "python_eval",
    b"exec(": "python_exec",
    b"pickle.loads": "pickle_loads",
    b"/bin/sh": "shell_spawn",
    b"powershell": "powershell",
    b"curl http": "network_downloader",
    b"wget http": "network_downloader",
    b"base64.b64decode": "encoded_payload",
}

SAFETENSORS_SUSPICIOUS_METADATA_KEYS = {
    "chat_template",
    "system_prompt",
    "developer_prompt",
    "trust_remote_code",
    "tool_call_schema",
}

RISKY_TEMPLATE_MARKERS = (
    "tool_call",
    "function_call",
    "developer",
    "system",
    "ignore previous",
    "bypass",
)

PERMISSIVE_LICENSES = {
    "apache-2.0",
    "apache 2.0",
    "mit",
    "bsd-2-clause",
    "bsd-3-clause",
    "isc",
}

RESTRICTIVE_LICENSE_HINTS = (
    "non-commercial",
    "noncommercial",
    "research only",
    "no redistribution",
    "restricted",
    "unknown",
)

# Sensitive-key matching and value masking are centralized in scanner.redaction
# so the API and Model Intake share one key-set (previously these diverged).
# These names are kept as aliases for backward compatibility.
SENSITIVE_METADATA_KEYS = SENSITIVE_KEYS
SENSITIVE_METADATA_KEY_FRAGMENTS = SENSITIVE_KEY_FRAGMENTS
_is_sensitive_metadata_key = is_sensitive_key
_redact_reference = redact_url_credentials


def redact_model_intake_value(value: Any) -> Any:
    """Mask secrets in model-intake metadata and user-visible artifacts."""
    return redact_sensitive(value, redact_strings=True)


def redact_generated_evidence(evidence: Any) -> Any:
    """Redact scanner evidence without masking a scanner's own control state.

    ``statuses`` is keyed by scanner name, and ``shakerscan-secret-rules``
    matches the shared sensitive-key fragment matcher, so the generic redactor
    replaced that scanner's ``PASS`` with ``***`` and left an operator unable to
    tell whether the secret scan had run. Normalized control states come from a
    closed vocabulary and cannot carry secret material, so they are restored;
    anything outside that vocabulary stays redacted, and scanner findings —
    which genuinely can quote matched secrets — are untouched.
    """
    redacted = redact_model_intake_value(evidence)
    if not isinstance(evidence, dict) or not isinstance(redacted, dict):
        return redacted
    statuses = evidence.get("statuses")
    redacted_statuses = redacted.get("statuses")
    if isinstance(statuses, dict) and isinstance(redacted_statuses, dict):
        redacted["statuses"] = {
            name: status
            if status in _model_intake_scanners.NORMALIZED_STATUSES
            else redacted_statuses.get(name)
            for name, status in statuses.items()
        }
    return redacted


def _artifact_name(ref: str) -> str:
    parsed = urllib.parse.urlparse(ref)
    path = parsed.path or ref
    name = Path(path).name
    return name or ref.rstrip("/").split("/")[-1] or "model-artifact"


def _artifact_ext(name: str) -> str:
    suffixes = Path(name).suffixes
    if len(suffixes) >= 2 and suffixes[-2:] in ([".tar", ".gz"], [".tar", ".xz"], [".tar", ".bz2"]):
        return "".join(suffixes[-2:]).lower()
    return Path(name).suffix.lower()


def _sandbox_artifact_filename(
    artifact_ref: str,
    metadata: dict[str, Any],
    artifact_meta: dict[str, Any],
) -> str:
    huggingface_fetch = artifact_meta.get("huggingface") if isinstance(artifact_meta.get("huggingface"), dict) else {}
    return str(
        huggingface_fetch.get("filename")
        or metadata.get("huggingface_file")
        or metadata.get("hf_file")
        or _artifact_name(artifact_ref)
    )


def _is_model_artifact_path(path: str) -> bool:
    name = Path(path).name.lower()
    return name in MODEL_ARTIFACT_FILENAMES or Path(name).suffix.lower() in RISKY_EXTENSIONS | SAFER_MODEL_EXTENSIONS


def parse_huggingface_ref(ref: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    """Normalize common Hugging Face refs without contacting the Hub."""
    metadata = metadata or {}
    raw = str(ref or "").strip()
    revision = str(metadata.get("revision") or metadata.get("model_revision") or "main").strip() or "main"
    repo_id = str(metadata.get("huggingface_repo") or metadata.get("hf_repo") or "").strip()
    filename = str(metadata.get("huggingface_file") or metadata.get("hf_file") or "").strip()
    source_url = raw

    parsed = urllib.parse.urlparse(raw)
    query = urllib.parse.parse_qs(parsed.query or "")
    if query.get("revision"):
        revision = query["revision"][0] or revision
    if query.get("rev"):
        revision = query["rev"][0] or revision
    if query.get("filename"):
        filename = query["filename"][0] or filename

    if parsed.scheme in {"http", "https"} and parsed.netloc.endswith("huggingface.co"):
        parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
        marker_index = next((idx for idx, part in enumerate(parts) if part in {"blob", "resolve", "raw", "tree"}), None)
        if marker_index is not None:
            repo_id = "/".join(parts[:marker_index]) or repo_id
            if len(parts) > marker_index + 1:
                revision = parts[marker_index + 1] or revision
            if len(parts) > marker_index + 2 and parts[marker_index] != "tree":
                filename = "/".join(parts[marker_index + 2:]) or filename
        elif parts:
            if len(parts) == 1:
                repo_id = parts[0]
            else:
                repo_id = "/".join(parts[:2])
                remainder = "/".join(parts[2:])
                if remainder and _is_model_artifact_path(remainder):
                    filename = remainder

    elif parsed.scheme == "hf":
        parts = [urllib.parse.unquote(part) for part in f"{parsed.netloc}{parsed.path}".split("/") if part]
        if parts:
            if "@" in parts[0]:
                parts[0], rev = parts[0].split("@", 1)
                revision = rev or revision
            elif len(parts) >= 2 and "@" in parts[1]:
                parts[1], rev = parts[1].split("@", 1)
                revision = rev or revision

            if repo_id:
                consumed = 0
            elif len(parts) == 1:
                repo_id = parts[0]
                consumed = 1
            elif len(parts) == 2 and _is_model_artifact_path(parts[1]):
                repo_id = parts[0]
                consumed = 1
            else:
                repo_id = "/".join(parts[:2])
                consumed = 2
            if not filename and len(parts) > consumed:
                filename = "/".join(parts[consumed:])

    resolve_url = None
    if repo_id and filename:
        resolve_url = (
            "https://huggingface.co/"
            f"{urllib.parse.quote(repo_id, safe='/')}/resolve/"
            f"{urllib.parse.quote(revision, safe='/')}/"
            f"{urllib.parse.quote(filename, safe='/')}"
        )

    return {
        "kind": "huggingface",
        "input": raw,
        "repo_id": repo_id or None,
        "filename": filename or None,
        "revision": revision,
        "resolve_url": resolve_url,
        "source_url": source_url,
    }


def _split_tag_digest(image_ref: str) -> tuple[str, str | None, str | None]:
    digest = None
    if "@" in image_ref:
        image_ref, digest = image_ref.split("@", 1)
    tag = None
    last_slash = image_ref.rfind("/")
    last_colon = image_ref.rfind(":")
    if last_colon > last_slash:
        image_ref, tag = image_ref[:last_colon], image_ref[last_colon + 1:]
    return image_ref, tag, digest


def _signed_http_hint(ref: str) -> bool:
    parsed = urllib.parse.urlparse(ref)
    return parsed.scheme in {"http", "https"}


def _normalized_hostname(parsed: urllib.parse.ParseResult) -> str:
    return (parsed.hostname or "").lower().rstrip(".")


def _is_s3_hostname(host: str) -> bool:
    return host == "s3.amazonaws.com" or (
        host.endswith(".amazonaws.com")
        and (host.startswith("s3.") or host.startswith("s3-") or ".s3." in host or ".s3-" in host)
    )


def _is_azure_blob_hostname(host: str) -> bool:
    return host.endswith(".blob.core.windows.net") and host != "blob.core.windows.net"


def _quote_path(path: str) -> str:
    return urllib.parse.quote(path.strip("/"), safe="/")


def _cloud_object_fetch_url(parsed_ref: dict[str, Any]) -> str | None:
    kind = str(parsed_ref.get("kind") or "")
    if kind == "s3":
        bucket = str(parsed_ref.get("bucket") or "").strip()
        key = str(parsed_ref.get("object_key") or "").strip()
        if not bucket or not key:
            return None
        region = parsed_ref.get("region")
        host = f"{bucket}.s3.{region}.amazonaws.com" if region else f"{bucket}.s3.amazonaws.com"
        return f"https://{host}/{_quote_path(key)}"
    if kind == "gcs":
        bucket = str(parsed_ref.get("bucket") or "").strip()
        key = str(parsed_ref.get("object_key") or "").strip()
        if not bucket or not key:
            return None
        return f"https://storage.googleapis.com/{urllib.parse.quote(bucket, safe='')}/{_quote_path(key)}"
    if kind == "azure_blob":
        account = str(parsed_ref.get("account") or "").strip()
        container = str(parsed_ref.get("container") or "").strip()
        blob_path = str(parsed_ref.get("blob_path") or "").strip()
        if not account or not container or not blob_path:
            return None
        return f"https://{urllib.parse.quote(account, safe='')}.blob.core.windows.net/{urllib.parse.quote(container, safe='')}/{_quote_path(blob_path)}"
    return None


def normalize_model_artifact_reference(
    ref: str,
    metadata: dict[str, Any] | None = None,
    platform: str | None = None,
) -> dict[str, Any]:
    """Parse common model registry/storage references into stable metadata."""
    metadata = metadata or {}
    raw = str(ref or "").strip()
    parsed = urllib.parse.urlparse(raw)
    explicit_platform = (platform or "").strip().lower()
    kind = explicit_platform if explicit_platform and explicit_platform != "auto" else _source_kind(raw, metadata)
    warnings: list[str] = []
    parsed_ref: dict[str, Any] = {
        "kind": kind,
        "ref": raw,
        "registry": parsed.netloc or None,
        "repository": None,
        "path": parsed.path.lstrip("/") or None,
        "fetchable": parsed.scheme in {"http", "https", "file"} or not parsed.scheme,
        "metadata": {"artifact_platform": kind},
        "warnings": warnings,
    }

    if kind == "huggingface":
        hf_ref = parse_huggingface_ref(raw, metadata)
        parsed_ref.update(hf_ref)
        parsed_ref["repository"] = hf_ref.get("repo_id")
        parsed_ref["path"] = hf_ref.get("filename")
        parsed_ref["fetchable"] = bool(hf_ref.get("resolve_url") or _signed_http_hint(raw))
        parsed_ref["metadata"].update({
            "huggingface_repo": hf_ref.get("repo_id"),
            "huggingface_file": hf_ref.get("filename"),
            "revision": hf_ref.get("revision"),
        })
        extension = _artifact_ext(parsed_ref.get("path") or _artifact_name(raw))
        parsed_ref["extension"] = extension
        parsed_ref["format_posture"] = (
            "safer_static_format" if extension in SAFER_MODEL_EXTENSIONS
            else "unsafe_or_review_required" if extension in RISKY_EXTENSIONS
            else "unknown_or_unclassified_format"
        )
        parsed_ref["adapter"] = _adapter_capabilities("huggingface")
        return parsed_ref

    if kind == "s3":
        bucket = parsed.netloc
        key = parsed.path.lstrip("/")
        region = metadata.get("region") or metadata.get("aws_region") or metadata.get("s3_region")
        if parsed.scheme in {"http", "https"}:
            host = _normalized_hostname(parsed)
            if host == "s3.amazonaws.com" or (host.endswith(".amazonaws.com") and host.startswith(("s3.", "s3-"))):
                parts = [part for part in parsed.path.split("/") if part]
                bucket = parts[0] if parts else ""
                key = "/".join(parts[1:])
            elif _is_s3_hostname(host):
                bucket = host.split(".s3", 1)[0]
                region_match = re.search(r"\.s3[.-]([a-z0-9-]+)\.amazonaws\.com$", host)
                if region_match:
                    region = region_match.group(1)
        parsed_ref.update({"registry": "amazon-s3", "repository": bucket or None, "path": key or None, "bucket": bucket or None, "object_key": key or None, "region": region or None})
        fetch_url = raw if _signed_http_hint(raw) else _cloud_object_fetch_url(parsed_ref)
        parsed_ref.update({"fetch_url": fetch_url, "fetchable": bool(fetch_url)})
        parsed_ref["metadata"].update({"artifact_bucket": bucket, "artifact_path": key, "storage_provider": "s3", "artifact_fetch_url": fetch_url, "region": region})
        if parsed.scheme == "s3":
            warnings.append("S3 object refs are fetched anonymously through the provider HTTPS endpoint; private objects need a presigned HTTPS URL.")

    elif kind in {"gs", "gcs"}:
        bucket = parsed.netloc
        key = parsed.path.lstrip("/")
        if parsed.scheme in {"http", "https"}:
            host = parsed.netloc
            parts = [part for part in parsed.path.split("/") if part]
            if host == "storage.googleapis.com":
                bucket = parts[0] if parts else ""
                key = "/".join(parts[1:])
            elif host.endswith(".storage.googleapis.com"):
                bucket = host.removesuffix(".storage.googleapis.com")
        parsed_ref.update({"kind": "gcs", "registry": "google-cloud-storage", "repository": bucket or None, "path": key or None, "bucket": bucket or None, "object_key": key or None})
        fetch_url = raw if _signed_http_hint(raw) else _cloud_object_fetch_url(parsed_ref)
        parsed_ref.update({"fetch_url": fetch_url, "fetchable": bool(fetch_url)})
        parsed_ref["metadata"].update({"artifact_platform": "gcs", "artifact_bucket": bucket, "artifact_path": key, "storage_provider": "gcs", "artifact_fetch_url": fetch_url})
        if parsed.scheme in {"gs", "gcs"}:
            warnings.append("GCS object refs are fetched anonymously through storage.googleapis.com; private objects need a signed HTTPS URL.")

    elif kind in {"azure", "azure_blob"}:
        account = metadata.get("artifact_account") or metadata.get("azure_account") or metadata.get("storage_account")
        container = parsed.netloc
        blob_path = parsed.path.lstrip("/")
        host = _normalized_hostname(parsed)
        if parsed.scheme in {"http", "https"} and _is_azure_blob_hostname(host):
            account = host.removesuffix(".blob.core.windows.net")
            parts = [part for part in parsed.path.split("/") if part]
            container = parts[0] if parts else ""
            blob_path = "/".join(parts[1:])
        elif parsed.scheme == "azure":
            parts = [part for part in parsed.path.split("/") if part]
            if not account and parsed.netloc and parts:
                account = parsed.netloc
                container = parts[0]
                blob_path = "/".join(parts[1:])
        parsed_ref.update({"kind": "azure_blob", "registry": account or "azure-blob", "repository": container or None, "path": blob_path or None, "account": account, "container": container or None, "blob_path": blob_path or None})
        fetch_url = raw if _signed_http_hint(raw) else _cloud_object_fetch_url(parsed_ref)
        parsed_ref.update({"fetch_url": fetch_url, "fetchable": bool(fetch_url)})
        parsed_ref["metadata"].update({"artifact_platform": "azure_blob", "artifact_account": account, "artifact_container": container, "artifact_path": blob_path, "storage_provider": "azure_blob", "artifact_fetch_url": fetch_url})
        if parsed.scheme == "azure" and fetch_url:
            warnings.append("Azure Blob refs are fetched anonymously through blob.core.windows.net; private blobs need a signed HTTPS URL.")
        elif parsed.scheme == "azure":
            warnings.append("Azure Blob refs need an account, container, and blob path, or use a signed HTTPS URL.")

    elif kind == "oci":
        image_ref = raw.removeprefix("oci://")
        registry, _, repository = image_ref.partition("/")
        repository, tag, digest = _split_tag_digest(repository or image_ref)
        fetch_url = None
        try:
            fetch_url = _registry_gateway_fetch_url(raw, metadata)
        except ValueError as exc:
            warnings.append(str(exc))
        parsed_ref.update({"registry": registry or None, "repository": repository or None, "path": repository or None, "tag": tag, "digest": digest, "fetch_url": fetch_url, "fetchable": bool(fetch_url)})
        parsed_ref["metadata"].update({"oci_registry": registry, "oci_repository": repository, "oci_tag": tag, "digest": digest})
        if not fetch_url:
            warnings.append("OCI intake requires a bound immutable HTTPS export URL for artifact acquisition.")
        if tag and not digest:
            warnings.append("OCI reference is tag-based. Pin to a digest before production approval.")
        if not tag and not digest:
            warnings.append("OCI reference is missing a tag or digest.")

    elif kind == "mlflow":
        model_name = None
        model_stage = None
        run_id = None
        artifact_path = None
        if raw.startswith("models:/"):
            parts = [part for part in raw.removeprefix("models:/").split("/") if part]
            model_name = parts[0] if parts else None
            model_stage = "/".join(parts[1:]) if len(parts) > 1 else None
        elif raw.startswith("runs:/"):
            parts = [part for part in raw.removeprefix("runs:/").split("/") if part]
            run_id = parts[0] if parts else None
            artifact_path = "/".join(parts[1:]) if len(parts) > 1 else None
        fetch_url = None
        try:
            fetch_url = _registry_gateway_fetch_url(raw, metadata)
        except ValueError as exc:
            warnings.append(str(exc))
        parsed_ref.update({"registry": "mlflow", "repository": model_name or run_id, "path": artifact_path or model_stage, "model_name": model_name, "stage": model_stage, "run_id": run_id, "fetch_url": fetch_url, "fetchable": bool(fetch_url)})
        parsed_ref["metadata"].update({"mlflow_model_name": model_name, "mlflow_stage": model_stage, "mlflow_run_id": run_id, "artifact_path": artifact_path})
        if not fetch_url:
            warnings.append("MLflow intake requires a bound immutable HTTPS export URL for artifact acquisition.")

    else:
        ext = _artifact_ext(_artifact_name(raw))
        parsed_ref["extension"] = ext
        parsed_ref["metadata"].update({"artifact_platform": "http" if parsed.scheme in {"http", "https"} else kind})

    extension = _artifact_ext(parsed_ref.get("path") or _artifact_name(raw))
    parsed_ref["extension"] = extension
    if extension in RISKY_EXTENSIONS:
        warnings.append("Artifact extension is pickle-like or framework-serialized and should be reviewed before deployment.")
    parsed_ref["format_posture"] = "safer_static_format" if extension in SAFER_MODEL_EXTENSIONS else "unsafe_or_review_required" if extension in RISKY_EXTENSIONS else "unknown_or_unclassified_format"
    parsed_ref["adapter"] = _adapter_capabilities(str(parsed_ref.get("kind") or kind))
    return parsed_ref


def _severity_score(severity: str) -> int:
    return {"critical": 30, "high": 20, "medium": 10, "low": 3, "info": 0}.get(severity, 0)


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    description: str,
    artifact_ref: str,
    evidence: dict[str, Any],
    remediation: str,
) -> dict[str, Any]:
    return {
        "id": f"model_intake:{finding_id}",
        "title": title,
        "description": description,
        "severity": severity,
        "tool": "model_intake",
        "cwe": "CWE-494",
        "cwe_name": "Download of Code Without Integrity Check",
        "owasp": "LLM05:2025",
        "url": artifact_ref,
        "evidence": {
            **evidence,
            "remediation": remediation,
        },
        "remediation": remediation,
    }


def _intake_decision(
    findings: list[dict[str, Any]],
    *,
    intake_mode: str = "admission",
) -> dict[str, Any]:
    preflight = str(intake_mode or "").strip().lower() == "preflight"
    if not findings:
        if preflight:
            return {
                "decision": "review",
                "decision_reason": "Preflight completed without findings; run server-governed admission before deployment.",
            }
        return {
            "decision": "allow",
            "decision_reason": "No model-intake findings were detected.",
        }
    severities = {str(finding.get("severity") or "").lower() for finding in findings}
    if severities & {"critical", "high"}:
        return {
            "decision": "block",
            "decision_reason": "One or more critical/high model-intake findings require blocking deployment.",
        }
    if not (severities - {"", "info", "low"}):
        if preflight:
            return {
                "decision": "review",
                "decision_reason": "Preflight is non-admissible; run server-governed admission before deployment.",
            }
        return {
            "decision": "allow",
            "decision_reason": "Only advisory low/info model-intake findings were detected.",
        }
    return {
        "decision": "review",
        "decision_reason": "Model-intake findings require review before deployment approval.",
    }


def _corporate_use_assessment(
    *,
    findings: list[dict[str, Any]],
    decision: dict[str, Any],
    intake_mode: str,
    acquisition_complete: bool,
    checksum_status: str,
    generated_evidence: dict[str, Any],
    dynamic_sandbox: dict[str, Any],
    generated_evaluation: dict[str, Any],
    signature_status: dict[str, Any],
    attestation_verification: dict[str, Any],
    deployment_approved: bool,
    custom_code_required: bool,
) -> dict[str, Any]:
    scanner_results = generated_evidence.get("results") if isinstance(generated_evidence.get("results"), list) else []
    scanner_statuses = {
        str(item.get("scanner", {}).get("name") or "unknown"): str(item.get("execution", {}).get("status") or "NOT_RUN")
        for item in scanner_results if isinstance(item, dict)
    }
    pickle_result = next(
        (item for item in scanner_results if item.get("scanner", {}).get("name") == "python-pickletools"),
        {},
    )
    pickle_classification = str(pickle_result.get("summary", {}).get("semantic_classification") or "not_run")
    finding_ids = {str(item.get("id") or "") for item in findings}
    proven_malicious = (
        pickle_classification == "dangerous_callable_detected"
        or scanner_statuses.get("modelscan") == "FAIL"
        or "model_intake:sha256_mismatch" in finding_ids
    )
    serialization_finding = next((item for item in findings if item.get("id") == "model_intake:unsafe_serialization"), None)
    controls: list[dict[str, Any]] = []

    def control(identifier: str, label: str, status: str, detail: str) -> None:
        controls.append({"id": identifier, "label": label, "status": status, "detail": detail})

    control(
        "complete_acquisition", "Complete immutable acquisition",
        "PASS" if acquisition_complete else "FAIL",
        "The complete subject was acquired and digest-bound." if acquisition_complete else "Only a partial or incomplete subject was inspected.",
    )
    control(
        "integrity", "Artifact integrity",
        "PASS" if checksum_status == "verified" else "FAIL" if checksum_status == "mismatch" else "INDETERMINATE",
        f"Checksum status: {checksum_status}.",
    )
    pickle_status = scanner_statuses.get("python-pickletools")
    modelscan_status = scanner_statuses.get("modelscan")
    malicious_primitive_coverage_complete = (
        pickle_classification == "expected_framework_pickle"
        and pickle_status == "PASS"
        and modelscan_status in {"PASS", "NOT_APPLICABLE"}
    ) or (
        not serialization_finding
        and pickle_status == "NOT_APPLICABLE"
        and modelscan_status in {"PASS", "NOT_APPLICABLE"}
    )
    control(
        "malicious_primitives", "Known malicious serialization primitives",
        "FAIL" if proven_malicious else "PASS" if malicious_primitive_coverage_complete else "INDETERMINATE",
        (
            "A dangerous callable, known malicious primitive, or digest mismatch was proven."
            if proven_malicious
            else "No known malicious callable was proven; executable-format capability is assessed separately."
            if pickle_classification == "expected_framework_pickle"
            else "No executable serialization was detected and the applicable malicious-primitive scanners completed."
            if malicious_primitive_coverage_complete and not serialization_finding
            else "Semantic malicious-primitive coverage is incomplete."
        ),
    )
    control(
        "serialization_policy", "Corporate serialization policy",
        "FAIL" if serialization_finding else "PASS",
        str(serialization_finding.get("description") if serialization_finding else "No executable-capable model serialization was detected."),
    )
    semgrep_status = scanner_statuses.get("semgrep", "NOT_APPLICABLE" if not custom_code_required else "NOT_RUN")
    control(
        "repository_code", "Custom repository code",
        "NOT_APPLICABLE" if not custom_code_required else "FAIL" if semgrep_status == "FAIL" else "REVIEW" if semgrep_status == "WARNING" else "PASS" if semgrep_status == "PASS" else "INDETERMINATE",
        f"Semgrep status: {semgrep_status}; custom code still requires a recorded human ownership/review decision." if custom_code_required else "The repository manifest did not require custom executable code.",
    )
    dependency_status = scanner_statuses.get("trivy")
    control(
        "dependencies", "Dependency and CVE review",
        "PASS" if dependency_status == "PASS" else "FAIL" if dependency_status == "FAIL" or (custom_code_required and dependency_status in {None, "NOT_APPLICABLE"}) else "NOT_APPLICABLE" if dependency_status == "NOT_APPLICABLE" else "INDETERMINATE",
        (
            "Custom executable code has no dependency manifest/runtime inventory, so CVE coverage is incomplete."
            if custom_code_required and dependency_status in {None, "NOT_APPLICABLE"}
            else f"Dependency scanner status: {dependency_status or 'NOT_RUN'}."
        ),
    )
    sandbox_status = str(dynamic_sandbox.get("status") or "NOT_RUN")
    runtime = dynamic_sandbox.get("inspection", {}).get("runtime") if isinstance(dynamic_sandbox.get("inspection"), dict) else {}
    load_level = str((runtime or {}).get("load_level") or "none")
    control(
        "isolated_runtime", "No-egress isolated runtime",
        "PASS" if sandbox_status == "PASS" else "FAIL" if sandbox_status in {"FAIL", "BLOCKED_BY_POLICY"} else "INDETERMINATE",
        f"Sandbox status: {sandbox_status}; proven load level: {load_level}.",
    )
    security_eval_status = str(generated_evaluation.get("security_status") or generated_evaluation.get("status") or "NOT_RUN")
    quality_status = str(generated_evaluation.get("quality_status") or "NOT_MEASURED")
    control("security_evaluation", "Embedding and data-plane security evaluation", security_eval_status, "Covers digest binding, ACL leakage, poisoning, stability, graph boundaries, deletion, and cache authorization.")
    control("retrieval_quality", "Organization-specific retrieval quality", quality_status, "Recall, latency, memory, and corpus relevance are a separate organizational acceptance decision.")
    control(
        "publisher_trust", "Publisher signature and provenance",
        "PASS" if signature_status.get("verified") and attestation_verification.get("verified") else "FAIL",
        f"Signature: {signature_status.get('status')}; attestation: {attestation_verification.get('status')}.",
    )
    control(
        "deployment_approval", "Recorded deployment approval",
        "PASS" if deployment_approved else "FAIL",
        "A recorded corporate owner approved this exact subject." if deployment_approved else "Corporate deployment approval is missing.",
    )

    raw_decision = str(decision.get("decision") or "review")
    if proven_malicious:
        verdict = "REJECT"
    elif intake_mode == "preflight":
        verdict = "PREFLIGHT_ONLY"
    elif raw_decision == "allow":
        verdict = "APPROVED"
    elif raw_decision == "block":
        verdict = "NOT_APPROVED"
    else:
        verdict = "REVIEW_REQUIRED"
    blocking_findings = [
        {
            "id": item.get("id"),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "remediation": item.get("remediation") or item.get("evidence", {}).get("remediation"),
        }
        for item in findings if str(item.get("severity") or "").lower() in {"critical", "high"}
    ]
    action_findings = blocking_findings or [
        {
            "remediation": item.get("remediation") or item.get("evidence", {}).get("remediation"),
        }
        for item in findings
        if str(item.get("severity") or "").lower() in {"medium", "low"}
    ]
    next_actions = list(dict.fromkeys(
        str(item.get("remediation") or "").strip()
        for item in action_findings
        if str(item.get("remediation") or "").strip()
    ))
    return {
        "schema_version": "model-intake-corporate-use/v1",
        "verdict": verdict,
        "can_use_in_corporate_environment": verdict == "APPROVED",
        "admission_mode": intake_mode,
        "decision": raw_decision,
        "plain_language": (
            "Approved for corporate use under the recorded policy and exact artifact digest."
            if verdict == "APPROVED"
            else "Reject this artifact: a malicious primitive or integrity failure was proven."
            if verdict == "REJECT"
            else "This was only a preflight and cannot approve corporate use."
            if verdict == "PREFLIGHT_ONLY"
            else "Do not deploy yet; resolve the failed controls and rerun admission."
        ),
        "controls": controls,
        "control_counts": {
            status: sum(1 for item in controls if item["status"] == status)
            for status in ("PASS", "FAIL", "REVIEW", "INDETERMINATE", "NOT_APPLICABLE", "NOT_MEASURED", "WARNING")
        },
        "malicious_primitive_proven": proven_malicious,
        "pickle_semantic_classification": pickle_classification,
        "primary_blockers": blocking_findings[:20],
        "next_actions": next_actions[:20],
        "limitations": list(dict.fromkeys([
            *(["custom_model_code_not_executed"] if load_level == "weights" else []),
            *(["embedding_known_answers_not_executed"] if load_level != "model" else []),
            *(["retrieval_quality_not_organization_approved"] if quality_status not in {"PASS"} else []),
        ])),
    }


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


_MODEL_INTAKE_ACTIVITY_FIELDS = (
    "source_kind",
    "status",
    "source",
    "bytes_observed",
    "bytes_total",
    "complete",
    "truncated",
    "files_expected",
    "files_acquired",
    "generated_scanners",
    "sandbox",
    "signature",
    "attestation",
    "evaluation",
    "checksum",
    "admission",
    "decision",
    "findings_count",
)


def _model_intake_activity_record(
    *,
    phase: str,
    progress: int,
    **details: Any,
) -> dict[str, Any]:
    """Build a content-free, UI-safe activity record for durable/live logs."""
    normalized: dict[str, Any] = {
        "phase": re.sub(r"[^a-z0-9_]+", "_", str(phase).strip().lower())[:64] or "model_intake",
        "progress": max(0, min(100, int(progress))),
    }
    for key in _MODEL_INTAKE_ACTIVITY_FIELDS:
        value = details.get(key)
        if value is None or isinstance(value, (dict, list, tuple, set)):
            continue
        if isinstance(value, bool):
            normalized[key] = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            normalized[key] = value
        else:
            normalized[key] = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(value).strip())[:120]
    tokens = [
        "[model-intake]",
        f"phase={normalized['phase']}",
        f"progress={normalized['progress']}",
    ]
    for key in _MODEL_INTAKE_ACTIVITY_FIELDS:
        if key not in normalized:
            continue
        value = normalized[key]
        if isinstance(value, bool):
            value = str(value).lower()
        tokens.append(f"{key}={value}")
    normalized["line"] = " ".join(tokens)
    return normalized


async def _emit_model_intake_activity(
    activity: list[dict[str, Any]],
    callback: Any,
    *,
    phase: str,
    progress: int,
    **details: Any,
) -> None:
    record = _model_intake_activity_record(phase=phase, progress=progress, **details)
    activity.append(record)
    if callback is None:
        return
    try:
        callback_result = callback(dict(record))
        if asyncio.iscoroutine(callback_result):
            await callback_result
    except Exception:
        # Operational logging must never change the security decision or make a
        # completed intake fail. The durable activity record remains in result.
        return


def _read_local(path_ref: str, max_bytes: int) -> tuple[bytes, dict[str, Any]]:
    parsed = urllib.parse.urlparse(path_ref)
    path = urllib.request.url2pathname(parsed.path) if parsed.scheme == "file" else path_ref
    p = Path(path)
    with p.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    total_size = p.stat().st_size
    return data[:max_bytes], {
        "source": "local_file",
        "bytes_observed": min(len(data), max_bytes),
        "bytes_total": total_size,
        "truncated": total_size > max_bytes,
    }


def _parse_content_range(value: str | None) -> dict[str, int | None] | None:
    if not value:
        return None
    match = re.match(r"^\s*bytes\s+(\d+)-(\d+)/(\d+|\*)\s*$", value, flags=re.IGNORECASE)
    if not match:
        return None
    total = None if match.group(3) == "*" else int(match.group(3))
    return {
        "start": int(match.group(1)),
        "end": int(match.group(2)),
        "total": total,
    }


def _artifact_size_for_inspection(
    artifact_meta: dict[str, Any],
    metadata: dict[str, Any],
    artifact_bytes: bytes,
    *,
    truncated: bool,
) -> tuple[int | None, str | None]:
    candidates: list[tuple[Any, str]] = [
        (artifact_meta.get("bytes_total"), "fetch.bytes_total"),
    ]
    content_range = _parse_content_range(str(artifact_meta.get("content_range") or ""))
    if content_range:
        candidates.append((content_range.get("total"), "fetch.content_range"))
    if not truncated:
        candidates.append((len(artifact_bytes), "observed_complete_artifact"))
    candidates.append((metadata.get("artifact_size_bytes"), "metadata.artifact_size_bytes"))

    for raw_size, source in candidates:
        if isinstance(raw_size, bool):
            continue
        try:
            size = int(raw_size)
        except (TypeError, ValueError):
            continue
        if size > 0:
            return size, source
    return None, None


def _download_http(
    url: str,
    max_bytes: int,
    timeout_seconds: int,
    headers: dict[str, str] | None = None,
    fetch_policy: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    data, meta = _safe_download_http(
        url,
        max_bytes,
        timeout_seconds,
        headers=headers,
        policy=fetch_policy,
    )
    content_range = _parse_content_range(str(meta.get("content_range") or ""))
    if content_range:
        total = content_range.get("total")
        meta["truncated"] = total is None or int(content_range["end"]) + 1 < int(total)
    return data, meta


def _download_huggingface(
    ref: str,
    metadata: dict[str, Any],
    max_bytes: int,
    timeout_seconds: int,
    fetch_policy: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    hf_ref = parse_huggingface_ref(ref, metadata)
    if not hf_ref.get("repo_id"):
        return b"", {
            "source": "huggingface",
            "bytes_observed": 0,
            "huggingface": hf_ref,
            "error": "Hugging Face reference must include a model repository.",
        }
    if not hf_ref.get("filename"):
        return b"", {
            "source": "huggingface",
            "bytes_observed": 0,
            "huggingface": hf_ref,
            "error": "Hugging Face reference must identify an artifact file. Use the resolver to choose one.",
        }

    auth_headers: dict[str, str] = {}
    metadata_token = str(metadata.get("hf_token") or "").strip()
    env_token = str(os.getenv("HF_TOKEN") or "").strip()
    token = metadata_token or env_token
    auth_source = "metadata" if metadata_token else "env" if env_token else None
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"
    if fetch_policy is None:
        data, fetch_meta = _download_http(str(hf_ref["resolve_url"]), max_bytes, timeout_seconds, auth_headers)
    else:
        data, fetch_meta = _download_http(
            str(hf_ref["resolve_url"]), max_bytes, timeout_seconds, auth_headers, fetch_policy
        )
    return data, {
        **fetch_meta,
        "source": "huggingface",
        "huggingface": hf_ref,
        "authenticated": bool(token),
        "auth_source": auth_source,
    }


def _download_huggingface_complete(
    ref: str,
    metadata: dict[str, Any],
    inspection_bytes: int,
    max_artifact_bytes: int,
    timeout_seconds: int,
    quarantine_dir: Path,
    fetch_policy: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    hf_ref = parse_huggingface_ref(ref, metadata)
    if not hf_ref.get("repo_id") or not hf_ref.get("filename"):
        return b"", {
            "source": "huggingface",
            "bytes_observed": 0,
            "huggingface": hf_ref,
            "error": "Hugging Face reference must identify a repository and artifact file.",
        }
    metadata_token = str(metadata.get("hf_token") or "").strip()
    env_token = str(os.getenv("HF_TOKEN") or "").strip()
    token = metadata_token or env_token
    auth_headers = {"Authorization": f"Bearer {token}"} if token else None
    data, fetch_meta = _safe_download_http_to_quarantine(
        str(hf_ref["resolve_url"]),
        inspection_bytes,
        max_artifact_bytes,
        timeout_seconds,
        quarantine_dir,
        headers=auth_headers,
        policy=fetch_policy,
    )
    return data, {
        **fetch_meta,
        "source": "huggingface",
        "huggingface": hf_ref,
        "authenticated": bool(token),
        "auth_source": "metadata" if metadata_token else "env" if env_token else None,
    }


async def _acquire_huggingface_repository_snapshot(
    metadata: dict[str, Any],
    *,
    artifact_ref: str | None = None,
    timeout_seconds: int,
    quarantine_dir: Path,
    fetch_policy: dict[str, Any] | None,
    max_repository_bytes: int,
    max_repository_files: int,
    selected_artifact_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Acquire every file in a pinned Hugging Face manifest into quarantine."""
    declared = metadata.get("repository_manifest") if isinstance(metadata.get("repository_manifest"), dict) else {}
    hf_ref = parse_huggingface_ref(artifact_ref or "", metadata)
    repo_id = str(hf_ref.get("repo_id") or metadata.get("huggingface_repo") or "").strip()
    revision = str(hf_ref.get("revision") or metadata.get("revision") or "").strip()
    if not repo_id or not re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", repo_id):
        return {"status": "INCOMPLETE", "complete": False, "error": "invalid_huggingface_repository"}
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", revision):
        return {"status": "INCOMPLETE", "complete": False, "error": "repository_revision_not_immutable"}
    try:
        authoritative = await _fetch_authoritative_huggingface_manifest(
            repo_id,
            revision,
            timeout_seconds=timeout_seconds,
            fetch_policy=fetch_policy,
            max_repository_files=max_repository_files,
            metadata=metadata,
        )
    except Exception as exc:
        return {
            "status": "INCOMPLETE",
            "complete": False,
            "error": f"authoritative_manifest_fetch_failed:{type(exc).__name__}:{exc}",
        }
    files = authoritative.get("files") if isinstance(authoritative.get("files"), list) else []
    if not authoritative.get("complete"):
        return {
            "status": "INCOMPLETE",
            "complete": False,
            "error": "authoritative_manifest_incomplete",
            "repository_manifest": authoritative,
        }
    declared_manifest_sha256 = str(declared.get("manifest_sha256") or "").strip().lower()
    authoritative_manifest_sha256 = str(authoritative.get("manifest_sha256") or "").strip().lower()
    if declared_manifest_sha256 and declared_manifest_sha256 != authoritative_manifest_sha256:
        return {
            "schema_version": "model-intake-repository-snapshot/v1",
            "status": "INCOMPLETE",
            "complete": False,
            "error": "declared_manifest_does_not_match_authoritative_manifest",
            "declared_manifest_sha256": declared_manifest_sha256,
            "authoritative_manifest_sha256": authoritative_manifest_sha256,
            "repository_manifest": authoritative,
        }
    if len(files) > max_repository_files:
        return {
            "status": "INCOMPLETE",
            "complete": False,
            "error": "repository_file_limit_exceeded",
            "files_discovered": len(files),
            "file_limit": max_repository_files,
        }
    declared_bytes = sum(int(item.get("size_bytes") or 0) for item in files if isinstance(item, dict))
    if declared_bytes > max_repository_bytes:
        return {
            "status": "INCOMPLETE",
            "complete": False,
            "error": "repository_byte_limit_exceeded",
            "declared_bytes": declared_bytes,
            "byte_limit": max_repository_bytes,
        }

    metadata_token = str(metadata.get("hf_token") or "").strip()
    env_token = str(os.getenv("HF_TOKEN") or "").strip()
    token = metadata_token or env_token
    auth_headers = {"Authorization": f"Bearer {token}"} if token else None
    selected_path = str(metadata.get("huggingface_file") or "").strip()
    selected_artifact_meta = selected_artifact_meta or {}
    acquired: list[dict[str, Any]] = []
    total_bytes = 0
    failures: list[dict[str, Any]] = []
    embedding_hints: dict[str, Any] = {}

    for item in files:
        if not isinstance(item, dict):
            failures.append({"path": None, "error": "invalid_manifest_file_record"})
            break
        path = str(item.get("path") or "").strip()
        if not path:
            failures.append({"path": None, "error": "missing_manifest_path"})
            break
        observed: dict[str, Any]
        can_reuse_selected = (
            path == selected_path
            and selected_artifact_meta.get("complete") is True
            and selected_artifact_meta.get("sha256")
            and selected_artifact_meta.get("quarantine_object")
        )
        if can_reuse_selected:
            observed = selected_artifact_meta
        else:
            remaining = max_repository_bytes - total_bytes
            if remaining <= 0:
                failures.append({"path": path, "error": "repository_byte_limit_exceeded"})
                break
            resolve_url = (
                f"https://huggingface.co/{urllib.parse.quote(repo_id, safe='/')}/resolve/"
                f"{urllib.parse.quote(revision, safe='')}/{urllib.parse.quote(path, safe='/')}"
            )
            try:
                prefix, observed = await asyncio.to_thread(
                    _safe_download_http_to_quarantine,
                    resolve_url,
                    min(1_048_576, remaining),
                    remaining,
                    timeout_seconds,
                    quarantine_dir,
                    auth_headers,
                    fetch_policy,
                )
            except Exception as exc:
                failures.append({"path": path, "error": f"{type(exc).__name__}: {exc}"})
                break
            embedding_hints = merge_embedding_configuration_hints(
                embedding_hints, collect_embedding_configuration_hints(path, prefix)
            )
        observed_sha = str(observed.get("sha256") or "").lower()
        expected_sha = str(item.get("sha256") or "").lower()
        if expected_sha and observed_sha != expected_sha:
            failures.append({
                "path": path,
                "error": "sha256_mismatch",
                "expected_sha256": expected_sha,
                "observed_sha256": observed_sha,
            })
            break
        size = int(observed.get("bytes_total") or observed.get("bytes_observed") or 0)
        total_bytes += size
        if total_bytes > max_repository_bytes:
            failures.append({"path": path, "error": "repository_byte_limit_exceeded"})
            break
        acquired.append({
            "path": path,
            "size_bytes": size,
            "sha256": observed_sha,
            "quarantine_object": observed.get("quarantine_object"),
            "declared_sha256": expected_sha or None,
            "declared_blob_id": item.get("blob_id"),
            "categories": item.get("categories") or [],
        })

    canonical = {
        "provider": "huggingface",
        "repository": repo_id,
        "revision": revision,
        "files": [
            {"path": item["path"], "size_bytes": item["size_bytes"], "sha256": item["sha256"]}
            for item in sorted(acquired, key=lambda value: value["path"])
        ],
    }
    snapshot_sha256 = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    complete = not failures and len(acquired) == len(files)
    return {
        "schema_version": "model-intake-repository-snapshot/v1",
        "status": "PASS" if complete else "INCOMPLETE",
        "complete": complete,
        "repository": repo_id,
        "revision": revision,
        "declared_manifest_sha256": declared.get("manifest_sha256"),
        "authoritative_manifest_sha256": authoritative.get("manifest_sha256"),
        "repository_manifest": authoritative,
        "snapshot_sha256": snapshot_sha256,
        "files_expected": len(files),
        "files_acquired": len(acquired),
        "bytes_acquired": total_bytes,
        "byte_limit": max_repository_bytes,
        "file_limit": max_repository_files,
        "authenticated": bool(token),
        "failures": failures[:20],
        "files": acquired,
        "embedding_configuration_hints": embedding_hints,
    }


def _normalize_huggingface_manifest(
    model_info: dict[str, Any],
    repo_id: str,
    revision: str,
    *,
    max_repository_files: int,
) -> dict[str, Any]:
    if str(model_info.get("sha") or "").lower() != revision.lower():
        raise ValueError("resolved_revision_does_not_match_requested_revision")
    siblings = model_info.get("siblings") if isinstance(model_info.get("siblings"), list) else []
    files: list[dict[str, Any]] = []
    invalid_paths: list[dict[str, str]] = []
    duplicate_paths: list[str] = []
    case_collisions: list[list[str]] = []
    seen: set[str] = set()
    seen_case: dict[str, str] = {}
    for sibling in siblings[:max_repository_files]:
        if not isinstance(sibling, dict):
            invalid_paths.append({"path": "", "reason": "invalid_file_record"})
            continue
        path = str(sibling.get("rfilename") or sibling.get("path") or "")
        parts = path.split("/")
        if (
            not path
            or "\x00" in path
            or "\\" in path
            or path.startswith("/")
            or re.match(r"^[A-Za-z]:", path)
            or any(part in {"", ".", ".."} for part in parts)
        ):
            invalid_paths.append({"path": path[:512], "reason": "unsafe_or_non_normalized_path"})
            continue
        if path in seen:
            duplicate_paths.append(path)
            continue
        folded = path.casefold()
        if folded in seen_case and seen_case[folded] != path:
            case_collisions.append([seen_case[folded], path])
        else:
            seen_case[folded] = path
        seen.add(path)
        lfs = sibling.get("lfs") if isinstance(sibling.get("lfs"), dict) else {}
        extension = Path(path).suffix.lower()
        categories = []
        if extension == ".py":
            categories.append("python_source")
        if extension in EXECUTABLE_EXTENSIONS:
            categories.append("executable")
        files.append({
            "path": path,
            "size_bytes": sibling.get("size") or lfs.get("size"),
            "sha256": lfs.get("sha256"),
            "blob_id": sibling.get("blobId"),
            "categories": categories or ["other"],
        })
    files.sort(key=lambda item: item["path"])
    canonical = {
        "provider": "huggingface",
        "repository": repo_id,
        "revision": revision,
        "files": [
            {key: item.get(key) for key in ("path", "size_bytes", "sha256", "blob_id") if item.get(key) not in (None, "")}
            for item in files
        ],
    }
    manifest_sha256 = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    config = model_info.get("config") if isinstance(model_info.get("config"), dict) else {}
    tags = model_info.get("tags") if isinstance(model_info.get("tags"), list) else []
    python_files = [item["path"] for item in files if "python_source" in item["categories"]]
    executable_files = [item["path"] for item in files if "executable" in item["categories"]]
    complete = (
        bool(siblings)
        and len(siblings) <= max_repository_files
        and len(files) + len(invalid_paths) + len(duplicate_paths) == len(siblings)
        and not invalid_paths
        and not duplicate_paths
        and not case_collisions
    )
    return {
        "schema_version": "model-intake-repository-manifest/v1",
        "provenance_class": "shakerscan_generated",
        "provider": "huggingface",
        "repository": repo_id,
        "revision": revision,
        "manifest_sha256": manifest_sha256,
        "complete": complete,
        "files_discovered": len(siblings),
        "files_recorded": len(files),
        "truncated_by_limit": len(siblings) > max_repository_files,
        "invalid_paths": invalid_paths[:100],
        "duplicate_paths": duplicate_paths[:100],
        "case_collisions": case_collisions[:100],
        "python_files": python_files,
        "executable_files": executable_files,
        "auto_map": config.get("auto_map"),
        "custom_code_required": bool(config.get("auto_map") or python_files or "custom_code" in tags),
        "files": files,
    }


async def _fetch_authoritative_huggingface_manifest(
    repo_id: str,
    revision: str,
    *,
    timeout_seconds: int,
    fetch_policy: dict[str, Any] | None,
    max_repository_files: int,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    url = (
        f"https://huggingface.co/api/models/{urllib.parse.quote(repo_id, safe='/')}"
        f"/revision/{urllib.parse.quote(revision, safe='')}?blobs=true"
    )
    token = str(metadata.get("hf_token") or os.getenv("HF_TOKEN") or "").strip()
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    raw, fetch_meta = await asyncio.to_thread(
        _download_http,
        url,
        20_000_000,
        timeout_seconds,
        headers,
        fetch_policy,
    )
    if fetch_meta.get("truncated"):
        raise ValueError("authoritative_manifest_response_truncated")
    model_info = json.loads(raw.decode("utf-8"))
    if not isinstance(model_info, dict):
        raise ValueError("authoritative_manifest_response_not_object")
    return _normalize_huggingface_manifest(
        model_info,
        repo_id,
        revision,
        max_repository_files=max_repository_files,
    )


def _contained_snapshot_path(subject_root: Path, selected_path: Any) -> Path:
    root = subject_root.resolve()
    candidate = (subject_root / str(selected_path or "")).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("selected_artifact_path_escapes_snapshot")
    return candidate


def _download_cloud_object(
    ref: str,
    metadata: dict[str, Any],
    max_bytes: int,
    timeout_seconds: int,
    fetch_policy: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    cloud_ref = normalize_model_artifact_reference(ref, metadata)
    fetch_url = cloud_ref.get("fetch_url")
    if not fetch_url:
        return b"", {
            "source": cloud_ref.get("kind") or urllib.parse.urlparse(ref).scheme,
            "bytes_observed": 0,
            "cloud": cloud_ref,
            "error": "Cloud object reference could not be converted to a fetchable HTTPS URL.",
        }
    if fetch_policy is None:
        data, fetch_meta = _download_http(str(fetch_url), max_bytes, timeout_seconds)
    else:
        data, fetch_meta = _download_http(str(fetch_url), max_bytes, timeout_seconds, None, fetch_policy)
    return data, {
        **fetch_meta,
        "source": cloud_ref.get("kind") or fetch_meta.get("source") or "cloud_object",
        "fetch_url": fetch_url,
        "cloud": cloud_ref,
    }


def _runtime_destination(
    label: str,
    configured_url: Any,
    fetch_meta: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    url = str(configured_url or "").strip()
    meta = fetch_meta if isinstance(fetch_meta, dict) else {}
    requested_url = str(meta.get("requested_url") or meta.get("fetch_url") or meta.get("url") or url).strip()
    final_url = str(meta.get("final_url") or requested_url or url).strip()
    if not requested_url and not final_url:
        return None
    record: dict[str, Any] = {
        "label": label,
        "url": requested_url or final_url,
    }
    if final_url:
        record["final_url"] = final_url
    if meta.get("status") is not None:
        record["status"] = meta.get("status")
    if meta.get("source"):
        record["source"] = meta.get("source")
    if meta.get("redirected") is not None:
        record["redirected"] = bool(meta.get("redirected"))
    if isinstance(meta.get("redirect_chain"), list):
        record["redirect_chain"] = meta.get("redirect_chain")
    if meta.get("remote_ip"):
        record["remote_ip"] = meta.get("remote_ip")
        record["resolved_host"] = urllib.parse.urlparse(final_url or requested_url).hostname
    return redact_model_intake_value(record)


def _registry_gateway_fetch_url(ref: str, metadata: dict[str, Any] | None) -> str | None:
    """Resolve provider exports without trusting an unbound caller URL."""
    values = metadata if isinstance(metadata, dict) else {}
    fetch_url = str(values.get("artifact_fetch_url") or values.get("registry_export_url") or "").strip()
    if not fetch_url:
        return None
    if str(values.get("artifact_fetch_subject") or "").strip() != ref:
        raise ValueError("Registry gateway export must bind artifact_fetch_subject to the exact model reference")
    expected = str(values.get("expected_sha256") or values.get("artifact_fetch_sha256") or values.get("sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Registry gateway export requires an expected SHA-256")
    parsed = urllib.parse.urlparse(fetch_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Registry gateway export must use an absolute HTTPS URL")
    return fetch_url


async def _fetch_artifact(
    ref: str,
    max_bytes: int,
    timeout_seconds: int,
    metadata: dict[str, Any] | None = None,
    allow_local_files: bool = False,
    fetch_policy: dict[str, Any] | None = None,
    complete_download: bool = False,
    max_artifact_bytes: int | None = None,
    quarantine_dir: Path | None = None,
) -> tuple[bytes, dict[str, Any]]:
    parsed = urllib.parse.urlparse(ref)
    parsed_host = (parsed.hostname or "").lower().rstrip(".")
    try:
        if complete_download:
            if not quarantine_dir:
                raise ValueError("Complete model acquisition requires a quarantine directory")
            complete_limit = int(max_artifact_bytes or max_bytes)
            if parsed.scheme == "hf" or (
                parsed.scheme in {"http", "https"}
                and (parsed_host == "huggingface.co" or parsed_host.endswith(".huggingface.co"))
            ):
                return await asyncio.to_thread(
                    _download_huggingface_complete,
                    ref,
                    metadata or {},
                    max_bytes,
                    complete_limit,
                    timeout_seconds,
                    quarantine_dir,
                    fetch_policy,
                )
            if parsed.scheme in {"s3", "gs", "gcs", "azure"}:
                cloud_ref = normalize_model_artifact_reference(ref, metadata or {})
                fetch_url = cloud_ref.get("fetch_url")
                if not fetch_url:
                    raise ValueError("Cloud object reference could not be converted to a fetchable HTTPS URL")
                data, meta = await asyncio.to_thread(
                    _safe_download_http_to_quarantine,
                    str(fetch_url),
                    max_bytes,
                    complete_limit,
                    timeout_seconds,
                    quarantine_dir,
                    None,
                    fetch_policy,
                )
                return data, {**meta, "source": cloud_ref.get("kind") or "cloud_object", "cloud": cloud_ref}
            if parsed.scheme in {"oci", "mlflow", "models", "runs"}:
                fetch_url = _registry_gateway_fetch_url(ref, metadata)
                if not fetch_url:
                    raise ValueError("Registry reference requires a bound immutable HTTPS export URL")
                data, meta = await asyncio.to_thread(
                    _safe_download_http_to_quarantine,
                    fetch_url,
                    max_bytes,
                    complete_limit,
                    timeout_seconds,
                    quarantine_dir,
                    None,
                    fetch_policy,
                )
                return data, {**meta, "source": parsed.scheme, "registry_reference": ref, "fetch_url": fetch_url}
            if parsed.scheme in {"http", "https"}:
                return await asyncio.to_thread(
                    _safe_download_http_to_quarantine,
                    ref,
                    max_bytes,
                    complete_limit,
                    timeout_seconds,
                    quarantine_dir,
                    None,
                    fetch_policy,
                )
            if parsed.scheme == "file" or not parsed.scheme:
                if not allow_local_files:
                    return b"", {
                        "source": "local_file",
                        "bytes_observed": 0,
                        "error": "Local artifact reads are disabled for model intake. Use http(s), hf, or cloud object references, or enable allow_local_files in local development.",
                    }
                local_path = Path(urllib.request.url2pathname(parsed.path) if parsed.scheme == "file" else ref)
                return await asyncio.to_thread(
                    _quarantine_local_file,
                    local_path,
                    quarantine_dir,
                    inspection_bytes=max_bytes,
                    max_artifact_bytes=complete_limit,
                )
        if parsed.scheme == "hf" or (
            parsed.scheme in {"http", "https"}
            and (parsed_host == "huggingface.co" or parsed_host.endswith(".huggingface.co"))
        ):
            return await asyncio.to_thread(
                _download_huggingface, ref, metadata or {}, max_bytes, timeout_seconds, fetch_policy
            )
        if parsed.scheme in {"s3", "gs", "gcs", "azure"}:
            return await asyncio.to_thread(
                _download_cloud_object, ref, metadata or {}, max_bytes, timeout_seconds, fetch_policy
            )
        if parsed.scheme in {"oci", "mlflow", "models", "runs"}:
            fetch_url = _registry_gateway_fetch_url(ref, metadata)
            if not fetch_url:
                raise ValueError("Registry reference requires a bound immutable HTTPS export URL")
            if fetch_policy is None:
                data, meta = await asyncio.to_thread(_download_http, fetch_url, max_bytes, timeout_seconds)
            else:
                data, meta = await asyncio.to_thread(_download_http, fetch_url, max_bytes, timeout_seconds, None, fetch_policy)
            return data, {**meta, "source": parsed.scheme, "registry_reference": ref, "fetch_url": fetch_url}
        if parsed.scheme in ("http", "https"):
            if fetch_policy is None:
                return await asyncio.to_thread(_download_http, ref, max_bytes, timeout_seconds)
            return await asyncio.to_thread(_download_http, ref, max_bytes, timeout_seconds, None, fetch_policy)
        if parsed.scheme == "file" or not parsed.scheme:
            if not allow_local_files:
                return b"", {
                    "source": "local_file",
                    "bytes_observed": 0,
                    "error": "Local artifact reads are disabled for model intake. Use http(s), hf, or cloud object references, or enable allow_local_files in local development.",
                }
            return await asyncio.to_thread(_read_local, ref, max_bytes)
    except Exception as exc:
        return b"", {
            "source": parsed.scheme or "local_file",
            "bytes_observed": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return b"", {
        "source": parsed.scheme,
        "bytes_observed": 0,
        "error": f"Unsupported artifact scheme: {parsed.scheme}",
    }


async def _fetch_json(
    url: str,
    timeout_seconds: int,
    max_bytes: int = 262_144,
    allow_local_files: bool = False,
    fetch_policy: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    data, meta = await _fetch_artifact(
        url,
        max_bytes=max_bytes,
        timeout_seconds=timeout_seconds,
        allow_local_files=allow_local_files,
        fetch_policy=fetch_policy,
    )
    fetch_meta = {**meta, "url": url}
    if fetch_meta.get("error"):
        return {}, fetch_meta
    if not data:
        fetch_meta["error"] = "Empty metadata response"
        return {}, fetch_meta
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fetch_meta["error"] = f"UnicodeDecodeError: {exc}"
        return {}, fetch_meta
    try:
        parsed = json.loads(decoded)
    except json.JSONDecodeError as exc:
        fetch_meta["error"] = f"JSONDecodeError: {exc}"
        return {}, fetch_meta
    if not isinstance(parsed, dict):
        fetch_meta["error"] = f"Metadata JSON root must be an object, got {type(parsed).__name__}"
        return {}, fetch_meta
    fetch_meta["parsed"] = True
    return parsed, fetch_meta


def _pickle_detection(data: bytes, ext: str = "") -> tuple[bool, str | None]:
    if data.startswith(PICKLE_MAGIC_PREFIXES):
        return True, "protocol_magic"
    if ext in SAFER_MODEL_EXTENSIONS or data.startswith(b"PK\x03\x04"):
        return False, None
    # Do not classify arbitrary binary text such as "evaluation" or "execution"
    # as pickle. pickletools disassembles opcodes without importing or executing
    # the payload and also recognizes protocols 0 and 1, which have no magic.
    try:
        for opcode, _argument, _position in pickletools.genops(data):
            if opcode.name == "STOP":
                return True, "pickletools_semantic"
        return False, None
    except Exception:
        sample = data[:65536]
        return (True, "marker_fallback") if any(marker in sample for marker in PICKLE_OPCODE_MARKERS) else (False, None)


def _looks_like_pickle(data: bytes, ext: str = "") -> bool:
    return _pickle_detection(data, ext)[0]


# Embedding facts the controlled deployment bundle requires an operator to
# declare. They are published by the model itself, and the snapshot loop already
# holds these small config files in memory, so reading them here binds the
# suggestion to the exact revision that was scanned. They remain suggestions:
# the operator still confirms the deployment contract.
EMBEDDING_HINT_FILES = {
    "config.json",
    "sentence_bert_config.json",
    "modules.json",
}
MAX_EMBEDDING_HINT_BYTES = 262_144
_POOLING_MODES = (
    ("pooling_mode_cls_token", "cls"),
    ("pooling_mode_mean_tokens", "mean"),
    ("pooling_mode_max_tokens", "max"),
    ("pooling_mode_lasttoken", "lasttoken"),
    ("pooling_mode_mean_sqrt_len_tokens", "mean_sqrt_len"),
)


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def collect_embedding_configuration_hints(path: str, data: bytes) -> dict[str, Any]:
    """Read embedding facts from one snapshot file, or return {} when it has none."""
    posix = str(path).replace("\\", "/")
    name = posix.rsplit("/", 1)[-1].lower()
    is_pooling_config = name == "config.json" and "_pooling/" in posix.lower()
    if name not in EMBEDDING_HINT_FILES and not is_pooling_config:
        return {}
    if not data or len(data) > MAX_EMBEDDING_HINT_BYTES:
        return {}
    try:
        parsed = json.loads(data.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}

    hints: dict[str, Any] = {}
    if is_pooling_config and isinstance(parsed, dict):
        # The pooling module is authoritative for both the served width and mode.
        dimension = _positive_int(parsed.get("word_embedding_dimension"))
        if dimension:
            hints["dimension"] = dimension
        for flag, mode in _POOLING_MODES:
            if parsed.get(flag) is True:
                hints["pooling"] = mode
                break
        return {**hints, "source": posix} if hints else {}
    if name == "config.json" and isinstance(parsed, dict):
        for key in ("hidden_size", "d_model", "n_embd", "dim"):
            dimension = _positive_int(parsed.get(key))
            if dimension:
                hints["dimension"] = dimension
                break
        sequence = _positive_int(parsed.get("max_position_embeddings"))
        if sequence:
            hints["max_sequence_length"] = sequence
        dtype = str(parsed.get("torch_dtype") or "").strip().lower()
        if dtype:
            hints["precision"] = dtype
        return {**hints, "source": posix} if hints else {}
    if name == "sentence_bert_config.json" and isinstance(parsed, dict):
        # The serving limit, which may be lower than the architectural maximum.
        sequence = _positive_int(parsed.get("max_seq_length"))
        if sequence:
            hints["max_sequence_length"] = sequence
        return {**hints, "source": posix} if hints else {}
    if name == "modules.json" and isinstance(parsed, list):
        types = {str(item.get("type") or "").lower() for item in parsed if isinstance(item, dict)}
        hints["normalization"] = any(entry.endswith(".normalize") for entry in types)
        return {**hints, "source": posix}
    return {}


def merge_embedding_configuration_hints(
    collected: dict[str, Any], addition: dict[str, Any]
) -> dict[str, Any]:
    """Merge one file's hints. A pooling module wins over the base config.json."""
    if not addition:
        return collected
    source = str(addition.get("source") or "")
    authoritative = "_pooling/" in source.lower() or source.endswith("sentence_bert_config.json")
    for key, value in addition.items():
        if key == "source":
            continue
        if key not in collected or authoritative:
            collected[key] = value
    sources = collected.setdefault("sources", [])
    if source and source not in sources:
        sources.append(source)
    return collected


def _inspect_zip_path(path: str | Path) -> dict[str, Any]:
    if not zipfile.is_zipfile(path):
        return {"is_zip": False, "entries": []}
    entries = []
    risky_entries = []
    executable_entries = []
    pickle_entries = []
    path_traversal_entries = []
    nested_archive_entries = []
    zip_bomb_entries = []
    risky_config_entries = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist()[:500]:
            entry = info.filename
            entries.append(entry)
            ext = Path(entry).suffix.lower()
            lowered = entry.lower()
            parts = Path(entry.replace("\\", "/")).parts
            if entry.startswith(("/", "\\")) or ".." in parts or re.match(r"^[a-zA-Z]:", entry):
                path_traversal_entries.append(entry)
            if lowered.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".7z")):
                nested_archive_entries.append(entry)
            if info.compress_size > 0 and info.file_size > 1_000_000 and info.file_size / info.compress_size > 100:
                zip_bomb_entries.append(entry)
            if ext in RISKY_EXTENSIONS or lowered.endswith("/data.pkl") or lowered.endswith("pickle"):
                risky_entries.append(entry)
            if ext in EXECUTABLE_EXTENSIONS:
                executable_entries.append(entry)
            if lowered.endswith((".pkl", ".pickle", "data.pkl")):
                pickle_entries.append(entry)
            if (
                info.file_size <= 262_144
                and Path(entry).name.lower() in {"config.json", "tokenizer_config.json", "generation_config.json"}
            ):
                try:
                    content = zf.read(info, pwd=None)[:262_144].lower()
                except (KeyError, RuntimeError, zipfile.BadZipFile):
                    content = b""
                if b"trust_remote_code" in content and b"true" in content:
                    risky_config_entries.append({"entry": entry, "risk": "trust_remote_code"})
                if b"chat_template" in content and any(marker in content for marker in (b"tool_call", b"system", b"developer")):
                    risky_config_entries.append({"entry": entry, "risk": "risky_chat_template"})
    return {
        "is_zip": True,
        "entries": entries[:50],
        "entry_count": len(entries),
        "risky_entries": risky_entries[:50],
        "pickle_entries": pickle_entries[:50],
        "executable_entries": executable_entries[:50],
        "path_traversal_entries": path_traversal_entries[:50],
        "nested_archive_entries": nested_archive_entries[:50],
        "zip_bomb_entries": zip_bomb_entries[:50],
        "risky_config_entries": risky_config_entries[:50],
    }


def _inspect_zip(data: bytes) -> dict[str, Any]:
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        if not zipfile.is_zipfile(tmp_path):
            return {"is_zip": False, "entries": []}
        return _inspect_zip_path(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "approved"}


def _metadata_value(metadata: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = metadata.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _source_kind(ref: str, metadata: dict[str, Any]) -> str:
    platform_hint = _metadata_value(metadata, "artifact_platform", "storage_provider", "registry_provider")
    if platform_hint:
        normalized = str(platform_hint).strip().lower().replace("-", "_")
        if normalized in {"huggingface", "oci", "s3", "gcs", "azure", "azure_blob", "mlflow"}:
            return normalized
    parsed = urllib.parse.urlparse(ref)
    host = _normalized_hostname(parsed)
    if _metadata_value(metadata, "huggingface_repo", "hf_repo"):
        return "huggingface"
    if ref.startswith("hf://") or "huggingface.co/" in ref:
        return "huggingface"
    if ref.startswith("oci://") or _metadata_value(metadata, "oci_ref", "image_ref"):
        return "oci"
    if ref.startswith(("mlflow://", "models:/", "runs:/")) or _metadata_value(metadata, "mlflow_model_uri", "mlflow_run_id"):
        return "mlflow"
    if ref.startswith(("s3://", "gs://", "gcs://", "azure://")):
        return urllib.parse.urlparse(ref).scheme
    if _is_s3_hostname(host):
        return "s3"
    if host == "storage.googleapis.com" or host.endswith(".storage.googleapis.com"):
        return "gcs"
    if _is_azure_blob_hostname(host):
        return "azure_blob"
    return parsed.scheme or "local"


def _registry_reference(ref: str, metadata: dict[str, Any]) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(ref)
    source_kind = _source_kind(ref, metadata)
    reference = {
        "kind": source_kind,
        "ref": ref,
        "registry": None,
        "repository": None,
        "path": parsed.path or None,
        "revision": metadata.get("revision") or metadata.get("model_revision") or parsed.query or None,
        "digest": metadata.get("digest") or metadata.get("image_digest") or None,
    }

    if source_kind == "huggingface":
        if ref.startswith("hf://"):
            parts = [part for part in parsed.path.split("/") if part]
            repository = f"{parsed.netloc}/{parts[0]}" if parsed.netloc and parts else parsed.netloc or None
            reference.update({"registry": "huggingface", "repository": repository, "path": "/".join(parts[1:]) or None})
        elif "huggingface.co" in ref:
            parts = [part for part in parsed.path.split("/") if part]
            repository = "/".join(parts[:2]) if len(parts) >= 2 else None
            revision = reference["revision"]
            if len(parts) >= 4 and parts[2] in {"blob", "resolve"}:
                revision = parts[3]
            reference.update({"registry": parsed.netloc, "repository": repository, "revision": revision})
    elif source_kind == "oci":
        image_ref = ref.removeprefix("oci://")
        digest = reference["digest"]
        if "@" in image_ref:
            image_ref, digest = image_ref.split("@", 1)
        registry, _, repository = image_ref.partition("/")
        reference.update({"registry": registry or None, "repository": repository or image_ref, "digest": digest})
    elif source_kind in {"s3", "gs", "gcs", "azure"}:
        reference.update({"registry": parsed.netloc or None, "repository": parsed.netloc or None, "path": parsed.path.lstrip("/") or None})
    elif source_kind == "azure_blob":
        parts = [part for part in parsed.path.split("/") if part]
        reference.update({"registry": parsed.netloc, "repository": parts[0] if parts else None, "path": "/".join(parts[1:]) or None})
    elif source_kind == "mlflow":
        reference.update({"registry": parsed.scheme or "mlflow", "repository": parsed.netloc or parsed.path.strip("/") or ref, "path": parsed.path or None})
    elif parsed.netloc:
        reference.update({"registry": parsed.netloc, "repository": parsed.path.strip("/") or None})

    return reference


def _decode_signature_value(raw: Any) -> bytes | None:
    """Decode an inline detached signature value: base64, hex, or raw bytes/text."""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    text = str(raw).strip()
    if not text:
        return None
    import base64
    import binascii
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error):
        pass
    try:
        return bytes.fromhex(text)
    except ValueError:
        pass
    return text.encode("utf-8", "ignore")


def _verify_signature_crypto(
    public_key_pem: Any,
    signature_bytes: bytes | None,
    payload_bytes: bytes | None,
    *,
    rsa_padding: str = "pss",
    hash_name: str = "sha256",
) -> dict[str, Any]:
    """Real detached-signature verification via the cryptography library.

    Never raises. ``verified`` is True only when an actual cryptographic check
    passed — caller-supplied metadata booleans never set it (that is the whole
    point of R1). When the cryptography library is unavailable, reports
    ``verifier_unavailable`` rather than silently passing.
    """
    if not (public_key_pem and signature_bytes and payload_bytes):
        return {"available": None, "attempted": False, "verified": False, "error": "missing_material"}
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding as asy_padding, rsa
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return {"available": False, "attempted": False, "verified": False, "error": "verifier_unavailable"}
    try:
        pem = public_key_pem if isinstance(public_key_pem, (bytes, bytearray)) else str(public_key_pem).encode()
        key = load_pem_public_key(bytes(pem))
    except Exception as exc:  # noqa: BLE001 - report, never raise
        return {"available": True, "attempted": False, "verified": False, "error": f"public_key_load_failed:{type(exc).__name__}"}
    hash_cls = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}.get(
        str(hash_name).lower(), hashes.SHA256
    )
    hash_alg = hash_cls()
    try:
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(bytes(signature_bytes), bytes(payload_bytes))
            algorithm = "ed25519"
        elif isinstance(key, rsa.RSAPublicKey):
            normalized_padding = str(rsa_padding).lower().replace("-", "").replace("_", "")
            if normalized_padding in {"pkcs1", "pkcs1v15", "pkcs1v1.5"}:
                pad = asy_padding.PKCS1v15()
                padding_name = "pkcs1v15"
            else:
                pad = asy_padding.PSS(mgf=asy_padding.MGF1(hash_alg), salt_length=asy_padding.PSS.MAX_LENGTH)
                padding_name = "pss"
            key.verify(bytes(signature_bytes), bytes(payload_bytes), pad, hash_alg)
            algorithm = f"rsa-{padding_name}-{str(hash_name).lower()}"
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(bytes(signature_bytes), bytes(payload_bytes), ec.ECDSA(hash_alg))
            algorithm = f"ecdsa-{str(hash_name).lower()}"
        else:
            return {"available": True, "attempted": False, "verified": False, "error": "unsupported_key_type"}
    except InvalidSignature:
        return {"available": True, "attempted": True, "verified": False, "verifier": "cryptography", "error": "invalid_signature"}
    except Exception as exc:  # noqa: BLE001
        return {"available": True, "attempted": True, "verified": False, "error": f"verify_error:{type(exc).__name__}"}
    return {"available": True, "attempted": True, "verified": True, "verifier": f"cryptography:{algorithm}", "algorithm": algorithm}


def _public_key_sha256(public_key_pem: Any) -> str | None:
    """SHA-256 over the DER SubjectPublicKeyInfo — a stable signing-key fingerprint."""
    try:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            load_pem_public_key,
        )
    except ImportError:
        return None
    try:
        pem = public_key_pem if isinstance(public_key_pem, (bytes, bytearray)) else str(public_key_pem).encode()
        key = load_pem_public_key(bytes(pem))
        der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    except Exception:  # noqa: BLE001 - report no fingerprint, never raise
        return None
    return hashlib.sha256(der).hexdigest()


def _iter_str_tokens(raw: Any):
    """Yield individual tokens from a list/tuple/set or a comma/space-delimited string."""
    if raw is None:
        return
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            yield from _iter_str_tokens(item)
        return
    for token in re.split(r"[,\s]+", str(raw)):
        if token:
            yield token


def _iter_pem_blocks(raw: Any):
    """Yield individual PEM blocks from a list or a (possibly multi-key) PEM bundle."""
    if raw is None:
        return
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            yield from _iter_pem_blocks(item)
        return
    text = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
    blocks = re.findall(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", text, re.DOTALL)
    if blocks:
        yield from blocks
    elif text.strip():
        yield text


def _configured_trust_anchor_fingerprints(options: dict[str, Any]) -> set[str]:
    """Collect operator-configured trusted signing-key SHA-256 fingerprints.

    Trust anchors come ONLY from operator-controlled inputs (scan options and
    environment), never from the artifact's own metadata — a publisher could
    otherwise self-declare their key as trusted, which is the self-signing hole
    this guards against.
    """
    fingerprints: set[str] = set()

    def _add_fp(raw: Any) -> None:
        for token in _iter_str_tokens(raw):
            norm = token.strip().lower().replace(":", "")
            if norm:
                fingerprints.add(norm)

    def _add_key(raw: Any) -> None:
        for pem in _iter_pem_blocks(raw):
            fp = _public_key_sha256(pem)
            if fp:
                fingerprints.add(fp)

    _add_fp(options.get("signature_trusted_key_sha256"))
    _add_fp(options.get("signature_trusted_key_fingerprints"))
    _add_key(options.get("signature_trusted_keys"))
    _add_fp(os.environ.get("MODEL_INTAKE_TRUSTED_KEY_SHA256"))
    _add_key(os.environ.get("MODEL_INTAKE_TRUSTED_SIGNING_KEYS"))
    return fingerprints


def _evaluate_signature_trust_root(public_key_pem: Any, options: dict[str, Any]) -> dict[str, Any]:
    """Decide whether a (validly-signing) key chains to a configured trust anchor.

    ``trusted_root`` is True/False when anchors are configured, or None when none
    are configured (trusted provenance simply cannot be established — a valid
    signature alone does not prove a trusted publisher).
    """
    anchors = _configured_trust_anchor_fingerprints(options)
    key_fp = _public_key_sha256(public_key_pem)
    if not anchors:
        trusted_root: bool | None = None
    else:
        trusted_root = bool(key_fp and key_fp in anchors)
    return {
        "key_fingerprint": key_fp,
        "trusted_root": trusted_root,
        "trust_anchors_configured": bool(anchors),
    }


async def _load_and_verify_signature(
    options: dict[str, Any],
    metadata: dict[str, Any],
    signature_url: Any,
    artifact_bytes: bytes,
    sha256: str | None,
    *,
    timeout_seconds: int,
    allow_local_files: bool,
    fetch_policy: dict[str, Any] | None = None,
    artifact_payload_complete: bool = True,
    artifact_subject_complete: bool = True,
) -> dict[str, Any]:
    """Gather signature material (inline or fetched) and run real verification.

    A public key is required to verify; without one we cannot cryptographically
    verify and return ``no_public_key`` (metadata claims may still be reported as
    *claimed*, never *verified*).
    """
    pub_inline = options.get("signature_public_key") or metadata.get("signature_public_key")
    pub_url = options.get("signature_public_key_url") or metadata.get("signature_public_key_url")
    sig_inline = options.get("signature_value") or metadata.get("signature_value")
    rsa_padding = str(options.get("signature_rsa_padding") or metadata.get("signature_rsa_padding") or "pss")
    hash_name = str(options.get("signature_hash") or metadata.get("signature_hash") or "sha256")
    payload_kind = str(options.get("signature_payload") or metadata.get("signature_payload") or "artifact").lower()
    expected_sha256 = str(options.get("expected_sha256") or metadata.get("sha256") or "").strip().lower() or None

    public_key_pem: Any = None
    if pub_inline:
        public_key_pem = pub_inline
    elif pub_url:
        pk_bytes, _pk_meta = await _fetch_artifact(
            str(pub_url), max_bytes=1_000_000, timeout_seconds=timeout_seconds,
            metadata=metadata, allow_local_files=allow_local_files, fetch_policy=fetch_policy,
        )
        if pk_bytes:
            public_key_pem = pk_bytes
    if not public_key_pem:
        return {"available": None, "attempted": False, "verified": False, "error": "no_public_key"}

    signature_bytes = _decode_signature_value(sig_inline) if sig_inline else None
    if not signature_bytes and signature_url:
        sig_bytes, _sig_meta = await _fetch_artifact(
            str(signature_url), max_bytes=1_000_000, timeout_seconds=timeout_seconds,
            metadata=metadata, allow_local_files=allow_local_files, fetch_policy=fetch_policy,
        )
        if sig_bytes:
            signature_bytes = sig_bytes
    if not signature_bytes:
        return {"available": True, "attempted": False, "verified": False, "error": "no_signature"}

    if not artifact_subject_complete:
        return {
            "available": True,
            "attempted": False,
            "verified": False,
            "signature_valid": False,
            "attestation_subject_digest_match": None,
            "error": "complete_artifact_required_for_signature_verification",
            "payload_kind": payload_kind,
        }

    digest_based = False
    if payload_kind in ("digest_hex", "digesthex", "digest-hex") and sha256:
        payload_bytes: bytes | None = sha256.encode()
        digest_based = True
    elif payload_kind in ("digest_raw", "digest", "digestraw", "digest-raw") and sha256:
        try:
            payload_bytes = bytes.fromhex(sha256)
        except ValueError:
            payload_bytes = sha256.encode()
        digest_based = True
    else:
        if not artifact_payload_complete:
            return {
                "available": True,
                "attempted": False,
                "verified": False,
                "signature_valid": False,
                "attestation_subject_digest_match": None,
                "error": "raw_artifact_payload_not_fully_materialized",
                "payload_kind": "artifact",
            }
        payload_bytes = artifact_bytes

    result = _verify_signature_crypto(
        public_key_pem, signature_bytes, payload_bytes, rsa_padding=rsa_padding, hash_name=hash_name
    )
    signature_valid = bool(result.get("verified"))
    result["signature_valid"] = signature_valid
    if signature_valid:
        subject_digest_match = bool(
            not expected_sha256 or (sha256 and sha256 == expected_sha256)
        )
        result["attestation_subject_digest_match"] = subject_digest_match
        result["payload_kind"] = "digest" if digest_based else "artifact"
        # A valid signature only establishes TRUSTED provenance when the signing key
        # chains to an operator-configured trust anchor. Without that, a publisher
        # could self-sign, so downgrade ``verified`` from cryptographic-pass-only to
        # cryptographic-pass-AND-trusted.
        trust = _evaluate_signature_trust_root(public_key_pem, options)
        result.update(trust)
        result["verified"] = signature_valid and subject_digest_match and trust.get("trusted_root") is True
    return result


def _signature_verification_status(
    metadata: dict[str, Any],
    signature_url: Any,
    signed_by: Any,
    crypto: dict[str, Any] | None = None,
) -> dict[str, Any]:
    claim_keys = (
        "signature_verified",
        "sigstore_verified",
        "cosign_verified",
        "attestation_verified",
        "provenance_verified",
    )
    # Metadata booleans asserting cryptographic verification are CLAIMS, not proof
    # (R1). Only the real verifier result can set cryptographically_verified.
    crypto_claim_keys = (
        "signature_cryptographically_verified",
        "cryptographic_signature_verified",
        "sigstore_bundle_verified",
        "cosign_bundle_verified",
        "attestation_cryptographically_verified",
        "provenance_cryptographically_verified",
    )
    claimed_verified = any(_boolish(metadata.get(key)) for key in (*claim_keys, *crypto_claim_keys))
    crypto = crypto or {}
    # ``signature_valid`` = the raw cryptographic check passed; ``cryptographically_verified``
    # additionally requires the signing key to chain to a configured trust anchor.
    signature_valid = bool(crypto.get("signature_valid")) or bool(crypto.get("verified"))
    cryptographically_verified = bool(crypto.get("verified"))
    trusted_root = crypto.get("trusted_root")
    crypto_attempted = bool(crypto.get("attempted"))
    crypto_invalid = crypto_attempted and not signature_valid
    present = bool(
        signature_url
        or signed_by
        or metadata.get("attestation_url")
        or metadata.get("provenance_url")
        or crypto.get("available") is True
    )
    subject_digest_match = crypto.get("attestation_subject_digest_match")
    if signature_valid and subject_digest_match is False:
        status = "subject_digest_mismatch"
    elif cryptographically_verified:
        status = "verified"
    elif signature_valid and trusted_root is False:
        # Signature math passed but the signing key is not a configured trust anchor.
        status = "untrusted_key"
    elif signature_valid:
        # Signature math passed but no trust anchors are configured, so provenance
        # cannot be established (the key may be self-signed).
        status = "untrusted_root"
    elif crypto_invalid:
        status = "invalid"
    elif claimed_verified:
        status = "claimed_verified"
    elif present:
        status = "present_unverified"
    else:
        status = "missing"
    return {
        "status": status,
        "verified": cryptographically_verified,
        "signature_valid": signature_valid,
        "trusted_root": trusted_root,
        "key_fingerprint": crypto.get("key_fingerprint"),
        "trust_anchors_configured": bool(crypto.get("trust_anchors_configured")),
        "claimed_present": present,
        "claimed_verified": claimed_verified,
        "cryptographically_verified": cryptographically_verified,
        "crypto_attempted": crypto_attempted,
        "crypto_invalid": crypto_invalid,
        "present": present,
        "signature_url": signature_url,
        "signed_by": signed_by,
        "verifier": crypto.get("verifier"),
        "algorithm": crypto.get("algorithm"),
        "transparency_log_verified": bool(crypto.get("transparency_log_verified")),
        "attestation_subject_digest_match": subject_digest_match,
        "crypto_error": crypto.get("error"),
        "verification_evidence": {
            key: metadata.get(key)
            for key in (*claim_keys, *crypto_claim_keys)
            if metadata.get(key) not in (None, "", [], {})
        },
    }


_SPDX_PERMISSIVE = {
    "apache-2.0", "mit", "bsd-2-clause", "bsd-3-clause", "isc", "0bsd", "bsl-1.0",
    "zlib", "unlicense", "cc0-1.0", "mpl-2.0", "python-2.0", "postgresql", "openrail",
    "openrail++", "bigscience-openrail-m", "creativeml-openrail-m", "llama2", "llama3",
}
_SPDX_COPYLEFT = {
    "gpl-2.0", "gpl-3.0", "agpl-3.0", "lgpl-2.1", "lgpl-3.0", "epl-2.0", "cddl-1.0",
    "ms-rl", "osl-3.0",
}
_SPDX_ALIASES = {
    "apache 2.0": "apache-2.0", "apache2": "apache-2.0", "apache2.0": "apache-2.0",
    "apache license 2.0": "apache-2.0", "bsd": "bsd-3-clause", "gplv2": "gpl-2.0",
    "gplv3": "gpl-3.0", "gpl2": "gpl-2.0", "gpl3": "gpl-3.0", "agplv3": "agpl-3.0",
    "lgplv3": "lgpl-3.0", "the unlicense": "unlicense", "cc-0": "cc0-1.0",
}
_SPDX_SUFFIXES = ("-only", "-or-later", "+")


def _normalize_spdx_token(token: str) -> str:
    t = str(token or "").strip().strip("()").strip().lower()
    return _SPDX_ALIASES.get(t, t)


def _spdx_base(token: str) -> str:
    base = _normalize_spdx_token(token)
    for suffix in _SPDX_SUFFIXES:
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


def _classify_license_token(token: str) -> str:
    normalized = _normalize_spdx_token(token)
    if not normalized:
        return "missing"
    if any(hint in normalized for hint in RESTRICTIVE_LICENSE_HINTS):
        return "restricted"
    base = _spdx_base(normalized)
    if base in _SPDX_PERMISSIVE or normalized in PERMISSIVE_LICENSES:
        return "permissive"
    if base in _SPDX_COPYLEFT or base.startswith(("gpl-", "agpl-", "lgpl-")):
        return "restricted"
    if base.startswith(("apache", "mit", "bsd", "isc", "mpl", "openrail")):
        return "permissive"
    return "review_required"


def _license_policy(license_ref: Any) -> dict[str, Any]:
    """Classify a license, normalizing SPDX identifiers and parsing expressions.

    Supports SPDX expressions like "MIT OR Apache-2.0" and "(MIT AND GPL-3.0-only)":
    restricted if any sub-license is restricted, permissive only if all are.
    """
    license_text = str(license_ref or "").strip()
    if not license_text:
        return {"license": license_ref, "status": "missing", "normalized": [], "review_required": True}
    tokens = [t for t in (part.strip() for part in re.split(r"\s+(?:and|or|with)\s+|[()]", license_text, flags=re.IGNORECASE)) if t]
    classes = [_classify_license_token(t) for t in tokens] or ["review_required"]
    if "restricted" in classes:
        status = "restricted"
    elif all(c == "permissive" for c in classes):
        status = "permissive"
    else:
        status = "review_required"
    return {
        "license": license_ref,
        "status": status,
        "normalized": [_normalize_spdx_token(t) for t in tokens],
        "review_required": status in {"missing", "restricted", "review_required"},
    }


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _evidence_status(value: Any, *keys: str) -> str:
    if not isinstance(value, dict):
        return ""
    for key in keys:
        raw = value.get(key)
        if raw not in (None, "", [], {}):
            return str(raw).strip().lower()
    return ""


def _sbom_policy(value: Any, *, strict: bool, trusted_provenance: bool = False) -> dict[str, Any]:
    if value in (None, "", [], {}):
        return {"status": "missing", "valid": False, "component_count": 0, "format": None}
    if isinstance(value, str):
        return {
            "status": "reference_unverified" if strict else "reference_present",
            "valid": not strict,
            "component_count": None,
            "format": "url",
        }
    if isinstance(value, list):
        valid = (bool(value) and trusted_provenance) if strict else True
        return {
            "status": "valid" if valid else "untrusted_provenance" if value else "empty",
            "valid": valid,
            "component_count": len(value),
            "format": "component_list",
            "trusted_provenance": trusted_provenance,
        }
    if not isinstance(value, dict):
        return {"status": "invalid_shape", "valid": False, "component_count": 0, "format": type(value).__name__}

    if str(value.get("bomFormat") or "").lower() == "cyclonedx":
        components = value.get("components")
        count = len(components) if isinstance(components, list) else 0
        valid = (count > 0 and trusted_provenance) if strict else True
        return {
            "status": "valid" if valid else "untrusted_provenance" if count else "empty",
            "valid": valid,
            "component_count": count,
            "format": "cyclonedx",
            "trusted_provenance": trusted_provenance,
        }
    if value.get("spdxVersion"):
        packages = value.get("packages")
        count = len(packages) if isinstance(packages, list) else 0
        valid = (count > 0 and trusted_provenance) if strict else True
        return {
            "status": "valid" if valid else "untrusted_provenance" if count else "empty",
            "valid": valid,
            "component_count": count,
            "format": "spdx",
        }
    if isinstance(value.get("components"), list):
        count = len(value["components"])
        valid = (count > 0 and trusted_provenance) if strict else True
        return {
            "status": "valid" if valid else "untrusted_provenance" if count else "empty",
            "valid": valid,
            "component_count": count,
            "format": "generic_components",
        }
    return {"status": "invalid_shape" if strict else "present_unvalidated", "valid": not strict, "component_count": 0, "format": "unknown"}


def _malware_policy(
    value: Any,
    *,
    strict: bool,
    expected_sha256: Any,
    max_age_days: int = 30,
    trusted_provenance: bool = False,
) -> dict[str, Any]:
    if value in (None, "", [], {}):
        return {"status": "missing", "valid": False}
    if isinstance(value, str):
        return {"status": "reference_unverified" if strict else "reference_present", "valid": not strict}
    if not isinstance(value, dict):
        return {"status": "invalid_shape", "valid": False}

    status = _evidence_status(value, "status", "result", "verdict")
    clean = status in {"clean", "passed", "pass", "no_findings", "no findings"}
    scanner = _metadata_value(value, "scanner", "engine", "tool")
    version = _metadata_value(value, "engine_version", "scanner_version", "version")
    digest = _metadata_value(value, "artifact_digest", "sha256", "model_sha256", "digest")
    timestamp_value = _metadata_value(value, "timestamp", "scanned_at", "date")
    scanned_at = _parse_datetime(timestamp_value)
    stale = False
    if scanned_at is not None:
        age_days = (datetime.now(timezone.utc) - scanned_at).days
        stale = age_days > max_age_days
    expected = str(expected_sha256 or "").strip().lower()
    digest_matches = not expected or str(digest or "").replace("sha256:", "").strip().lower() == expected
    valid = clean and bool(scanner) and bool(version) and bool(scanned_at) and bool(digest) and digest_matches and not stale and trusted_provenance
    return {
        "status": "valid" if valid else "invalid",
        "valid": valid if strict else clean,
        "clean": clean,
        "scanner_present": bool(scanner),
        "engine_version_present": bool(version),
        "timestamp_present": bool(scanned_at),
        "artifact_digest_present": bool(digest),
        "artifact_digest_matches": digest_matches,
        "stale": stale,
        "max_age_days": max_age_days,
        "trusted_provenance": trusted_provenance,
    }


def _eval_policy(value: Any, *, strict: bool, expected_sha256: Any, trusted_provenance: bool = False) -> dict[str, Any]:
    if value in (None, "", [], {}):
        return {"status": "missing", "valid": False}
    if isinstance(value, str):
        return {"status": "reference_unverified" if strict else "reference_present", "valid": not strict}
    if not isinstance(value, dict):
        return {"status": "invalid_shape", "valid": False}

    status = _evidence_status(value, "status", "result", "verdict")
    passed = status in {"passed", "pass", "clean", "accepted"}
    suite = _metadata_value(value, "suite_id", "eval_suite_id", "suite", "report_id")
    timestamp = _parse_datetime(_metadata_value(value, "date", "evaluated_at", "timestamp"))
    digest = _metadata_value(value, "target_sha256", "model_sha256", "artifact_digest", "model_digest")
    thresholds = _metadata_value(value, "thresholds", "acceptance_thresholds", "criteria")
    expected = str(expected_sha256 or "").strip().lower()
    digest_matches = not expected or str(digest or "").replace("sha256:", "").strip().lower() == expected
    valid = passed and bool(suite) and bool(timestamp) and bool(digest) and digest_matches and bool(thresholds) and trusted_provenance
    return {
        "status": "valid" if valid else "invalid",
        "valid": valid if strict else passed,
        "passed": passed,
        "suite_present": bool(suite),
        "date_present": bool(timestamp),
        "target_digest_present": bool(digest),
        "target_digest_matches": digest_matches,
        "thresholds_present": bool(thresholds),
        "trusted_provenance": trusted_provenance,
    }


def _approval_policy(metadata: dict[str, Any], *, deployment_approved: bool, strict: bool) -> dict[str, Any]:
    if not deployment_approved:
        return {"status": "missing", "valid": False}
    approved_by = _metadata_value(metadata, "approved_by", "approver")
    approved_at = _parse_datetime(_metadata_value(metadata, "approved_at", "approval_timestamp", "approval_date"))
    policy_version = _metadata_value(metadata, "approval_policy_version", "policy_version")
    environment = _metadata_value(metadata, "environment", "deployment_environment", "approved_environment")
    valid = bool(approved_by and approved_at and policy_version and environment)
    return {
        "status": "valid" if valid else "incomplete",
        "valid": valid if strict else True,
        "approved_by_present": bool(approved_by),
        "approved_at_present": bool(approved_at),
        "policy_version_present": bool(policy_version),
        "environment_present": bool(environment),
    }


def _scan_suspicious_loader_markers(
    data: bytes,
    zip_info: dict[str, Any],
    *,
    extension: str = "",
) -> list[dict[str, str]]:
    # Do not substring-scan opaque tensor payloads. Arbitrary tensor bytes can
    # spell words such as ``powershell`` by chance, while the structured GGUF,
    # ONNX, and safetensors inspectors already parse the fields that can affect
    # loading. Code, configuration, archives, and executable-serialization
    # formats remain covered by AST/Semgrep, archive inspection, pickle
    # analysis, ModelScan/Fickling, and this bounded fallback heuristic.
    structured_weight_formats = {".gguf", ".onnx", ".safetensors"}
    sample = b"" if extension.lower() in structured_weight_formats else data[:1_000_000].lower()
    hits = [
        {"marker": label, "source": "artifact_bytes"}
        for marker, label in SUSPICIOUS_LOADER_MARKERS.items()
        if marker.lower() in sample
    ]
    for entry in (zip_info.get("entries") or []):
        lowered = str(entry).lower()
        if any(name in lowered for name in ("postinstall", "setup.py", "requirements.txt", "install.sh", "download")):
            hits.append({"marker": "loader_or_install_file", "source": lowered})
    deduped: dict[tuple[str, str], dict[str, str]] = {}
    for hit in hits:
        deduped[(hit["marker"], hit["source"])] = hit
    return list(deduped.values())[:25]


def _inspect_safetensors(
    data: bytes,
    *,
    artifact_truncated: bool = False,
    artifact_size: int | None = None,
    artifact_size_source: str | None = None,
) -> dict[str, Any]:
    header: dict[str, Any] = {
        "present": False,
        "valid_json": False,
        "valid": False,
        "conclusive_invalid": False,
        "validation_complete": False,
    }
    if len(data) < 8:
        header["error"] = "too_short_for_header_length"
        header["conclusive_invalid"] = not artifact_truncated
        header["valid"] = False if header["conclusive_invalid"] else None
        return header

    header_len = int.from_bytes(data[:8], "little", signed=False)
    header["length"] = header_len
    if header_len <= 0:
        header["error"] = "empty_header"
        header["conclusive_invalid"] = True
        return header
    if header_len > 100_000_000:
        header["error"] = "header_length_unreasonable"
        header["conclusive_invalid"] = True
        return header
    if len(data) < 8 + header_len:
        header["error"] = "header_not_fully_observed" if artifact_truncated else "truncated_header"
        header["conclusive_invalid"] = not artifact_truncated
        header["valid"] = False if header["conclusive_invalid"] else None
        return header

    duplicate_keys: list[str] = []

    def object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in seen and key not in duplicate_keys:
                duplicate_keys.append(key)
            seen.add(key)
            obj[key] = value
        return obj

    try:
        parsed = json.loads(
            data[8:8 + header_len].decode("utf-8"),
            object_pairs_hook=object_pairs_hook,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        header["error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
        header["conclusive_invalid"] = True
        return header

    if not isinstance(parsed, dict):
        header["error"] = "header_json_not_object"
        header["conclusive_invalid"] = True
        return header

    header["present"] = True
    header["valid_json"] = True
    if duplicate_keys:
        header["duplicate_keys"] = duplicate_keys[:25]

    metadata = parsed.get("__metadata__")
    metadata_keys = sorted(metadata.keys())[:25] if isinstance(metadata, dict) else []
    suspicious_metadata_keys = [
        key for key in metadata_keys
        if key.lower() in SAFETENSORS_SUSPICIOUS_METADATA_KEYS
        or any(fragment in key.lower() for fragment in ("token", "secret", "credential"))
    ]
    if isinstance(metadata, dict):
        for key, value in metadata.items():
            text = str(value or "").lower()
            if key.lower() == "chat_template" and any(marker in text for marker in RISKY_TEMPLATE_MARKERS):
                suspicious_metadata_keys.append(key)

    tensor_ranges: list[tuple[int, int, str]] = []
    invalid_tensors: list[dict[str, Any]] = []
    payload_size: int | None = None
    if not artifact_truncated:
        payload_size = max(0, len(data) - 8 - header_len)
        artifact_size_source = artifact_size_source or "observed_complete_artifact"
    elif artifact_size is not None and artifact_size >= 8 + header_len:
        payload_size = artifact_size - 8 - header_len

    for name, tensor in parsed.items():
        if name == "__metadata__":
            continue
        tensor_ref = hashlib.sha256(str(name).encode("utf-8", "replace")).hexdigest()[:16]
        if not isinstance(tensor, dict):
            invalid_tensors.append({"tensor_ref": tensor_ref, "reason": "metadata_not_object"})
            continue
        offsets = tensor.get("data_offsets")
        dtype = tensor.get("dtype")
        shape = tensor.get("shape")
        if not (
            isinstance(offsets, list)
            and len(offsets) == 2
            and all(type(item) is int for item in offsets)
        ):
            invalid_tensors.append({"tensor_ref": tensor_ref, "reason": "missing_or_invalid_data_offsets"})
            continue
        if not isinstance(dtype, str) or dtype not in _SAFETENSORS_DTYPE_SIZES:
            invalid_tensors.append({"tensor_ref": tensor_ref, "reason": "unsupported_dtype"})
            continue
        if not isinstance(shape, list) or not all(type(item) is int and item >= 0 for item in shape):
            invalid_tensors.append({"tensor_ref": tensor_ref, "reason": "invalid_shape"})
            continue
        start, end = offsets
        if start < 0 or end < start or (payload_size is not None and end > payload_size):
            invalid_tensors.append({
                "tensor_ref": tensor_ref,
                "reason": "offset_out_of_bounds",
                "start": start,
                "end": end,
                "payload_size": payload_size,
            })
            continue
        elements = math.prod(shape)
        if end - start != elements * _SAFETENSORS_DTYPE_SIZES[dtype]:
            invalid_tensors.append({
                "tensor_ref": tensor_ref,
                "reason": "shape_byte_span_mismatch",
            })
            continue
        tensor_ranges.append((start, end, tensor_ref))

    overlaps: list[dict[str, Any]] = []
    for previous, current in zip(sorted(tensor_ranges), sorted(tensor_ranges)[1:]):
        if current[0] < previous[1]:
            overlaps.append({
                "previous_tensor": previous[2],
                "tensor": current[2],
                "previous_end": previous[1],
                "start": current[0],
            })

    coverage_errors: list[str] = []
    if payload_size is not None:
        cursor = 0
        for start, end, _tensor_ref in sorted(item for item in tensor_ranges if item[1] > item[0]):
            if start < cursor:
                coverage_errors.append("overlapping_tensor_spans")
            elif start > cursor:
                coverage_errors.append("unexplained_payload_gap")
            cursor = max(cursor, end)
        if cursor != payload_size:
            coverage_errors.append("unexplained_trailing_payload" if cursor < payload_size else "payload_overrun")

    tensor_count = len([key for key in parsed.keys() if key != "__metadata__"])
    if not tensor_count:
        invalid_tensors.append({"reason": "tensor_inventory_empty"})
    if metadata is not None and (
        not isinstance(metadata, dict)
        or not all(isinstance(key, str) and isinstance(value, str) for key, value in metadata.items())
    ):
        invalid_tensors.append({"reason": "invalid_metadata_map"})
    conclusive_invalid = bool(duplicate_keys or invalid_tensors or overlaps or coverage_errors)
    validation_complete = payload_size is not None
    header.update({
        "valid": False if conclusive_invalid else True if validation_complete else None,
        "conclusive_invalid": conclusive_invalid,
        "validation_complete": validation_complete,
        "tensor_count": tensor_count,
        "metadata_keys": metadata_keys,
        "suspicious_metadata_keys": sorted(set(suspicious_metadata_keys))[:25],
        "invalid_tensors": invalid_tensors[:25],
        "overlapping_tensors": overlaps[:25],
        "payload_coverage_complete": validation_complete and not coverage_errors,
        "coverage_errors": sorted(set(coverage_errors)),
        "payload_size": payload_size,
        "payload_bounds_checked": payload_size is not None,
        "artifact_size": artifact_size if artifact_size is not None else len(data) if not artifact_truncated else None,
        "artifact_size_source": artifact_size_source,
    })
    return header


def _extract_ascii_strings(data: bytes, *, minimum: int = 4, limit: int = 200) -> list[str]:
    strings = [
        match.group(0).decode("utf-8", errors="ignore")
        for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data)
    ]
    return strings[:limit]


def _inspect_onnx(data: bytes) -> dict[str, Any]:
    sample = data[:2_000_000]
    strings = _extract_ascii_strings(sample, limit=500)
    lowered_strings = [item.lower() for item in strings]
    external_locations = [
        item for item in strings
        # ONNX graph/node/tensor names commonly begin with "/" (for example
        # "/Cast_output_0").  They are not filesystem locations.  The worker
        # deliberately does not parse untrusted protobuf, so this bounded hint
        # must require a path/URI-shaped value; the isolated official ONNX
        # parser remains authoritative for external_data key/value fields.
        if item.startswith(("file:", "http://", "https://", "s3://", "gs://", "../", "..\\"))
        or item.lower().endswith((".bin", ".data", ".weights", ".raw"))
    ][:25]
    custom_domains = [
        item for item in strings
        if item.startswith(("ai.onnx.contrib", "com.microsoft", "com.", "org."))
        or "customop" in item.lower()
    ][:25]
    return {
        "parsed_with": "bounded_string_table",
        "parser_status": "not_executed_in_worker",
        "parser_reason": "untrusted_protobuf_requires_generated_scanner_or_sandbox",
        "graph_name": None,
        "external_data_hint": bool(external_locations),
        "external_data_locations": sorted(set(external_locations))[:25],
        "custom_operator_hint": any(
            marker in " ".join(lowered_strings)
            for marker in ("ai.onnx.contrib", "com.microsoft", "customop")
        ) or bool(custom_domains),
        "custom_operator_domains": sorted(set(custom_domains))[:25],
    }


def _inspect_gguf(data: bytes) -> dict[str, Any]:
    magic_present = data.startswith(b"GGUF")
    version = int.from_bytes(data[4:8], "little", signed=False) if magic_present and len(data) >= 8 else None
    tensor_count = None
    metadata_kv_count = None
    if magic_present and len(data) >= 24:
        try:
            tensor_count, metadata_kv_count = struct.unpack_from("<QQ", data, 8)
        except struct.error:
            tensor_count = None
            metadata_kv_count = None
    strings = _extract_ascii_strings(data[:1_000_000], limit=200)
    suspicious_strings = [
        item for item in strings
        if item.startswith(("http://", "https://", "file:", "s3://", "gs://"))
        or any(marker in item.lower() for marker in RISKY_TEMPLATE_MARKERS)
    ][:25]
    return {
        "magic_present": magic_present,
        "version": version,
        "tensor_count": tensor_count,
        "metadata_kv_count": metadata_kv_count,
        "valid_header": bool(magic_present and version in {1, 2, 3}),
        "suspicious_metadata_strings": suspicious_strings,
    }


def _inspect_format(
    name: str,
    ext: str,
    data: bytes,
    zip_info: dict[str, Any],
    *,
    artifact_truncated: bool = False,
    artifact_size: int | None = None,
    artifact_size_source: str | None = None,
) -> dict[str, Any]:
    inspection: dict[str, Any] = {
        "artifact_name": name,
        "extension": ext,
        "format": ext.lstrip(".") or "unknown",
        "lower_code_execution_risk": ext in SAFER_MODEL_EXTENSIONS,
    }
    if ext == ".safetensors":
        inspection["safetensors_header"] = _inspect_safetensors(
            data,
            artifact_truncated=artifact_truncated,
            artifact_size=artifact_size,
            artifact_size_source=artifact_size_source,
        )
    elif ext == ".onnx":
        inspection["onnx"] = _inspect_onnx(data)
    elif ext == ".gguf":
        inspection["gguf"] = _inspect_gguf(data)

    if zip_info.get("is_zip"):
        entries = [str(entry) for entry in (zip_info.get("entries") or [])]
        inspection["archive_components"] = {
            "tokenizer_files": [entry for entry in entries if Path(entry).name in {"tokenizer.json", "vocab.json", "merges.txt"}][:20],
            "adapter_files": [entry for entry in entries if "adapter" in entry.lower()][:20],
            "config_files": [entry for entry in entries if Path(entry).name in {"config.json", "generation_config.json"}][:20],
        }
    return inspection


def _component_list(value: Any, component_type: str) -> list[dict[str, Any]]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, dict) and isinstance(value.get("components"), list):
        return _component_list(value.get("components"), component_type)
    raw_items = value if isinstance(value, list) else [value]
    components: list[dict[str, Any]] = []
    for item in raw_items:
        if isinstance(item, dict):
            name = item.get("name") or item.get("ref") or item.get("url") or item.get("purl") or component_type
            components.append({"type": component_type, "name": str(name), **item})
        elif item:
            components.append({"type": component_type, "name": str(item), "ref": str(item)})
    return components


def _generate_aibom(
    *,
    artifact_ref: str,
    name: str,
    ext: str,
    sha256: str | None,
    metadata: dict[str, Any],
    registry: dict[str, Any],
    license_ref: Any,
    signature_status: dict[str, Any],
    format_inspection: dict[str, Any],
) -> dict[str, Any]:
    components: list[dict[str, Any]] = [
        {
            "type": "model_artifact",
            "name": name,
            "ref": artifact_ref,
            "format": ext,
            "hashes": [{"alg": "SHA-256", "content": sha256}] if sha256 else [],
            "licenses": [license_ref] if license_ref else [],
            "registry": registry,
        }
    ]
    components.extend(_component_list(_metadata_value(metadata, "base_model", "base_models", "foundation_model"), "base_model"))
    components.extend(_component_list(_metadata_value(metadata, "adapters", "adapter_refs", "lora_adapters"), "adapter"))
    components.extend(_component_list(_metadata_value(metadata, "tokenizer", "tokenizer_ref", "tokenizer_sha256"), "tokenizer"))
    components.extend(_component_list(_metadata_value(metadata, "training_data_ref", "training_datasets", "datasets", "dataset_refs"), "dataset"))
    components.extend(_component_list(_metadata_value(metadata, "dependencies", "package_dependencies", "runtime_dependencies"), "dependency"))
    sbom = _metadata_value(metadata, "sbom", "sbom_url")
    if isinstance(sbom, dict):
        components.extend(_component_list(sbom.get("components"), "dependency"))

    fields = {
        "artifact": True,
        "hash": bool(sha256),
        "license": bool(license_ref),
        "provenance": bool(_metadata_value(metadata, "source_repo", "source_repository", "commit_sha", "attestation_url", "provenance_url")),
        "base_model": any(component.get("type") == "base_model" for component in components),
        "tokenizer": any(component.get("type") == "tokenizer" for component in components),
        "datasets": any(component.get("type") == "dataset" for component in components),
        "dependencies": any(component.get("type") == "dependency" for component in components),
        "signature_verification": signature_status.get("verified") is True,
    }
    score = round(sum(1 for present in fields.values() if present) / len(fields), 3)
    return {
        "bom_format": "ShakerScan AIBOM",
        "schema_version": "2026-05-19.aibom.v1",
        "serial_number": f"urn:shakerscan:aibom:{hashlib.sha256(artifact_ref.encode()).hexdigest()[:24]}",
        "components": components,
        "provenance": {
            "source_repo": _metadata_value(metadata, "source_repo", "source_repository"),
            "commit_sha": metadata.get("commit_sha"),
            "training_data_ref": _metadata_value(metadata, "training_data_ref", "datasets", "dataset_refs"),
            "attestation_url": _metadata_value(metadata, "attestation_url", "provenance_url"),
            "signature": signature_status,
        },
        "format_inspection": format_inspection,
        "completeness": {
            "score": score,
            "fields": fields,
            "missing": [key for key, present in fields.items() if not present],
        },
    }


async def run_model_intake_scan(
    artifact_ref: str,
    raw_options: dict[str, Any] | None = None,
    *,
    event_callback: Any = None,
) -> dict[str, Any]:
    """Run model artifact intake checks without executing model code."""
    options = raw_options or {}
    activity: list[dict[str, Any]] = []
    inline_metadata = options.get("metadata_json") if isinstance(options.get("metadata_json"), dict) else {}
    metadata = _strip_untrusted_governance_metadata(dict(inline_metadata))
    metadata_url = options.get("metadata_url")
    metadata_fetch_meta: dict[str, Any] = {}
    def bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(options.get(name) or default)
        except (TypeError, ValueError):
            value = default
        return max(minimum, min(value, maximum))

    timeout_seconds = bounded_int("timeout_seconds", 20, 1, MAX_TIMEOUT_SECONDS)
    # How many artifact bytes intake may acquire. Real models are routinely
    # 1GB+, so this is bounded by the artifact ceiling rather than the
    # in-memory inspection ceiling.
    max_download_bytes = bounded_int("max_download_bytes", 10_000_000, 1024, MAX_ARTIFACT_BYTES)
    complete_artifact_download = _boolish(options.get("complete_artifact_download"))
    max_artifact_bytes = bounded_int("max_artifact_bytes", 10_000_000_000, 1024, MAX_ARTIFACT_BYTES)
    # Only a bounded prefix is ever held in worker memory. Anything larger is
    # streamed into content-addressed quarantine instead, which is what makes a
    # full-artifact SHA-256 (and therefore checksum/signature verification)
    # reachable for a multi-gigabyte model.
    inspection_bytes = min(max_download_bytes, MAX_INSPECTION_BYTES)
    stream_to_quarantine = complete_artifact_download or max_download_bytes > inspection_bytes
    # An explicit complete-download request is capped by max_artifact_bytes; an
    # implicit escalation is capped by exactly what the caller asked to fetch.
    effective_artifact_bytes = (
        max_artifact_bytes
        if complete_artifact_download
        else max_download_bytes
    )
    complete_repository_snapshot = _boolish(options.get("complete_repository_snapshot"))
    max_repository_bytes = bounded_int("max_repository_bytes", 50_000_000_000, 1024, MAX_REPOSITORY_BYTES)
    max_repository_files = bounded_int("max_repository_files", 10_000, 1, MAX_REPOSITORY_FILES)
    await _emit_model_intake_activity(
        activity,
        event_callback,
        phase="intake_started",
        progress=15,
        status="RUNNING",
        source_kind=_source_kind(artifact_ref, metadata),
    )
    quarantine_dir = Path(
        str(
            options.get("quarantine_dir")
            or os.getenv("MODEL_INTAKE_QUARANTINE_DIR")
            or "/results/model-intake-quarantine"
        )
    )
    allow_local_files = _boolish(options.get("allow_local_files")) or _boolish(os.getenv("MODEL_INTAKE_ALLOW_LOCAL_FILES"))
    acquisition_option_names = {
        "allow_insecure_http",
        "allow_private_networks",
        "allowed_acquisition_hosts",
        "allowed_acquisition_ports",
        "max_acquisition_redirects",
    }
    has_explicit_acquisition_policy = any(name in options for name in acquisition_option_names) or any(
        os.getenv(name)
        for name in (
            "MODEL_INTAKE_ALLOW_INSECURE_HTTP",
            "MODEL_INTAKE_ALLOW_PRIVATE_NETWORKS",
            "MODEL_INTAKE_ALLOWED_HOSTS",
            "MODEL_INTAKE_ALLOWED_PORTS",
        )
    )
    fetch_policy = _acquisition_policy(options) if has_explicit_acquisition_policy else None

    if metadata_url:
        remote_metadata, metadata_fetch_meta = await _fetch_json(
            str(metadata_url),
            timeout_seconds=timeout_seconds,
            allow_local_files=allow_local_files,
            fetch_policy=fetch_policy,
        )
        metadata = {
            **_strip_untrusted_governance_metadata(remote_metadata),
            **metadata,
        }

    acquisition_metadata = {
        **metadata,
        "expected_sha256": options.get("expected_sha256") or metadata.get("expected_sha256") or metadata.get("sha256"),
    }
    artifact_bytes, artifact_meta = await _fetch_artifact(
        artifact_ref,
        max_bytes=inspection_bytes,
        timeout_seconds=timeout_seconds,
        metadata=acquisition_metadata,
        allow_local_files=allow_local_files,
        fetch_policy=fetch_policy,
        complete_download=stream_to_quarantine,
        max_artifact_bytes=effective_artifact_bytes,
        quarantine_dir=quarantine_dir if stream_to_quarantine else None,
    )
    await _emit_model_intake_activity(
        activity,
        event_callback,
        phase="artifact_acquisition",
        progress=35,
        status=(
            "FAILED"
            if artifact_meta.get("error")
            else "PARTIAL"
            if artifact_meta.get("truncated")
            else "PASS"
        ),
        source=artifact_meta.get("source"),
        bytes_observed=artifact_meta.get("bytes_observed"),
        bytes_total=artifact_meta.get("bytes_total"),
        complete=not bool(artifact_meta.get("error")) and not bool(artifact_meta.get("truncated")),
        truncated=bool(artifact_meta.get("truncated")),
    )

    unsupported_scheme_error = bool(
        artifact_meta.get("error")
        and "unsupported artifact scheme" in str(artifact_meta.get("error", "")).lower()
    )
    artifact_filename = _artifact_name(artifact_ref)
    name = str(options.get("artifact_name") or artifact_filename)
    ext = _artifact_ext(artifact_filename) or _artifact_ext(name)
    sha256 = str(artifact_meta.get("sha256") or "").strip() or (
        hashlib.sha256(artifact_bytes).hexdigest() if artifact_bytes else None
    )
    quarantine_path = str(artifact_meta.get("_quarantine_path") or "").strip()
    zip_info = (
        _inspect_complete_archive(quarantine_path, max_expanded_bytes=effective_artifact_bytes)
        if quarantine_path
        else _inspect_zip(artifact_bytes)
        if artifact_bytes[:4] == b"PK\x03\x04"
        else {"is_zip": False, "entries": []}
    )
    artifact_truncated = bool(artifact_meta.get("truncated"))
    inspection_truncated = bool(artifact_meta.get("inspection_truncated") or artifact_truncated)
    if artifact_truncated and artifact_bytes.startswith(b"PK\x03\x04") and not zip_info.get("is_archive"):
        zip_info = {
            **zip_info,
            "is_archive": True,
            "is_zip": True,
            "complete": False,
            "limit_reasons": ["artifact_truncated_before_archive_inventory"],
            "errors": [],
        }

    findings: list[dict[str, Any]] = []
    expected_sha256 = options.get("expected_sha256") or metadata.get("sha256")
    signature_url = options.get("signature_url") or metadata.get("signature_url") or metadata.get("signature")
    signed_by = metadata.get("signed_by") or metadata.get("attestation_signer")
    provenance_ref = _metadata_value(metadata, "source_repo", "source_repository", "commit_sha", "training_data_ref", "provenance_url", "attestation_url")
    model_card = options.get("model_card_url") or _metadata_value(metadata, "model_card_url", "model_card", "card_url")
    deployment_approved = _boolish(options.get("deployment_approved"))
    require_approval = _boolish(options.get("require_deployment_approval"))
    require_signature = _boolish(options.get("require_signature", True))
    require_hash = _boolish(options.get("require_hash", True))
    require_governance = _boolish(options.get("require_model_governance", True))
    deployment_environment = str(
        options.get("environment")
        or options.get("deployment_environment")
        or metadata.get("environment")
        or metadata.get("deployment_environment")
        or ""
    ).strip().lower()
    strict_governance = (
        _boolish(options.get("strict_governance"))
        or _boolish(metadata.get("strict_governance"))
        or _boolish(metadata.get("production_policy"))
        or deployment_environment == "production"
    )
    model_card_fetch_meta: dict[str, Any] = {}
    if isinstance(model_card, str) and urllib.parse.urlparse(model_card).scheme in {"http", "https"}:
        model_card_bytes, model_card_fetch_meta = await _fetch_artifact(
            model_card,
            max_bytes=2_000_000,
            timeout_seconds=timeout_seconds,
            allow_local_files=False,
            fetch_policy=fetch_policy,
        )
        model_card_fetch_meta = {
            **model_card_fetch_meta,
            "url": model_card,
            "content_sha256": hashlib.sha256(model_card_bytes).hexdigest() if model_card_bytes else None,
            "content_retained": False,
        }
    license_ref = _metadata_value(metadata, "license", "model_license", "license_url")
    sbom_ref = _metadata_value(metadata, "sbom_url", "sbom", "dependencies", "package_dependencies")
    malware_scan_ref = _metadata_value(metadata, "malware_scan_url", "malware_scan_result", "yara_scan", "av_scan")
    eval_ref = _metadata_value(metadata, "eval_report_url", "security_evals", "red_team_report", "eval_results")
    deployment_restrictions = _metadata_value(metadata, "deployment_restrictions", "allowed_environments", "use_restrictions")
    monitoring_plan = _metadata_value(metadata, "monitoring_plan", "monitoring_plan_url", "drift_monitoring", "incident_response_plan")
    training_data_ref = _metadata_value(metadata, "training_data_ref", "training_datasets", "datasets", "dataset_refs")
    dataset_digest = _metadata_value(metadata, "dataset_digest", "training_data_digest", "dataset_sha256", "training_data_sha256")
    base_model_ref = _metadata_value(metadata, "base_model", "base_models", "foundation_model")
    fine_tune_provenance = _metadata_value(metadata, "fine_tuning_job", "fine_tune_job", "training_run_id", "training_pipeline")
    poisoning_eval_ref = _metadata_value(metadata, "poisoning_evals", "backdoor_evals", "canary_eval_report", "data_poisoning_evals")
    repository_manifest = metadata.get("repository_manifest") if isinstance(metadata.get("repository_manifest"), dict) else {}
    repository_snapshot: dict[str, Any] = {
        "status": "SKIPPED_BY_POLICY",
        "complete": False,
        "requested": False,
    }
    if complete_repository_snapshot:
        if _source_kind(artifact_ref, metadata) != "huggingface":
            repository_snapshot = {
                "status": "UNSUPPORTED",
                "complete": False,
                "requested": True,
                "error": "complete_repository_snapshot_is_currently_supported_for_huggingface_only",
            }
        else:
            repository_snapshot = await _acquire_huggingface_repository_snapshot(
                metadata,
                artifact_ref=artifact_ref,
                timeout_seconds=timeout_seconds,
                quarantine_dir=quarantine_dir,
                fetch_policy=fetch_policy,
                max_repository_bytes=max_repository_bytes,
                max_repository_files=max_repository_files,
                selected_artifact_meta=artifact_meta,
            )
            repository_snapshot["requested"] = True
            if isinstance(repository_snapshot.get("repository_manifest"), dict):
                repository_manifest = repository_snapshot["repository_manifest"]
    await _emit_model_intake_activity(
        activity,
        event_callback,
        phase="repository_snapshot",
        progress=45,
        status=repository_snapshot.get("status"),
        complete=bool(repository_snapshot.get("complete")),
        files_expected=repository_snapshot.get("files_expected"),
        files_acquired=repository_snapshot.get("files_acquired"),
    )
    run_generated_scanners = _boolish(options.get("run_generated_scanners"))
    generated_evidence: dict[str, Any] = {
        "schema_version": "model-intake-generated-evidence/v1",
        "provenance_class": "shakerscan_generated",
        "status": "SKIPPED_BY_POLICY",
        "results": [],
        "statuses": {},
        "expectation_matrix": [],
        "required_non_pass": [],
    }
    if run_generated_scanners:
        subject_path: Path | None = None
        subject = {
            "kind": "repository_snapshot" if repository_snapshot.get("complete") else "model_artifact",
            "filename": name,
            "digest": (
                f"sha256:{repository_snapshot.get('snapshot_sha256')}"
                if repository_snapshot.get("complete")
                else f"sha256:{sha256}" if sha256 and not artifact_truncated else None
            ),
            "complete": bool(repository_snapshot.get("complete") or (artifact_meta.get("complete") and not artifact_truncated)),
        }
        scanner_results: list[dict[str, Any]] = []
        with TemporaryDirectory(prefix="model-intake-subject-") as subject_tmp:
            if repository_snapshot.get("complete"):
                try:
                    subject_path = _model_intake_scanners.materialize_snapshot_tree(
                        repository_snapshot,
                        quarantine_dir,
                        Path(subject_tmp) / "snapshot",
                    )
                except Exception as exc:
                    scanner_results.append(_model_intake_scanners._scanner_result(
                        name="subject-materialization",
                        version=None,
                        status="INCOMPLETE",
                        subject=subject,
                        started_at=datetime.now(timezone.utc).isoformat(),
                        finished_at=datetime.now(timezone.utc).isoformat(),
                        execution={"error": f"{type(exc).__name__}: {exc}", "required": True},
                    ))
            elif quarantine_path and Path(quarantine_path).is_file():
                safe_subject_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", Path(name).name).strip(".-") or "model-artifact.bin"
                materialized_artifact = Path(subject_tmp) / safe_subject_name
                shutil.copyfile(quarantine_path, materialized_artifact)
                os.chmod(materialized_artifact, 0o444)
                subject_path = materialized_artifact
            else:
                scanner_results.append(_model_intake_scanners._scanner_result(
                    name="subject-materialization",
                    version=None,
                    status="INCOMPLETE",
                    subject=subject,
                    started_at=datetime.now(timezone.utc).isoformat(),
                    finished_at=datetime.now(timezone.utc).isoformat(),
                    execution={"error": "complete_quarantine_subject_required", "required": True},
                ))

            if subject_path is not None:
                selected_snapshot_path = None
                if subject_path.is_dir() and metadata.get("huggingface_file"):
                    try:
                        selected_snapshot_path = _contained_snapshot_path(
                            subject_path,
                            metadata.get("huggingface_file"),
                        )
                    except ValueError:
                        scanner_results.append(_model_intake_scanners._scanner_result(
                            name="subject-selection",
                            version=None,
                            status="INCOMPLETE",
                            subject=subject,
                            started_at=datetime.now(timezone.utc).isoformat(),
                            finished_at=datetime.now(timezone.utc).isoformat(),
                            execution={"error": "selected_artifact_path_escapes_snapshot", "required": True},
                        ))
                artifact_scan_path = (
                    selected_snapshot_path
                    if selected_snapshot_path is not None and selected_snapshot_path.is_file()
                    else subject_path
                )
                scanner_results.append(await asyncio.to_thread(
                    _model_intake_scanners.run_builtin_pickle_scan, artifact_scan_path, subject,
                ))
                scanner_results.append(
                    await asyncio.to_thread(
                        _model_intake_scanners.run_builtin_source_scan,
                        subject_path if subject_path.is_dir() else None,
                        subject,
                    )
                )
                for builtin_scanner in (
                    _model_intake_scanners.run_builtin_secret_scan,
                    _model_intake_scanners.run_builtin_malware_scan,
                    _model_intake_scanners.run_builtin_sbom_scan,
                    _model_intake_scanners.run_builtin_binary_inventory,
                    _model_intake_scanners.run_builtin_license_inventory,
                ):
                    scanner_results.append(await asyncio.to_thread(builtin_scanner, subject_path, subject))
                requested_scanners = options.get("generated_scanner_names")
                requested_names = {
                    str(item).strip()
                    for item in requested_scanners
                    if str(item).strip()
                } if isinstance(requested_scanners, list) else None
                scanner_plan = _model_intake_scanners.resolve_scanner_plan(
                    subject_path,
                    requested_names=requested_names,
                    profile="strict" if strict_governance else "baseline",
                )
                registered_names = {
                    spec.name for spec in _model_intake_scanners.EXTERNAL_SCANNERS
                } | _model_intake_scanners.BUILTIN_SCANNER_NAMES
                for unknown_name in sorted((requested_names or set()) - registered_names):
                    scanner_results.append(_model_intake_scanners._scanner_result(
                        name=unknown_name,
                        version=None,
                        status="UNSUPPORTED",
                        subject=subject,
                        started_at=datetime.now(timezone.utc).isoformat(),
                        finished_at=datetime.now(timezone.utc).isoformat(),
                        execution={
                            "required": True,
                            "reason": "unknown_scanner_adapter",
                            "adapter_kind": "evidence_scanner",
                        },
                    ))
                for planned in scanner_plan:
                    spec = planned["spec"]
                    if not planned["applicable"]:
                        scanner_results.append(_model_intake_scanners._scanner_result(
                            name=spec.name,
                            version=None,
                            status="NOT_APPLICABLE",
                            subject=subject,
                            started_at=datetime.now(timezone.utc).isoformat(),
                            finished_at=datetime.now(timezone.utc).isoformat(),
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
                    scan_target = artifact_scan_path if spec.target_scope == "artifact" else subject_path
                    scanner_results.append(
                        await asyncio.to_thread(
                            _model_intake_scanners.run_external_scanner,
                            spec,
                            scan_target,
                            subject,
                        )
                    )
        generated_summary = _model_intake_scanners.generated_evidence_summary(scanner_results)
        required_non_pass_results = [
            item for item in scanner_results
            if item.get("execution", {}).get("status") in _model_intake_scanners.REQUIRED_NON_PASS_STATUSES
            and bool(item.get("execution", {}).get("required"))
        ]
        generated_evidence = {
            **generated_summary,
            "status": (
                "PASS" if not required_non_pass_results
                else "REVIEW_REQUIRED" if all(
                    item.get("execution", {}).get("status") == "WARNING"
                    for item in required_non_pass_results
                )
                else "FAIL"
            ),
        }
    await _emit_model_intake_activity(
        activity,
        event_callback,
        phase="generated_scanners",
        progress=60,
        status=generated_evidence.get("status"),
        generated_scanners=generated_evidence.get("status"),
    )
    run_dynamic_sandbox = _boolish(options.get("run_dynamic_sandbox"))
    require_dynamic_sandbox = _boolish(options.get("require_dynamic_sandbox"))
    dynamic_sandbox: dict[str, Any] = {
        "schema_version": "model-intake-sandbox/v1",
        "provenance_class": "shakerscan_generated",
        "status": "SKIPPED_BY_POLICY",
    }
    if run_dynamic_sandbox or require_dynamic_sandbox:
        quarantine_object = str(artifact_meta.get("quarantine_object") or "")
        if not quarantine_object or artifact_truncated or not artifact_meta.get("complete"):
            dynamic_sandbox = {
                **dynamic_sandbox,
                "status": "INCOMPLETE",
                "error": "complete_quarantined_artifact_required",
            }
        else:
            sandbox_root = Path(str(options.get("sandbox_queue_dir") or os.getenv("MODEL_INTAKE_SANDBOX_QUEUE_DIR") or "/results/model-intake-sandbox"))
            dynamic_sandbox = await asyncio.to_thread(
                _request_sandbox_analysis,
                quarantine_object,
                _sandbox_artifact_filename(artifact_ref or "", metadata, artifact_meta),
                queue_root=sandbox_root,
                timeout_seconds=bounded_int("sandbox_timeout_seconds", 120, 1, 600),
            )
    await _emit_model_intake_activity(
        activity,
        event_callback,
        phase="dynamic_sandbox",
        progress=70,
        status=dynamic_sandbox.get("status"),
        sandbox=dynamic_sandbox.get("status"),
    )
    metadata_unavailable = bool(metadata_url and metadata_fetch_meta.get("error") and not metadata)
    require_signature_verification = _boolish(options.get("require_signature_verification"))
    require_cryptographic_signature_verification = _boolish(
        options.get("require_cryptographic_signature_verification")
        or metadata.get("require_cryptographic_signature_verification")
    )
    registry_reference = _registry_reference(artifact_ref, metadata)
    source_adapter = _adapter_capabilities(_source_kind(artifact_ref, metadata))
    crypto_signature_result = await _load_and_verify_signature(
        options, metadata, signature_url, artifact_bytes, sha256,
        timeout_seconds=timeout_seconds,
        allow_local_files=allow_local_files,
        fetch_policy=fetch_policy,
        artifact_payload_complete=not inspection_truncated,
        artifact_subject_complete=bool(artifact_meta.get("complete")) or not artifact_truncated,
    )
    signature_status = _signature_verification_status(metadata, signature_url, signed_by, crypto_signature_result)
    attestation_bundle = options.get("attestation_bundle_json") or metadata.get("attestation_bundle_json")
    require_attestation_verification = _boolish(options.get("require_attestation_verification"))
    require_transparency_log = _boolish(options.get("require_transparency_log"))
    attestation_verification = _verify_dsse_in_toto(
        attestation_bundle,
        subject_sha256=sha256,
        subject_complete=bool(artifact_meta.get("complete")) or not artifact_truncated,
        trusted_public_keys=options.get("attestation_trusted_keys") or options.get("signature_trusted_keys"),
        trusted_key_sha256=options.get("attestation_trusted_key_sha256") or options.get("signature_trusted_key_sha256"),
        allowed_predicate_types=options.get("allowed_attestation_predicate_types"),
        required_builder_ids=options.get("required_attestation_builder_ids"),
        require_transparency_log=require_transparency_log,
    ) if attestation_bundle else {
        "schema_version": "model-intake-attestation/v1",
        "provenance_class": "declared",
        "status": "FAIL" if require_attestation_verification or require_transparency_log else "SKIPPED_BY_POLICY",
        "verified": False,
        "transparency_log_verified": False,
        "transparency_log_status": "UNSUPPORTED",
        "blockers": [
            blocker for required, blocker in (
                (require_attestation_verification, "attestation_bundle_required"),
                (require_transparency_log, "transparency_log_proof_required"),
            ) if required
        ],
    }
    license_policy = _license_policy(license_ref)
    generated_results = generated_evidence.get("results") if isinstance(generated_evidence.get("results"), list) else []
    generated_sbom_result = next(
        (item for item in generated_results if item.get("scanner", {}).get("name") == "shakerscan-sbom"),
        None,
    )
    generated_malware_result = next(
        (item for item in generated_results if item.get("scanner", {}).get("name") == "shakerscan-malware-rules"),
        None,
    )
    generated_sbom = (
        generated_sbom_result.get("summary", {}).get("sbom")
        if generated_sbom_result and generated_sbom_result.get("execution", {}).get("status") in {"PASS", "WARNING"}
        else None
    )
    generated_malware = None
    if generated_malware_result and generated_malware_result.get("execution", {}).get("status") == "PASS":
        generated_malware = {
            "status": "clean",
            "scanner": generated_malware_result.get("scanner", {}).get("name"),
            "engine_version": generated_malware_result.get("scanner", {}).get("version"),
            "timestamp": generated_malware_result.get("execution", {}).get("finished_at"),
            "artifact_digest": generated_malware_result.get("subject", {}).get("digest"),
            "provenance_class": "shakerscan_generated",
        }
    evaluation_spec = options.get("evaluation_spec_json")
    precomputed_evaluation = options.get("generated_evaluation_report")
    run_generated_evaluation = _boolish(options.get("run_generated_evaluation")) or isinstance(evaluation_spec, dict)
    require_generated_evaluation = _boolish(options.get("require_generated_evaluation"))
    generated_evaluation = (
        _verify_model_intake_evaluation(
            precomputed_evaluation,
            artifact_sha256=sha256 if sha256 and not artifact_truncated else None,
        )
        if isinstance(precomputed_evaluation, dict)
        else _evaluate_model_intake(
            evaluation_spec,
            artifact_sha256=sha256 if sha256 and not artifact_truncated else None,
        )
        if run_generated_evaluation or require_generated_evaluation
        else {
            "schema_version": "model-intake-evaluation/v1",
            "provenance_class": "shakerscan_generated",
            "status": "SKIPPED_BY_POLICY",
        }
    )
    await _emit_model_intake_activity(
        activity,
        event_callback,
        phase="trust_and_evaluation",
        progress=85,
        status="COMPLETE" if not artifact_meta.get("error") else "FAILED",
        signature=signature_status.get("status"),
        attestation=attestation_verification.get("status"),
        evaluation=generated_evaluation.get("status"),
    )
    effective_sbom_evidence = generated_sbom or sbom_ref
    sbom_policy = _sbom_policy(
        effective_sbom_evidence,
        strict=strict_governance,
        trusted_provenance=bool(generated_sbom),
    )
    try:
        malware_scan_max_age_days = int(options.get("malware_scan_max_age_days") or metadata.get("malware_scan_max_age_days") or 30)
    except (TypeError, ValueError):
        malware_scan_max_age_days = 30
    effective_malware_evidence = generated_malware or malware_scan_ref
    malware_policy = _malware_policy(
        effective_malware_evidence,
        strict=strict_governance,
        expected_sha256=(
            repository_snapshot.get("snapshot_sha256")
            if generated_malware and repository_snapshot.get("complete")
            else sha256 or expected_sha256
        ),
        max_age_days=malware_scan_max_age_days,
        trusted_provenance=bool(generated_malware),
    )
    effective_eval_evidence = generated_evaluation if generated_evaluation.get("status") != "SKIPPED_BY_POLICY" else eval_ref
    eval_policy = _eval_policy(
        effective_eval_evidence,
        strict=strict_governance,
        expected_sha256=sha256 or expected_sha256,
        trusted_provenance=effective_eval_evidence is generated_evaluation,
    )
    approval_policy = _approval_policy(metadata, deployment_approved=deployment_approved, strict=strict_governance)
    artifact_size, artifact_size_source = _artifact_size_for_inspection(
        artifact_meta,
        metadata,
        artifact_bytes,
        truncated=artifact_truncated,
    )
    format_inspection = _inspect_format(
        name,
        ext,
        artifact_bytes,
        zip_info,
        artifact_truncated=inspection_truncated,
        artifact_size=artifact_size,
        artifact_size_source=artifact_size_source,
    )
    suspicious_loader_markers = _scan_suspicious_loader_markers(
        artifact_bytes,
        zip_info,
        extension=ext,
    )
    # An AIBOM hash is generated evidence only when it covers the complete
    # observed artifact. Keep publisher/caller claims in a distinct field.
    aibom_hash = str(sha256 or "").strip() if sha256 and not artifact_truncated else None
    aibom = _generate_aibom(
        artifact_ref=artifact_ref,
        name=name,
        ext=ext,
        sha256=aibom_hash,
        metadata=metadata,
        registry=registry_reference,
        license_ref=license_ref,
        signature_status=signature_status,
        format_inspection=format_inspection,
    )
    aibom["declared_artifact_hash"] = (
        {"alg": "SHA-256", "content": str(expected_sha256).strip().lower(), "provenance_class": "declared"}
        if expected_sha256 else None
    )
    aibom["observed_artifact_hash"] = (
        {"alg": "SHA-256", "content": aibom_hash, "provenance_class": "shakerscan_generated", "scope": "full_artifact"}
        if aibom_hash else None
    )

    if metadata_fetch_meta.get("error"):
        findings.append(_finding(
            finding_id="metadata_fetch_failed",
            title="Model intake metadata could not be fetched",
            severity="high",
            description="The model intake metadata URL could not be read or parsed, so metadata-backed governance checks are indeterminate.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_url": str(metadata_url), "metadata_fetch": metadata_fetch_meta},
            remediation="Make the metadata URL reachable and return a JSON object, or provide equivalent metadata_json directly in the intake request.",
        ))

    if strict_governance and model_card_fetch_meta.get("error"):
        findings.append(_finding(
            finding_id="model_card_fetch_failed",
            title="Model card could not be acquired",
            severity="medium",
            description="The declared model-card URL could not be acquired through the hardened intake fetcher, so its contents were not reviewed.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "model_card_url": model_card, "model_card_fetch": model_card_fetch_meta},
            remediation="Publish the model card at an approved reachable HTTPS destination and rerun intake.",
        ))

    if (require_attestation_verification or require_transparency_log) and not attestation_verification.get("verified"):
        findings.append(_finding(
            finding_id="attestation_not_verified",
            title="Model provenance attestation did not pass verification",
            severity="high",
            description="Policy requires an offline-verifiable DSSE in-toto attestation bound to the exact complete artifact digest and an operator-trusted signing key.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "attestation": attestation_verification},
            remediation="Provide a DSSE in-toto/SLSA statement signed by an allowed key, with the exact artifact SHA-256 subject and required builder/transparency evidence.",
        ))

    if require_dynamic_sandbox and dynamic_sandbox.get("status") != "PASS":
        sandbox_status = str(dynamic_sandbox.get("status") or "NOT_RUN")
        sandbox_remediation = (
            "Convert in a no-egress sandbox to safetensors or another non-executable format, then verify "
            "tensor equivalence and rerun intake. If a temporary exception is approved, bind it to a "
            "digest and an isolated weights-only loader."
            if sandbox_status == "BLOCKED_BY_POLICY"
            else "Run the exact quarantined artifact through the no-network sandbox and resolve all format, "
            "runtime, isolation, or resource failures."
        )
        findings.append(_finding(
            finding_id="dynamic_sandbox_non_pass",
            title="Required no-egress model sandbox did not pass",
            severity="high",
            description=f"The isolated dynamic inspection ended with status {sandbox_status}; unsupported, blocked, timed-out, crashed, and incomplete runs never count as approval evidence.",
            artifact_ref=artifact_ref,
            evidence={"sandbox": dynamic_sandbox},
            remediation=sandbox_remediation,
        ))

    if require_generated_evaluation and generated_evaluation.get("status") != "PASS":
        findings.append(_finding(
            finding_id="generated_evaluation_non_pass",
            title="Required model and data-plane evaluation did not pass",
            severity="high",
            description=f"The provider-neutral embedding, retrieval, authorization, graph, deletion, stability, poisoning, or capacity evaluation ended with status {generated_evaluation.get('status')}.",
            artifact_ref=artifact_ref,
            evidence={
                "evaluation_status": generated_evaluation.get("status"),
                "evaluation_evidence_sha256": generated_evaluation.get("evidence_sha256"),
                "blockers": generated_evaluation.get("blockers", []),
            },
            remediation="Run the versioned corporate evaluation suite against the exact artifact and intended data plane, then meet every predeclared threshold.",
        ))

    require_signed_admission = _boolish(options.get("require_signed_admission"))
    if require_signed_admission:
        findings.append(_finding(
            finding_id="admission_control_plane_required",
            title="Dedicated Model Intake admission control plane is required",
            severity="high",
            description=(
                "The evidence-producing worker generated a technical decision candidate but is intentionally "
                "unable to sign or register a deployable admission. A separate control-plane service must "
                "verify frozen evidence, policy, and approvals before invoking a narrow signer."
            ),
            artifact_ref=artifact_ref,
            evidence={"worker_signing_authority": False, "dedicated_admission_service": "NOT_IMPLEMENTED"},
            remediation="Submit the frozen evidence manifest to the dedicated admission service when that release gate is available; never install an admission private key in a scanner worker.",
        ))
    if require_signed_admission and (not sha256 or artifact_truncated):
        findings.append(_finding(
            finding_id="admission_subject_incomplete",
            title="Required admission statement has no complete artifact subject",
            severity="high",
            description="A deployable admission must bind to the SHA-256 of the complete artifact; a missing or prefix-only digest cannot authorize model loading.",
            artifact_ref=artifact_ref,
            evidence={"sha256_present": bool(sha256), "artifact_truncated": artifact_truncated},
            remediation="Enable complete artifact acquisition, retain the content-addressed object, and rerun intake before admission.",
        ))

    if artifact_meta.get("error"):
        if unsupported_scheme_error:
            findings.append(_finding(
                finding_id="unsupported_artifact_scheme",
                title="Model artifact scheme is unsupported",
                severity="high",
                description="The configured artifact URL uses a registry scheme not currently supported by the intake fetcher.",
                artifact_ref=artifact_ref,
                evidence={"artifact": name, "fetch": artifact_meta},
                remediation="Use a fetchable artifact source or configure a registry fetcher for Hugging Face, OCI, S3/GCS/Azure Blob, or the internal model gateway.",
            ))
        else:
            findings.append(_finding(
                finding_id="artifact_fetch_failed",
                title="Model artifact could not be fetched for intake",
                severity="high",
                description="The model artifact could not be downloaded or read, so provenance and serialization checks could not complete.",
                artifact_ref=artifact_ref,
                evidence={"artifact": name, "fetch": artifact_meta},
                remediation="Make the model artifact reachable to the intake worker or provide an internal registry reference with access credentials.",
            ))

    if repository_manifest and not repository_manifest.get("complete"):
        findings.append(_finding(
            finding_id="repository_manifest_incomplete",
            title="Model repository manifest is incomplete or unsafe",
            severity="high",
            description="The pinned repository inventory was truncated or contains invalid, duplicate, or case-colliding paths.",
            artifact_ref=artifact_ref,
            evidence={
                "manifest_sha256": repository_manifest.get("manifest_sha256"),
                "files_discovered": repository_manifest.get("files_discovered"),
                "files_recorded": repository_manifest.get("files_recorded"),
                "truncated_by_limit": repository_manifest.get("truncated_by_limit"),
                "invalid_paths": repository_manifest.get("invalid_paths") or [],
                "duplicate_paths": repository_manifest.get("duplicate_paths") or [],
                "case_collisions": repository_manifest.get("case_collisions") or [],
            },
            remediation="Reject the repository until every path is normalized, unique, and represented in a complete immutable manifest.",
        ))

    if zip_info.get("is_archive") and not zip_info.get("complete", True):
        findings.append(_finding(
            finding_id="archive_inspection_incomplete",
            title="Model archive inspection did not complete",
            severity="high",
            description="The complete artifact exceeded a recursive archive safety budget or contained an unreadable nested archive.",
            artifact_ref=artifact_ref,
            evidence={"archive": zip_info},
            remediation="Reject the package, reduce archive nesting/expansion, and rerun until every member is inventoried within policy bounds.",
        ))

    if zip_info.get("path_traversal_entries") or zip_info.get("archive_link_entries") or zip_info.get("archive_device_entries"):
        findings.append(_finding(
            finding_id="unsafe_archive_members",
            title="Model archive contains unsafe extraction members",
            severity="critical",
            description="The archive contains traversal paths, links, or device/FIFO entries that must never be extracted into a runtime filesystem.",
            artifact_ref=artifact_ref,
            evidence={
                "path_traversal_entries": zip_info.get("path_traversal_entries") or [],
                "archive_link_entries": zip_info.get("archive_link_entries") or [],
                "archive_device_entries": zip_info.get("archive_device_entries") or [],
            },
            remediation="Remove unsafe members and republish a flat, immutable package before intake.",
        ))

    if repository_manifest.get("custom_code_required"):
        semgrep_result = next(
            (
                item for item in generated_evidence.get("results") or []
                if item.get("scanner", {}).get("name") == "semgrep"
            ),
            {},
        )
        semgrep_status = str(semgrep_result.get("execution", {}).get("status") or "NOT_RUN")
        findings.append(_finding(
            finding_id="custom_model_code_requires_review",
            title="Model repository contains custom executable code",
            severity=(
                "high" if semgrep_status in {"FAIL", "INCOMPLETE", "CRASHED", "UNSUPPORTED", "NOT_RUN"} and strict_governance
                else "medium"
            ),
            description=(
                f"The repository contains executable files that can run during model or tokenizer loading. Semgrep finished with {semgrep_status}; static analysis does not replace recorded human ownership and review."
            ),
            artifact_ref=artifact_ref,
            evidence={
                "manifest_sha256": repository_manifest.get("manifest_sha256"),
                "auto_map": repository_manifest.get("auto_map"),
                "python_files": (repository_manifest.get("python_files") or [])[:100],
                "executable_files": (repository_manifest.get("executable_files") or [])[:100],
                "semgrep_status": semgrep_status,
                "semgrep_evidence_sha256": semgrep_result.get("evidence_sha256"),
            },
            remediation=(
                "Resolve Semgrep blockers, record a human review of every executable repository file, and load only in a no-egress pinned runtime."
                if semgrep_status == "FAIL"
                else "Record a human review of every executable repository file, constrain the exact digest to a no-egress runtime, and document accepted warning paths."
            ),
        ))

    if complete_repository_snapshot and not repository_snapshot.get("complete"):
        findings.append(_finding(
            finding_id="repository_snapshot_incomplete",
            title="Complete model repository snapshot acquisition failed",
            severity="high",
            description="The requested immutable repository snapshot was unsupported, exceeded a bound, failed integrity verification, or did not acquire every manifest file.",
            artifact_ref=artifact_ref,
            evidence={
                "status": repository_snapshot.get("status"),
                "error": repository_snapshot.get("error"),
                "files_expected": repository_snapshot.get("files_expected"),
                "files_acquired": repository_snapshot.get("files_acquired"),
                "bytes_acquired": repository_snapshot.get("bytes_acquired"),
                "failures": repository_snapshot.get("failures") or [],
            },
            remediation="Retry from an immutable supported registry revision with sufficient file/byte quota and resolve every failed file before approval.",
        ))

    if run_generated_scanners:
        for scanner_result in generated_evidence.get("results") or []:
            scanner_name = str(scanner_result.get("scanner", {}).get("name") or "unknown")
            scanner_status = str(scanner_result.get("execution", {}).get("status") or "CRASHED")
            required = bool(scanner_result.get("execution", {}).get("required"))
            review_remediation = (
                "Review the digest-bound scanner findings, document a disposition for the exact subject, "
                "and rerun after any required remediation."
            )
            if scanner_status in _model_intake_scanners.REQUIRED_NON_PASS_STATUSES and required:
                reviewable = scanner_status in {"WARNING", "REVIEW_REQUIRED"}
                findings.append(_finding(
                    finding_id=f"generated_scanner_{re.sub(r'[^a-z0-9]+', '_', scanner_name.lower()).strip('_')}_non_pass",
                    title=(
                        f"Required generated scanner requires review: {scanner_name}"
                        if reviewable else f"Required generated scanner did not pass: {scanner_name}"
                    ),
                    severity="medium" if reviewable else "high",
                    description=(
                        f"The required scanner completed with normalized status {scanner_status}; its exact "
                        "digest-bound findings require an explicit review disposition."
                        if reviewable else
                        f"The required scanner ended with normalized status {scanner_status}; missing, crashed, "
                        "timed-out, unsupported, and incomplete execution never counts as a pass."
                    ),
                    artifact_ref=artifact_ref,
                    evidence={
                        "scanner": scanner_result.get("scanner"),
                        "execution": scanner_result.get("execution"),
                        "coverage": scanner_result.get("coverage"),
                        "evidence_sha256": scanner_result.get("evidence_sha256"),
                    },
                    remediation=(
                        review_remediation
                        if reviewable else
                        "Install and pin the scanner, restore its rules/database, and rerun it against the same "
                        "complete subject until it produces a valid PASS or reviewed finding result."
                    ),
                ))
            if scanner_status in {"FAIL", "WARNING", "INCOMPLETE"} and scanner_result.get("findings"):
                findings.append(_finding(
                    finding_id=f"generated_scanner_{re.sub(r'[^a-z0-9]+', '_', scanner_name.lower()).strip('_')}_findings",
                    title=f"Generated scanner reported model-intake concerns: {scanner_name}",
                    severity="high" if scanner_status == "FAIL" else "medium",
                    description="A ShakerScan-generated scanner result contains policy-relevant findings that require resolution or review.",
                    artifact_ref=artifact_ref,
                    evidence={
                        "scanner": scanner_result.get("scanner"),
                        "status": scanner_status,
                        "findings": (scanner_result.get("findings") or [])[:100],
                        "evidence_sha256": scanner_result.get("evidence_sha256"),
                    },
                    remediation=(
                        review_remediation
                        if scanner_status == "WARNING" else
                        "Review the digest-bound raw scanner evidence, remove or replace the unsafe content, "
                        "and rerun the complete intake."
                    ),
                ))

    checksum_status = "missing"
    if expected_sha256 and sha256 and not artifact_truncated and str(expected_sha256).lower() == sha256.lower():
        checksum_status = "verified"
    elif expected_sha256 and sha256 and artifact_truncated:
        checksum_status = "known_unverified_truncated"
    elif expected_sha256:
        checksum_status = "provided_unverified"

    if expected_sha256 and sha256 and not artifact_truncated and str(expected_sha256).lower() != sha256.lower():
        checksum_status = "mismatch"
        findings.append(_finding(
            finding_id="sha256_mismatch",
            title="Model artifact checksum mismatch",
            severity="critical",
            description="The observed model artifact hash does not match the expected SHA-256 value.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "expected_sha256": expected_sha256, "observed_sha256": sha256},
            remediation="Block deployment, verify the source registry, and re-publish the artifact with a trusted checksum.",
        ))
    elif expected_sha256 and sha256 and artifact_truncated:
        findings.append(_finding(
            finding_id="checksum_not_fully_verified",
            title="Model artifact checksum available but not fully verified",
            severity="medium" if require_hash else "info",
            description="A full-artifact SHA-256 value was supplied, but intake only inspected a byte range due to the configured download cap.",
            artifact_ref=artifact_ref,
            evidence={
                "artifact": name,
                "expected_sha256": expected_sha256,
                "observed_sha256": sha256,
                "observed_scope": "inspected_bytes",
                "bytes_observed": artifact_meta.get("bytes_observed"),
                "download_limit": max_download_bytes,
            },
            remediation="Increase the download cap to verify the full artifact, or rely on registry digest/signature evidence as the release pin.",
        ))
    elif require_hash and expected_sha256 and not sha256 and not metadata_unavailable and not artifact_meta.get("error"):
        findings.append(_finding(
            finding_id="checksum_not_verified",
            title="Model artifact checksum could not be verified",
            severity="medium",
            description="A full-artifact SHA-256 value was supplied, but intake could not observe artifact bytes to verify it.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "expected_sha256": expected_sha256, "fetch": artifact_meta},
            remediation="Make the model artifact reachable to intake or verify the digest through a trusted registry/signature verifier before deployment.",
        ))
    elif require_hash and not expected_sha256 and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_checksum",
            title="Model artifact missing expected checksum",
            severity="medium",
            description="No expected checksum was supplied for the model artifact, limiting integrity verification.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "observed_sha256": sha256},
            remediation="Require SHA-256 or stronger digest pinning in model intake metadata before deployment approval.",
        ))

    if require_signature and not (signature_url or signed_by) and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_signature",
            title="Model artifact missing signature or attestation",
            severity="medium",
            description="The model artifact did not include a signature, signer, or provenance attestation reference.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "signature_url": signature_url, "signed_by": signed_by},
            remediation="Require Sigstore, registry signing, or an equivalent signed attestation for deployable model artifacts.",
        ))

    # A present-but-invalid signature (real verifier ran and rejected it) is a red
    # flag regardless of policy flags — surface it as high severity.
    if signature_status["status"] == "invalid" and not metadata_unavailable:
        findings.append(_finding(
            finding_id="signature_invalid",
            title="Model artifact signature failed cryptographic verification",
            severity="high",
            description="A detached signature was present and the cryptographic verifier rejected it against the artifact/digest and supplied public key.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "signature": signature_status},
            remediation="Do not deploy. Re-sign the artifact with the correct key, or correct the public key / payload (artifact vs digest) used for verification.",
        ))

    if signature_status["status"] == "subject_digest_mismatch" and not metadata_unavailable:
        findings.append(_finding(
            finding_id="signature_subject_digest_mismatch",
            title="Signature subject digest does not match the acquired artifact",
            severity="critical",
            description="The signature math passed, but the expected signed subject digest is not the SHA-256 digest of the complete acquired artifact.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "signature": signature_status, "observed_sha256": sha256, "expected_sha256": expected_sha256},
            remediation="Block deployment and issue a new signature or attestation bound to the exact quarantined artifact digest.",
        ))

    effective_require_verification = require_signature_verification or require_cryptographic_signature_verification
    untrusted_signature = signature_status["status"] in {"untrusted_key", "untrusted_root"}
    if (
        effective_require_verification
        and signature_status["status"] in {"present_unverified", "claimed_verified", "untrusted_key", "untrusted_root", "subject_digest_mismatch"}
        and not metadata_unavailable
    ):
        crypto_strict = require_cryptographic_signature_verification
        if untrusted_signature:
            description = (
                "A detached signature is cryptographically valid, but the signing key does not chain to "
                "a configured trust anchor, so the artifact's provenance is untrusted (it may be self-signed). "
                "Trusted verification requires an operator-configured trust root."
            )
        elif crypto_strict:
            description = (
                "Policy requires cryptographic signature verification, but intake could not verify the "
                "signature; only a metadata claim is present."
            )
        else:
            description = (
                "The artifact has signature or attestation metadata, but intake does not have cryptographic verification evidence."
            )
        findings.append(_finding(
            finding_id="signature_not_verified",
            title="Model artifact signature is present but not cryptographically verified",
            severity="high" if (crypto_strict or untrusted_signature) else "medium",
            description=description,
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "signature": signature_status},
            remediation=(
                "Configure a trusted signing key (signature_trusted_keys / signature_trusted_key_sha256 or the "
                "MODEL_INTAKE_TRUSTED_* environment variables) and re-sign with a key that chains to it."
                if untrusted_signature
                else "Provide a public key (signature_public_key/_url) and detached signature (signature_value/signature_url) so intake can run real cryptographic verification, or verify with Sigstore/cosign and record the verifier result."
            ),
        ))

    risky_ext = ext in RISKY_EXTENSIONS
    pickle_like, pickle_detection_method = _pickle_detection(artifact_bytes, ext)
    zip_pickle_entries = zip_info.get("pickle_entries") or []
    zip_risky_entries = zip_info.get("risky_entries") or []
    if risky_ext or pickle_like or zip_pickle_entries:
        pickle_scanner = next(
            (
                item for item in generated_evidence.get("results") or []
                if item.get("scanner", {}).get("name") == "python-pickletools"
            ),
            {},
        )
        pickle_semantic_classification = str(
            pickle_scanner.get("summary", {}).get("semantic_classification") or "not_run"
        )
        proven_dangerous_pickle = pickle_semantic_classification == "dangerous_callable_detected"
        expected_framework_pickle = pickle_semantic_classification == "expected_framework_pickle"
        findings.append(_finding(
            finding_id="unsafe_serialization",
            title=(
                "Dangerous callable detected in executable model serialization"
                if proven_dangerous_pickle
                else "Executable model serialization requires conversion or isolated loading"
            ),
            severity=(
                "critical"
                if proven_dangerous_pickle
                else "high"
                if expected_framework_pickle or zip_pickle_entries or risky_ext
                else "critical"
                if pickle_detection_method in {"protocol_magic", "pickletools_semantic"}
                else "high"
            ),
            description=(
                "Semantic pickle analysis resolved a callable associated with command execution or another dangerous capability."
                if proven_dangerous_pickle
                else "No known malicious callable was proven, but this framework/pickle format remains executable-capable and is prohibited by the default corporate admission policy."
                if expected_framework_pickle
                else "The model artifact uses executable-capable serialization and semantic classification is incomplete or still requires review."
            ),
            artifact_ref=artifact_ref,
            evidence={
                "artifact": name,
                "extension": ext,
                "pickle_like_header": pickle_like,
                "pickle_detection_method": pickle_detection_method,
                "pickle_semantic_classification": pickle_semantic_classification,
                "malicious_primitive_proven": proven_dangerous_pickle,
                "zip_pickle_entries": zip_pickle_entries,
                "risky_entries": zip_risky_entries,
            },
            remediation=(
                "Reject the artifact, remove the dangerous callable, and rebuild from a trusted source into a non-executable format."
                if proven_dangerous_pickle
                else "Convert in a no-egress sandbox to safetensors or another non-executable format, then verify tensor equivalence and rerun intake. If a temporary exception is approved, bind it to a digest and an isolated weights-only loader."
            ),
        ))

    safetensors_header = format_inspection.get("safetensors_header") if isinstance(format_inspection.get("safetensors_header"), dict) else {}
    if ext == ".safetensors" and artifact_bytes and safetensors_header.get("conclusive_invalid"):
        findings.append(_finding(
            finding_id="safetensors_header_invalid",
            title="Safetensors header failed structural validation",
            severity="high",
            description="The safetensors header is missing, malformed, truncated, has duplicate keys, overlapping tensor ranges, or tensor offsets outside the payload.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "safetensors_header": safetensors_header},
            remediation="Reject malformed safetensors artifacts and re-export from a trusted conversion pipeline with valid tensor offsets.",
        ))
    if safetensors_header.get("suspicious_metadata_keys"):
        findings.append(_finding(
            finding_id="safetensors_suspicious_metadata",
            title="Safetensors metadata contains risky runtime hints",
            severity="medium",
            description="The safetensors metadata includes prompt, credential, remote-code, or tool-template markers that should be reviewed before deployment.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "safetensors_header": safetensors_header},
            remediation="Remove sensitive or behavior-changing metadata and review tokenizer/chat-template configuration separately from tensor artifacts.",
        ))

    onnx_inspection = format_inspection.get("onnx") if isinstance(format_inspection.get("onnx"), dict) else {}
    if onnx_inspection.get("external_data_hint"):
        findings.append(_finding(
            finding_id="onnx_external_data_reference",
            title="ONNX artifact references external tensor data",
            severity="medium",
            description="The ONNX artifact appears to reference external data, which can move executable or model-critical content outside the inspected artifact.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "onnx": onnx_inspection},
            remediation="Bundle and hash external tensor data, reject absolute/remote locations, and verify the complete model directory before deployment.",
        ))
    if onnx_inspection.get("custom_operator_hint"):
        findings.append(_finding(
            finding_id="onnx_custom_operator",
            title="ONNX artifact may require custom operators",
            severity="medium",
            description="The ONNX artifact contains custom-operator hints that may require privileged runtime extensions.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "onnx": onnx_inspection},
            remediation="Review custom operator implementations and load the model only in a restricted runtime with approved extensions.",
        ))

    gguf_inspection = format_inspection.get("gguf") if isinstance(format_inspection.get("gguf"), dict) else {}
    if ext == ".gguf" and artifact_bytes and not gguf_inspection.get("valid_header"):
        findings.append(_finding(
            finding_id="gguf_header_invalid",
            title="GGUF artifact header is invalid or unsupported",
            severity="high",
            description="The GGUF artifact does not have a valid GGUF magic/version header, so intake cannot trust its model metadata.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "gguf": gguf_inspection},
            remediation="Reject malformed GGUF artifacts and require a valid GGUF export from a trusted build pipeline.",
        ))
    if gguf_inspection.get("suspicious_metadata_strings"):
        findings.append(_finding(
            finding_id="gguf_suspicious_metadata",
            title="GGUF metadata contains risky URLs or templates",
            severity="medium",
            description="The GGUF metadata includes URLs or prompt/tool template strings that can indicate unexpected runtime behavior.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "gguf": gguf_inspection},
            remediation="Review tokenizer templates, embedded URLs, and metadata provenance before approving the artifact.",
        ))

    executable_entries = zip_info.get("executable_entries") or []
    if executable_entries:
        findings.append(_finding(
            finding_id="embedded_executable",
            title="Model artifact contains executable payloads",
            severity="high",
            description="The artifact archive includes executable files or scripts that should not be present in a model artifact.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "executable_entries": executable_entries},
            remediation="Block deployment pending malware analysis and require a clean re-packaged artifact.",
        ))

    path_traversal_entries = zip_info.get("path_traversal_entries") or []
    if path_traversal_entries:
        findings.append(_finding(
            finding_id="archive_path_traversal",
            title="Model archive contains path traversal entries",
            severity="high",
            description="The model archive contains absolute or parent-directory paths that could overwrite files when extracted unsafely.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "path_traversal_entries": path_traversal_entries},
            remediation="Reject the artifact and require a package with normalized relative paths only.",
        ))

    zip_bomb_entries = zip_info.get("zip_bomb_entries") or []
    if zip_bomb_entries:
        findings.append(_finding(
            finding_id="archive_zip_bomb_risk",
            title="Model archive has zip-bomb compression characteristics",
            severity="high",
            description="One or more archive entries expand far beyond their compressed size and can exhaust intake or deployment resources.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "zip_bomb_entries": zip_bomb_entries},
            remediation="Reject highly compressed oversized archive entries or unpack only inside strict resource limits.",
        ))

    nested_archive_entries = zip_info.get("nested_archive_entries") or []
    if nested_archive_entries:
        findings.append(_finding(
            finding_id="nested_model_archive",
            title="Model artifact contains nested archives",
            severity="medium",
            description="Nested archives reduce inspectability and can hide executable or oversized payloads from shallow intake checks.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "nested_archive_entries": nested_archive_entries},
            remediation="Require a flattened model package or recursively inspect nested archives in a sandboxed intake pipeline.",
        ))

    risky_config_entries = zip_info.get("risky_config_entries") or []
    if risky_config_entries:
        findings.append(_finding(
            finding_id="risky_model_config",
            title="Model package configuration requests risky runtime behavior",
            severity="high",
            description="The model package contains configuration such as trust_remote_code or risky chat templates that can expand runtime execution or tool-use risk.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "risky_config_entries": risky_config_entries},
            remediation="Disable trust_remote_code, review chat templates, and require conversion through a controlled model packaging pipeline.",
        ))

    if suspicious_loader_markers:
        findings.append(_finding(
            finding_id="suspicious_loader_markers",
            title="Model artifact contains suspicious loader markers",
            severity="high" if any(hit["marker"] in {"shell_spawn", "network_downloader", "powershell"} for hit in suspicious_loader_markers) else "medium",
            description="The artifact contains strings or files associated with dynamic loading, shell execution, or network download behavior.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "markers": suspicious_loader_markers},
            remediation="Review the artifact in an isolated malware sandbox, remove loader scripts, and require clean YARA/AV results before deployment.",
        ))

    if not provenance_ref and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_provenance",
            title="Model artifact missing provenance metadata",
            severity="medium",
            description="The artifact intake metadata did not identify source repository, commit, training data reference, or provenance attestation.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "source_kind": _source_kind(artifact_ref, metadata), "metadata_keys": sorted(metadata.keys())},
            remediation="Require source repository, commit hash, training data reference, build workflow, and attestation URL before deployment approval.",
        ))

    if require_governance and strict_governance and not training_data_ref and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_dataset_lineage",
            title="Model training dataset lineage missing",
            severity="medium",
            description="Strict model-intake policy requires training dataset lineage so poisoning and unauthorized data-source risk can be reviewed.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Record training dataset references, ownership, allowed source policy, and dataset version before production deployment.",
        ))

    if require_governance and strict_governance and training_data_ref and not dataset_digest and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_dataset_digest",
            title="Model training dataset digest missing",
            severity="medium",
            description="Training dataset lineage was provided without a digest, so intake cannot bind eval and approval evidence to immutable data.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "training_data_ref": training_data_ref},
            remediation="Attach a dataset SHA-256, manifest digest, or signed data version identifier for the training corpus.",
        ))

    if require_governance and strict_governance and not base_model_ref and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_base_model_lineage",
            title="Base model lineage missing",
            severity="medium",
            description="Strict model-intake policy requires base model lineage to assess inherited license, safety, and supply-chain risk.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Record base model identifier, version, digest, and source registry for derivative or fine-tuned models.",
        ))

    if require_governance and strict_governance and not fine_tune_provenance and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_training_pipeline_provenance",
            title="Fine-tuning or training pipeline provenance missing",
            severity="low",
            description="No fine-tuning job, training run, or build pipeline provenance was supplied for the model artifact.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Record the fine-tuning job, build workflow, runner identity, and attested source revision for reproducibility.",
        ))

    if require_governance and strict_governance and not poisoning_eval_ref and generated_evaluation.get("status") == "SKIPPED_BY_POLICY" and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_poisoning_eval_evidence",
            title="Model poisoning or backdoor eval evidence missing",
            severity="medium",
            description="Strict model-intake policy requires data/model poisoning or backdoor eval evidence before production deployment.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Attach canary, backdoor, data-poisoning, or regression eval evidence bound to the artifact digest and model version.",
        ))

    if not model_card and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_model_card",
            title="Model artifact missing model card or risk documentation",
            severity="low",
            description="No model card, risk assessment, or usage constraints were supplied with the artifact.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name},
            remediation="Require model card metadata describing intended use, limitations, safety tests, license, and deployment constraints.",
        ))

    if require_approval and not deployment_approved and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_deployment_approval",
            title="Model deployment approval missing",
            severity="high",
            description="The intake request requires deployment approval, but approval metadata was absent or false.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "approved_by": metadata.get("approved_by"), "deployment_approved": deployment_approved},
            remediation="Route the artifact through approval before deployment and record approver, timestamp, and policy version.",
        ))

    if require_approval and strict_governance and deployment_approved and not approval_policy["valid"] and not metadata_unavailable:
        findings.append(_finding(
            finding_id="incomplete_deployment_approval",
            title="Model deployment approval evidence is incomplete",
            severity="medium",
            description="Strict model-intake policy requires approver, timestamp, policy version, and approved environment, not only a boolean approval flag.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "approval_policy": approval_policy},
            remediation="Record approved_by, approval timestamp, approval policy version, and deployment environment before production approval.",
        ))

    if require_governance and not license_ref and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_license_review",
            title="Model license review missing",
            severity="medium",
            description="The intake metadata did not include a model license, license URL, or license review result.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Record model license, usage constraints, and legal/security review status before deployment.",
        ))

    if require_governance and license_policy["status"] == "restricted" and not metadata_unavailable:
        findings.append(_finding(
            finding_id="restricted_license_policy",
            title="Model license requires deployment review",
            severity="medium",
            description="The supplied model license metadata contains restricted-use language that requires explicit approval before deployment.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "license_policy": license_policy},
            remediation="Confirm the intended deployment is allowed by the model license and record legal/security approval in intake metadata.",
        ))

    if require_governance and not effective_sbom_evidence and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_sbom_or_dependencies",
            title="Model dependency/SBOM evidence missing",
            severity="medium",
            description="No SBOM, dependency inventory, or package exposure evidence was supplied for the model artifact.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Attach SBOM or dependency inventory for model package code, adapters, tokenizers, and serving dependencies.",
        ))

    if require_governance and effective_sbom_evidence and strict_governance and not sbom_policy["valid"] and not metadata_unavailable:
        custom_code_without_dependencies = bool(repository_manifest.get("custom_code_required")) and sbom_policy.get("status") == "empty"
        findings.append(_finding(
            finding_id="runtime_dependency_inventory_missing" if custom_code_without_dependencies else "invalid_sbom_evidence",
            title="Runtime dependency inventory missing for custom model code" if custom_code_without_dependencies else "Model SBOM evidence is incomplete or unvalidated",
            severity="high" if custom_code_without_dependencies else "medium",
            description=(
                "The repository contains custom executable model code but no dependency manifest or generated runtime component inventory, so library and CVE review is not reproducible."
                if custom_code_without_dependencies
                else "Strict model-intake policy requires a CycloneDX/SPDX or component-list SBOM with at least one component."
            ),
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "sbom_policy": sbom_policy},
            remediation="Build a hash-locked runtime for the pinned model revision, generate its CycloneDX/SPDX SBOM, and run offline SCA against the installed components.",
        ))

    if require_governance and not effective_malware_evidence and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_malware_scan",
            title="Model malware scan evidence missing",
            severity="medium",
            description="The intake metadata did not include malware, YARA, or antivirus scan evidence.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Require static malware/YARA scanning and record scan result, engine, and timestamp before approval.",
        ))

    if require_governance and effective_malware_evidence and strict_governance and not malware_policy["valid"] and not metadata_unavailable:
        findings.append(_finding(
            finding_id="invalid_malware_scan_evidence",
            title="Model malware scan evidence is incomplete, stale, or not bound to the artifact",
            severity="medium",
            description="Strict model-intake policy requires a clean malware scan with scanner/version, timestamp, artifact digest, and fresh evidence.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "malware_policy": malware_policy},
            remediation="Run malware/YARA scanning against the exact artifact digest and record scanner, engine version, timestamp, and clean status.",
        ))

    if require_governance and not effective_eval_evidence and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_eval_evidence",
            title="Model security evaluation evidence missing",
            severity="medium",
            description="No security eval, red-team report, or model behavior evaluation evidence was supplied.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Attach safety/security eval results, red-team coverage, and deployment-specific acceptance criteria.",
        ))

    if require_governance and effective_eval_evidence and strict_governance and not eval_policy["valid"] and not metadata_unavailable:
        findings.append(_finding(
            finding_id="invalid_security_eval_evidence",
            title="Model security evaluation evidence is incomplete or not bound to the artifact",
            severity="medium",
            description="Strict model-intake policy requires passing security eval evidence with suite id, date, target digest, and thresholds.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "eval_policy": eval_policy},
            remediation="Attach eval suite id, date, target artifact digest, result, and acceptance thresholds for the deployment model version.",
        ))

    if require_governance and not deployment_restrictions and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_deployment_restrictions",
            title="Model deployment restrictions missing",
            severity="low",
            description="No approved environments, usage restrictions, or deployment constraints were supplied.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Record approved environments, data-use restrictions, prohibited use cases, and rollback constraints.",
        ))

    if require_governance and not monitoring_plan and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_monitoring_plan",
            title="Model monitoring plan missing",
            severity="low",
            description="No post-deployment monitoring, drift, abuse, or incident-response plan was supplied.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Define monitoring for drift, abuse, data leakage, cost anomalies, incidents, and periodic reassessment.",
        ))

    format_specific_blocked = any(
        f["id"] in {
            "model_intake:safetensors_header_invalid",
            "model_intake:gguf_header_invalid",
        }
        for f in findings
    )
    format_specific_indeterminate = bool(
        ext == ".safetensors"
        and safetensors_header.get("valid") is None
        and not safetensors_header.get("conclusive_invalid")
    )
    if (
        ext in SAFER_MODEL_EXTENSIONS
        and not any(f["id"].endswith("unsafe_serialization") for f in findings)
        and not format_specific_blocked
        and not format_specific_indeterminate
    ):
        format_posture = "safer_static_format"
    elif ext in RISKY_EXTENSIONS or pickle_like:
        format_posture = "unsafe_executable_serialization"
    else:
        format_posture = "unknown_or_unclassified_format"

    observed_hash_scope = "inspected_bytes" if artifact_truncated and sha256 else "full_artifact" if sha256 else None
    checksum_match = True if checksum_status == "verified" else False if checksum_status == "mismatch" else None
    if checksum_status == "verified":
        checksum_policy_status = "pass"
    elif require_hash and expected_sha256:
        checksum_policy_status = "fail_unverified"
    elif require_hash:
        checksum_policy_status = "fail_missing"
    elif expected_sha256:
        checksum_policy_status = "review"
    else:
        checksum_policy_status = "not_required"
    format_specific_ok: bool | None = not any(
        finding["id"] in {
            "model_intake:safetensors_header_invalid",
            "model_intake:onnx_external_data_reference",
            "model_intake:onnx_custom_operator",
            "model_intake:gguf_header_invalid",
        }
        for finding in findings
    )
    if format_specific_indeterminate:
        format_specific_ok = None

    score = max(0, 100 - sum(_severity_score(f.get("severity", "info")) for f in findings))
    intake_mode = str(options.get("intake_mode") or "admission").strip().lower()
    decision = _intake_decision(findings, intake_mode=intake_mode)
    findings_digest = hashlib.sha256(
        json.dumps(findings, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    attestation_evidence_sha256 = attestation_verification.get("envelope_sha256")
    admission_statement = _build_admission_statement(
        subject_sha256=sha256 if observed_hash_scope == "full_artifact" else None,
        repository_snapshot_sha256=repository_snapshot.get("snapshot_sha256"),
        generated_evidence_sha256=generated_evidence.get("evidence_sha256"),
        sandbox_evidence_sha256=dynamic_sandbox.get("evidence_sha256"),
        attestation_evidence_sha256=attestation_evidence_sha256,
        evaluation_evidence_sha256=generated_evaluation.get("evidence_sha256"),
        policy_profile=str(options.get("policy_profile") or deployment_environment or "") or None,
        policy_version=str(metadata.get("policy_version") or metadata.get("approval_policy_version") or "") or None,
        decision=decision["decision"],
        decision_reason=decision["decision_reason"],
        findings_digest=findings_digest,
        expires_days=bounded_int("admission_expires_days", 30, 1, 365),
    )
    admission_package = _build_admission_candidate(admission_statement)
    safe_artifact_ref = redact_model_intake_value(artifact_ref)
    safe_registry_reference = redact_model_intake_value(registry_reference)
    safe_metadata = redact_model_intake_value(metadata)
    safe_metadata_fetch_meta = redact_model_intake_value(metadata_fetch_meta)
    safe_model_card_fetch_meta = redact_model_intake_value(model_card_fetch_meta)
    public_artifact_meta = {key: value for key, value in artifact_meta.items() if not str(key).startswith("_")}
    safe_artifact_meta = redact_model_intake_value(public_artifact_meta)
    safe_signature_status = redact_model_intake_value(signature_status)
    safe_aibom = redact_model_intake_value(aibom)
    safe_findings = redact_model_intake_value(findings)
    runtime_destinations = [
        item for item in (
            _runtime_destination("artifact", artifact_ref, artifact_meta),
            _runtime_destination("metadata", metadata_url, metadata_fetch_meta) if metadata_url else None,
            _runtime_destination("signature", signature_url, None) if signature_url else None,
            _runtime_destination(
                "signature_public_key",
                options.get("signature_public_key_url") or metadata.get("signature_public_key_url"),
                None,
            ) if (options.get("signature_public_key_url") or metadata.get("signature_public_key_url")) else None,
            _runtime_destination("model_card", model_card, model_card_fetch_meta) if isinstance(model_card, str) else None,
        )
        if item
    ]
    summary = {
        "artifact_name": name,
        "intake_mode": intake_mode,
        "admission_eligible": intake_mode == "admission",
        "artifact_ref": safe_artifact_ref,
        "source_kind": _source_kind(artifact_ref, metadata),
        "registry": safe_registry_reference,
        "source_adapter": source_adapter,
        "extension": ext,
        "sha256": sha256,
        "sha256_scope": observed_hash_scope,
        "acquisition_complete": bool(artifact_meta.get("complete")) and not artifact_truncated,
        "inspection_complete": not inspection_truncated,
        "quarantine_object": artifact_meta.get("quarantine_object"),
        "repository_manifest_sha256": repository_manifest.get("manifest_sha256"),
        "repository_manifest_complete": repository_manifest.get("complete") if repository_manifest else None,
        "repository_files_discovered": repository_manifest.get("files_discovered") if repository_manifest else None,
        "custom_code_required": repository_manifest.get("custom_code_required") if repository_manifest else None,
        "repository_snapshot_sha256": repository_snapshot.get("snapshot_sha256"),
        "repository_snapshot_complete": repository_snapshot.get("complete") if complete_repository_snapshot else None,
        "generated_evidence_status": generated_evidence.get("status"),
        "generated_evidence_sha256": generated_evidence.get("evidence_sha256"),
        "expected_sha256": expected_sha256,
        "checksum_status": checksum_status,
        "checksum_match": checksum_match,
        "checksum_policy_status": checksum_policy_status,
        "format_posture": format_posture,
        "signature_verification_status": signature_status["status"],
        "license_policy_status": license_policy["status"],
        "strict_governance": strict_governance,
        "deployment_environment": deployment_environment or None,
        "sbom_policy_status": sbom_policy["status"],
        "malware_policy_status": malware_policy["status"],
        "eval_policy_status": eval_policy["status"],
        "approval_policy_status": approval_policy["status"],
        "aibom_generated": True,
        "aibom_completeness": aibom["completeness"]["score"],
        "provenance_present": bool(provenance_ref),
        "signature_present": bool(signature_url or signed_by),
        "signature_claimed_present": signature_status["claimed_present"],
        "signature_verified": signature_status["verified"],
        "signature_valid": signature_status.get("signature_valid"),
        "signature_trusted_root": signature_status.get("trusted_root"),
        "signature_key_fingerprint": signature_status.get("key_fingerprint"),
        "signature_trust_anchors_configured": signature_status.get("trust_anchors_configured"),
        "signature_claimed_verified": signature_status["claimed_verified"],
        "signature_cryptographically_verified": signature_status["cryptographically_verified"],
        "signature_verifier": signature_status.get("verifier"),
        "signature_transparency_log_verified": signature_status.get("transparency_log_verified"),
        "signature_attestation_subject_digest_match": signature_status.get("attestation_subject_digest_match"),
        "signature_crypto_attempted": signature_status.get("crypto_attempted"),
        "attestation_verification_status": attestation_verification.get("status"),
        "attestation_verified": bool(attestation_verification.get("verified")),
        "dynamic_sandbox_status": dynamic_sandbox.get("status"),
        "dynamic_sandbox_evidence_sha256": dynamic_sandbox.get("evidence_sha256"),
        "generated_evaluation_status": generated_evaluation.get("status"),
        "generated_evaluation_sha256": generated_evaluation.get("evidence_sha256"),
        "admission_status": admission_package.get("status"),
        "admission_statement_sha256": admission_package.get("statement_sha256"),
        "expected_hash_present": bool(expected_sha256),
        "deployment_approved": deployment_approved,
        "license_present": bool(license_ref),
        "sbom_present": bool(effective_sbom_evidence),
        "malware_scan_present": bool(effective_malware_evidence),
        "eval_evidence_present": bool(effective_eval_evidence),
        "deployment_restrictions_present": bool(deployment_restrictions),
        "monitoring_plan_present": bool(monitoring_plan),
        "training_data_lineage_present": bool(training_data_ref),
        "dataset_digest_present": bool(dataset_digest),
        "base_model_lineage_present": bool(base_model_ref),
        "training_pipeline_provenance_present": bool(fine_tune_provenance),
        "poisoning_eval_present": bool(poisoning_eval_ref),
        "metadata_fetch_failed": bool(metadata_fetch_meta.get("error")),
        "model_card_fetch_failed": bool(model_card_fetch_meta.get("error")),
        "model_card_content_sha256": model_card_fetch_meta.get("content_sha256"),
        "findings_count": len(findings),
    }

    corporate_use = _corporate_use_assessment(
        findings=findings,
        decision=decision,
        intake_mode=intake_mode,
        acquisition_complete=bool(artifact_meta.get("complete")) and not artifact_truncated,
        checksum_status=checksum_status,
        generated_evidence=generated_evidence,
        dynamic_sandbox=dynamic_sandbox,
        generated_evaluation=generated_evaluation,
        signature_status=signature_status,
        attestation_verification=attestation_verification,
        deployment_approved=deployment_approved,
        custom_code_required=bool(repository_manifest.get("custom_code_required")),
    )
    summary["corporate_use_verdict"] = corporate_use["verdict"]
    summary["can_use_in_corporate_environment"] = corporate_use["can_use_in_corporate_environment"]

    await _emit_model_intake_activity(
        activity,
        event_callback,
        phase="decision",
        progress=95,
        status="COMPLETE",
        checksum=checksum_status,
        admission=admission_package.get("status"),
        decision=decision.get("decision"),
        findings_count=len(findings),
    )

    return {
        "schema_version": "2026-05-10.model-intake.v1",
        "scan_mode": "model_intake",
        "target": safe_artifact_ref,
        "model_intake": {
            "summary": summary,
            "corporate_use": redact_model_intake_value(corporate_use),
            "activity": activity,
            "source_adapter": source_adapter,
            "attestation": redact_model_intake_value(attestation_verification),
            "dynamic_sandbox": redact_model_intake_value(dynamic_sandbox),
            "generated_evaluation": redact_model_intake_value(generated_evaluation),
            "admission": redact_model_intake_value(admission_package),
            "runtime_destinations": runtime_destinations,
            "artifact": {
                "name": name,
                "extension": ext,
                "fetch": safe_artifact_meta,
                "archive": zip_info,
            },
            "metadata": safe_metadata,
            "metadata_fetch": safe_metadata_fetch_meta if metadata_url else None,
            "model_card_fetch": safe_model_card_fetch_meta if model_card_fetch_meta else None,
            "aibom": safe_aibom,
            "repository_snapshot": redact_model_intake_value(repository_snapshot),
            "generated_evidence": redact_generated_evidence(generated_evidence),
            "supply_chain": {
                "registry": safe_registry_reference,
                "signature": safe_signature_status,
                "license_policy": license_policy,
                "sbom_policy": sbom_policy,
                "malware_policy": malware_policy,
                "eval_policy": eval_policy,
                "approval_policy": approval_policy,
                "suspicious_loader_markers": suspicious_loader_markers,
                "format_inspection": format_inspection,
            },
            "checks": {
                "provenance": None if metadata_unavailable else bool(provenance_ref),
                "unsafe_serialization": not any(f["id"].endswith("unsafe_serialization") for f in findings),
                "artifact_signing": None if metadata_unavailable else bool(signature_url or signed_by),
                "signature_verification": None if not require_signature_verification or metadata_unavailable else signature_status["verified"],
                "checksum": None if metadata_unavailable else checksum_status == "verified",
                "aibom": True,
                "repository_manifest": repository_manifest.get("complete") if repository_manifest else None,
                "repository_snapshot": repository_snapshot.get("complete") if complete_repository_snapshot else None,
                "generated_scanners": generated_evidence.get("status") == "PASS" if run_generated_scanners else None,
                "dynamic_sandbox": dynamic_sandbox.get("status") == "PASS" if (run_dynamic_sandbox or require_dynamic_sandbox) else None,
                "custom_code_review": (
                    any(
                        item.get("scanner", {}).get("name") == "semgrep"
                        and item.get("execution", {}).get("status") in {"PASS", "WARNING"}
                        for item in generated_evidence.get("results") or []
                    )
                    if repository_manifest.get("custom_code_required") else None
                ),
                "format_specific_inspection": format_specific_ok,
                "license_policy": None if metadata_unavailable or not license_ref else license_policy["status"] == "permissive",
                "approval": (None if metadata_unavailable else deployment_approved) if require_approval else None,
                "approval_evidence": (
                    None if metadata_unavailable else approval_policy["valid"]
                ) if require_approval and strict_governance else None,
                "license_review": (None if metadata_unavailable else bool(license_ref)) if require_governance else None,
                "sbom_dependencies": (
                    None if metadata_unavailable else (sbom_policy["valid"] if strict_governance else bool(sbom_ref))
                ) if require_governance else None,
                "malware_scan": (
                    None if metadata_unavailable else (malware_policy["valid"] if strict_governance else bool(malware_scan_ref))
                ) if require_governance else None,
                "security_evals": (
                    None if metadata_unavailable else (eval_policy["valid"] if strict_governance else bool(effective_eval_evidence))
                ) if require_governance else None,
                "deployment_restrictions": (None if metadata_unavailable else bool(deployment_restrictions)) if require_governance else None,
                "monitoring_plan": (None if metadata_unavailable else bool(monitoring_plan)) if require_governance else None,
                "dataset_lineage": (
                    None if metadata_unavailable else bool(training_data_ref)
                ) if require_governance and strict_governance else None,
                "dataset_digest": (
                    None if metadata_unavailable else bool(dataset_digest)
                ) if require_governance and strict_governance and bool(training_data_ref) else None,
                "base_model_lineage": (
                    None if metadata_unavailable else bool(base_model_ref)
                ) if require_governance and strict_governance else None,
                "poisoning_evals": (
                    None if metadata_unavailable else bool(poisoning_eval_ref)
                ) if require_governance and strict_governance else None,
            },
        },
        "findings": safe_findings,
        "result": {
            "score": score,
            "grade": _grade(score),
            **decision,
        },
    }


__all__ = ["normalize_model_artifact_reference", "parse_huggingface_ref", "run_model_intake_scan"]
