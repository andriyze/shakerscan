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
import os
import re
import struct
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

try:
    from redaction import (
        SENSITIVE_KEYS,
        SENSITIVE_KEY_FRAGMENTS,
        is_sensitive_key,
        redact_sensitive,
        redact_url_credentials,
    )
except ModuleNotFoundError as exc:
    if exc.name != "redaction":
        raise
    from scanner.redaction import (
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
PICKLE_OPCODE_MARKERS = (b"__reduce__", b"GLOBAL", b"cposix\nsystem", b"cos\nsystem", b"subprocess", b"eval", b"exec")

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
        return parsed_ref

    if kind == "s3":
        bucket = parsed.netloc
        key = parsed.path.lstrip("/")
        region = metadata.get("region") or metadata.get("aws_region") or metadata.get("s3_region")
        if parsed.scheme in {"http", "https"}:
            host = parsed.netloc
            if host.startswith("s3.") or host == "s3.amazonaws.com":
                parts = [part for part in parsed.path.split("/") if part]
                bucket = parts[0] if parts else ""
                key = "/".join(parts[1:])
            elif ".s3." in host or host.endswith(".s3.amazonaws.com"):
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
        if parsed.scheme in {"http", "https"} and ".blob.core.windows.net" in parsed.netloc:
            account = parsed.netloc.split(".blob.core.windows.net", 1)[0]
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
        parsed_ref.update({"registry": registry or None, "repository": repository or None, "path": repository or None, "tag": tag, "digest": digest, "fetchable": False})
        parsed_ref["metadata"].update({"oci_registry": registry, "oci_repository": repository, "oci_tag": tag, "digest": digest})
        warnings.append("Native OCI artifact fetching is not enabled yet; export or sign a fetchable artifact URL for executable intake.")
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
        parsed_ref.update({"registry": "mlflow", "repository": model_name or run_id, "path": artifact_path or model_stage, "model_name": model_name, "stage": model_stage, "run_id": run_id, "fetchable": False})
        parsed_ref["metadata"].update({"mlflow_model_name": model_name, "mlflow_stage": model_stage, "mlflow_run_id": run_id, "artifact_path": artifact_path})
        warnings.append("MLflow registry refs need an exported model artifact URL or a gateway fetcher before executable intake.")

    else:
        ext = _artifact_ext(_artifact_name(raw))
        parsed_ref["extension"] = ext
        parsed_ref["metadata"].update({"artifact_platform": "http" if parsed.scheme in {"http", "https"} else kind})

    extension = _artifact_ext(parsed_ref.get("path") or _artifact_name(raw))
    parsed_ref["extension"] = extension
    if extension in RISKY_EXTENSIONS:
        warnings.append("Artifact extension is pickle-like or framework-serialized and should be reviewed before deployment.")
    parsed_ref["format_posture"] = "safer_static_format" if extension in SAFER_MODEL_EXTENSIONS else "unsafe_or_review_required" if extension in RISKY_EXTENSIONS else "unknown_or_unclassified_format"
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


def _intake_decision(findings: list[dict[str, Any]]) -> dict[str, Any]:
    if not findings:
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
        return {
            "decision": "allow",
            "decision_reason": "Only advisory low/info model-intake findings were detected.",
        }
    return {
        "decision": "review",
        "decision_reason": "Model-intake findings require review before deployment approval.",
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


def _download_http(
    url: str,
    max_bytes: int,
    timeout_seconds: int,
    headers: dict[str, str] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    request_headers = {
        "User-Agent": "ShakerScan-ModelIntake/1.0",
        "Range": f"bytes=0-{max_bytes - 1}",
        **(headers or {}),
    }
    request = urllib.request.Request(
        url,
        headers=request_headers,
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        data = response.read(max_bytes + 1)
        headers = dict(response.headers.items())
        content_range = _parse_content_range(headers.get("Content-Range"))
        content_length = headers.get("Content-Length")
        try:
            declared_length = int(content_length) if content_length is not None else None
        except ValueError:
            declared_length = None
        if content_range:
            total = content_range.get("total")
            truncated = total is None or int(content_range["end"]) + 1 < int(total)
        else:
            truncated = len(data) > max_bytes or (declared_length is not None and declared_length > max_bytes)
        return data[:max_bytes], {
            "source": "http",
            "status": getattr(response, "status", None),
            "content_type": headers.get("Content-Type"),
            "content_length": content_length,
            "content_range": headers.get("Content-Range"),
            "range_requested": f"bytes=0-{max_bytes - 1}",
            "range_satisfied": bool(content_range),
            "bytes_observed": min(len(data), max_bytes),
            "truncated": truncated,
        }


def _download_huggingface(ref: str, metadata: dict[str, Any], max_bytes: int, timeout_seconds: int) -> tuple[bytes, dict[str, Any]]:
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
    data, fetch_meta = _download_http(str(hf_ref["resolve_url"]), max_bytes, timeout_seconds, auth_headers)
    return data, {
        **fetch_meta,
        "source": "huggingface",
        "huggingface": hf_ref,
        "authenticated": bool(token),
        "auth_source": auth_source,
    }


def _download_cloud_object(ref: str, metadata: dict[str, Any], max_bytes: int, timeout_seconds: int) -> tuple[bytes, dict[str, Any]]:
    cloud_ref = normalize_model_artifact_reference(ref, metadata)
    fetch_url = cloud_ref.get("fetch_url")
    if not fetch_url:
        return b"", {
            "source": cloud_ref.get("kind") or urllib.parse.urlparse(ref).scheme,
            "bytes_observed": 0,
            "cloud": cloud_ref,
            "error": "Cloud object reference could not be converted to a fetchable HTTPS URL.",
        }
    data, fetch_meta = _download_http(str(fetch_url), max_bytes, timeout_seconds)
    return data, {
        **fetch_meta,
        "source": cloud_ref.get("kind") or fetch_meta.get("source") or "cloud_object",
        "fetch_url": fetch_url,
        "cloud": cloud_ref,
    }


async def _fetch_artifact(
    ref: str,
    max_bytes: int,
    timeout_seconds: int,
    metadata: dict[str, Any] | None = None,
    allow_local_files: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    parsed = urllib.parse.urlparse(ref)
    try:
        if parsed.scheme == "hf" or (parsed.scheme in {"http", "https"} and parsed.netloc.endswith("huggingface.co")):
            return await asyncio.to_thread(_download_huggingface, ref, metadata or {}, max_bytes, timeout_seconds)
        if parsed.scheme in {"s3", "gs", "gcs", "azure"}:
            return await asyncio.to_thread(_download_cloud_object, ref, metadata or {}, max_bytes, timeout_seconds)
        if parsed.scheme in ("http", "https"):
            return await asyncio.to_thread(_download_http, ref, max_bytes, timeout_seconds)
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
) -> tuple[dict[str, Any], dict[str, Any]]:
    data, meta = await _fetch_artifact(
        url,
        max_bytes=max_bytes,
        timeout_seconds=timeout_seconds,
        allow_local_files=allow_local_files,
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


def _looks_like_pickle(data: bytes, ext: str = "") -> bool:
    if data.startswith(PICKLE_MAGIC_PREFIXES):
        return True
    if ext in SAFER_MODEL_EXTENSIONS:
        return False
    sample = data[:65536]
    return any(marker in sample for marker in PICKLE_OPCODE_MARKERS)


def _inspect_zip(data: bytes) -> dict[str, Any]:
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        if not zipfile.is_zipfile(tmp_path):
            return {"is_zip": False, "entries": []}
        entries = []
        risky_entries = []
        executable_entries = []
        pickle_entries = []
        path_traversal_entries = []
        nested_archive_entries = []
        zip_bomb_entries = []
        risky_config_entries = []
        with zipfile.ZipFile(tmp_path) as zf:
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
    host = parsed.netloc.lower()
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
    if host == "s3.amazonaws.com" or host.startswith("s3.") or ".s3." in host or ".s3-" in host:
        return "s3"
    if host == "storage.googleapis.com" or host.endswith(".storage.googleapis.com"):
        return "gcs"
    if "blob.core.windows.net" in host:
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
            if str(rsa_padding).lower() == "pkcs1":
                pad = asy_padding.PKCS1v15()
            else:
                pad = asy_padding.PSS(mgf=asy_padding.MGF1(hash_alg), salt_length=asy_padding.PSS.MAX_LENGTH)
            key.verify(bytes(signature_bytes), bytes(payload_bytes), pad, hash_alg)
            algorithm = f"rsa-{str(rsa_padding).lower()}-{str(hash_name).lower()}"
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


async def _load_and_verify_signature(
    options: dict[str, Any],
    metadata: dict[str, Any],
    signature_url: Any,
    artifact_bytes: bytes,
    sha256: str | None,
    *,
    timeout_seconds: int,
    allow_local_files: bool,
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
            metadata=metadata, allow_local_files=allow_local_files,
        )
        if pk_bytes:
            public_key_pem = pk_bytes
    if not public_key_pem:
        return {"available": None, "attempted": False, "verified": False, "error": "no_public_key"}

    signature_bytes = _decode_signature_value(sig_inline) if sig_inline else None
    if not signature_bytes and signature_url:
        sig_bytes, _sig_meta = await _fetch_artifact(
            str(signature_url), max_bytes=1_000_000, timeout_seconds=timeout_seconds,
            metadata=metadata, allow_local_files=allow_local_files,
        )
        if sig_bytes:
            signature_bytes = sig_bytes
    if not signature_bytes:
        return {"available": True, "attempted": False, "verified": False, "error": "no_signature"}

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
        payload_bytes = artifact_bytes

    result = _verify_signature_crypto(
        public_key_pem, signature_bytes, payload_bytes, rsa_padding=rsa_padding, hash_name=hash_name
    )
    if result.get("verified"):
        result["attestation_subject_digest_match"] = bool(
            not expected_sha256 or (sha256 and sha256 == expected_sha256)
        )
        result["payload_kind"] = "digest" if digest_based else "artifact"
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
    cryptographically_verified = bool(crypto.get("verified"))
    crypto_attempted = bool(crypto.get("attempted"))
    crypto_invalid = crypto_attempted and not cryptographically_verified
    present = bool(signature_url or signed_by or metadata.get("attestation_url") or metadata.get("provenance_url"))
    if cryptographically_verified:
        status = "verified"
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
        "attestation_subject_digest_match": crypto.get("attestation_subject_digest_match"),
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


def _sbom_policy(value: Any, *, strict: bool) -> dict[str, Any]:
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
        return {
            "status": "valid" if value else "empty",
            "valid": bool(value) or not strict,
            "component_count": len(value),
            "format": "component_list",
        }
    if not isinstance(value, dict):
        return {"status": "invalid_shape", "valid": False, "component_count": 0, "format": type(value).__name__}

    if str(value.get("bomFormat") or "").lower() == "cyclonedx":
        components = value.get("components")
        count = len(components) if isinstance(components, list) else 0
        return {
            "status": "valid" if count else "empty",
            "valid": count > 0 or not strict,
            "component_count": count,
            "format": "cyclonedx",
        }
    if value.get("spdxVersion"):
        packages = value.get("packages")
        count = len(packages) if isinstance(packages, list) else 0
        return {
            "status": "valid" if count else "empty",
            "valid": count > 0 or not strict,
            "component_count": count,
            "format": "spdx",
        }
    if isinstance(value.get("components"), list):
        count = len(value["components"])
        return {
            "status": "valid" if count else "empty",
            "valid": count > 0 or not strict,
            "component_count": count,
            "format": "generic_components",
        }
    return {"status": "invalid_shape" if strict else "present_unvalidated", "valid": not strict, "component_count": 0, "format": "unknown"}


def _malware_policy(value: Any, *, strict: bool, expected_sha256: Any, max_age_days: int = 30) -> dict[str, Any]:
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
    valid = clean and bool(scanner) and bool(version) and bool(scanned_at) and bool(digest) and digest_matches and not stale
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
    }


def _eval_policy(value: Any, *, strict: bool, expected_sha256: Any) -> dict[str, Any]:
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
    valid = passed and bool(suite) and bool(timestamp) and bool(digest) and digest_matches and bool(thresholds)
    return {
        "status": "valid" if valid else "invalid",
        "valid": valid if strict else passed,
        "passed": passed,
        "suite_present": bool(suite),
        "date_present": bool(timestamp),
        "target_digest_present": bool(digest),
        "target_digest_matches": digest_matches,
        "thresholds_present": bool(thresholds),
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


def _scan_suspicious_loader_markers(data: bytes, zip_info: dict[str, Any]) -> list[dict[str, str]]:
    sample = data[:1_000_000].lower()
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


def _inspect_safetensors(data: bytes) -> dict[str, Any]:
    header: dict[str, Any] = {"present": False, "valid_json": False, "valid": False}
    if len(data) < 8:
        header["error"] = "too_short_for_header_length"
        return header

    header_len = int.from_bytes(data[:8], "little", signed=False)
    header["length"] = header_len
    if header_len <= 0:
        header["error"] = "empty_header"
        return header
    if header_len > 100_000_000:
        header["error"] = "header_length_unreasonable"
        return header
    if header_len > 1_048_576:
        header["error"] = "header_exceeds_intake_limit"
        return header
    if len(data) < 8 + header_len:
        header["error"] = "truncated_header"
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
        return header

    if not isinstance(parsed, dict):
        header["error"] = "header_json_not_object"
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
    payload_size = max(0, len(data) - 8 - header_len)
    for name, tensor in parsed.items():
        if name == "__metadata__":
            continue
        if not isinstance(tensor, dict):
            invalid_tensors.append({"tensor": name, "reason": "metadata_not_object"})
            continue
        offsets = tensor.get("data_offsets")
        if not (
            isinstance(offsets, list)
            and len(offsets) == 2
            and all(isinstance(item, int) for item in offsets)
        ):
            invalid_tensors.append({"tensor": name, "reason": "missing_or_invalid_data_offsets"})
            continue
        start, end = offsets
        if start < 0 or end < start or end > payload_size:
            invalid_tensors.append({
                "tensor": name,
                "reason": "offset_out_of_bounds",
                "start": start,
                "end": end,
                "payload_size": payload_size,
            })
            continue
        tensor_ranges.append((start, end, str(name)))

    overlaps: list[dict[str, Any]] = []
    for previous, current in zip(sorted(tensor_ranges), sorted(tensor_ranges)[1:]):
        if current[0] < previous[1]:
            overlaps.append({
                "previous_tensor": previous[2],
                "tensor": current[2],
                "previous_end": previous[1],
                "start": current[0],
            })

    header.update({
        "valid": not duplicate_keys and not invalid_tensors and not overlaps,
        "tensor_count": len([key for key in parsed.keys() if key != "__metadata__"]),
        "metadata_keys": metadata_keys,
        "suspicious_metadata_keys": sorted(set(suspicious_metadata_keys))[:25],
        "invalid_tensors": invalid_tensors[:25],
        "overlapping_tensors": overlaps[:25],
        "payload_size": payload_size,
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
        if item.startswith(("/", "file:", "http://", "https://", "s3://", "gs://", "../"))
        or "external_data" in item.lower()
        or item.lower().endswith((".bin", ".data"))
    ][:25]
    custom_domains = [
        item for item in strings
        if item.startswith(("ai.onnx.contrib", "com.microsoft", "com.", "org."))
        or "customop" in item.lower()
    ][:25]
    parsed_with = "string_table"
    graph_name = None
    try:
        import onnx  # type: ignore

        model = onnx.load_model_from_string(data)
        parsed_with = "onnx"
        graph_name = getattr(getattr(model, "graph", None), "name", None) or None
        for initializer in getattr(getattr(model, "graph", None), "initializer", []) or []:
            for entry in getattr(initializer, "external_data", []) or []:
                key = getattr(entry, "key", "")
                value = getattr(entry, "value", "")
                if key == "location" and value:
                    external_locations.append(str(value))
        for node in getattr(getattr(model, "graph", None), "node", []) or []:
            domain = getattr(node, "domain", "")
            if domain and domain not in {"", "ai.onnx", "ai.onnx.ml"}:
                custom_domains.append(str(domain))
    except Exception:
        pass

    return {
        "parsed_with": parsed_with,
        "graph_name": graph_name,
        "external_data_hint": (
            b"external_data" in sample.lower()
            or b"location" in sample.lower()
            or bool(external_locations)
        ),
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


def _inspect_format(name: str, ext: str, data: bytes, zip_info: dict[str, Any]) -> dict[str, Any]:
    inspection: dict[str, Any] = {
        "artifact_name": name,
        "extension": ext,
        "format": ext.lstrip(".") or "unknown",
        "lower_code_execution_risk": ext in SAFER_MODEL_EXTENSIONS,
    }
    if ext == ".safetensors":
        inspection["safetensors_header"] = _inspect_safetensors(data)
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


async def run_model_intake_scan(artifact_ref: str, raw_options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run model artifact intake checks without executing model code."""
    options = raw_options or {}
    inline_metadata = options.get("metadata_json") if isinstance(options.get("metadata_json"), dict) else {}
    metadata = dict(inline_metadata)
    metadata_url = options.get("metadata_url")
    metadata_fetch_meta: dict[str, Any] = {}
    timeout_seconds = int(options.get("timeout_seconds") or 20)
    max_download_bytes = int(options.get("max_download_bytes") or 10_000_000)
    allow_local_files = _boolish(options.get("allow_local_files")) or _boolish(os.getenv("MODEL_INTAKE_ALLOW_LOCAL_FILES"))

    if metadata_url:
        remote_metadata, metadata_fetch_meta = await _fetch_json(
            str(metadata_url),
            timeout_seconds=timeout_seconds,
            allow_local_files=allow_local_files,
        )
        metadata = {**remote_metadata, **metadata}

    artifact_bytes, artifact_meta = await _fetch_artifact(
        artifact_ref,
        max_bytes=max_download_bytes,
        timeout_seconds=timeout_seconds,
        metadata=metadata,
        allow_local_files=allow_local_files,
    )

    unsupported_scheme_error = bool(
        artifact_meta.get("error")
        and "unsupported artifact scheme" in str(artifact_meta.get("error", "")).lower()
    )
    artifact_filename = _artifact_name(artifact_ref)
    name = str(options.get("artifact_name") or artifact_filename)
    ext = _artifact_ext(artifact_filename) or _artifact_ext(name)
    sha256 = hashlib.sha256(artifact_bytes).hexdigest() if artifact_bytes else None
    zip_info = _inspect_zip(artifact_bytes) if artifact_bytes[:4] == b"PK\x03\x04" else {"is_zip": False, "entries": []}
    artifact_truncated = bool(artifact_meta.get("truncated"))

    findings: list[dict[str, Any]] = []
    expected_sha256 = options.get("expected_sha256") or metadata.get("sha256")
    signature_url = options.get("signature_url") or metadata.get("signature_url") or metadata.get("signature")
    signed_by = metadata.get("signed_by") or metadata.get("attestation_signer")
    provenance_ref = _metadata_value(metadata, "source_repo", "source_repository", "commit_sha", "training_data_ref", "provenance_url", "attestation_url")
    model_card = options.get("model_card_url") or _metadata_value(metadata, "model_card_url", "model_card", "card_url")
    deployment_approved = _boolish(options.get("deployment_approved") or metadata.get("deployment_approved"))
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
    metadata_unavailable = bool(metadata_url and metadata_fetch_meta.get("error") and not metadata)
    require_signature_verification = _boolish(options.get("require_signature_verification"))
    require_cryptographic_signature_verification = _boolish(
        options.get("require_cryptographic_signature_verification")
        or metadata.get("require_cryptographic_signature_verification")
    )
    registry_reference = _registry_reference(artifact_ref, metadata)
    crypto_signature_result = await _load_and_verify_signature(
        options, metadata, signature_url, artifact_bytes, sha256,
        timeout_seconds=timeout_seconds, allow_local_files=allow_local_files,
    )
    signature_status = _signature_verification_status(metadata, signature_url, signed_by, crypto_signature_result)
    license_policy = _license_policy(license_ref)
    sbom_policy = _sbom_policy(sbom_ref, strict=strict_governance)
    try:
        malware_scan_max_age_days = int(options.get("malware_scan_max_age_days") or metadata.get("malware_scan_max_age_days") or 30)
    except (TypeError, ValueError):
        malware_scan_max_age_days = 30
    malware_policy = _malware_policy(
        malware_scan_ref,
        strict=strict_governance,
        expected_sha256=expected_sha256,
        max_age_days=malware_scan_max_age_days,
    )
    eval_policy = _eval_policy(eval_ref, strict=strict_governance, expected_sha256=expected_sha256)
    approval_policy = _approval_policy(metadata, deployment_approved=deployment_approved, strict=strict_governance)
    format_inspection = _inspect_format(name, ext, artifact_bytes, zip_info)
    suspicious_loader_markers = _scan_suspicious_loader_markers(artifact_bytes, zip_info)
    aibom_hash = str(expected_sha256 or sha256 or "").strip() or None
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

    effective_require_verification = require_signature_verification or require_cryptographic_signature_verification
    if (
        effective_require_verification
        and signature_status["status"] in {"present_unverified", "claimed_verified"}
        and not metadata_unavailable
    ):
        crypto_strict = require_cryptographic_signature_verification
        findings.append(_finding(
            finding_id="signature_not_verified",
            title="Model artifact signature is present but not cryptographically verified",
            severity="high" if crypto_strict else "medium",
            description=(
                "Policy requires cryptographic signature verification, but intake could not verify the "
                "signature; only a metadata claim is present."
                if crypto_strict
                else "The artifact has signature or attestation metadata, but intake does not have cryptographic verification evidence."
            ),
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "signature": signature_status},
            remediation="Provide a public key (signature_public_key/_url) and detached signature (signature_value/signature_url) so intake can run real cryptographic verification, or verify with Sigstore/cosign and record the verifier result.",
        ))

    risky_ext = ext in RISKY_EXTENSIONS
    pickle_like = _looks_like_pickle(artifact_bytes, ext)
    zip_pickle_entries = zip_info.get("pickle_entries") or []
    zip_risky_entries = zip_info.get("risky_entries") or []
    if risky_ext or pickle_like or zip_pickle_entries:
        findings.append(_finding(
            finding_id="unsafe_serialization",
            title="Unsafe model serialization format detected",
            severity="critical" if pickle_like or zip_pickle_entries else "high",
            description="The model artifact appears to use pickle-like or framework serialization that can execute code during load.",
            artifact_ref=artifact_ref,
            evidence={
                "artifact": name,
                "extension": ext,
                "pickle_like_header": pickle_like,
                "zip_pickle_entries": zip_pickle_entries,
                "risky_entries": zip_risky_entries,
            },
            remediation="Prefer non-executable formats such as safetensors, ONNX, TFLite, or GGUF. If legacy formats are unavoidable, load only in a sandboxed conversion pipeline.",
        ))

    safetensors_header = format_inspection.get("safetensors_header") if isinstance(format_inspection.get("safetensors_header"), dict) else {}
    if ext == ".safetensors" and artifact_bytes and not safetensors_header.get("valid"):
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

    if require_governance and strict_governance and not poisoning_eval_ref and not metadata_unavailable:
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

    if require_governance and not sbom_ref and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_sbom_or_dependencies",
            title="Model dependency/SBOM evidence missing",
            severity="medium",
            description="No SBOM, dependency inventory, or package exposure evidence was supplied for the model artifact.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Attach SBOM or dependency inventory for model package code, adapters, tokenizers, and serving dependencies.",
        ))

    if require_governance and sbom_ref and strict_governance and not sbom_policy["valid"] and not metadata_unavailable:
        findings.append(_finding(
            finding_id="invalid_sbom_evidence",
            title="Model SBOM evidence is incomplete or unvalidated",
            severity="medium",
            description="Strict model-intake policy requires a CycloneDX/SPDX or component-list SBOM with at least one component.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "sbom_policy": sbom_policy},
            remediation="Attach a valid CycloneDX or SPDX SBOM with package components, purls, hashes, and license evidence.",
        ))

    if require_governance and not malware_scan_ref and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_malware_scan",
            title="Model malware scan evidence missing",
            severity="medium",
            description="The intake metadata did not include malware, YARA, or antivirus scan evidence.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Require static malware/YARA scanning and record scan result, engine, and timestamp before approval.",
        ))

    if require_governance and malware_scan_ref and strict_governance and not malware_policy["valid"] and not metadata_unavailable:
        findings.append(_finding(
            finding_id="invalid_malware_scan_evidence",
            title="Model malware scan evidence is incomplete, stale, or not bound to the artifact",
            severity="medium",
            description="Strict model-intake policy requires a clean malware scan with scanner/version, timestamp, artifact digest, and fresh evidence.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "malware_policy": malware_policy},
            remediation="Run malware/YARA scanning against the exact artifact digest and record scanner, engine version, timestamp, and clean status.",
        ))

    if require_governance and not eval_ref and not metadata_unavailable:
        findings.append(_finding(
            finding_id="missing_eval_evidence",
            title="Model security evaluation evidence missing",
            severity="medium",
            description="No security eval, red-team report, or model behavior evaluation evidence was supplied.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Attach safety/security eval results, red-team coverage, and deployment-specific acceptance criteria.",
        ))

    if require_governance and eval_ref and strict_governance and not eval_policy["valid"] and not metadata_unavailable:
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
    if ext in SAFER_MODEL_EXTENSIONS and not any(f["id"].endswith("unsafe_serialization") for f in findings) and not format_specific_blocked:
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
    format_specific_ok = not any(
        finding["id"] in {
            "model_intake:safetensors_header_invalid",
            "model_intake:onnx_external_data_reference",
            "model_intake:onnx_custom_operator",
            "model_intake:gguf_header_invalid",
        }
        for finding in findings
    )

    score = max(0, 100 - sum(_severity_score(f.get("severity", "info")) for f in findings))
    safe_artifact_ref = redact_model_intake_value(artifact_ref)
    safe_registry_reference = redact_model_intake_value(registry_reference)
    safe_metadata = redact_model_intake_value(metadata)
    safe_metadata_fetch_meta = redact_model_intake_value(metadata_fetch_meta)
    safe_artifact_meta = redact_model_intake_value(artifact_meta)
    safe_signature_status = redact_model_intake_value(signature_status)
    safe_aibom = redact_model_intake_value(aibom)
    safe_findings = redact_model_intake_value(findings)
    summary = {
        "artifact_name": name,
        "artifact_ref": safe_artifact_ref,
        "source_kind": _source_kind(artifact_ref, metadata),
        "registry": safe_registry_reference,
        "extension": ext,
        "sha256": sha256,
        "sha256_scope": observed_hash_scope,
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
        "signature_claimed_verified": signature_status["claimed_verified"],
        "signature_cryptographically_verified": signature_status["cryptographically_verified"],
        "signature_verifier": signature_status.get("verifier"),
        "signature_transparency_log_verified": signature_status.get("transparency_log_verified"),
        "signature_attestation_subject_digest_match": signature_status.get("attestation_subject_digest_match"),
        "signature_crypto_attempted": signature_status.get("crypto_attempted"),
        "expected_hash_present": bool(expected_sha256),
        "deployment_approved": deployment_approved,
        "license_present": bool(license_ref),
        "sbom_present": bool(sbom_ref),
        "malware_scan_present": bool(malware_scan_ref),
        "eval_evidence_present": bool(eval_ref),
        "deployment_restrictions_present": bool(deployment_restrictions),
        "monitoring_plan_present": bool(monitoring_plan),
        "training_data_lineage_present": bool(training_data_ref),
        "dataset_digest_present": bool(dataset_digest),
        "base_model_lineage_present": bool(base_model_ref),
        "training_pipeline_provenance_present": bool(fine_tune_provenance),
        "poisoning_eval_present": bool(poisoning_eval_ref),
        "metadata_fetch_failed": bool(metadata_fetch_meta.get("error")),
        "findings_count": len(findings),
    }

    return {
        "schema_version": "2026-05-10.model-intake.v1",
        "scan_mode": "model_intake",
        "target": safe_artifact_ref,
        "model_intake": {
            "summary": summary,
            "artifact": {
                "name": name,
                "extension": ext,
                "fetch": safe_artifact_meta,
                "archive": zip_info,
            },
            "metadata": safe_metadata,
            "metadata_fetch": safe_metadata_fetch_meta if metadata_url else None,
            "aibom": safe_aibom,
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
                    None if metadata_unavailable else (eval_policy["valid"] if strict_governance else bool(eval_ref))
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
            **_intake_decision(findings),
        },
    }


__all__ = ["normalize_model_artifact_reference", "parse_huggingface_ref", "run_model_intake_scan"]
