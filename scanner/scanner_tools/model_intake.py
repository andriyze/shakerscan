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
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


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


def _download_http(url: str, max_bytes: int, timeout_seconds: int) -> tuple[bytes, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ShakerScan-ModelIntake/1.0",
            "Range": f"bytes=0-{max_bytes - 1}",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        data = response.read(max_bytes + 1)
        headers = dict(response.headers.items())
        return data[:max_bytes], {
            "source": "http",
            "status": getattr(response, "status", None),
            "content_type": headers.get("Content-Type"),
            "content_length": headers.get("Content-Length"),
            "bytes_observed": min(len(data), max_bytes),
            "truncated": len(data) > max_bytes or bool(headers.get("Content-Range")),
        }


async def _fetch_artifact(ref: str, max_bytes: int, timeout_seconds: int) -> tuple[bytes, dict[str, Any]]:
    parsed = urllib.parse.urlparse(ref)
    try:
        if parsed.scheme in ("http", "https"):
            return await asyncio.to_thread(_download_http, ref, max_bytes, timeout_seconds)
        if parsed.scheme == "file" or not parsed.scheme:
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


async def _fetch_json(url: str, timeout_seconds: int, max_bytes: int = 262_144) -> dict[str, Any]:
    data, _meta = await _fetch_artifact(url, max_bytes=max_bytes, timeout_seconds=timeout_seconds)
    try:
        parsed = json.loads(data.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _looks_like_pickle(data: bytes) -> bool:
    if data.startswith(PICKLE_MAGIC_PREFIXES):
        return True
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
        with zipfile.ZipFile(tmp_path) as zf:
            for info in zf.infolist()[:500]:
                entry = info.filename
                entries.append(entry)
                ext = Path(entry).suffix.lower()
                lowered = entry.lower()
                if ext in RISKY_EXTENSIONS or lowered.endswith("/data.pkl") or lowered.endswith("pickle"):
                    risky_entries.append(entry)
                if ext in EXECUTABLE_EXTENSIONS:
                    executable_entries.append(entry)
                if lowered.endswith((".pkl", ".pickle", "data.pkl")):
                    pickle_entries.append(entry)
        return {
            "is_zip": True,
            "entries": entries[:50],
            "entry_count": len(entries),
            "risky_entries": risky_entries[:50],
            "pickle_entries": pickle_entries[:50],
            "executable_entries": executable_entries[:50],
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
    if _metadata_value(metadata, "huggingface_repo", "hf_repo"):
        return "huggingface"
    if ref.startswith("hf://") or "huggingface.co/" in ref:
        return "huggingface"
    if ref.startswith("oci://") or _metadata_value(metadata, "oci_ref", "image_ref"):
        return "oci"
    parsed = urllib.parse.urlparse(ref)
    return parsed.scheme or "local"


async def run_model_intake_scan(artifact_ref: str, raw_options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run model artifact intake checks without executing model code."""
    options = raw_options or {}
    metadata = options.get("metadata_json") if isinstance(options.get("metadata_json"), dict) else {}
    metadata_url = options.get("metadata_url")
    timeout_seconds = int(options.get("timeout_seconds") or 20)
    max_download_bytes = int(options.get("max_download_bytes") or 10_000_000)

    if metadata_url:
        remote_metadata = await _fetch_json(str(metadata_url), timeout_seconds=timeout_seconds)
        metadata = {**remote_metadata, **metadata}

    artifact_bytes, artifact_meta = await _fetch_artifact(
        artifact_ref,
        max_bytes=max_download_bytes,
        timeout_seconds=timeout_seconds,
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
    license_ref = _metadata_value(metadata, "license", "model_license", "license_url")
    sbom_ref = _metadata_value(metadata, "sbom_url", "sbom", "dependencies", "package_dependencies")
    malware_scan_ref = _metadata_value(metadata, "malware_scan_url", "malware_scan_result", "yara_scan", "av_scan")
    eval_ref = _metadata_value(metadata, "eval_report_url", "security_evals", "red_team_report", "eval_results")
    deployment_restrictions = _metadata_value(metadata, "deployment_restrictions", "allowed_environments", "use_restrictions")
    monitoring_plan = _metadata_value(metadata, "monitoring_plan", "monitoring_plan_url", "drift_monitoring", "incident_response_plan")

    if artifact_meta.get("error"):
        if unsupported_scheme_error:
            findings.append(_finding(
                finding_id="unsupported_artifact_scheme",
                title="Model artifact scheme is unsupported",
                severity="high",
                description="The configured artifact URL uses a registry scheme not currently supported by the intake fetcher.",
                artifact_ref=artifact_ref,
                evidence={"artifact": name, "fetch": artifact_meta},
                remediation="Use a supported artifact source (http/https) or extend model-intake fetch support for hf/oci registries.",
            ))
            return {
                "schema_version": "2026-05-10.model-intake.v1",
                "scan_mode": "model_intake",
                "target": artifact_ref,
                "model_intake": {
                    "summary": {
                        "artifact_name": name,
                        "artifact_ref": artifact_ref,
                        "source_kind": _source_kind(artifact_ref, metadata),
                        "extension": ext,
                        "sha256": sha256,
                        "format_posture": "unknown_or_unclassified_format",
                        "provenance_present": False,
                        "signature_present": False,
                        "expected_hash_present": bool(expected_sha256),
                        "deployment_approved": deployment_approved,
                        "license_present": bool(license_ref),
                        "sbom_present": bool(sbom_ref),
                        "malware_scan_present": bool(malware_scan_ref),
                        "eval_evidence_present": bool(eval_ref),
                        "deployment_restrictions_present": bool(deployment_restrictions),
                        "monitoring_plan_present": bool(monitoring_plan),
                        "findings_count": len(findings),
                    },
                    "artifact": {
                        "name": name,
                        "extension": ext,
                        "fetch": artifact_meta,
                        "archive": zip_info,
                    },
                    "metadata": metadata,
                    "checks": {
                        "provenance": False,
                        "unsafe_serialization": None,
                        "artifact_signing": False,
                        "checksum": False,
                        "approval": deployment_approved if require_approval else None,
                        "license_review": False if require_governance else None,
                        "sbom_dependencies": False if require_governance else None,
                        "malware_scan": False if require_governance else None,
                        "security_evals": False if require_governance else None,
                        "deployment_restrictions": False if require_governance else None,
                        "monitoring_plan": False if require_governance else None,
                    },
                },
                "findings": findings,
                "result": {
                    "score": max(0, 100 - _severity_score("high")),
                    "grade": _grade(max(0, 100 - _severity_score("high"))),
                    **_intake_decision(findings),
                },
            }
        findings.append(_finding(
            finding_id="artifact_fetch_failed",
            title="Model artifact could not be fetched for intake",
            severity="high",
            description="The model artifact could not be downloaded or read, so provenance and serialization checks could not complete.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "fetch": artifact_meta},
            remediation="Make the model artifact reachable to the intake worker or provide an internal registry reference with access credentials.",
        ))

    if expected_sha256 and sha256 and str(expected_sha256).lower() != sha256.lower():
        findings.append(_finding(
            finding_id="sha256_mismatch",
            title="Model artifact checksum mismatch",
            severity="critical",
            description="The observed model artifact hash does not match the expected SHA-256 value.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "expected_sha256": expected_sha256, "observed_sha256": sha256},
            remediation="Block deployment, verify the source registry, and re-publish the artifact with a trusted checksum.",
        ))
    elif require_hash and not expected_sha256:
        findings.append(_finding(
            finding_id="missing_checksum",
            title="Model artifact missing expected checksum",
            severity="medium",
            description="No expected checksum was supplied for the model artifact, limiting integrity verification.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "observed_sha256": sha256},
            remediation="Require SHA-256 or stronger digest pinning in model intake metadata before deployment approval.",
        ))

    if require_signature and not (signature_url or signed_by):
        findings.append(_finding(
            finding_id="missing_signature",
            title="Model artifact missing signature or attestation",
            severity="medium",
            description="The model artifact did not include a signature, signer, or provenance attestation reference.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "signature_url": signature_url, "signed_by": signed_by},
            remediation="Require Sigstore, registry signing, or an equivalent signed attestation for deployable model artifacts.",
        ))

    risky_ext = ext in RISKY_EXTENSIONS
    pickle_like = _looks_like_pickle(artifact_bytes)
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

    if not provenance_ref:
        findings.append(_finding(
            finding_id="missing_provenance",
            title="Model artifact missing provenance metadata",
            severity="medium",
            description="The artifact intake metadata did not identify source repository, commit, training data reference, or provenance attestation.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "source_kind": _source_kind(artifact_ref, metadata), "metadata_keys": sorted(metadata.keys())},
            remediation="Require source repository, commit hash, training data reference, build workflow, and attestation URL before deployment approval.",
        ))

    if not model_card:
        findings.append(_finding(
            finding_id="missing_model_card",
            title="Model artifact missing model card or risk documentation",
            severity="low",
            description="No model card, risk assessment, or usage constraints were supplied with the artifact.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name},
            remediation="Require model card metadata describing intended use, limitations, safety tests, license, and deployment constraints.",
        ))

    if require_approval and not deployment_approved:
        findings.append(_finding(
            finding_id="missing_deployment_approval",
            title="Model deployment approval missing",
            severity="high",
            description="The intake request requires deployment approval, but approval metadata was absent or false.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "approved_by": metadata.get("approved_by"), "deployment_approved": deployment_approved},
            remediation="Route the artifact through approval before deployment and record approver, timestamp, and policy version.",
        ))

    if require_governance and not license_ref:
        findings.append(_finding(
            finding_id="missing_license_review",
            title="Model license review missing",
            severity="medium",
            description="The intake metadata did not include a model license, license URL, or license review result.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Record model license, usage constraints, and legal/security review status before deployment.",
        ))

    if require_governance and not sbom_ref:
        findings.append(_finding(
            finding_id="missing_sbom_or_dependencies",
            title="Model dependency/SBOM evidence missing",
            severity="medium",
            description="No SBOM, dependency inventory, or package exposure evidence was supplied for the model artifact.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Attach SBOM or dependency inventory for model package code, adapters, tokenizers, and serving dependencies.",
        ))

    if require_governance and not malware_scan_ref:
        findings.append(_finding(
            finding_id="missing_malware_scan",
            title="Model malware scan evidence missing",
            severity="medium",
            description="The intake metadata did not include malware, YARA, or antivirus scan evidence.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Require static malware/YARA scanning and record scan result, engine, and timestamp before approval.",
        ))

    if require_governance and not eval_ref:
        findings.append(_finding(
            finding_id="missing_eval_evidence",
            title="Model security evaluation evidence missing",
            severity="medium",
            description="No security eval, red-team report, or model behavior evaluation evidence was supplied.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Attach safety/security eval results, red-team coverage, and deployment-specific acceptance criteria.",
        ))

    if require_governance and not deployment_restrictions:
        findings.append(_finding(
            finding_id="missing_deployment_restrictions",
            title="Model deployment restrictions missing",
            severity="low",
            description="No approved environments, usage restrictions, or deployment constraints were supplied.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Record approved environments, data-use restrictions, prohibited use cases, and rollback constraints.",
        ))

    if require_governance and not monitoring_plan:
        findings.append(_finding(
            finding_id="missing_monitoring_plan",
            title="Model monitoring plan missing",
            severity="low",
            description="No post-deployment monitoring, drift, abuse, or incident-response plan was supplied.",
            artifact_ref=artifact_ref,
            evidence={"artifact": name, "metadata_keys": sorted(metadata.keys())},
            remediation="Define monitoring for drift, abuse, data leakage, cost anomalies, incidents, and periodic reassessment.",
        ))

    if ext in SAFER_MODEL_EXTENSIONS and not any(f["id"].endswith("unsafe_serialization") for f in findings):
        format_posture = "safer_static_format"
    elif ext in RISKY_EXTENSIONS or pickle_like:
        format_posture = "unsafe_executable_serialization"
    else:
        format_posture = "unknown_or_unclassified_format"

    score = max(0, 100 - sum(_severity_score(f.get("severity", "info")) for f in findings))
    summary = {
        "artifact_name": name,
        "artifact_ref": artifact_ref,
        "source_kind": _source_kind(artifact_ref, metadata),
        "extension": ext,
        "sha256": sha256,
        "format_posture": format_posture,
        "provenance_present": bool(provenance_ref),
        "signature_present": bool(signature_url or signed_by),
        "expected_hash_present": bool(expected_sha256),
        "deployment_approved": deployment_approved,
        "license_present": bool(license_ref),
        "sbom_present": bool(sbom_ref),
        "malware_scan_present": bool(malware_scan_ref),
        "eval_evidence_present": bool(eval_ref),
        "deployment_restrictions_present": bool(deployment_restrictions),
        "monitoring_plan_present": bool(monitoring_plan),
        "findings_count": len(findings),
    }

    return {
        "schema_version": "2026-05-10.model-intake.v1",
        "scan_mode": "model_intake",
        "target": artifact_ref,
        "model_intake": {
            "summary": summary,
            "artifact": {
                "name": name,
                "extension": ext,
                "fetch": artifact_meta,
                "archive": zip_info,
            },
            "metadata": metadata,
            "checks": {
                "provenance": bool(provenance_ref),
                "unsafe_serialization": not any(f["id"].endswith("unsafe_serialization") for f in findings),
                "artifact_signing": bool(signature_url or signed_by),
                "checksum": bool(expected_sha256 and sha256 and str(expected_sha256).lower() == sha256.lower()),
                "approval": deployment_approved if require_approval else None,
                "license_review": bool(license_ref) if require_governance else None,
                "sbom_dependencies": bool(sbom_ref) if require_governance else None,
                "malware_scan": bool(malware_scan_ref) if require_governance else None,
                "security_evals": bool(eval_ref) if require_governance else None,
                "deployment_restrictions": bool(deployment_restrictions) if require_governance else None,
                "monitoring_plan": bool(monitoring_plan) if require_governance else None,
            },
        },
        "findings": findings,
        "result": {
            "score": score,
            "grade": _grade(score),
            **_intake_decision(findings),
        },
    }


__all__ = ["run_model_intake_scan"]
