"""Model Intake routes.

Extracted verbatim from the api.py monolith. Owns the Model Intake surface —
source resolution and submission, evidence scans and SBOM exports, scanner and
provider readiness, runner jobs and storage, trust anchors and signatures, the
controlled admission workflow with its approvals and policy decisions, promotion
and deployment bindings, reassessment, retention cleanup, and the automatic
review controller.

Collaborators that are still hubs inside api.py are injected by the composition
root as lazily-resolved callables.
"""

from __future__ import annotations

import asyncio
import base64
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import io
import ipaddress
import json
import math
import os
import re
import secrets
import shlex
import shutil
import subprocess
import threading
import time
from typing import Annotated, Any, Callable, Literal, Mapping, Optional, Sequence, Union
import urllib.parse
import uuid
import zipfile

import asyncpg
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from api_utils import (
        SEVERITY_ORDER, _clean_string_list, _content_free_hash, _direct_query_value,
        _int_or_none, _iso_or_none, _json_safe_row, _optional_uuid, _parse_iso_datetime,
        _record_map, _row_value, _severity_sort_value, _uuid_or_400, utc_now, utc_now_iso,
    )
    from operator_auth import (
        _MODEL_INTAKE_APPROVAL_ROLES, _mint_model_intake_local_session,
        _model_intake_authenticated_subject, _model_intake_automatic_system_request,
        _model_intake_configured_operator_credentials, _model_intake_local_session_allowed,
        _model_intake_operator_roles, _model_intake_submission_subject,
        _require_model_intake_operator,
    )
    from model_intake_authority import _invalidate_model_intake_authority_change
    from api_utils import _short_url_label, extract_root_domain
    from job_queue import enqueue_job
    from model_intake_admissions import REASSESSMENT_TRIGGERS, triggered_status as _model_admission_triggered_status
    from model_intake_agent import embedding_test_plan as _model_intake_embedding_test_plan, parse_planner_reply as _parse_model_intake_planner_reply, planner_prompt as _model_intake_planner_prompt
    from model_intake_components import component_identities as _model_intake_component_identities
    from model_intake_control_plane import AdmissionContractError as _ModelAdmissionContractError, build_approval_receipt as _build_model_approval_receipt, build_deployment_bundle as _build_model_deployment_bundle, evaluate_policy as _evaluate_model_admission_policy, freeze_evidence_manifest as _freeze_model_evidence_manifest, policy_bundle_identity as _model_policy_bundle_identity, verify_admission_v2 as _verify_model_admission_v2
    from model_intake_loader_profiles import resolve_conversion_profile as _resolve_model_conversion_profile, resolve_loader_profile as _resolve_model_loader_profile
    from model_intake_reporting import EXTERNAL_APPROVAL_REQUIREMENTS as _MODEL_INTAKE_EXTERNAL_REQUIREMENTS, SHAKERSCAN_CHECK_CATALOG as _MODEL_INTAKE_CHECK_CATALOG, apply_automatic_review_context as _apply_model_intake_automatic_review_context, build_model_intake_report as _build_model_intake_report, model_intake_report_to_sarif as _model_intake_report_to_sarif, render_model_intake_html as _render_model_intake_html
    from model_intake_runner_controller import firecracker_readiness as _model_firecracker_readiness, runner_memory_admission as _model_runner_memory_admission
    from model_intake_runner_evaluation import derive_embedding_evaluation as _derive_model_runner_embedding_evaluation
    from model_intake_runner_inputs import suite_identity as _model_intake_runner_input_suite
    from model_intake_runner_receipts import EVIDENCE_POLICY as _MODEL_RUNNER_EVIDENCE_POLICY, verify_runner_envelope as _verify_model_runner_envelope
    from model_intake_sbom import build_model_intake_cyclonedx as _build_model_intake_cyclonedx, build_model_intake_license_bom as _build_model_intake_license_bom, build_model_intake_spdx as _build_model_intake_spdx, model_intake_bom_completeness as _model_intake_bom_completeness, model_intake_license_display as _model_intake_license_display, render_third_party_notices_draft as _render_model_intake_third_party_notices
    from pathlib import Path
    from serialization import _decode_json_value, _json_object, _str_list, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..api_utils import (
        SEVERITY_ORDER, _clean_string_list, _content_free_hash, _direct_query_value,
        _int_or_none, _iso_or_none, _json_safe_row, _optional_uuid, _parse_iso_datetime,
        _record_map, _row_value, _severity_sort_value, _uuid_or_400, utc_now, utc_now_iso,
    )
    from ..operator_auth import (
        _MODEL_INTAKE_APPROVAL_ROLES, _mint_model_intake_local_session,
        _model_intake_authenticated_subject, _model_intake_automatic_system_request,
        _model_intake_configured_operator_credentials, _model_intake_local_session_allowed,
        _model_intake_operator_roles, _model_intake_submission_subject,
        _require_model_intake_operator,
    )
    from ..model_intake_authority import _invalidate_model_intake_authority_change
    from ..api_utils import _short_url_label, extract_root_domain
    from ..job_queue import enqueue_job
    from ..model_intake_admissions import REASSESSMENT_TRIGGERS, triggered_status as _model_admission_triggered_status
    from ..model_intake_agent import embedding_test_plan as _model_intake_embedding_test_plan, parse_planner_reply as _parse_model_intake_planner_reply, planner_prompt as _model_intake_planner_prompt
    from ..model_intake_components import component_identities as _model_intake_component_identities
    from ..model_intake_control_plane import AdmissionContractError as _ModelAdmissionContractError, build_approval_receipt as _build_model_approval_receipt, build_deployment_bundle as _build_model_deployment_bundle, evaluate_policy as _evaluate_model_admission_policy, freeze_evidence_manifest as _freeze_model_evidence_manifest, policy_bundle_identity as _model_policy_bundle_identity, verify_admission_v2 as _verify_model_admission_v2
    from ..model_intake_loader_profiles import resolve_conversion_profile as _resolve_model_conversion_profile, resolve_loader_profile as _resolve_model_loader_profile
    from ..model_intake_reporting import EXTERNAL_APPROVAL_REQUIREMENTS as _MODEL_INTAKE_EXTERNAL_REQUIREMENTS, SHAKERSCAN_CHECK_CATALOG as _MODEL_INTAKE_CHECK_CATALOG, apply_automatic_review_context as _apply_model_intake_automatic_review_context, build_model_intake_report as _build_model_intake_report, model_intake_report_to_sarif as _model_intake_report_to_sarif, render_model_intake_html as _render_model_intake_html
    from ..model_intake_runner_controller import firecracker_readiness as _model_firecracker_readiness, runner_memory_admission as _model_runner_memory_admission
    from ..model_intake_runner_evaluation import derive_embedding_evaluation as _derive_model_runner_embedding_evaluation
    from ..model_intake_runner_inputs import suite_identity as _model_intake_runner_input_suite
    from ..model_intake_runner_receipts import EVIDENCE_POLICY as _MODEL_RUNNER_EVIDENCE_POLICY, verify_runner_envelope as _verify_model_runner_envelope
    from ..model_intake_sbom import build_model_intake_cyclonedx as _build_model_intake_cyclonedx, build_model_intake_license_bom as _build_model_intake_license_bom, build_model_intake_spdx as _build_model_intake_spdx, model_intake_bom_completeness as _model_intake_bom_completeness, model_intake_license_display as _model_intake_license_display, render_third_party_notices_draft as _render_model_intake_third_party_notices
    from pathlib import Path
    from ..serialization import _decode_json_value, _json_object, _str_list, row_to_dict


try:
    from scanner_tools.model_intake_acquisition import acquisition_policy as _model_acquisition_policy, download_http as _model_download_http
    from scanner_tools.model_intake_admission import trusted_public_keys_from_env as _model_admission_trusted_keys, verify_package as _verify_model_admission_package
    from scanner_tools.model_intake_evaluation import evaluate as _evaluate_model_intake_request
    from scanner_tools.model_intake_providers import provider_readiness as _model_provider_readiness
    from scanner_tools.model_intake_registry import adapter_capabilities as _model_adapter_capabilities, adapter_catalog as _model_adapter_catalog
    from scanner_tools.model_intake_retention import execute_cleanup as _execute_model_quarantine_cleanup, plan_cleanup as _plan_model_quarantine_cleanup
    from scanner_tools.model_intake_scanners import scan_materialized_snapshot as _scan_materialized_model_snapshot, scanner_adapter_readiness as _model_scanner_adapter_readiness
except ModuleNotFoundError:  # source checkout keeps scanner tools in scanner/
    from scanner.scanner_tools.model_intake_acquisition import acquisition_policy as _model_acquisition_policy, download_http as _model_download_http
    from scanner.scanner_tools.model_intake_admission import trusted_public_keys_from_env as _model_admission_trusted_keys, verify_package as _verify_model_admission_package
    from scanner.scanner_tools.model_intake_evaluation import evaluate as _evaluate_model_intake_request
    from scanner.scanner_tools.model_intake_providers import provider_readiness as _model_provider_readiness
    from scanner.scanner_tools.model_intake_registry import adapter_capabilities as _model_adapter_capabilities, adapter_catalog as _model_adapter_catalog
    from scanner.scanner_tools.model_intake_retention import execute_cleanup as _execute_model_quarantine_cleanup, plan_cleanup as _plan_model_quarantine_cleanup
    from scanner.scanner_tools.model_intake_scanners import scan_materialized_snapshot as _scan_materialized_model_snapshot, scanner_adapter_readiness as _model_scanner_adapter_readiness


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


MODEL_INTAKE_SAFER_EXTENSIONS = {".safetensors", ".onnx", ".tflite", ".gguf"}
MODEL_INTAKE_RISKY_EXTENSIONS = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt", ".bin", ".mar"}
MODEL_INTAKE_ADMISSION_FORBIDDEN_FIELDS = {
    "signature_trusted_keys",
    "signature_trusted_key_sha256",
    "attestation_trusted_keys",
    "attestation_trusted_key_sha256",
    "allowed_attestation_predicate_types",
    "required_attestation_builder_ids",
    "trust_anchor_ids",
    "deployment_approved",
    "policy_exceptions",
}
MODEL_INTAKE_GUEST_KERNEL_URL = (
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/x86_64/vmlinux-6.1.128"
)
MODEL_INTAKE_GUEST_KERNEL_SHA256 = (
    "27a8310b9a727517e9eb02044524b6ceb77de5728e3491b6974d5c846227ecc8"
)
_MODEL_INTAKE_PROVIDER_AUTHORITY_KEYS = {
    "huggingface_repo",
    "revision",
    "huggingface_file",
    "huggingface_file_inventory",
    "repository_manifest",
    "source_repo",
    "python_files",
    "custom_code_required",
    "auto_map",
}
MODEL_INTAKE_TOKENIZER_FILES = {
    "merges.txt",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer.model",
    "tokenizer_config.json",
    "vocab.json",
    "vocab.txt",
}
MODEL_INTAKE_DEPENDENCY_FILES = {
    "conda.yml",
    "dockerfile",
    "environment.yml",
    "package-lock.json",
    "package.json",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "requirements-dev.txt",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
}
MODEL_INTAKE_REPOSITORY_MANIFEST_MAX_FILES = 10_000
HF_MODEL_INFO_MAX_BYTES = 10_000_000
MODEL_INTAKE_ADMISSION_FORBIDDEN_METADATA_KEYS = {
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
_MODEL_INTAKE_STAGE_LOG_LINES = 200
MODEL_INTAKE_GUEST_ROOTFS_INPUTS = (
    "runner/guest/Dockerfile",
    "runner/guest/requirements.lock",
    "runner/guest/guest-init",
    "runner/guest/guest_worker.py",
)
MODEL_INTAKE_COMMON_ARTIFACTS = {
    "model.safetensors",
    "pytorch_model.bin",
    "tf_model.h5",
    "model.onnx",
    "model.tflite",
    "model.gguf",
    "adapter_model.safetensors",
    "adapter_model.bin",
}
MODEL_INTAKE_METADATA_FILES = {
    "config.json",
    "generation_config.json",
    "model_index.json",
    "model.safetensors.index.json",
    "readme.md",
}
MODEL_INTAKE_EXECUTABLE_EXTENSIONS = {
    ".py", ".pyc", ".pyo", ".ipynb", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".so", ".dll", ".dylib", ".exe", ".whl",
}





def configure_model_intake_router(
    pool_provider: Callable[[], Any], **collaborators: Callable[..., Any]
) -> None:
    """Bind the pool and the collaborators this domain needs."""
    global _pool_provider
    _pool_provider = pool_provider
    _deps.update(collaborators)


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool


def _dep(name: str) -> Callable[..., Any]:
    call = _deps.get(name)
    if call is None:
        raise HTTPException(status_code=503, detail=f"{name} is not ready")
    return call

# Hub collaborators that still live in api.py, injected and resolved lazily.
def get_redis(*a: Any, **k: Any) -> Any:
    return _dep("get_redis")(*a, **k)


def _sanitize_scan_options(*a: Any, **k: Any) -> Any:
    return _dep("sanitize_scan_options")(*a, **k)


def _model_intake_json_object(*a: Any, **k: Any) -> Any:
    return _dep("model_intake_json_object")(*a, **k)


def _results_dir() -> Any:
    return _dep("results_dir")()


async def _validate_approval_receipt_for_action(*a: Any, **k: Any) -> Any:
    return await _dep("validate_approval_receipt_for_action")(*a, **k)


async def _require_approval_receipt_if_policy_enabled(*a: Any, **k: Any) -> Any:
    return await _dep("require_approval_receipt_if_policy_enabled")(*a, **k)


async def _record_command_result(*a: Any, **k: Any) -> Any:
    return await _dep("record_command_result")(*a, **k)


def _worker_freshness_snapshot(*a: Any, **k: Any) -> Any:
    return _dep("worker_freshness_snapshot")(*a, **k)


import logging

logger = logging.getLogger("shakerscan.api.model_intake")
QUEUE_NAME = os.environ.get("SCAN_QUEUE_NAME", "scan_jobs")

@router.get("/model-intake/trust-anchors")
async def list_model_intake_trust_anchors(active_only: bool = True):
    where = "WHERE is_active = true" if active_only else ""
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            f"SELECT * FROM model_intake_trust_anchors {where} ORDER BY is_active DESC, policy_profile NULLS LAST, name"
        )
    return {"trust_anchors": [row_to_dict(row) for row in rows]}


@router.post("/model-intake/trust-anchors")
async def create_model_intake_trust_anchor(req: ModelIntakeTrustAnchorRequest, http_request: Request):
    actor = _model_intake_authenticated_subject(http_request)
    _validate_model_intake_trust_anchor_request(req)
    async with _pool().acquire() as conn, conn.transaction():
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO model_intake_trust_anchors
                    (name, description, public_key_pem, public_key_sha256, policy_profile,
                     purpose, environment, valid_from, valid_until, issuer_constraint,
                     subject_constraint, builder_id_constraint, source, version, owner, is_active)
                VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8,NOW()),$9,$10,$11,$12,$13,$14,$15,$16)
                RETURNING *
                """,
                req.name.strip(),
                req.description,
                str(req.public_key_pem or "").strip() or None,
                str(req.public_key_sha256 or "").strip().lower() or None,
                str(req.policy_profile or "").strip().lower() or None,
                req.purpose,
                req.environment,
                req.valid_from,
                req.valid_until,
                req.issuer_constraint,
                req.subject_constraint,
                req.builder_id_constraint,
                req.source,
                req.version,
                req.owner,
                req.is_active,
            )
        except asyncpg.UniqueViolationError:
            raise HTTPException(status_code=409, detail="Model Intake trust anchor name already exists")
        invalidation = (
            await _invalidate_model_intake_authority_change(
                conn,
                actor=actor,
                trigger_type="trust_anchor_change",
                reason=f"Activated trust anchor {row['id']}",
                environments=[str(row["environment"])],
            )
            if row["is_active"] else {"admissions_invalidated": 0, "deployment_bindings_staled": 0}
        )
    return {**row_to_dict(row), "downstream_invalidation": invalidation}


@router.patch("/model-intake/trust-anchors/{anchor_id}")
async def update_model_intake_trust_anchor(anchor_id: str, req: ModelIntakeTrustAnchorRequest, http_request: Request):
    actor = _model_intake_authenticated_subject(http_request)
    _validate_model_intake_trust_anchor_request(req)
    async with _pool().acquire() as conn, conn.transaction():
        previous = await conn.fetchrow(
            "SELECT id,environment,is_active FROM model_intake_trust_anchors WHERE id=$1 FOR UPDATE",
            uuid.UUID(anchor_id),
        )
        if not previous:
            raise HTTPException(status_code=404, detail="Model Intake trust anchor not found")
        row = await conn.fetchrow(
            """
            UPDATE model_intake_trust_anchors SET
                name=$2, description=$3, public_key_pem=$4, public_key_sha256=$5,
                policy_profile=$6, purpose=$7, environment=$8, valid_from=COALESCE($9,valid_from),
                valid_until=$10, issuer_constraint=$11, subject_constraint=$12,
                builder_id_constraint=$13, source=$14, version=$15, owner=$16,
                is_active=$17, updated_at=NOW()
            WHERE id=$1
            RETURNING *
            """,
            uuid.UUID(anchor_id),
            req.name.strip(),
            req.description,
            str(req.public_key_pem or "").strip() or None,
            str(req.public_key_sha256 or "").strip().lower() or None,
            str(req.policy_profile or "").strip().lower() or None,
            req.purpose,
            req.environment,
            req.valid_from,
            req.valid_until,
            req.issuer_constraint,
            req.subject_constraint,
            req.builder_id_constraint,
            req.source,
            req.version,
            req.owner,
            req.is_active,
        )
        affected = bool(previous["is_active"] or row["is_active"])
        invalidation = (
            await _invalidate_model_intake_authority_change(
                conn,
                actor=actor,
                trigger_type="trust_anchor_change",
                reason=f"Changed trust anchor {anchor_id}",
                environments=[str(previous["environment"]), str(row["environment"])],
            )
            if affected else {"admissions_invalidated": 0, "deployment_bindings_staled": 0}
        )
    return {**row_to_dict(row), "downstream_invalidation": invalidation}


@router.delete("/model-intake/trust-anchors/{anchor_id}")
async def deactivate_model_intake_trust_anchor(anchor_id: str, http_request: Request):
    actor = _model_intake_authenticated_subject(http_request)
    async with _pool().acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            UPDATE model_intake_trust_anchors
            SET is_active=false, revoked_at=NOW(),
                revocation_reason='operator deactivated trust anchor', updated_at=NOW()
            WHERE id=$1 AND is_active=true
            RETURNING *
            """,
            uuid.UUID(anchor_id),
        )
        if not row:
            raise HTTPException(status_code=409, detail="Model Intake trust anchor is absent or already inactive")
        invalidation = await _invalidate_model_intake_authority_change(
            conn,
            actor=actor,
            trigger_type="trust_anchor_change",
            reason=f"Deactivated trust anchor {anchor_id}",
            environments=[str(row["environment"])],
        )
    return {
        "deactivated": True,
        "trust_anchor": row_to_dict(row),
        "downstream_invalidation": invalidation,
    }


@router.post("/model-intake/submissions")
async def create_model_intake_submission(request: ModelSubmissionRequest, http_request: Request):
    """Create work only; this endpoint can never issue an admission."""
    forbidden = _model_intake_forbidden_metadata_paths(request.declared_metadata, "declared_metadata")
    if forbidden:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "model_submission_governance_authority_forbidden",
                "fields": forbidden,
            },
        )
    requested_by = _model_intake_submission_subject(http_request)
    source_hash = hashlib.sha256(request.source.strip().encode()).hexdigest()
    declarations = {
        **request.declared_metadata,
        "publisher_signature": request.publisher_signature,
        "upstream_attestation": request.upstream_attestation,
        "provenance_class": "DECLARED",
    }
    async with _pool().acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            INSERT INTO model_intake_submissions
                (requested_by,requested_environment,source_kind,source_reference_hash,
                 expected_artifact_sha256,intended_use,declared_metadata,state)
            VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,'submitted')
            RETURNING *
            """,
            requested_by,
            request.intended_environment,
            request.source_kind,
            source_hash,
            request.expected_artifact_sha256.lower() if request.expected_artifact_sha256 else None,
            json.dumps(request.intended_use),
            json.dumps(declarations),
        )
        await conn.execute(
            """
            INSERT INTO model_intake_submission_events
                (submission_id,event_type,actor,reason,previous_state,new_state,metadata_json)
            VALUES ($1,'submission_created',$2,'Model intake submission created','submitted','submitted',$3::jsonb)
            """,
            row["id"],
            requested_by,
            json.dumps({"requested_environment": request.intended_environment}),
        )
    return {
        "submission": row_to_dict(row),
        "source_reference_hash": source_hash,
        "next_actions": ["queue_static_run", "attach_generated_evidence", "freeze_evidence"],
        "deployable": False,
    }


@router.get("/model-intake/submissions")
async def list_model_intake_submissions(
    http_request: Request,
    state: Optional[str] = Query(
        None,
        pattern="^(submitted|static_running|evidence_ready|awaiting_approval|policy_decided|admitted|blocked|revoked)$",
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List controlled-workflow records without returning source references or evidence payloads."""
    _model_intake_authenticated_subject(http_request)
    where = "WHERE state=$1" if state else ""
    args: list[Any] = [state] if state else []
    args.extend([limit, offset])
    limit_index = len(args) - 1
    offset_index = len(args)
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT id,requested_by,requested_environment,source_kind,source_reference_hash,
                   expected_artifact_sha256,scan_id,state,created_at,updated_at
            FROM model_intake_submissions {where}
            ORDER BY created_at DESC LIMIT ${limit_index} OFFSET ${offset_index}
            """,
            *args,
        )
        total = await conn.fetchval(
            f"SELECT COUNT(*) FROM model_intake_submissions {where}",
            *([state] if state else []),
        )
    return {
        "submissions": [row_to_dict(row) for row in rows],
        "total": int(total or 0),
        "limit": limit,
        "offset": offset,
    }


@router.get("/model-intake/submissions/{submission_id}")
async def get_model_intake_submission(submission_id: str, http_request: Request):
    _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    async with _pool().acquire() as conn:
        submission = await conn.fetchrow("SELECT * FROM model_intake_submissions WHERE id=$1", submission_uuid)
        if not submission:
            raise HTTPException(status_code=404, detail="Model submission not found")
        subjects = await conn.fetch(
            "SELECT * FROM model_intake_subjects WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        evidence = await conn.fetch(
            "SELECT * FROM model_intake_evidence_records WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        manifests = await conn.fetch(
            "SELECT * FROM model_intake_evidence_manifests WHERE submission_id=$1 ORDER BY version", submission_uuid
        )
        approvals = await conn.fetch(
            "SELECT * FROM model_intake_approval_receipts WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        decisions = await conn.fetch(
            "SELECT * FROM model_intake_policy_decisions WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        admissions = await conn.fetch(
            "SELECT * FROM model_intake_admissions WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        events = await conn.fetch(
            "SELECT * FROM model_intake_submission_events WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
    return {
        "submission": row_to_dict(submission),
        "subjects": [row_to_dict(item) for item in subjects],
        "evidence": [row_to_dict(item) for item in evidence],
        "manifests": [row_to_dict(item) for item in manifests],
        "approvals": [row_to_dict(item) for item in approvals],
        "policy_decisions": [row_to_dict(item) for item in decisions],
        "admissions": [row_to_dict(item) for item in admissions],
        "events": [row_to_dict(item) for item in events],
    }


@router.get("/model-intake/submissions/{submission_id}/report")
async def get_model_intake_submission_report(
    submission_id: str,
    http_request: Request,
    format: str = Query("json", pattern="^(json|html|sarif)$"),
):
    """Export one normalized, content-free report over authoritative workflow records."""
    _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    async with _pool().acquire() as conn:
        submission = await conn.fetchrow("SELECT * FROM model_intake_submissions WHERE id=$1", submission_uuid)
        if not submission:
            raise HTTPException(status_code=404, detail="Model submission not found")
        subjects = await conn.fetch(
            "SELECT * FROM model_intake_subjects WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        evidence = await conn.fetch(
            "SELECT * FROM model_intake_evidence_records WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        manifests = await conn.fetch(
            "SELECT * FROM model_intake_evidence_manifests WHERE submission_id=$1 ORDER BY version", submission_uuid
        )
        approvals = await conn.fetch(
            "SELECT * FROM model_intake_approval_receipts WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        decisions = await conn.fetch(
            "SELECT * FROM model_intake_policy_decisions WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        admissions = await conn.fetch(
            "SELECT * FROM model_intake_admissions WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        events = await conn.fetch(
            "SELECT * FROM model_intake_submission_events WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        runner_jobs = await conn.fetch(
            "SELECT * FROM model_intake_runner_jobs WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        agent_sessions = await conn.fetch(
            "SELECT * FROM model_intake_agent_sessions WHERE submission_id=$1 ORDER BY created_at", submission_uuid
        )
        signer_anchors = await conn.fetch(
            """
            SELECT public_key_pem,builder_id_constraint FROM model_intake_trust_anchors
            WHERE is_active=true AND revoked_at IS NULL AND purpose='admission_signer'
              AND environment=$1 AND valid_from<=NOW()
              AND (valid_until IS NULL OR valid_until>NOW())
            """,
            submission["requested_environment"],
        )
    admission_rows = [row_to_dict(item) for item in admissions]
    manifest_rows = [row_to_dict(item) for item in manifests]
    subject_rows = [row_to_dict(item) for item in subjects]
    active_admission = next((
        item for item in reversed(admission_rows) if item.get("status") == "active"
    ), None)
    admission_verification = None
    if active_admission:
        trusted_keys = [
            str(item["public_key_pem"] or "") for item in signer_anchors if item["public_key_pem"]
        ]
        trusted_builders = {
            str(item["builder_id_constraint"] or "")
            for item in signer_anchors if item["builder_id_constraint"]
        }
        env_keys = os.getenv("MODEL_INTAKE_ADMISSION_V2_TRUSTED_PUBLIC_KEYS", "").strip()
        if env_keys:
            trusted_keys.extend(_model_admission_trusted_keys(env_keys))
        trusted_builders.update({
            item.strip()
            for item in os.getenv("MODEL_INTAKE_ADMISSION_V2_TRUSTED_BUILDERS", "").split(",")
            if item.strip()
        })
        latest_manifest = manifest_rows[-1] if manifest_rows else {}
        subject_map = {str(item.get("subject_kind") or ""): item for item in subject_rows}
        try:
            admission_verification = _verify_model_admission_v2(
                active_admission.get("admission_package"),
                trusted_public_keys=trusted_keys,
                trusted_builder_ids=trusted_builders,
                expected_bundle_sha256=str(latest_manifest.get("subject_bundle_sha256") or ""),
                expected_environment=str(submission["requested_environment"]),
                expected_components={
                    "model_artifact_sha256": str(subject_map.get("artifact", {}).get("sha256") or ""),
                    "repository_snapshot_sha256": str(subject_map.get("repository_snapshot", {}).get("sha256") or ""),
                },
            )
        except (ValueError, _ModelAdmissionContractError):
            admission_verification = {
                "verified": False,
                "status": "FAIL",
                "blockers": ["authoritative_report_admission_verification_error"],
                "trusted_key_fingerprints": [],
            }
    report = _build_model_intake_report(
        submission=row_to_dict(submission),
        subjects=subject_rows,
        evidence=[row_to_dict(item) for item in evidence],
        manifests=manifest_rows,
        approvals=[row_to_dict(item) for item in approvals],
        policy_decisions=[row_to_dict(item) for item in decisions],
        admissions=admission_rows,
        events=[row_to_dict(item) for item in events],
        runner_jobs=[row_to_dict(item) for item in runner_jobs],
        agent_sessions=[row_to_dict(item) for item in agent_sessions],
        admission_verification=admission_verification,
    )
    filename = f"model-intake-{submission_uuid}"
    if format == "html":
        return Response(
            content=_render_model_intake_html(report),
            media_type="text/html",
            headers={"Content-Disposition": f'inline; filename="{filename}.html"'},
        )
    if format == "sarif":
        return JSONResponse(
            content=_model_intake_report_to_sarif(report),
            media_type="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="{filename}.sarif.json"'},
        )
    return report


@router.post("/model-intake/submissions/{submission_id}/static-runs")
async def attach_model_intake_static_run(
    submission_id: str,
    request: ModelSubmissionStaticRunRequest,
    http_request: Request,
):
    """Attach only a server-persisted completed scan; never accept caller evidence JSON."""
    actor = _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    scan_uuid = _model_intake_uuid(request.scan_id, "scan id")
    async with _pool().acquire() as conn, conn.transaction():
        submission = await conn.fetchrow(
            "SELECT * FROM model_intake_submissions WHERE id=$1 FOR UPDATE",
            submission_uuid,
        )
        registered_subjects = await conn.fetch(
            "SELECT subject_kind,sha256 FROM model_intake_subjects WHERE submission_id=$1",
            submission_uuid,
        )
        scan = await conn.fetchrow(
            "SELECT id,status,result,target_url,scan_type FROM scans WHERE id=$1",
            scan_uuid,
        )
        if not submission:
            raise HTTPException(status_code=404, detail="Model submission not found")
        if not scan or scan["status"] != "completed" or scan["scan_type"] != "model_intake":
            raise HTTPException(status_code=409, detail="A completed Model Intake scan is required")
        result = _model_intake_json_object(scan["result"])
        model_intake = result.get("model_intake") if isinstance(result.get("model_intake"), dict) else {}
        summary = model_intake.get("summary") if isinstance(model_intake.get("summary"), dict) else {}
        custom_code_sha = _model_intake_snapshot_custom_code_sha256(model_intake)
        snapshot = model_intake.get("repository_snapshot") if isinstance(model_intake.get("repository_snapshot"), dict) else {}
        try:
            components = _model_intake_component_identities(snapshot.get("files") or [])
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        embedding_hints = (
            snapshot.get("embedding_configuration_hints")
            if isinstance(snapshot.get("embedding_configuration_hints"), dict)
            else {}
        )
        artifact_sha = str(summary.get("sha256") or "").lower()
        snapshot_sha = str(summary.get("repository_snapshot_sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", artifact_sha):
            raise HTTPException(status_code=409, detail="Scan lacks a complete artifact SHA-256 subject")
        expected = str(submission["expected_artifact_sha256"] or "").lower()
        if expected and expected != artifact_sha:
            raise HTTPException(status_code=409, detail="Scan artifact does not match submission expectation")
        scan_source_hash = hashlib.sha256(str(scan["target_url"] or "").strip().encode()).hexdigest()
        if scan_source_hash != str(submission["source_reference_hash"]):
            # Provider normalization can legitimately change an hf:// reference
            # into its immutable HTTPS resolve URL. In that case the exact
            # expected digest is the stronger binding. Without either binding,
            # attaching another model's completed scan would corrupt the
            # submission's provenance record.
            if not expected or expected != artifact_sha:
                raise HTTPException(
                    status_code=409,
                    detail="Static scan source does not match the controlled submission",
                )
        findings = result.get("findings") if isinstance(result.get("findings"), list) else []
        required_static_checks = _model_intake_required_static_checks(summary, model_intake)
        static_status = _model_intake_static_evidence_status(
            model_intake,
            summary,
            findings,
            required_static_checks,
        )
        generated_evidence = (
            model_intake.get("generated_evidence")
            if isinstance(model_intake.get("generated_evidence"), dict)
            else {}
        )
        supply_chain = model_intake.get("supply_chain") if isinstance(model_intake.get("supply_chain"), dict) else {}
        license_compliance = (
            supply_chain.get("license_compliance")
            if isinstance(supply_chain.get("license_compliance"), dict)
            else {}
        )
        artifact_size_bytes = _model_intake_artifact_size_bytes(model_intake, summary)
        artifact_detail = (
            model_intake.get("artifact")
            if isinstance(model_intake.get("artifact"), dict)
            else {}
        )
        static_evidence_payload = {
            "schema_version": "model-intake-static-report-summary/v1",
            "subject_identity": {
                "artifact_sha256": artifact_sha,
                "repository_snapshot_sha256": snapshot_sha or None,
                "repository_manifest_sha256": summary.get("repository_manifest_sha256"),
                "repository": snapshot.get("repository"),
                "revision": snapshot.get("revision") or summary.get("revision"),
                "artifact_name": summary.get("artifact_name"),
            },
            "artifact_extension": str(artifact_detail.get("extension") or "").lower()[:20],
            "repository_file_manifest": _model_intake_repository_manifest_summary(snapshot),
            "scan_findings": _model_intake_finding_summary(findings),
            "required_static_checks": required_static_checks,
            "checks": (
                model_intake.get("checks")
                if isinstance(model_intake.get("checks"), dict)
                else {}
            ),
            "scanner_results": _model_intake_scanner_result_summaries(generated_evidence),
            "runtime_dependencies": _model_intake_json_object(
                generated_evidence.get("runtime_dependencies")
            ),
            "vulnerability_summary": _model_intake_json_object(
                generated_evidence.get("vulnerability_summary")
            ),
            "vulnerability_inventory": [
                item for item in generated_evidence.get("vulnerability_inventory") or []
                if isinstance(item, dict)
            ][:1000],
            "license_compliance": {
                "outcome": license_compliance.get("outcome"),
                "policy_status": license_compliance.get("policy_status"),
                "policy_version": license_compliance.get("policy_version"),
                "legal_review_required": license_compliance.get("legal_review_required"),
                "classification_counts": license_compliance.get("classification_counts") or {},
                "reason_codes": [
                    str(item.get("code") or "")
                    for item in license_compliance.get("reasons") or []
                    if isinstance(item, dict) and item.get("code")
                ],
                "obligations": license_compliance.get("obligations") or [],
                "evidence_sha256": license_compliance.get("evidence_sha256"),
            },
        }
        payload_digest = hashlib.sha256(json.dumps({
            "scan_id": str(scan_uuid),
            "summary": summary,
            "checks": model_intake.get("checks"),
            "generated_scanners": model_intake.get("generated_scanners"),
            "finding_fingerprints": sorted(str(item.get("fingerprint") or item.get("id") or "") for item in findings if isinstance(item, dict)),
        }, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        await conn.execute(
            """
            INSERT INTO model_intake_subjects
                (submission_id,subject_kind,immutable_uri,sha256,size_bytes,source_revision,metadata_json)
            VALUES ($1,'artifact',$2,$3,$4,$5,$6::jsonb)
            ON CONFLICT (submission_id,subject_kind,sha256) DO NOTHING
            """,
            submission_uuid,
            f"scan://{scan_uuid}/artifact",
            artifact_sha,
            artifact_size_bytes,
            summary.get("revision"),
            json.dumps({"registered_by": actor, "required_static_checks": required_static_checks}),
        )
        if re.fullmatch(r"[0-9a-f]{64}", snapshot_sha):
            await conn.execute(
                """
                INSERT INTO model_intake_subjects
                    (submission_id,subject_kind,immutable_uri,sha256,manifest_sha256,metadata_json)
                VALUES ($1,'repository_snapshot',$2,$3,$4,$5::jsonb)
                ON CONFLICT (submission_id,subject_kind,sha256) DO NOTHING
                """,
                submission_uuid,
                f"scan://{scan_uuid}/repository-snapshot",
                snapshot_sha,
                summary.get("repository_manifest_sha256"),
                json.dumps({"registered_by": actor}),
            )
        if custom_code_sha:
            await conn.execute(
                """
                INSERT INTO model_intake_subjects
                    (submission_id,subject_kind,immutable_uri,sha256,manifest_sha256,metadata_json)
                VALUES ($1,'custom_code',$2,$3,$4,$5::jsonb)
                ON CONFLICT (submission_id,subject_kind,sha256) DO NOTHING
                """,
                submission_uuid,
                f"scan://{scan_uuid}/repository-snapshot/python",
                custom_code_sha,
                snapshot_sha or None,
                json.dumps({"registered_by": actor, "source": "authoritative_snapshot"}),
            )
        for subject_kind, digest_key, count_key in (
            ("tokenizer", "tokenizer_sha256", "tokenizer_file_count"),
            ("configuration", "configuration_sha256", "configuration_file_count"),
        ):
            component_sha = components[digest_key]
            if not component_sha:
                continue
            await conn.execute(
                """
                INSERT INTO model_intake_subjects
                    (submission_id,subject_kind,immutable_uri,sha256,manifest_sha256,metadata_json)
                VALUES ($1,$2,$3,$4,$5,$6::jsonb)
                ON CONFLICT (submission_id,subject_kind,sha256) DO NOTHING
                """,
                submission_uuid,
                subject_kind,
                f"scan://{scan_uuid}/repository-snapshot/{subject_kind}",
                component_sha,
                snapshot_sha or None,
                json.dumps({
                    "registered_by": actor,
                    "source": "authoritative_snapshot",
                    "file_count": components[count_key],
                    # Embedding facts the model publishes about itself, read from
                    # the exact scanned revision. The deployment bundle still
                    # requires the operator to confirm them; this only removes
                    # the manual lookup.
                    **(
                        {"embedding_configuration_hints": embedding_hints}
                        if subject_kind == "configuration" and embedding_hints
                        else {}
                    ),
                }),
            )
        evidence = await conn.fetchrow(
            """
            INSERT INTO model_intake_evidence_records
                (submission_id,evidence_type,schema_version,provenance_class,producer_id,
                 producer_version,builder_id,invocation_id,subject_bindings,payload_sha256,
                 payload_json,object_storage_uri,status,started_at,finished_at,expires_at)
            VALUES ($1,'static_analysis','model-intake-static-evidence/v1','GENERATED_STATIC',
                    'shakerscan-static-worker',$2,$3,$4,$5::jsonb,$6,$7::jsonb,$8,$9,NOW(),NOW(),NOW()+INTERVAL '30 days')
            ON CONFLICT (producer_id,invocation_id) DO NOTHING
            RETURNING *
            """,
            submission_uuid,
            str(result.get("scanner_version") or "unknown"),
            str(result.get("worker_build_fingerprint") or "shakerscan-worker"),
            str(scan_uuid),
            json.dumps({
                "model_artifact_sha256": artifact_sha,
                "repository_snapshot_sha256": snapshot_sha or None,
                "custom_code_sha256": custom_code_sha,
                "tokenizer_sha256": components["tokenizer_sha256"],
                "configuration_sha256": components["configuration_sha256"],
            }),
            payload_digest,
            json.dumps(static_evidence_payload, sort_keys=True, separators=(",", ":"), default=str),
            f"scan://{scan_uuid}/result",
            static_status,
        )
        duplicate = evidence is None
        if duplicate:
            evidence = await conn.fetchrow(
                "SELECT * FROM model_intake_evidence_records WHERE producer_id=$1 AND invocation_id=$2",
                "shakerscan-static-worker",
                str(scan_uuid),
            )
            if not evidence or evidence["payload_sha256"] != payload_digest:
                raise HTTPException(status_code=409, detail="Static scan invocation replay changed payload")
        invalidation = (
            {"admissions_invalidated": 0, "deployment_bindings_staled": 0}
            if duplicate
            else await _reset_model_intake_for_new_evidence(
                conn,
                submission_uuid,
                actor=actor,
                evidence_type="static_analysis",
                evidence_id=str(evidence["id"]),
            )
        )
        await conn.execute(
            "UPDATE model_intake_submissions SET scan_id=$2,updated_at=NOW() WHERE id=$1",
            submission_uuid,
            scan_uuid,
        )
    return {
        "submission_id": str(submission_uuid),
        "evidence": row_to_dict(evidence),
        "required_static_checks": required_static_checks,
        "downstream_invalidation": invalidation,
        "deployable": False,
    }


@router.post("/model-intake/submissions/{submission_id}/evidence-receipts")
async def attach_model_intake_runner_evidence(
    submission_id: str,
    request: ModelRunnerEvidenceReceiptRequest,
    http_request: Request,
):
    """Verify a trusted runner signature before persisting generated evidence."""
    actor = _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    async with _pool().acquire() as conn, conn.transaction():
        return await _persist_model_intake_runner_evidence(
            conn,
            submission_uuid,
            request.signature_envelope,
            actor=actor,
        )


@router.post("/model-intake/submissions/{submission_id}/runner-jobs")
async def create_model_intake_runner_job(
    submission_id: str,
    request: ModelRunnerJobCreateRequest,
    http_request: Request,
):
    """Queue a fixed server-derived Firecracker runtime or conversion job."""
    actor = _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    try:
        bundle = _build_model_deployment_bundle(
            request.deployment_bundle, require_data_plane=False
        )
    except _ModelAdmissionContractError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT s.*,sc.result FROM model_intake_submissions s
            LEFT JOIN scans sc ON sc.id=s.scan_id WHERE s.id=$1
            """,
            submission_uuid,
        )
        # Read the registered subjects in the same acquisition. Without this the
        # exact-subject check below referenced an undefined name and every
        # attempt to queue a Firecracker job raised NameError, so the microVM
        # tier could never be exercised through its own API at all.
        registered_subjects = await conn.fetch(
            "SELECT subject_kind,sha256 FROM model_intake_subjects WHERE submission_id=$1",
            submission_uuid,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Model submission not found")
    if bundle["target_environment"] != row["requested_environment"]:
        raise HTTPException(status_code=409, detail="Deployment bundle environment differs from submission")
    if request.operation == "runtime" and not request.known_answer_embedding_sha256:
        raise HTTPException(
            status_code=422,
            detail="Runtime admission requires a reviewed known-answer embedding digest; use a failed calibration run only outside this admission endpoint",
        )
    try:
        known_answer_suite = _model_intake_runner_input_suite(request.known_answer_inputs)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan_result = _model_intake_json_object(row["result"])
    subject_pairs = {(str(item["subject_kind"]), str(item["sha256"])) for item in registered_subjects}
    if ("artifact", bundle["model_artifact_sha256"]) not in subject_pairs or (
        "repository_snapshot", bundle["repository_snapshot_sha256"]
    ) not in subject_pairs:
        raise HTTPException(status_code=409, detail="Deployment bundle subjects were not registered for this submission")
    try:
        materialized = await asyncio.to_thread(
            _model_intake_snapshot_materialization,
            scan_result,
            artifact_sha256=bundle["model_artifact_sha256"],
            repository_snapshot_sha256=bundle["repository_snapshot_sha256"],
        )
    except HTTPException as source_error:
        if source_error.status_code != 409:
            raise
        try:
            materialized = await asyncio.to_thread(
                _model_intake_converted_snapshot_materialization,
                artifact_sha256=bundle["model_artifact_sha256"],
                repository_snapshot_sha256=bundle["repository_snapshot_sha256"],
            )
        except (HTTPException, OSError):
            raise source_error
    if bundle.get("custom_code_sha256") != materialized["custom_code_sha256"]:
        raise HTTPException(
            status_code=409,
            detail="Deployment bundle custom-code digest differs from the authoritative snapshot",
        )
    if bundle["tokenizer_sha256"] != materialized["tokenizer_sha256"]:
        raise HTTPException(
            status_code=409,
            detail="Deployment bundle tokenizer digest differs from the authoritative snapshot",
        )
    if bundle["configuration_sha256"] != materialized["configuration_sha256"]:
        raise HTTPException(
            status_code=409,
            detail="Deployment bundle configuration digest differs from the authoritative snapshot",
        )
    resolver = _resolve_model_conversion_profile if request.operation == "conversion" else _resolve_model_loader_profile
    resolution = resolver(
        materialized["profile_manifest"],
        artifact_path=materialized["artifact_path"],
        runtime_image_digest=bundle["runtime_image_digest"],
        reviewed_custom_code_sha256=materialized["custom_code_sha256"],
    )
    if resolution.get("status") != "READY" or not isinstance(resolution.get("profile"), dict):
        raise HTTPException(status_code=409, detail={"code": "runner_loader_profile_not_ready", **resolution})
    profile = resolution["profile"]
    if bundle["loader_profile_sha256"] != profile["profile_sha256"]:
        raise HTTPException(
            status_code=409,
            detail="Deployment bundle loader-profile digest differs from the authoritative server resolution",
        )
    runner_request = {
        "submission_id": str(submission_uuid),
        "mode": "conversion" if request.operation == "conversion" else "runtime",
        "environment": row["requested_environment"],
        "subject_path": materialized["subject_path"],
        "repository_manifest_path": materialized["repository_manifest_path"],
        "repository_snapshot_sha256": bundle["repository_snapshot_sha256"],
        "tokenizer_sha256": bundle["tokenizer_sha256"],
        "configuration_sha256": bundle["configuration_sha256"],
        "model_artifact_sha256": bundle["model_artifact_sha256"],
        "deployment_bundle_sha256": bundle["bundle_sha256"],
        "runtime_image_digest": bundle["runtime_image_digest"],
        "loader_profile": profile,
        "loader_profile_sha256": profile["profile_sha256"],
        "reviewed_custom_code_sha256": materialized["custom_code_sha256"],
        "known_answer_inputs": known_answer_suite["inputs"],
        "known_answer_embedding_sha256": request.known_answer_embedding_sha256.lower() if request.known_answer_embedding_sha256 else None,
        "vcpu_count": request.vcpu_count,
        "memory_mib": request.memory_mib,
        "timeout_seconds": request.timeout_seconds,
        "output_bytes": request.output_bytes,
    }
    request_bytes = json.dumps(runner_request, sort_keys=True, separators=(",", ":")).encode()
    stored_request = {
        "schema_version": "model-intake-runner-request-record/v1",
        "operation": request.operation,
        "environment": row["requested_environment"],
        "deployment_bundle_sha256": bundle["bundle_sha256"],
        "model_artifact_sha256": bundle["model_artifact_sha256"],
        "repository_snapshot_sha256": bundle["repository_snapshot_sha256"],
        "tokenizer_sha256": bundle["tokenizer_sha256"],
        "configuration_sha256": bundle["configuration_sha256"],
        "runtime_image_digest": bundle["runtime_image_digest"],
        "loader_profile_id": profile["profile_id"],
        "loader_profile_sha256": profile["profile_sha256"],
        "known_answer_suite_version": known_answer_suite["suite_version"],
        "known_answer_input_count": known_answer_suite["input_count"],
        "known_answer_inputs_sha256": known_answer_suite["inputs_sha256"],
        "known_answer_total_utf8_bytes": known_answer_suite["total_utf8_bytes"],
        "known_answer_embedding_sha256": request.known_answer_embedding_sha256.lower() if request.known_answer_embedding_sha256 else None,
        "vcpu_count": request.vcpu_count,
        "memory_mib": request.memory_mib,
        "timeout_seconds": request.timeout_seconds,
        "output_bytes": request.output_bytes,
    }
    remote = await asyncio.to_thread(
        _model_intake_runner_http,
        "POST",
        "/internal/model-intake/runner/jobs",
        runner_request,
    )
    try:
        remote_id = uuid.UUID(str(remote["id"]))
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="Runner returned an invalid job identifier") from exc
    async with _pool().acquire() as conn:
        job = await conn.fetchrow(
            """
            INSERT INTO model_intake_runner_jobs
                (submission_id,operation,state,remote_job_id,request_sha256,request_json,created_by)
            VALUES ($1,$2,'pending',$3,$4,$5::jsonb,$6) RETURNING *
            """,
            submission_uuid,
            request.operation,
            remote_id,
            hashlib.sha256(request_bytes).hexdigest(),
            json.dumps(stored_request),
            actor,
        )
    return {"job": row_to_dict(job), "loader_profile": profile, "deployable": False}


@router.get("/model-intake/submissions/{submission_id}/runner-jobs")
async def list_model_intake_runner_jobs(submission_id: str, http_request: Request):
    _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM model_intake_runner_jobs WHERE submission_id=$1 ORDER BY created_at DESC",
            submission_uuid,
        )
    return {"jobs": [row_to_dict(row) for row in rows]}


@router.post("/model-intake/submissions/{submission_id}/runner-jobs/{job_id}/refresh")
async def refresh_model_intake_runner_job(submission_id: str, job_id: str, http_request: Request):
    actor = _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    job_uuid = _model_intake_uuid(job_id, "runner job id")
    async with _pool().acquire() as conn:
        job = await conn.fetchrow(
            "SELECT * FROM model_intake_runner_jobs WHERE id=$1 AND submission_id=$2",
            job_uuid,
            submission_uuid,
        )
    if not job:
        raise HTTPException(status_code=404, detail="Runner job not found")
    remote = await asyncio.to_thread(
        _model_intake_runner_http,
        "GET",
        f"/internal/model-intake/runner/jobs/{job['remote_job_id']}",
        None,
    )
    state = str(remote.get("state") or "")
    if state not in {"pending", "running", "completed", "failed"}:
        raise HTTPException(status_code=502, detail="Runner returned an invalid job state")
    result = remote.get("result") if isinstance(remote.get("result"), dict) else None
    error = remote.get("error") if isinstance(remote.get("error"), dict) else None
    evidence = None
    verified_evidence_envelope: dict[str, Any] = {}
    async with _pool().acquire() as conn, conn.transaction():
        current = await conn.fetchrow(
            "SELECT * FROM model_intake_runner_jobs WHERE id=$1 AND submission_id=$2 FOR UPDATE",
            job_uuid,
            submission_uuid,
        )
        if not current:
            raise HTTPException(status_code=404, detail="Runner job not found")
        evidence_id = current["evidence_record_id"]
        if state == "completed" and result and not evidence_id:
            envelope = result.get("receipt") if isinstance(result.get("receipt"), dict) else None
            if not envelope:
                raise HTTPException(status_code=502, detail="Completed runner job omitted its signed receipt")
            persisted = await _persist_model_intake_runner_evidence(conn, submission_uuid, envelope, actor=actor)
            evidence = persisted["evidence"]
            evidence_id = uuid.UUID(evidence["id"])
        updated = await conn.fetchrow(
            """
            UPDATE model_intake_runner_jobs SET state=$2,result_json=$3::jsonb,error_json=$4::jsonb,
                evidence_record_id=$5,started_at=COALESCE(started_at,$6),finished_at=$7,updated_at=NOW()
            WHERE id=$1 RETURNING *
            """,
            job_uuid,
            state,
            json.dumps(result) if result else None,
            json.dumps(error) if error else None,
            evidence_id,
            datetime.fromisoformat(str(remote["started_at"]).replace("Z", "+00:00")) if remote.get("started_at") else None,
            datetime.fromisoformat(str(remote["finished_at"]).replace("Z", "+00:00")) if remote.get("finished_at") else None,
        )
        if evidence_id:
            verified_evidence_envelope = _model_intake_json_object(await conn.fetchval(
                "SELECT signature_envelope FROM model_intake_evidence_records WHERE id=$1",
                evidence_id,
            ))
    conversion_rescan = None
    if state == "completed" and result:
        claims = _model_intake_untrusted_runner_claims(verified_evidence_envelope)
        if _model_intake_conversion_output_usable(claims):
            conversion_rescan = await _register_and_rescan_converted_snapshot(
                submission_uuid,
                claims,
                actor=actor,
            )
    return {
        "job": row_to_dict(updated),
        "evidence": evidence,
        "conversion_rescan": conversion_rescan,
        "deployable": False,
    }


@router.post("/model-intake/submissions/{submission_id}/agent/session")
async def create_model_intake_agent_session(
    submission_id: str,
    request: ModelIntakeAgentSessionRequest,
    http_request: Request,
):
    """Create a keyless Codex-driven planning session; no model provider is called."""
    actor = _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    async with _pool().acquire() as conn:
        exists = await conn.fetchval("SELECT EXISTS(SELECT 1 FROM model_intake_submissions WHERE id=$1)", submission_uuid)
        if not exists:
            raise HTTPException(status_code=404, detail="Model submission not found")
        session_id = uuid.uuid4()
        prompt = _model_intake_planner_prompt(str(submission_uuid), request.objective, request.action_budget)
        row = await conn.fetchrow(
            """
            INSERT INTO model_intake_agent_sessions
                (id,submission_id,objective,status,max_iterations,action_budget,transcript_json,created_by)
            VALUES ($1,$2,$3,'awaiting_planner',$4,$5,$6::jsonb,$7) RETURNING *
            """,
            session_id,
            submission_uuid,
            request.objective,
            request.max_iterations,
            request.action_budget,
            json.dumps([{"role": "system", "content": prompt}]),
            actor,
        )
    return {"session": row_to_dict(row), "observation": prompt, "authority": "advisory_only"}


@router.get("/model-intake/submissions/{submission_id}/agent/sessions")
async def list_model_intake_agent_sessions(submission_id: str, http_request: Request):
    _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    async with _pool().acquire() as conn:
        exists = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM model_intake_submissions WHERE id=$1)",
            submission_uuid,
        )
        if not exists:
            raise HTTPException(status_code=404, detail="Model submission not found")
        rows = await conn.fetch(
            """
            SELECT id,submission_id,objective,status,max_iterations,iteration,action_budget,
                   actions_used,final_assessment_json,created_by,created_at,updated_at
            FROM model_intake_agent_sessions WHERE submission_id=$1 ORDER BY created_at DESC
            LIMIT 100
            """,
            submission_uuid,
        )
    return {"sessions": [row_to_dict(row) for row in rows], "authority": "advisory_only"}


@router.get("/model-intake/agent/session/{session_id}")
async def get_model_intake_agent_session(session_id: str, http_request: Request):
    _model_intake_authenticated_subject(http_request)
    session_uuid = _model_intake_uuid(session_id, "agent session id")
    async with _pool().acquire() as conn:
        session = await conn.fetchrow(
            "SELECT * FROM model_intake_agent_sessions WHERE id=$1",
            session_uuid,
        )
        if not session:
            raise HTTPException(status_code=404, detail="Model Intake agent session not found")
        actions = await conn.fetch(
            """
            SELECT id,iteration,action_index,action_name,arguments_sha256,status,result_json,
                   created_at FROM model_intake_agent_actions
            WHERE session_id=$1 ORDER BY iteration,action_index
            """,
            session_uuid,
        )
    return {
        "session": row_to_dict(session),
        "actions": [row_to_dict(row) for row in actions],
        "authority": "advisory_only",
    }


@router.post("/model-intake/agent/session/{session_id}/cancel")
async def cancel_model_intake_agent_session(session_id: str, http_request: Request):
    actor = _model_intake_authenticated_subject(http_request)
    session_uuid = _model_intake_uuid(session_id, "agent session id")
    async with _pool().acquire() as conn, conn.transaction():
        session = await conn.fetchrow(
            "SELECT * FROM model_intake_agent_sessions WHERE id=$1 FOR UPDATE",
            session_uuid,
        )
        if not session:
            raise HTTPException(status_code=404, detail="Model Intake agent session not found")
        if session["status"] == "completed":
            raise HTTPException(status_code=409, detail="Completed Model Intake agent sessions cannot be cancelled")
        if session["status"] == "cancelled":
            return {"session": row_to_dict(session), "cancelled": True, "idempotent": True, "authority": "advisory_only"}
        transcript = _decode_json_value(session["transcript_json"])
        transcript = transcript if isinstance(transcript, list) else []
        transcript.append({
            "role": "controller",
            "content": {
                "status": "cancelled",
                "reason": "cancelled_by_authenticated_operator",
                "actor": actor,
                "authority": "advisory_only",
            },
        })
        updated = await conn.fetchrow(
            """
            UPDATE model_intake_agent_sessions SET status='cancelled',transcript_json=$2::jsonb,
                   updated_at=NOW() WHERE id=$1 RETURNING *
            """,
            session_uuid,
            json.dumps(transcript),
        )
    return {"session": row_to_dict(updated), "cancelled": True, "idempotent": False, "authority": "advisory_only"}


@router.post("/model-intake/agent/session/{session_id}/reply")
async def reply_model_intake_agent_session(
    session_id: str,
    request: ModelIntakeAgentReplyRequest,
    http_request: Request,
):
    actor = _model_intake_authenticated_subject(http_request)
    session_uuid = _model_intake_uuid(session_id, "agent session id")
    try:
        parsed = _parse_model_intake_planner_reply(request.reply)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    async with _pool().acquire() as conn, conn.transaction():
        session = await conn.fetchrow(
            "SELECT * FROM model_intake_agent_sessions WHERE id=$1 FOR UPDATE",
            session_uuid,
        )
        if not session:
            raise HTTPException(status_code=404, detail="Model Intake agent session not found")
        if session["status"] != "awaiting_planner":
            raise HTTPException(status_code=409, detail="Model Intake agent session is terminal")
        if int(session["iteration"]) >= int(session["max_iterations"]):
            raise HTTPException(status_code=409, detail="Model Intake agent iteration budget exhausted")
        transcript = _decode_json_value(session["transcript_json"])
        transcript = transcript if isinstance(transcript, list) else []
        transcript.append({"role": "planner", "content": request.reply})
        next_iteration = int(session["iteration"]) + 1
        if parsed["done"]:
            transcript.append({"role": "controller", "content": {"status": "completed", "authority": "advisory_only"}})
            updated = await conn.fetchrow(
                """UPDATE model_intake_agent_sessions
                   SET status='completed',iteration=$2,transcript_json=$3::jsonb,
                       final_assessment_json=$4::jsonb,updated_at=NOW()
                   WHERE id=$1 RETURNING *""",
                session_uuid,
                next_iteration,
                json.dumps(transcript),
                json.dumps(parsed),
            )
            return {"session": row_to_dict(updated), "final_assessment": parsed, "authority": "advisory_only"}
        calls = parsed["tool_calls"]
        if int(session["actions_used"]) + len(calls) > int(session["action_budget"]):
            raise HTTPException(status_code=409, detail="Model Intake agent action budget exhausted")
        observations = []
        for call in calls:
            status = "completed"
            try:
                result = await _execute_model_intake_agent_action(
                    conn,
                    session["submission_id"],
                    call["name"],
                    call["arguments"],
                )
            except Exception as exc:
                status = "error"
                result = {"error": type(exc).__name__, "message": str(exc)[:2000]}
            arguments_sha = hashlib.sha256(
                json.dumps(call["arguments"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            action = await conn.fetchrow(
                """INSERT INTO model_intake_agent_actions
                       (session_id,iteration,action_name,arguments_sha256,status,result_json)
                   VALUES ($1,$2,$3,$4,$5,$6::jsonb) RETURNING id,action_name,status,result_json""",
                session_uuid,
                next_iteration,
                call["name"],
                arguments_sha,
                status,
                json.dumps(result, default=str),
            )
            observations.append(row_to_dict(action))
        remaining = int(session["action_budget"]) - int(session["actions_used"]) - len(calls)
        controller_observation = {
            "actions": observations,
            "remaining_actions": remaining,
            "authority": "advisory_only",
            "deployable": False,
        }
        transcript.append({"role": "controller", "content": controller_observation})
        updated = await conn.fetchrow(
            """UPDATE model_intake_agent_sessions
               SET iteration=$2,actions_used=actions_used+$3,transcript_json=$4::jsonb,updated_at=NOW()
               WHERE id=$1 RETURNING *""",
            session_uuid,
            next_iteration,
            len(calls),
            json.dumps(transcript, default=str),
        )
    return {
        "session": row_to_dict(updated),
        "observation": controller_observation,
        "next_prompt": _model_intake_planner_prompt(
            str(updated["submission_id"]),
            str(updated["objective"]),
            remaining,
        ),
        "authority": "advisory_only",
    }


@router.post("/model-intake/submissions/{submission_id}/freeze-evidence")
async def freeze_model_intake_evidence(
    submission_id: str,
    request: ModelEvidenceFreezeRequest,
    http_request: Request,
):
    actor = _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    try:
        # Data-plane digests describe a serving application and vector index
        # that may not exist. MI-16 applies only when that integration does, so
        # their absence must surface as an unperformed control in the report
        # rather than blocking the operator from freezing evidence at all.
        bundle = _build_model_deployment_bundle(
            request.deployment_bundle, require_data_plane=False
        )
    except _ModelAdmissionContractError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    async with _pool().acquire() as conn, conn.transaction():
        submission = await conn.fetchrow("SELECT * FROM model_intake_submissions WHERE id=$1 FOR UPDATE", submission_uuid)
        if not submission:
            raise HTTPException(status_code=404, detail="Model submission not found")
        if bundle["target_environment"] != submission["requested_environment"]:
            raise HTTPException(status_code=409, detail="Deployment bundle environment differs from submission")
        subjects = await conn.fetch(
            "SELECT subject_kind,sha256 FROM model_intake_subjects WHERE submission_id=$1", submission_uuid
        )
        subject_pairs = {(str(item["subject_kind"]), str(item["sha256"])) for item in subjects}
        if ("artifact", bundle["model_artifact_sha256"]) not in subject_pairs:
            raise HTTPException(status_code=409, detail="Deployment bundle artifact was not generated for this submission")
        if ("repository_snapshot", bundle["repository_snapshot_sha256"]) not in subject_pairs:
            raise HTTPException(status_code=409, detail="Deployment bundle snapshot was not generated for this submission")
        for kind, digest in (
            ("custom_code", bundle.get("custom_code_sha256")),
            ("tokenizer", bundle["tokenizer_sha256"]),
            ("configuration", bundle["configuration_sha256"]),
        ):
            if digest and (kind, digest) not in subject_pairs:
                raise HTTPException(status_code=409, detail=f"Deployment bundle {kind} was not generated for this submission")
        records = [row_to_dict(item) for item in await conn.fetch(
            """
            SELECT DISTINCT ON (evidence_type) *
            FROM model_intake_evidence_records
            WHERE submission_id=$1
              AND evidence_type IN (
                  'static_analysis','conversion_equivalence','runtime_execution',
                  'embedding_evaluation','data_plane_evaluation'
              )
              AND (expires_at IS NULL OR expires_at>NOW())
            ORDER BY evidence_type,created_at DESC
            """,
            submission_uuid,
        )]
        for record in records:
            bindings = _model_intake_json_object(record.get("subject_bindings"))
            # asyncpg returns json/jsonb as text unless a codec is installed on
            # the connection.  The matching checks below already normalize
            # that representation, but the manifest builder receives the
            # record itself and requires a structured, non-empty mapping.
            # Persist the normalized value into the record so a real database
            # row cannot fail after passing the exact-subject checks.
            record["subject_bindings"] = bindings
            matches = _model_intake_evidence_matches_bundle(
                str(record.get("evidence_type") or ""), bindings, bundle
            )
            if not matches:
                raise HTTPException(
                    status_code=409,
                    detail=f"Evidence {record.get('evidence_type')} does not bind the exact deployment bundle",
                )
        version = int(await conn.fetchval(
            "SELECT COALESCE(MAX(version),0)+1 FROM model_intake_evidence_manifests WHERE submission_id=$1",
            submission_uuid,
        ))
        try:
            manifest = _freeze_model_evidence_manifest(
                submission_id=str(submission_uuid),
                subject_bundle_sha256=bundle["bundle_sha256"],
                version=version,
                evidence_records=records,
                frozen_by=actor,
            )
        except _ModelAdmissionContractError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        previous = await conn.fetchval(
            "SELECT id FROM model_intake_evidence_manifests WHERE submission_id=$1 ORDER BY version DESC LIMIT 1",
            submission_uuid,
        )
        row = await conn.fetchrow(
            """
            INSERT INTO model_intake_evidence_manifests
                (submission_id,version,manifest_sha256,evidence_ids,manifest_json,deployment_bundle_json,
                 subject_bundle_sha256,frozen_at,frozen_by,supersedes_id)
            VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7,$8,$9,$10)
            RETURNING *
            """,
            submission_uuid,
            version,
            manifest["manifest_sha256"],
            json.dumps([item["id"] for item in manifest["evidence"]]),
            json.dumps(manifest),
            json.dumps(bundle),
            bundle["bundle_sha256"],
            datetime.fromisoformat(manifest["frozen_at"]),
            actor,
            previous,
        )
        await _transition_model_intake_submission(
            conn,
            submission_uuid,
            new_state="awaiting_approval",
            event_type="evidence_manifest_frozen",
            actor=actor,
            reason="Authoritative evidence was frozen for approval",
            metadata={"manifest_id": str(row["id"]), "manifest_sha256": manifest["manifest_sha256"]},
        )
    return {"manifest": row_to_dict(row), "deployment_bundle": bundle, "deployable": False}


@router.post("/model-intake/submissions/{submission_id}/approvals")
async def create_model_intake_approval(
    submission_id: str,
    request: ModelApprovalCreateRequest,
    http_request: Request,
):
    actor = _model_intake_authenticated_subject(http_request)
    if request.approval_type not in _model_intake_operator_roles(http_request):
        raise HTTPException(status_code=403, detail="Authenticated operator lacks the requested approval role")
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    manifest_uuid = _model_intake_uuid(request.evidence_manifest_id, "evidence manifest id")
    async with _pool().acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            SELECT submission.requested_by, submission.requested_environment,submission.state,
                   manifest.id,manifest.manifest_sha256,manifest.subject_bundle_sha256,
                   manifest.id=(
                       SELECT latest.id FROM model_intake_evidence_manifests AS latest
                       WHERE latest.submission_id=submission.id
                       ORDER BY latest.version DESC LIMIT 1
                   ) AS is_latest_manifest
            FROM model_intake_evidence_manifests AS manifest
            JOIN model_intake_submissions AS submission ON submission.id=manifest.submission_id
            WHERE manifest.id=$1 AND manifest.submission_id=$2
            FOR UPDATE OF submission
            """,
            manifest_uuid,
            submission_uuid,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Frozen evidence manifest not found")
        if row["state"] != "awaiting_approval":
            raise HTTPException(status_code=409, detail="Submission is not awaiting approval")
        if not row["is_latest_manifest"]:
            raise HTTPException(status_code=409, detail="Approval must bind the latest frozen evidence manifest")
        if actor == row["requested_by"]:
            raise HTTPException(status_code=409, detail="A submitter cannot approve its own submission")
        try:
            receipt = _build_model_approval_receipt(
                submission_id=str(submission_uuid),
                subject_bundle_sha256=row["subject_bundle_sha256"],
                evidence_manifest_sha256=row["manifest_sha256"],
                policy_bundle_sha256=_model_intake_policy_bundle_sha256(),
                environment=row["requested_environment"],
                approval_type=request.approval_type,
                decision=request.decision,
                approved_by_subject=actor,
                approved_by_role=request.approval_type,
                reason=request.reason,
                expires_at=utc_now() + timedelta(days=request.expires_days),
                restrictions=request.restrictions,
            )
        except _ModelAdmissionContractError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        approval = await conn.fetchrow(
            """
            INSERT INTO model_intake_approval_receipts
                (id,submission_id,evidence_manifest_id,receipt_sha256,receipt_json,approval_type,
                 decision,approved_by_subject,approved_by_role,expires_at)
            VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10)
            RETURNING *
            """,
            uuid.UUID(receipt["approval_id"]),
            submission_uuid,
            manifest_uuid,
            receipt["receipt_sha256"],
            json.dumps(receipt),
            request.approval_type,
            request.decision,
            actor,
            request.approval_type,
            datetime.fromisoformat(receipt["expires_at"]),
        )
        await _transition_model_intake_submission(
            conn,
            submission_uuid,
            new_state="blocked" if request.decision == "reject" else "awaiting_approval",
            event_type="approval_rejected" if request.decision == "reject" else "approval_recorded",
            actor=actor,
            reason=request.reason,
            metadata={
                "approval_id": str(approval["id"]),
                "approval_type": request.approval_type,
                "decision": request.decision,
                "evidence_manifest_id": str(manifest_uuid),
            },
        )
    return {"approval": row_to_dict(approval), "identity_source": "authenticated_server_context"}


@router.post("/model-intake/submissions/{submission_id}/policy-decisions")
async def create_model_intake_policy_decision(
    submission_id: str,
    request: ModelPolicyDecisionCreateRequest,
    http_request: Request,
):
    actor = _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    manifest_uuid = _model_intake_uuid(request.evidence_manifest_id, "evidence manifest id")
    async with _pool().acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            SELECT submission.requested_by,submission.state,manifest.manifest_json,manifest.deployment_bundle_json,
                   manifest.id=(
                       SELECT latest.id FROM model_intake_evidence_manifests AS latest
                       WHERE latest.submission_id=submission.id
                       ORDER BY latest.version DESC LIMIT 1
                   ) AS is_latest_manifest
            FROM model_intake_evidence_manifests AS manifest
            JOIN model_intake_submissions AS submission ON submission.id=manifest.submission_id
            WHERE manifest.id=$1 AND manifest.submission_id=$2
            FOR UPDATE OF submission
            """,
            manifest_uuid,
            submission_uuid,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Frozen evidence manifest not found")
        if row["state"] != "awaiting_approval":
            raise HTTPException(status_code=409, detail="Submission is not awaiting a policy decision")
        if not row["is_latest_manifest"]:
            raise HTTPException(status_code=409, detail="Policy decision must bind the latest frozen evidence manifest")
        approvals = [
            _model_intake_json_object(item["receipt_json"])
            for item in await conn.fetch(
                """
                SELECT receipt_json FROM model_intake_approval_receipts
                WHERE evidence_manifest_id=$1 AND revoked_at IS NULL AND expires_at>NOW()
                """,
                manifest_uuid,
            )
        ]
        try:
            decision = _evaluate_model_admission_policy(
                deployment_bundle=_model_intake_json_object(row["deployment_bundle_json"]),
                evidence_manifest=_model_intake_json_object(row["manifest_json"]),
                approvals=approvals,
                submitter_subject=row["requested_by"],
                policy_bundle_sha256=_model_intake_policy_bundle_sha256(),
            )
        except _ModelAdmissionContractError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        stored = await conn.fetchrow(
            """
            INSERT INTO model_intake_policy_decisions
                (id,submission_id,evidence_manifest_id,decision_sha256,decision_json,decision,
                 policy_provider,policy_bundle_sha256,input_sha256)
            VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)
            ON CONFLICT (decision_sha256) DO NOTHING
            RETURNING *
            """,
            uuid.UUID(decision["decision_id"]),
            submission_uuid,
            manifest_uuid,
            decision["decision_sha256"],
            json.dumps(decision),
            decision["decision"],
            decision["policy_provider"],
            decision["policy_bundle_sha256"],
            decision["input_sha256"],
        )
        if not stored:
            stored = await conn.fetchrow(
                """
                SELECT * FROM model_intake_policy_decisions
                WHERE decision_sha256=$1 AND submission_id=$2 AND evidence_manifest_id=$3
                """,
                decision["decision_sha256"],
                submission_uuid,
                manifest_uuid,
            )
            if not stored:
                raise HTTPException(status_code=409, detail="Policy decision digest is already bound elsewhere")
        state = "policy_decided" if decision["decision"] == "allow" else "blocked" if decision["decision"] == "block" else "awaiting_approval"
        await _transition_model_intake_submission(
            conn,
            submission_uuid,
            new_state=state,
            event_type="policy_decision_recorded",
            actor=actor,
            reason=f"Embedded policy returned {decision['decision']}",
            metadata={
                "policy_decision_id": str(stored["id"]),
                "decision_sha256": decision["decision_sha256"],
                "evidence_manifest_id": str(manifest_uuid),
            },
        )
    return {"policy_decision": row_to_dict(stored), "decision": decision}


@router.post("/model-intake/resolve")
async def resolve_model_intake(request: ModelIntakeResolveRequest):
    """Resolve a platform-specific model reference into a scan-ready payload."""
    ref = (request.ref or "").strip()
    if not ref:
        raise HTTPException(status_code=400, detail="ref is required")
    platform = request.platform
    metadata = dict(request.metadata_json or {})
    if platform == "auto":
        platform = _detect_model_intake_platform(ref, metadata)
    if platform == "huggingface":
        normalized_ref = ref if _is_hf_ref(ref) else f"https://huggingface.co/{ref}"
        result = await asyncio.to_thread(
            _resolve_huggingface_model_intake,
            request.model_copy(update={"ref": normalized_ref, "platform": "huggingface"}),
        )
        return {**result, "capabilities": _model_adapter_capabilities("huggingface")}

    normalize_model_artifact_reference, _ = _import_model_intake_helpers()
    normalized = normalize_model_artifact_reference(ref, metadata, platform)
    source_kind = str(normalized.get("kind") or platform or "http")
    metadata_out = {
        **(normalized.get("metadata") if isinstance(normalized.get("metadata"), dict) else {}),
        **metadata,
    }
    ext = str(normalized.get("extension") or Path(urllib.parse.urlparse(ref).path).suffix or "")
    selected_file = {
        "path": normalized.get("path") or _short_url_label(ref),
        "extension": ext,
        "format_posture": normalized.get("format_posture"),
        "risk": "lower" if ext in MODEL_INTAKE_SAFER_EXTENSIONS else "higher" if ext in MODEL_INTAKE_RISKY_EXTENSIONS else "unknown",
        "size_bytes": None,
        "sha256": metadata_out.get("sha256") or metadata_out.get("expected_sha256"),
        "score": 70 if ext in MODEL_INTAKE_SAFER_EXTENSIONS else 45 if ext in MODEL_INTAKE_RISKY_EXTENSIONS else 10,
    } if normalized.get("path") or ext else None
    scan_payload = {
        "artifact_url": ref,
        "name": f"{source_kind.replace('_', ' ').title()}: {_short_url_label(ref)}",
        "metadata_json": metadata_out,
        "expected_sha256": metadata_out.get("sha256") or metadata_out.get("expected_sha256"),
        "model_card_url": metadata_out.get("model_card_url"),
        "require_deployment_approval": True,
        "require_signature": True,
        "require_hash": True,
        "require_model_governance": True,
        "max_download_bytes": 10_000_000,
        "timeout_seconds": 20,
    }
    return {
        "platform": source_kind,
        "normalized_ref": ref,
        "repository": normalized.get("repository") or normalized.get("registry"),
        "revision": normalized.get("revision") or request.revision or normalized.get("tag") or normalized.get("digest"),
        "selected_file": selected_file,
        "candidate_files": [selected_file] if selected_file else [],
        "metadata_json": metadata_out,
        "warnings": normalized.get("warnings") or [],
        "scan_payload": scan_payload,
        "capabilities": _model_adapter_capabilities(source_kind),
    }


@router.get("/model-intake/capabilities")
async def model_intake_capabilities():
    """List provider-neutral intake adapter capabilities for UI and agents."""
    return {
        "schema_version": "model-intake-source-adapters/v1",
        "adapters": _model_adapter_catalog(),
    }


@router.get("/model-intake/operator-session")
async def model_intake_operator_session(http_request: Request):
    """Mint an opaque browser session only for a loopback-published install."""
    if not _model_intake_local_session_allowed():
        return {
            "available": False,
            "reason": "manual_required",
            "detail": "This remote or managed deployment requires a named Model Intake reviewer credential.",
            "hint": "Obtain the credential through your organization's approved secret or identity channel.",
        }
    secret = os.environ.get("MODEL_INTAKE_LOCAL_SESSION_SECRET", "").strip()
    if len(secret) < 32:
        return {
            "available": False,
            "reason": "not_configured",
            "detail": "The local Model Intake session is not configured. Restart ShakerScan to repair it.",
        }
    presented = http_request.headers.get("x-shakerscan-local-session-secret", "").strip()
    if not presented or not secrets.compare_digest(
        presented, secret
    ):
        raise HTTPException(status_code=403, detail="local Model Intake session bootstrap failed")
    token, expires_at = _mint_model_intake_local_session()
    return {
        "available": True,
        "reason": "local_session",
        "token": token,
        "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat(),
    }


@router.get("/model-intake/checks")
async def model_intake_check_catalog():
    """One authoritative control catalog for UI, agents, docs, and reports."""
    return {
        "schema_version": "model-intake-check-catalog/v1",
        "checks": _MODEL_INTAKE_CHECK_CATALOG,
        "external_approval_requirements": _MODEL_INTAKE_EXTERNAL_REQUIREMENTS,
        "status_note": (
            "Catalog membership describes capability only. Per-scan reports state what ran, "
            "what evidence was produced, and whether it passed, failed, was incomplete, or needs review."
        ),
    }


@router.get("/model-intake/scanners/readiness")
async def model_intake_scanner_readiness():
    """Report installed evidence adapters, immutable rule/database identity, and readiness."""
    return await asyncio.to_thread(_model_scanner_adapter_readiness)


@router.get("/model-intake/providers/readiness")
async def model_intake_provider_readiness():
    """Separate execution, evaluation, policy, and report providers from evidence scanners."""
    return await asyncio.to_thread(_model_provider_readiness)


@router.get("/model-intake/runners/readiness")
async def model_intake_runner_readiness():
    """Fail-closed readiness for the external Linux/KVM execution tier."""
    if os.getenv("MODEL_INTAKE_RUNNER_URL", "").strip():
        try:
            return await asyncio.to_thread(_model_intake_runner_http, "GET", "/health", None)
        except Exception as exc:
            return {
                "status": "NOT_READY",
                "ready": False,
                # An explicitly configured remote runner may live on a Linux
                # host reached from a macOS control plane, so an unreachable
                # service is a real fault rather than an unsupported tier.
                "supported_host": True,
                "executor": "firecracker-jailer",
                "checks": {"runner_service_reachable": False},
                "error": f"runner_service_unavailable:{type(exc).__name__}",
                "fallback_execution": False,
            }
    return await asyncio.to_thread(_model_firecracker_readiness)


@router.get("/model-intake/runners/storage")
async def model_intake_runner_storage():
    """Content-free disk capacity and retention status for the external runner."""
    if not os.getenv("MODEL_INTAKE_RUNNER_URL", "").strip():
        return {
            "schema_version": "model-intake-runner-storage/v1",
            "available": False,
            "reason": "runner_service_not_configured",
        }
    try:
        return await asyncio.to_thread(
            _model_intake_runner_http,
            "GET",
            "/internal/model-intake/runner/storage",
            None,
        )
    except Exception as exc:
        return {
            "schema_version": "model-intake-runner-storage/v1",
            "available": False,
            "reason": f"runner_service_unavailable:{type(exc).__name__}",
        }


@router.post("/model-intake/runners/storage/cleanup")
async def model_intake_runner_storage_cleanup(
    request: ModelRunnerStorageCleanupRequest,
    http_request: Request,
):
    """Preview or remove only inactive scratch and expired terminal metadata."""
    _model_intake_authenticated_subject(http_request)
    if not os.getenv("MODEL_INTAKE_RUNNER_URL", "").strip():
        raise HTTPException(status_code=503, detail="Model Intake runner service is not configured")
    try:
        return await asyncio.to_thread(
            _model_intake_runner_http,
            "POST",
            "/internal/model-intake/runner/storage/cleanup",
            request.model_dump(mode="json"),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/model-intake/runners/stage")
async def model_intake_runner_stage(http_request: Request):
    """Stage the guest kernel and image so the root install step stays short."""
    _require_model_intake_operator(http_request)
    from model_intake_runner_controller import cpu_exposes_virtualization, host_platform

    if host_platform() not in {"linux", "unknown"} or cpu_exposes_virtualization() is False:
        raise HTTPException(
            status_code=409,
            detail="This host cannot run the microVM tier, so staging its inputs would be useless.",
        )
    if shutil.which("docker") is None:
        raise HTTPException(
            status_code=503,
            detail="The API image has no Docker client; rebuild it to stage the guest image.",
        )
    with _MODEL_INTAKE_STAGE_LOCK:
        if _MODEL_INTAKE_STAGE_STATE.get("status") == "running":
            raise HTTPException(status_code=409, detail="Staging is already running.")
        _MODEL_INTAKE_STAGE_STATE.clear()
        _MODEL_INTAKE_STAGE_STATE.update({"status": "running", "phase": "starting", "log": []})
    threading.Thread(target=_model_intake_stage_run, daemon=True).start()
    return {"status": "running"}


@router.get("/model-intake/runners/stage")
async def model_intake_runner_stage_status(http_request: Request):
    """Staging progress. Content-free: digests and phases, never model bytes."""
    _require_model_intake_operator(http_request)
    recover_from_disk = False
    with _MODEL_INTAKE_STAGE_LOCK:
        if _MODEL_INTAKE_STAGE_STATE.get("status", "idle") == "idle":
            _MODEL_INTAKE_STAGE_STATE.update({
                "status": "recovering",
                "phase": "verifying_staged_artifacts",
            })
            recover_from_disk = True
        state = json.loads(json.dumps(_MODEL_INTAKE_STAGE_STATE, default=str))
    state.setdefault("status", "idle")
    # Progress is in-memory, but the artifacts are not. After an API restart the
    # UI would otherwise offer to re-stage a guest image that is already built
    # and verified on disk, which is a multi-gigabyte rebuild for nothing.
    if recover_from_disk:
        stage_dir = _model_intake_stage_dir()
        manifest = await asyncio.to_thread(_model_intake_stage_manifest, stage_dir)
        recovered_state = (
            {
                "status": "ready",
                "phase": "complete",
                "recovered_from_disk": True,
                "integrity_verified": True,
                "artifacts": manifest["artifacts"],
            }
            if manifest else {
                "status": "not_staged",
                "phase": "not_staged",
                "recovered_from_disk": False,
                "integrity_verified": False,
            }
        )
        with _MODEL_INTAKE_STAGE_LOCK:
            _MODEL_INTAKE_STAGE_STATE.clear()
            _MODEL_INTAKE_STAGE_STATE.update(recovered_state)
            state = json.loads(json.dumps(_MODEL_INTAKE_STAGE_STATE, default=str))
    return state


@router.get("/model-intake/submissions/{submission_id}/runner-bundle")
async def model_intake_runner_bundle(
    submission_id: str,
    http_request: Request,
    operation: str = Query("calibration", pattern="^(calibration|runtime|conversion)$"),
):
    """Return the deployment bundle this server would accept for a runner job.

    The UI previously rebuilt the loader-profile inputs itself, but
    ``profile_sha256`` hashes selection_facts, and the authoritative manifest
    hardcodes library_name and an empty architectures list. Any model whose
    metadata declares architectures produced a different digest, so the queue
    rejected the job it had just enabled. Deriving it here through the same code
    path the queue uses removes the possibility of divergence.
    """
    _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT s.requested_environment,sc.result FROM model_intake_submissions s
            LEFT JOIN scans sc ON sc.id=s.scan_id WHERE s.id=$1
            """,
            submission_uuid,
        )
        subjects = await conn.fetch(
            "SELECT subject_kind,sha256 FROM model_intake_subjects WHERE submission_id=$1",
            submission_uuid,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Model submission not found")
    digests = {str(item["subject_kind"]): str(item["sha256"]) for item in subjects}
    artifact_sha = digests.get("artifact", "")
    snapshot_sha = digests.get("repository_snapshot", "")
    if not artifact_sha or not snapshot_sha:
        raise HTTPException(
            status_code=409,
            detail=(
                "No registered artifact and repository-snapshot subjects. Attach a completed "
                "Full-depth Model Intake scan; a bounded-prefix scan records no snapshot."
            ),
        )
    readiness = await asyncio.to_thread(_model_intake_runner_readiness_snapshot)
    rootfs = str((readiness.get("verified_component_sha256") or {}).get("rootfs") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", rootfs):
        raise HTTPException(
            status_code=409,
            detail="Runner readiness reports no verified guest rootfs digest; install or repair the microVM runner",
        )
    materialized = await asyncio.to_thread(
        _model_intake_snapshot_materialization,
        _model_intake_json_object(row["result"]),
        artifact_sha256=artifact_sha,
        repository_snapshot_sha256=snapshot_sha,
    )
    runtime_image_digest = f"sha256:{rootfs}"
    resolver = _resolve_model_conversion_profile if operation == "conversion" else _resolve_model_loader_profile
    resolution = resolver(
        materialized["profile_manifest"],
        artifact_path=materialized["artifact_path"],
        runtime_image_digest=runtime_image_digest,
        reviewed_custom_code_sha256=materialized["custom_code_sha256"],
    )
    if resolution.get("status") != "READY" or not isinstance(resolution.get("profile"), dict):
        raise HTTPException(status_code=409, detail={"code": "runner_loader_profile_not_ready", **resolution})
    return {
        "operation": operation,
        "deployment_bundle": {
            "model_artifact_sha256": artifact_sha,
            "repository_snapshot_sha256": snapshot_sha,
            "custom_code_sha256": materialized["custom_code_sha256"],
            "tokenizer_sha256": materialized["tokenizer_sha256"],
            "configuration_sha256": materialized["configuration_sha256"],
            "runtime_image_digest": runtime_image_digest,
            "loader_profile_sha256": resolution["profile"]["profile_sha256"],
            "target_environment": str(row["requested_environment"]),
        },
        "profile_id": resolution["profile"].get("profile_id"),
        "artifact_path": materialized["artifact_path"],
    }


@router.get("/model-intake/submissions/{submission_id}/embedding-configuration")
async def model_intake_embedding_configuration(submission_id: str, http_request: Request):
    """Read the embedding facts the scanned revision publishes about itself.

    The deployment bundle makes the operator declare this contract, and the
    model states every value in its own config files. Reading them from the
    already-quarantined snapshot means a submission whose scan predates the
    scanner-side extraction still prefills, with no re-scan.
    """
    _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT s.id,sc.result FROM model_intake_submissions s
            LEFT JOIN scans sc ON sc.id=s.scan_id WHERE s.id=$1
            """,
            submission_uuid,
        )
        subjects = await conn.fetch(
            "SELECT subject_kind,sha256,metadata_json FROM model_intake_subjects WHERE submission_id=$1",
            submission_uuid,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Model submission not found")

    # A scan run after the scanner-side extraction already recorded them.
    for subject in subjects:
        if str(subject["subject_kind"]) != "configuration":
            continue
        recorded = _model_intake_json_object(subject["metadata_json"]).get(
            "embedding_configuration_hints"
        )
        if isinstance(recorded, dict) and recorded:
            return {"available": True, "source": "recorded_evidence", **recorded}

    digests = {str(item["subject_kind"]): str(item["sha256"]) for item in subjects}
    artifact_sha = digests.get("artifact", "")
    snapshot_sha = digests.get("repository_snapshot", "")
    if not artifact_sha or not snapshot_sha:
        return {"available": False, "reason": "no_registered_snapshot"}
    try:
        materialized = await asyncio.to_thread(
            _model_intake_snapshot_materialization,
            _model_intake_json_object(row["result"]),
            artifact_sha256=artifact_sha,
            repository_snapshot_sha256=snapshot_sha,
        )
    except HTTPException:
        return {"available": False, "reason": "snapshot_unavailable"}

    collect, merge = _import_embedding_hint_readers()

    def _read() -> dict[str, Any]:
        # subject_path is the host path handed to the runner; the API can only
        # read the container-visible copy.
        root = Path(materialized["container_subject_path"])
        hints: dict[str, Any] = {}
        for candidate in sorted(root.rglob("*.json")) + sorted(root.rglob("*.JSON")):
            relative = candidate.relative_to(root).as_posix()
            try:
                data = candidate.read_bytes()
            except OSError:
                continue
            hints = merge(hints, collect(relative, data))
        return hints

    hints = await asyncio.to_thread(_read)
    if not hints:
        return {"available": False, "reason": "model_publishes_no_embedding_facts"}
    return {"available": True, "source": "quarantined_snapshot", **hints}


@router.get("/model-intake/scans/{scan_id}/sbom")
async def download_model_intake_sbom(
    scan_id: str,
    format: str = Query("cyclonedx", pattern="^(cyclonedx|spdx|aibom)$"),
    download: bool = Query(True),
):
    """Export a completed Model Intake scan as a bill of materials.

    Everything here was produced by the scan itself. Nothing is re-inspected,
    so this stays a read of recorded evidence rather than a second opinion.
    """
    scan_uuid = _model_intake_uuid(scan_id, "scan id")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            "SELECT status,scan_type,result,completed_at FROM scans WHERE id=$1", scan_uuid
        )
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if str(row["scan_type"]) != "model_intake":
        raise HTTPException(status_code=409, detail="Scan is not a Model Intake scan")
    if str(row["status"]) != "completed":
        raise HTTPException(
            status_code=409,
            detail=f"Scan is {row['status']}; a bill of materials is only exported from a completed scan",
        )
    result = _model_intake_json_object(row["result"])
    if format == "aibom":
        aibom = result.get("model_intake", {}).get("aibom") if isinstance(result.get("model_intake"), dict) else None
        if not isinstance(aibom, dict) or not aibom:
            raise HTTPException(status_code=409, detail="This scan recorded no AIBOM")
        document, filename = aibom, f"shakerscan-aibom-{scan_uuid}.json"
    elif format == "spdx":
        # Anchor the SPDX creation timestamp to the scan so the same evidence
        # always exports byte-identically instead of changing per download.
        completed = row["completed_at"]
        created = (
            completed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if hasattr(completed, "astimezone")
            else ""
        )
        try:
            document = _build_model_intake_spdx(result, scan_id=str(scan_uuid), created=created)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        filename = f"shakerscan-sbom-{scan_uuid}.spdx.json"
    else:
        try:
            document = _build_model_intake_cyclonedx(result, scan_id=str(scan_uuid))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        filename = f"shakerscan-sbom-{scan_uuid}.cdx.json"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'} if download else {}
    return JSONResponse(content=document, headers=headers, media_type="application/json")


@router.get("/model-intake/scans/{scan_id}/sbom/summary")
async def model_intake_sbom_summary(scan_id: str):
    """Describe the exportable bill of materials without transferring it."""
    scan_uuid = _model_intake_uuid(scan_id, "scan id")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow("SELECT status,scan_type,result FROM scans WHERE id=$1", scan_uuid)
    if not row or str(row["scan_type"]) != "model_intake":
        raise HTTPException(status_code=404, detail="Model Intake scan not found")
    if str(row["status"]) != "completed":
        return {"available": False, "reason": f"scan_{row['status']}"}
    result = _model_intake_json_object(row["result"])
    try:
        document = _build_model_intake_cyclonedx(result, scan_id=str(scan_uuid))
    except ValueError:
        return {"available": False, "reason": "no_model_intake_evidence"}
    model_intake = result.get("model_intake") if isinstance(result.get("model_intake"), dict) else {}
    license_compliance = (
        model_intake.get("supply_chain", {}).get("license_compliance", {})
        if isinstance(model_intake, dict) and isinstance(model_intake.get("supply_chain"), dict)
        else {}
    )
    license_display = _model_intake_license_display(license_compliance)
    return {
        "available": True,
        "formats": ["cyclonedx", "spdx", "aibom"],
        "license_artifacts": ["license-bom", "third-party-notices"],
        "aibom_available": bool(isinstance(model_intake, dict) and model_intake.get("aibom")),
        "license_status": license_display["status"],
        "license_summary": license_display["summary"],
        "license_follow_up_required": license_display["follow_up_required"],
        "spec_version": document.get("specVersion"),
        **_model_intake_bom_completeness(document),
    }


@router.get("/model-intake/scans/{scan_id}/license-bom")
async def download_model_intake_license_bom(scan_id: str, download: bool = Query(True)):
    """Export the reconciled license evidence and deterministic policy result."""
    scan_uuid = _model_intake_uuid(scan_id, "scan id")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow("SELECT status,scan_type,result FROM scans WHERE id=$1", scan_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if str(row["scan_type"]) != "model_intake":
        raise HTTPException(status_code=409, detail="Scan is not a Model Intake scan")
    if str(row["status"]) != "completed":
        raise HTTPException(status_code=409, detail="License evidence is only exported from a completed scan")
    try:
        document = _build_model_intake_license_bom(
            _model_intake_json_object(row["result"]), scan_id=str(scan_uuid),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    headers = {
        "Content-Disposition": f'attachment; filename="shakerscan-license-bom-{scan_uuid}.json"'
    } if download else {}
    return JSONResponse(content=document, headers=headers, media_type="application/json")


@router.get("/model-intake/scans/{scan_id}/third-party-notices")
async def download_model_intake_third_party_notices(scan_id: str, download: bool = Query(True)):
    """Export a human-readable Third-Party Notices draft from recorded evidence."""
    scan_uuid = _model_intake_uuid(scan_id, "scan id")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow("SELECT status,scan_type,result FROM scans WHERE id=$1", scan_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if str(row["scan_type"]) != "model_intake":
        raise HTTPException(status_code=409, detail="Scan is not a Model Intake scan")
    if str(row["status"]) != "completed":
        raise HTTPException(status_code=409, detail="Notices are only exported from a completed scan")
    try:
        document = _render_model_intake_third_party_notices(
            _model_intake_json_object(row["result"]), scan_id=str(scan_uuid),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    headers = {
        "Content-Disposition": f'attachment; filename="THIRD-PARTY-NOTICES-{scan_uuid}.txt"'
    } if download else {}
    return Response(content=document, headers=headers, media_type="text/plain; charset=utf-8")


@router.get("/model-intake/runners/install-plan")
async def model_intake_runner_install_plan():
    """What it takes to install the microVM tier, and whether this host can.

    The API runs in a container and cannot install a root systemd unit on the
    host, so this deliberately returns a plan rather than performing one. It
    reports only what it can actually observe: /proc/cpuinfo is not namespaced,
    so the CPU verdict is the real host's, while /dev/kvm and the installed
    components live outside the container and are left to the CLI.
    """
    def _plan() -> dict[str, Any]:
        from model_intake_runner_controller import cpu_exposes_virtualization, host_platform

        platform_name = host_platform()
        virtualization = cpu_exposes_virtualization()
        configured = bool(os.getenv("MODEL_INTAKE_RUNNER_URL", "").strip())
        if platform_name not in {"linux", "unknown"}:
            supported, reason = False, (
                f"The microVM tier requires a Linux host; this deployment is on {platform_name}."
            )
        elif virtualization is False:
            supported, reason = False, (
                "This host exposes no CPU virtualization extension, so KVM cannot start. "
                "On a cloud instance that is usually a per-instance setting: AWS exposes it as "
                "the nested-virtualization CPU option on a stopped instance."
            )
        else:
            supported, reason = True, "This host can run the Model Intake microVM tier."
        runtime_dir = os.getenv("SHAKERSCAN_RUNTIME_DIR", "").strip()
        if runtime_dir and Path(runtime_dir).is_absolute():
            enter_runtime = f"cd {shlex.quote(runtime_dir)}"
            runtime_label = runtime_dir
            install_kind = os.getenv("SHAKERSCAN_INSTALL_KIND", "curl_install").strip() or "curl_install"
        else:
            enter_runtime = 'cd "$HOME/.shakerscan"'
            runtime_label = "~/.shakerscan"
            install_kind = "curl_install"
        command_prefix = f"{enter_runtime} && sudo ./scanner.sh model-intake-runner install"
        return {
            "schema_version": "model-intake-runner-install-plan/v1",
            "supported": supported,
            "reason": reason,
            "already_configured": configured,
            "host_platform": platform_name,
            "cpu_virtualization": virtualization,
            # Installing mutates the host as root, which the API container
            # cannot and should not do on the operator's behalf.
            "executed_by": "operator_on_host",
            "command": f"{command_prefix} --signer <choice> --confirm",
            "default_command": f"{command_prefix} --confirm",
            "production_command": f"{command_prefix} --signer kms:<key-id> --confirm",
            "status_command": f"{enter_runtime} && ./scanner.sh model-intake-runner status",
            "runtime_dir": runtime_label,
            "install_kind": install_kind,
            # local-pem is the default because it is the only option that works
            # without external setup. It is listed first for that reason, and
            # labelled non-production so the default never implies more trust
            # than it carries.
            "default_signer": "local-pem",
            "signer_choices": [
                {"value": "local-pem", "label": "Local key (default)", "production": False,
                 "detail": "Generated on the host. Proves the receipt path end to end; not a production trust anchor."},
                {"value": "kms:<key-id>", "label": "AWS KMS", "production": True,
                 "detail": "Purpose-scoped key; the production trust anchor for signed receipts."},
            ],
            "host_mutations": [
                "install firecracker + jailer, a pinned guest kernel, and the guest rootfs into /opt/shakerscan/model-intake-runner",
                "create /srv/jailer and /var/lib/shakerscan/model-intake-runner",
                "create the cgroup-v2 parent /sys/fs/cgroup/shakerscan-model-intake",
                "write /etc/shakerscan/model-intake-runner.env (mode 0600)",
                "install and enable the systemd unit shakerscan-model-intake-runner.service",
                "record MODEL_INTAKE_RUNNER_* in the ShakerScan .env and restart the api container",
            ],
            "cost": (
                "The guest rootfs bundles CPU PyTorch and transformers; expect a multi-gigabyte "
                "image and several minutes to build."
            ),
        }

    return await asyncio.to_thread(_plan)


@router.post("/model-intake/loader-profiles/resolve")
async def resolve_model_intake_loader_profile(request: ModelLoaderProfileResolveRequest):
    """Resolve by format/library/custom-code facts, never by a model allowlist."""
    return _resolve_model_loader_profile(
        request.repository_manifest,
        artifact_path=request.artifact_path,
        runtime_image_digest=request.runtime_image_digest.lower(),
        reviewed_custom_code_sha256=(
            request.reviewed_custom_code_sha256.lower()
            if request.reviewed_custom_code_sha256 else None
        ),
    )


@router.post("/model-intake/conversion-profiles/resolve")
async def resolve_model_intake_conversion_profile(request: ModelLoaderProfileResolveRequest):
    """Resolve the one fixed PyTorch-bin to safetensors Firecracker profile."""
    return _resolve_model_conversion_profile(
        request.repository_manifest,
        artifact_path=request.artifact_path,
        runtime_image_digest=request.runtime_image_digest.lower(),
        reviewed_custom_code_sha256=(
            request.reviewed_custom_code_sha256.lower()
            if request.reviewed_custom_code_sha256 else None
        ),
    )


@router.post("/model-intake/admission/verify")
async def verify_model_intake_admission(request: ModelIntakeAdmissionVerifyRequest, http_request: Request):
    """Fail closed unless a package authorizes these exact deployment subjects."""
    _require_model_intake_operator(http_request)
    trusted_keys = _model_admission_trusted_keys()
    if not trusted_keys:
        raise HTTPException(
            status_code=503,
            detail="MODEL_INTAKE_ADMISSION_TRUSTED_PUBLIC_KEYS is not configured",
        )
    result = _verify_model_admission_package(
        request.admission_package,
        trusted_public_keys=trusted_keys,
        expected_artifact_sha256=request.expected_artifact_sha256.lower(),
        expected_repository_snapshot_sha256=(
            request.expected_repository_snapshot_sha256.lower()
            if request.expected_repository_snapshot_sha256
            else None
        ),
        allow_legacy_v1=os.getenv("MODEL_INTAKE_ALLOW_LEGACY_V1_VERIFICATION", "").strip().lower()
        in {"1", "true", "yes"},
    )
    if not result.get("verified"):
        raise HTTPException(status_code=409, detail=result)
    async with _pool().acquire() as conn:
        await conn.execute(
            """UPDATE model_intake_admissions
               SET status='expired', updated_at=NOW()
               WHERE status='active' AND expires_at <= NOW()"""
        )
        admission = await conn.fetchrow(
            """SELECT id, scan_id, status, schema_version, expires_at, reassessment_due_at
               FROM model_intake_admissions
               WHERE statement_sha256=$1""",
            result.get("statement_sha256"),
        )
    if not admission:
        raise HTTPException(status_code=409, detail={**result, "verified": False, "status": "FAIL", "blockers": ["admission_not_registered"]})
    if admission["status"] != "active":
        raise HTTPException(status_code=409, detail={**result, "verified": False, "status": "FAIL", "blockers": [f"admission_{admission['status']}"]})
    result["registry"] = {
        "admission_id": str(admission["id"]),
        "scan_id": str(admission["scan_id"]),
        "status": admission["status"],
        "schema_version": admission["schema_version"],
        "expires_at": _iso_or_none(admission["expires_at"]),
        "reassessment_due_at": _iso_or_none(admission["reassessment_due_at"]),
    }
    return result


@router.post("/model-intake/submissions/{submission_id}/promote")
async def promote_model_intake_submission(
    submission_id: str,
    request: ModelPromotionRequest,
    http_request: Request,
):
    """Invoke the separate narrow signer by stored IDs; no evidence JSON crosses this API."""
    requested_by_subject = _model_intake_authenticated_subject(http_request)
    submission_uuid = _model_intake_uuid(submission_id, "submission id")
    decision_uuid = _model_intake_uuid(request.policy_decision_id, "policy decision id")
    async with _pool().acquire() as conn:
        decision = await conn.fetchrow(
            """
            SELECT decision.id,decision.decision,submission.state,
                   decision.evidence_manifest_id=(
                       SELECT latest.id FROM model_intake_evidence_manifests AS latest
                       WHERE latest.submission_id=submission.id
                       ORDER BY latest.version DESC LIMIT 1
                   ) AS binds_latest_manifest
            FROM model_intake_policy_decisions AS decision
            JOIN model_intake_submissions AS submission ON submission.id=decision.submission_id
            WHERE decision.id=$1 AND decision.submission_id=$2
            """,
            decision_uuid,
            submission_uuid,
        )
    if not decision:
        raise HTTPException(status_code=404, detail="Stored policy decision not found")
    if decision["decision"] != "allow":
        raise HTTPException(status_code=409, detail="Only a stored allow decision can be promoted")
    if decision["state"] != "policy_decided" or not decision["binds_latest_manifest"]:
        raise HTTPException(status_code=409, detail="Promotion requires the latest unchanged policy-decided evidence")
    try:
        result = await asyncio.to_thread(
            _call_model_intake_signer,
            str(decision_uuid),
            request.idempotency_key,
            requested_by_subject,
        )
    except (RuntimeError, OSError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": "model_intake_signer_unavailable_or_rejected", "message": str(exc)},
        ) from exc
    return result


@router.post("/model-intake/admissions/v2/verify")
async def verify_model_intake_admission_v2(
    request: ModelAdmissionV2VerifyRequest,
    http_request: Request,
):
    """Pure deployment gate: verify exact components and active registry state."""
    result, admission = await _verify_model_intake_admission_v2_request(request, http_request)
    async with _pool().acquire() as conn:
        observed = await conn.fetchval(
            """SELECT EXISTS(
                   SELECT 1 FROM model_intake_deployment_bindings
                   WHERE admission_id=$1 AND verifier_status='PASS'
                     AND observed_bundle_sha256=$2
               )""",
            admission["id"],
            request.expected_bundle_sha256.lower(),
        )
    result["deployment_observed"] = bool(observed)
    result["side_effects"] = False
    return result


@router.post("/model-intake/admissions/v2/observe")
async def observe_model_intake_deployment_v2(
    request: ModelAdmissionV2VerifyRequest,
    http_request: Request,
):
    """Explicitly record a deployment observation after the pure gate allows it."""
    result, admission = await _verify_model_intake_admission_v2_request(request, http_request)
    async with _pool().acquire() as conn:
        command = await conn.execute(
            """UPDATE model_intake_deployment_bindings
               SET observed_bundle_sha256=$2,verifier_status='PASS',observed_at=NOW()
               WHERE admission_id=$1""",
            admission["id"],
            request.expected_bundle_sha256.lower(),
        )
    if command == "UPDATE 0":
        raise HTTPException(status_code=409, detail="No registered deployment binding accepts this admission")
    result["deployment_observed"] = True
    result["side_effects"] = True
    return result


@router.get("/model-intake/admissions")
async def list_model_intake_admissions(
    status: Optional[str] = Query(default=None, pattern="^(active|denied|reassessment_required|revoked|expired|superseded)$"),
    artifact_sha256: Optional[str] = Query(default=None, pattern="^[0-9a-fA-F]{64}$"),
    limit: int = Query(default=100, ge=1, le=500),
):
    conditions = []
    args: list[Any] = []
    if status:
        args.append(status)
        conditions.append(f"status=${len(args)}")
    if artifact_sha256:
        args.append(artifact_sha256.lower())
        conditions.append(f"artifact_sha256=${len(args)}")
    args.append(limit)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    async with _pool().acquire() as conn:
        await _expire_model_intake_admissions(conn)
        rows = await conn.fetch(
            f"""SELECT id, scan_id, target_id, artifact_sha256, repository_snapshot_sha256,
                       statement_sha256, decision, status, schema_version, policy_profile, policy_version,
                       issued_at, expires_at, reassessment_due_at, revoked_at, revoked_by,
                       revocation_reason, created_at, updated_at
                FROM model_intake_admissions {where}
                ORDER BY created_at DESC LIMIT ${len(args)}""",
            *args,
        )
    return {"admissions": [row_to_dict(row) for row in rows]}


@router.get("/model-intake/admissions/{admission_id}")
async def get_model_intake_admission(admission_id: str):
    try:
        admission_uuid = uuid.UUID(admission_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid admission id")
    async with _pool().acquire() as conn:
        await _expire_model_intake_admissions(conn)
        row = await conn.fetchrow("SELECT * FROM model_intake_admissions WHERE id=$1", admission_uuid)
        events = await conn.fetch(
            "SELECT * FROM model_intake_admission_events WHERE admission_id=$1 ORDER BY created_at DESC LIMIT 200",
            admission_uuid,
        ) if row else []
    if not row:
        raise HTTPException(status_code=404, detail="Model admission not found")
    return {"admission": row_to_dict(row), "events": [row_to_dict(item) for item in events]}


@router.post("/model-intake/admissions/{admission_id}/revoke")
async def revoke_model_intake_admission(
    admission_id: str,
    request: ModelIntakeAdmissionRevokeRequest,
    http_request: Request,
):
    _require_model_intake_operator(http_request)
    try:
        admission_uuid = uuid.UUID(admission_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid admission id")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """WITH candidate AS (
                   SELECT id, status AS previous_status
                   FROM model_intake_admissions
                   WHERE id=$1 AND status IN ('active','reassessment_required')
                   FOR UPDATE
               )
               UPDATE model_intake_admissions AS admission
               SET status='revoked', revoked_at=NOW(), revoked_by=$2, revocation_reason=$3, updated_at=NOW()
               FROM candidate
               WHERE admission.id=candidate.id
               RETURNING admission.id, admission.status, admission.statement_sha256, candidate.previous_status""",
            admission_uuid, request.actor, request.reason,
        )
        if row:
            await conn.execute(
                """INSERT INTO model_intake_admission_events
                   (admission_id,event_type,actor,reason,previous_status,new_status,evidence_digest)
                   VALUES ($1,'revoked',$2,$3,$4,'revoked',$5)""",
                admission_uuid, request.actor, request.reason, row["previous_status"], row["statement_sha256"],
            )
    if not row:
        raise HTTPException(status_code=409, detail="Admission is absent or no longer deployable")
    return {"admission_id": str(row["id"]), "status": "revoked"}


@router.post("/model-intake/reassessment/events")
async def create_model_intake_reassessment_event(
    request: ModelIntakeReassessmentEventRequest,
    http_request: Request,
):
    _require_model_intake_operator(http_request)
    if not request.all_active and not request.artifact_sha256 and not request.statement_sha256:
        raise HTTPException(status_code=400, detail="Select artifact_sha256, statement_sha256, or explicitly set all_active")
    if request.all_active and not request.confirm_all_active:
        raise HTTPException(status_code=400, detail="all_active requires confirm_all_active=true")
    new_status = _model_admission_triggered_status(request.trigger_type, request.requested_action)
    conditions = ["admission.status IN ('active','reassessment_required')"]
    args: list[Any] = []
    if request.artifact_sha256:
        args.append(request.artifact_sha256.lower())
        conditions.append(f"admission.artifact_sha256=${len(args)}")
    if request.statement_sha256:
        args.append(request.statement_sha256.lower())
        conditions.append(f"admission.statement_sha256=${len(args)}")
    args.extend([new_status, request.actor, request.reason])
    status_arg, actor_arg, reason_arg = len(args) - 2, len(args) - 1, len(args)
    async with _pool().acquire() as conn:
        await _expire_model_intake_admissions(conn)
        if request.all_active:
            await _validate_approval_receipt_for_action(
                conn,
                request.approval_receipt_id,
                action_name="model_intake.reassessment.all_active",
                risk_tier="active",
                always_require_receipt=True,
            )
        rows = await conn.fetch(
            f"""WITH candidate AS (
                    SELECT admission.id, admission.status AS previous_status
                    FROM model_intake_admissions AS admission
                    WHERE {' AND '.join(conditions)}
                    FOR UPDATE
                )
                UPDATE model_intake_admissions AS admission
                SET status=${status_arg},
                    revoked_at=CASE WHEN ${status_arg}='revoked' THEN NOW() ELSE revoked_at END,
                    revoked_by=CASE WHEN ${status_arg}='revoked' THEN ${actor_arg} ELSE revoked_by END,
                    revocation_reason=CASE WHEN ${status_arg}='revoked' THEN ${reason_arg} ELSE revocation_reason END,
                    updated_at=NOW()
                FROM candidate
                WHERE admission.id=candidate.id
                RETURNING admission.id, admission.statement_sha256, candidate.previous_status""",
            *args,
        )
        for row in rows:
            await conn.execute(
                """INSERT INTO model_intake_admission_events
                   (admission_id,event_type,trigger_type,actor,reason,previous_status,new_status,evidence_digest,metadata_json)
                   VALUES ($1,'reassessment_trigger',$2,$3,$4,$5,$6,$7,$8::jsonb)""",
                row["id"], request.trigger_type, request.actor, request.reason, row["previous_status"], new_status,
                request.evidence_digest or row["statement_sha256"], json.dumps(request.metadata_json),
            )
    return {"affected": len(rows), "status": new_status, "trigger_type": request.trigger_type}


@router.post("/model-intake/retention/cleanup")
async def cleanup_model_intake_quarantine(
    request: ModelIntakeRetentionCleanupRequest,
    http_request: Request,
):
    if not request.dry_run:
        _require_model_intake_operator(http_request)
    quarantine_root = Path(
        os.getenv("MODEL_INTAKE_QUARANTINE_DIR") or _results_dir() / "model-intake-quarantine"
    )
    async with _pool().acquire() as conn:
        await _expire_model_intake_admissions(conn)
        rows = await conn.fetch(
            """SELECT artifact_sha256, repository_snapshot_sha256
               FROM model_intake_admissions
               WHERE status IN ('active','reassessment_required')"""
        )
        protected = {
            str(value).lower()
            for row in rows
            for value in (row["artifact_sha256"], row["repository_snapshot_sha256"])
            if value
        }
        plan = await asyncio.to_thread(
            _plan_model_quarantine_cleanup,
            quarantine_root,
            protected_digests=protected,
            retention_days=request.retention_days,
            max_total_bytes=request.max_total_bytes,
        )
        plan_sha256 = _content_free_hash(plan)
        plan["plan_sha256"] = plan_sha256
        if request.dry_run:
            plan["dry_run"] = True
            return plan
        if not request.confirm_delete or not request.actor or not request.reason:
            raise HTTPException(status_code=400, detail="Execution requires confirm_delete, actor, and reason")
        if not request.plan_sha256 or not secrets.compare_digest(request.plan_sha256.lower(), plan_sha256):
            raise HTTPException(status_code=409, detail="Cleanup plan changed; request a new dry-run preview")
        approval_context = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            action_name="model_intake.retention_cleanup",
            risk_tier="active",
            always_require_receipt=True,
        )
        execution = await asyncio.to_thread(_execute_model_quarantine_cleanup, quarantine_root, plan)
        command_result = await _record_command_result(
            conn,
            command="model_intake.retention_cleanup",
            status="completed" if not execution["skipped"] else "partial",
            risk_tier="active",
            approval_receipt_id=(approval_context or {}).get("approval_receipt_id"),
            scope_receipt_id=(approval_context or {}).get("scope_receipt_id"),
            operator_message=f"Deleted {execution['deleted_count']} expired Model Intake quarantine object(s)",
            result_json={
                "actor": request.actor,
                "reason": request.reason,
                "plan_sha256": plan_sha256,
                "deleted_count": execution["deleted_count"],
                "deleted_bytes": execution["deleted_bytes"],
                "skipped_count": len(execution["skipped"]),
            },
        )
    return {
        **execution,
        "dry_run": False,
        "plan_sha256": plan_sha256,
        "operation_id": str(command_result["id"]) if command_result else None,
    }


@router.post("/model-intake/scan")
async def scan_model_intake(request: ModelIntakeScanRequest):
    """Queue non-deployable technical evidence for the controlled workflow."""
    if request.intake_mode != "preflight":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "legacy_model_intake_admission_mode_removed",
                "message": (
                    "POST /model-intake/scan is preflight-only and cannot create an admission candidate. "
                    "Use /model-intake/submissions and the controlled evidence, approval, policy, and "
                    "promotion workflow for deployment authorization."
                ),
                "required_intake_mode": "preflight",
                "authoritative_workflow": "/model-intake/submissions",
            },
        )
    # Validate the raw public DTO before registry enrichment or policy
    # expansion can blur which authority came from the requester.
    _validate_model_intake_admission_request_authority(request)
    freshness = _worker_freshness_snapshot()
    unsafe_worker_count = int(freshness.get("stale_count") or 0) + int(freshness.get("pending_count") or 0)
    if request.require_current_workers and (
        not freshness.get("available")
        or int(freshness.get("fleet_size") or 0) < 1
        or unsafe_worker_count > 0
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "error": "workers_not_confirmed_current",
                "message": (
                    "Model Intake requires a non-empty, fingerprint-current worker fleet. "
                    "Restart workers and wait for current build fingerprints before retrying."
                ),
                "stale_workers": freshness.get("stale_names", []),
                "pending_workers": freshness.get("pending_names", []),
            },
        )
    request = await _enrich_model_intake_scan_request(request)
    request = await _expand_model_intake_policy_profile_requirements(request)
    request = await _expand_model_intake_saved_trust_anchors(request)
    artifact_ref = (request.artifact_url or "").strip()
    if not artifact_ref:
        raise HTTPException(status_code=400, detail="artifact_url is required")
    parsed = urllib.parse.urlparse(artifact_ref)
    if parsed.scheme and parsed.scheme not in {"http", "https", "hf", "oci", "s3", "gs", "gcs", "azure", "mlflow", "models"}:
        raise HTTPException(status_code=400, detail="artifact_url must use http(s), hf://, oci://, s3://, gs://, gcs://, azure://, mlflow://, or models:/")

    r = get_redis()
    job_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    target_name = request.name or f"Model artifact: {_short_url_label(artifact_ref)}"
    generated_evaluation_report = None
    if request.run_generated_evaluation or request.require_generated_evaluation or request.evaluation_spec_json is not None:
        generated_evaluation_report = _evaluate_model_intake_request(
            request.evaluation_spec_json,
            artifact_sha256=(request.expected_sha256 or "").strip().lower() or None,
        )
    options = {
        "run_kind": "model_intake",
        "intake_mode": request.intake_mode,
        "artifact_name": request.name,
        "metadata_url": request.metadata_url,
        "metadata_json": request.metadata_json or {},
        "expected_sha256": request.expected_sha256,
        "signature_url": request.signature_url,
        "signature_public_key": request.signature_public_key,
        "signature_public_key_url": request.signature_public_key_url,
        "signature_value": request.signature_value,
        "signature_rsa_padding": request.signature_rsa_padding,
        "signature_hash": request.signature_hash,
        "signature_payload": request.signature_payload,
        "signature_trusted_keys": request.signature_trusted_keys,
        "signature_trusted_key_sha256": request.signature_trusted_key_sha256,
        "attestation_bundle_json": request.attestation_bundle_json,
        "attestation_trusted_keys": request.attestation_trusted_keys,
        "attestation_trusted_key_sha256": request.attestation_trusted_key_sha256,
        "allowed_attestation_predicate_types": request.allowed_attestation_predicate_types,
        "required_attestation_builder_ids": request.required_attestation_builder_ids,
        "require_attestation_verification": request.require_attestation_verification,
        "require_transparency_log": request.require_transparency_log,
        "trust_anchor_ids": request.trust_anchor_ids or [],
        "model_card_url": request.model_card_url,
        "deployment_approved": request.deployment_approved,
        "require_deployment_approval": request.require_deployment_approval,
        "require_signature": request.require_signature,
        "require_signature_verification": request.require_signature_verification,
        "require_cryptographic_signature_verification": request.require_cryptographic_signature_verification,
        "require_hash": request.require_hash,
        "require_model_governance": request.require_model_governance,
        "policy_profile": request.policy_profile,
        "policy_exceptions": request.policy_exceptions or [],
        "max_download_bytes": request.max_download_bytes,
        "complete_artifact_download": request.complete_artifact_download,
        "max_artifact_bytes": request.max_artifact_bytes,
        "complete_repository_snapshot": request.complete_repository_snapshot,
        "max_repository_bytes": request.max_repository_bytes,
        "max_repository_files": request.max_repository_files,
        "run_generated_scanners": request.run_generated_scanners,
        "generated_scanner_names": request.generated_scanner_names,
        "run_dynamic_sandbox": request.run_dynamic_sandbox,
        "require_dynamic_sandbox": request.require_dynamic_sandbox,
        "require_current_workers": request.require_current_workers,
        "sandbox_timeout_seconds": request.sandbox_timeout_seconds,
        # The raw benchmark may contain embeddings. Only the content-free,
        # digest-bound computed report may enter durable scan options/Redis.
        "generated_evaluation_report": generated_evaluation_report,
        "run_generated_evaluation": request.run_generated_evaluation,
        "require_generated_evaluation": request.require_generated_evaluation,
        "require_signed_admission": request.require_signed_admission,
        "admission_expires_days": request.admission_expires_days,
        "admission_reassessment_days": request.admission_reassessment_days,
        "timeout_seconds": request.timeout_seconds,
        "allow_insecure_http": request.allow_insecure_http,
        "allow_private_networks": request.allow_private_networks,
        "allowed_acquisition_hosts": request.allowed_acquisition_hosts,
        "allowed_acquisition_ports": request.allowed_acquisition_ports,
        "max_acquisition_redirects": request.max_acquisition_redirects,
    }
    if freshness.get("available"):
        options["expected_build_fingerprint_at_submit"] = freshness.get("expected_build_fingerprint")
        options["stale_worker_count_at_submit"] = freshness.get("stale_count")
        options["pending_worker_count_at_submit"] = freshness.get("pending_count")
        options["worker_fleet_size_at_submit"] = freshness.get("fleet_size")
    if request.policy_profile in POLICY_PROFILES:
        options["environment"] = request.policy_profile
        if request.policy_profile == "production":
            options["strict_governance"] = True

    async with _pool().acquire() as conn:
        # Early missing-receipt guard before target-row creation.
        await _require_approval_receipt_if_policy_enabled(
            conn,
            request.approval_receipt_id,
            action_name="model_intake.scan",
        )
        target = await conn.fetchrow("SELECT id FROM targets WHERE url = $1", artifact_ref)
        if target:
            target_id = target["id"]
        else:
            target_id = await conn.fetchval("""
                INSERT INTO targets (url, name, root_domain, discovery_source)
                VALUES ($1, $2, $3, 'model-intake')
                ON CONFLICT (canonical_key) DO UPDATE SET url = targets.url
                RETURNING id
            """, artifact_ref, target_name, extract_root_domain(artifact_ref))

        approval_context = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=artifact_ref,
            target_id=target_id,
            action_name="model_intake.scan",
            risk_tier="active",
            always_require_receipt=bool(request.allow_insecure_http or request.allow_private_networks),
        )
        if approval_context:
            options.update(approval_context)

        await conn.execute("""
            INSERT INTO scans (
                id, target_id, target_url, job_id, status, options, scan_type, run_kind, subject_ref
            ) VALUES ($1, $2, $3, $4, 'pending', $5, 'model_intake', 'model_intake', $6)
        """,
            uuid.UUID(scan_id),
            target_id,
            artifact_ref,
            job_id,
            json.dumps(options),
            f"model_artifact:{hashlib.sha256(artifact_ref.encode()).hexdigest()[:16]}",
        )
        command_result = await _record_command_result(
            conn,
            command="model_intake.scan",
            status="queued",
            risk_tier="active",
            scan_id=scan_id,
            scope_receipt_id=options.get("scope_receipt_id"),
            approval_receipt_id=options.get("approval_receipt_id"),
            operator_message=f"Queued Model Intake scan for {_short_url_label(artifact_ref)}",
            result_json={
                "target": artifact_ref,
                "scan_type": "model_intake",
                "job_id": job_id,
                "policy_profile": options.get("policy_profile"),
            },
            next_action=f"/scans/{scan_id}",
        )

    job_data = {
        "job_id": job_id,
        "scan_id": scan_id,
        "target": artifact_ref,
        "options": options,
        "submitted_at": utc_now_iso(),
    }
    enqueue_job(r, QUEUE_NAME, job_data)
    r.hset(f"job:{job_id}", mapping={"status": "queued", "target": artifact_ref})

    response = {
        "scan_id": scan_id,
        "job_id": job_id,
        "status": "queued",
        "target": artifact_ref,
        "scan_type": "model_intake",
        "run_kind": "model_intake",
        "ui_url": f"/scans/{scan_id}",
    }
    if options.get("approval_receipt_id"):
        response["approval_receipt_id"] = options.get("approval_receipt_id")
        response["scope_receipt_id"] = options.get("scope_receipt_id")
    if command_result:
        response["operation_id"] = command_result["id"]
    return response


@router.post("/model-intake/automatic-reviews")
async def create_model_intake_automatic_review(request: ModelIntakeAutomaticReviewRequest):
    """Resolve and queue a one-link, durable technical review.

    This endpoint cannot approve or admit a model. It produces technical
    evidence and a frozen manifest, then names the human/external controls that
    remain.
    """
    source = request.source.strip()
    resolved = await resolve_model_intake(ModelIntakeResolveRequest(
        platform="auto", ref=source, revision=request.revision,
        metadata_json={}, timeout_seconds=20,
    ))
    scan_payload = resolved.get("scan_payload") if isinstance(resolved.get("scan_payload"), dict) else {}
    if not scan_payload.get("artifact_url"):
        raise HTTPException(status_code=422, detail="The model reference did not resolve to a testable artifact")
    # This scan is technical evidence for the controlled submission below,
    # not the admission decision itself.  Expanding the production admission
    # profile here duplicates missing signer/approval/evaluation controls as
    # static-scan failures and requires the container staging adapter even
    # though this controller subsequently runs the stronger exact-subject
    # Firecracker job.  Force complete acquisition/scanners/current workers
    # explicitly, and let the controlled production submission own its real
    # environment, runtime, trust, approval, and policy controls.
    policy_profile = "research"
    scan_request = ModelIntakeScanRequest(**{
        **scan_payload,
        "intake_mode": "preflight",
        "policy_profile": policy_profile,
        "complete_artifact_download": True,
        "complete_repository_snapshot": resolved.get("capabilities", {}).get("repository_snapshot") == "implemented",
        "run_generated_scanners": True,
        # Runtime qualification is performed later by the exact-subject
        # Firecracker controller. The container adapter is an Advanced/manual
        # staging option and must not create a duplicate unsupported runtime
        # failure in the one-link result.
        "run_dynamic_sandbox": False,
        "require_dynamic_sandbox": False,
        "require_current_workers": True,
    })
    queued = await scan_model_intake(scan_request)
    review_id = uuid.uuid4()
    repository = str(resolved.get("repository") or "").strip()
    pinned_revision = str(resolved.get("revision") or "").strip()
    source_label = (repository or str(scan_payload.get("name") or _short_url_label(source)))[:300]
    if repository and pinned_revision:
        source_label = f"{repository}@{pinned_revision[:12]}"
    timeline = [{"event": "static_scan_queued", "state": "static_scan_pending", "at": utc_now_iso()}]
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO model_intake_automatic_reviews
                (id,scan_id,source_kind,source_label,source_reference_hash,requested_environment,
                 state,current_step,progress,timeline_json)
            VALUES ($1,$2,$3,$4,$5,$6,'static_scan_pending','static_scan',5,$7::jsonb)
            RETURNING *
            """,
            review_id,
            uuid.UUID(str(queued["scan_id"])),
            str(resolved.get("platform") or "auto"),
            source_label,
            hashlib.sha256(source.encode()).hexdigest(),
            request.intended_environment,
            json.dumps(timeline),
        )
    return {
        "review": _model_intake_automatic_review_payload(row),
        "scan_id": queued["scan_id"],
        "ui_url": f"/model-intake?automatic_review={review_id}",
        "scan_report_url": f"/scans/{queued['scan_id']}",
        "authority": "technical_evidence_only",
    }


@router.get("/model-intake/automatic-reviews")
async def list_model_intake_automatic_reviews(limit: int = Query(10, ge=1, le=100)):
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT r.*,s.status AS static_scan_status,s.progress AS static_scan_progress,
                   s.current_phase AS static_scan_phase,
                   cj.state AS conversion_job_state,
                   kj.state AS calibration_job_state,
                   rj.state AS runtime_job_state
            FROM model_intake_automatic_reviews r
            LEFT JOIN scans s ON s.id=r.scan_id
            LEFT JOIN model_intake_runner_jobs cj ON cj.id=r.conversion_job_id
            LEFT JOIN model_intake_runner_jobs kj ON kj.id=r.calibration_job_id
            LEFT JOIN model_intake_runner_jobs rj ON rj.id=r.runtime_job_id
            ORDER BY r.created_at DESC LIMIT $1
            """,
            limit,
        )
    return {"reviews": [_model_intake_automatic_review_payload(row) for row in rows]}


@router.get("/model-intake/automatic-reviews/{review_id}")
async def get_model_intake_automatic_review(review_id: str):
    review_uuid = _model_intake_uuid(review_id, "automatic review id")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT r.*,s.status AS static_scan_status,s.progress AS static_scan_progress,
                   s.current_phase AS static_scan_phase,
                   cj.state AS conversion_job_state,
                   kj.state AS calibration_job_state,
                   rj.state AS runtime_job_state
            FROM model_intake_automatic_reviews r
            LEFT JOIN scans s ON s.id=r.scan_id
            LEFT JOIN model_intake_runner_jobs cj ON cj.id=r.conversion_job_id
            LEFT JOIN model_intake_runner_jobs kj ON kj.id=r.calibration_job_id
            LEFT JOIN model_intake_runner_jobs rj ON rj.id=r.runtime_job_id
            WHERE r.id=$1
            """,
            review_uuid,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Automatic Model Intake review not found")
    payload = _model_intake_automatic_review_payload(row)
    payload["scan_report_url"] = f"/scans/{row['scan_id']}" if row["scan_id"] else None
    payload["technical_report_urls"] = (
        {
            "json": f"/model-intake/automatic-reviews/{review_uuid}/report?format=json",
            "html": f"/model-intake/automatic-reviews/{review_uuid}/report?format=html",
            "sarif": f"/model-intake/automatic-reviews/{review_uuid}/report?format=sarif",
        }
        if row["submission_id"] else {}
    )
    return payload


@router.get("/model-intake/automatic-reviews/{review_id}/report")
async def get_model_intake_automatic_review_report(
    review_id: str,
    format: str = Query("json", pattern="^(json|html|sarif)$"),
):
    review_uuid = _model_intake_uuid(review_id, "automatic review id")
    async with _pool().acquire() as conn:
        review = await conn.fetchrow(
            "SELECT * FROM model_intake_automatic_reviews WHERE id=$1", review_uuid
        )
    submission_id = review["submission_id"] if review else None
    if not submission_id:
        raise HTTPException(status_code=409, detail="The automatic technical report is not ready")
    report = await get_model_intake_submission_report(
        str(submission_id), _model_intake_automatic_system_request(), format="json"
    )
    report = _apply_model_intake_automatic_review_context(report, row_to_dict(review))
    filename = f"model-intake-{submission_id}"
    if format == "html":
        return Response(
            content=_render_model_intake_html(report),
            media_type="text/html",
            headers={"Content-Disposition": f'inline; filename="{filename}.html"'},
        )
    if format == "sarif":
        return JSONResponse(
            content=_model_intake_report_to_sarif(report),
            media_type="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="{filename}.sarif.json"'},
        )
    return report


@router.get("/model-intake/scans/{scan_id}/evidence-export")
async def get_model_intake_evidence_export(scan_id: str):
    try:
        scan_uuid = uuid.UUID(str(scan_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="scan_id must be a UUID")
    async with _pool().acquire() as conn:
        scan = await conn.fetchrow("SELECT * FROM scans WHERE id=$1", scan_uuid)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    payload = row_to_dict(scan)
    result = _decode_json_value(payload.get("result")) or {}
    if payload.get("run_kind") != "model_intake" and not (isinstance(result, dict) and isinstance(result.get("model_intake"), dict)):
        raise HTTPException(status_code=404, detail="Model Intake scan not found")
    payload["result"] = result
    payload["options"] = _sanitize_scan_options(payload.get("options"))
    return _model_intake_evidence_export(payload)


@router.post("/model-intake/targets/{target_id}/rescan")
async def rescan_model_intake_target(target_id: str, http_request: Request):
    """Re-queue a model intake scan for an existing model target.

    Reuses the options of the target's most recent intake scan (policy profile,
    metadata, signature/hash requirements), so one-click re-checks from the
    exposure inventory run the same evaluation the artifact was admitted with.
    """
    actor = _model_intake_authenticated_subject(http_request)
    try:
        target_uuid = uuid.UUID(target_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid target id")

    async with _pool().acquire() as conn:
        target = await conn.fetchrow(
            "SELECT id, url FROM targets WHERE id = $1 AND is_active = true",
            target_uuid,
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        last_scan = await conn.fetchrow(
            """
            SELECT options FROM scans
            WHERE target_id = $1 AND run_kind = 'model_intake'
            ORDER BY created_at DESC LIMIT 1
            """,
            target_uuid,
        )
        if not last_scan:
            raise HTTPException(
                status_code=409,
                detail="No previous model intake scan to re-run. Submit one from Model Intake settings first.",
            )
        options, approval_receipt_id, authority_bearing = _prepare_model_intake_rescan_options(
            _decode_json_value(last_scan["options"])
        )
        artifact_ref = target["url"]

        approval_context = await _validate_approval_receipt_for_action(
            conn,
            approval_receipt_id,
            target_url=artifact_ref,
            target_id=target_uuid,
            action_name="model_intake.scan",
            risk_tier="active",
            always_require_receipt=authority_bearing,
            required_action_name="model_intake.scan" if approval_receipt_id else None,
            require_expiry=bool(approval_receipt_id),
            created_by=actor,
        )
        if approval_context:
            options.update(approval_context)

        r = get_redis()
        job_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        await conn.execute("""
            INSERT INTO scans (
                id, target_id, target_url, job_id, status, options, scan_type, run_kind, subject_ref
            ) VALUES ($1, $2, $3, $4, 'pending', $5, 'model_intake', 'model_intake', $6)
        """,
            uuid.UUID(scan_id),
            target_uuid,
            artifact_ref,
            job_id,
            json.dumps(options),
            f"model_artifact:{hashlib.sha256(artifact_ref.encode()).hexdigest()[:16]}",
        )
        command_result = await _record_command_result(
            conn,
            command="model_intake.scan",
            status="queued",
            risk_tier="active",
            scan_id=scan_id,
            scope_receipt_id=options.get("scope_receipt_id"),
            approval_receipt_id=options.get("approval_receipt_id"),
            operator_message=f"Queued Model Intake re-check for {_short_url_label(artifact_ref)}",
            result_json={
                "target": artifact_ref,
                "target_id": str(target_uuid),
                "scan_type": "model_intake",
                "job_id": job_id,
                "rescan": True,
            },
            created_by=actor,
            next_action=f"/scans/{scan_id}",
        )

    job_data = {
        "job_id": job_id,
        "scan_id": scan_id,
        "target": artifact_ref,
        "options": options,
        "submitted_at": utc_now_iso(),
    }
    enqueue_job(r, QUEUE_NAME, job_data)
    r.hset(f"job:{job_id}", mapping={"status": "queued", "target": artifact_ref})

    return {
        "scan_id": scan_id,
        "job_id": job_id,
        "status": "queued",
        "target": artifact_ref,
        "scan_type": "model_intake",
        "run_kind": "model_intake",
        "ui_url": f"/scans/{scan_id}",
        "operation_id": str(command_result["id"]) if command_result else None,
    }
class ModelIntakeScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_url: str
    name: Optional[str] = None
    intake_mode: Literal["admission", "preflight"] = Field(
        default="preflight",
        description=(
            "This legacy field is retained for request compatibility, but only preflight is accepted. "
            "Production authorization uses the separate submission/freeze/approval/policy/promotion "
            "workflow; admission mode on this endpoint is rejected."
        ),
    )
    metadata_url: Optional[str] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    expected_sha256: Optional[str] = None
    signature_url: Optional[str] = None
    # Real cryptographic signature material (operator-supplied; the artifact's own
    # metadata is never trusted for these). Exposing them here is what makes a
    # trusted signature_verified=True reachable via the public API.
    signature_public_key: Optional[str] = None
    signature_public_key_url: Optional[str] = None
    signature_value: Optional[str] = None
    signature_rsa_padding: Optional[str] = None
    signature_hash: Optional[str] = None
    signature_payload: Optional[str] = None
    # Operator-configured trust anchors. A valid signature only renders as
    # "verified" when its key chains to one of these (or a worker env anchor).
    # Scalar-or-list, matching the scanner internals (_iter_str_tokens / _iter_pem_blocks).
    signature_trusted_keys: Optional[Union[str, list[str]]] = None
    signature_trusted_key_sha256: Optional[Union[str, list[str]]] = None
    attestation_bundle_json: Optional[dict[str, Any]] = None
    attestation_trusted_keys: Optional[Union[str, list[str]]] = None
    attestation_trusted_key_sha256: Optional[Union[str, list[str]]] = None
    allowed_attestation_predicate_types: Optional[list[str]] = None
    required_attestation_builder_ids: Optional[list[str]] = None
    require_attestation_verification: bool = False
    require_transparency_log: bool = False
    trust_anchor_ids: Optional[list[str]] = None
    model_card_url: Optional[str] = None
    deployment_approved: bool = False
    require_deployment_approval: bool = True
    require_signature: bool = True
    require_signature_verification: bool = False
    require_cryptographic_signature_verification: bool = Field(
        default=False,
        description="Require a complete subject, valid cryptographic signature, matching subject digest, and operator-trusted signing key.",
    )
    require_hash: bool = True
    require_model_governance: bool = True
    policy_profile: Optional[str] = Field(
        default=None,
        description=(
            "Requested profile for preflight. Admission ignores this field and applies "
            "MODEL_INTAKE_ADMISSION_POLICY_PROFILE (production by default)."
        ),
    )
    policy_exceptions: Optional[list[dict[str, Any]]] = None
    max_download_bytes: int = Field(
        default=10_000_000,
        ge=1024,
        le=500_000_000_000,
        description=(
            "Artifact byte ceiling for this intake. Production models are routinely 1GB+, so anything "
            "above the in-memory inspection prefix is streamed into content-addressed quarantine "
            "automatically, which is what makes a full-artifact checksum and signature verifiable."
        ),
    )
    complete_artifact_download: bool = Field(
        default=False,
        description="Stream the complete artifact into content-addressed quarantine while retaining only a bounded inspection prefix in memory.",
    )
    max_artifact_bytes: int = Field(
        default=10_000_000_000,
        ge=1024,
        le=500_000_000_000,
        description="Fail-closed total-byte ceiling used only for complete artifact acquisition.",
    )
    complete_repository_snapshot: bool = Field(
        default=False,
        description="Acquire every file in a complete pinned Hugging Face repository manifest into quarantine.",
    )
    max_repository_bytes: int = Field(
        default=50_000_000_000,
        ge=1024,
        le=2_000_000_000_000,
        description="Fail-closed aggregate byte ceiling for complete repository snapshots.",
    )
    max_repository_files: int = Field(default=10_000, ge=1, le=10_000)
    run_generated_scanners: bool = Field(
        default=False,
        description="Run ShakerScan-generated semantic, malware, secret, SBOM, and SCA scanner plug-ins against the complete quarantined subject.",
    )
    generated_scanner_names: Optional[list[str]] = Field(default=None, max_length=50)
    run_dynamic_sandbox: bool = False
    require_dynamic_sandbox: bool = False
    require_current_workers: bool = Field(
        default=False,
        description="Reject submission unless every reported worker matches the current source fingerprint.",
    )
    sandbox_timeout_seconds: int = Field(default=120, ge=1, le=600)
    evaluation_spec_json: Optional[dict[str, Any]] = None
    run_generated_evaluation: bool = False
    require_generated_evaluation: bool = False
    require_signed_admission: bool = False
    admission_expires_days: int = Field(default=30, ge=1, le=365)
    admission_reassessment_days: int = Field(default=30, ge=1, le=365)
    timeout_seconds: int = Field(default=20, ge=1, le=120)
    allow_insecure_http: bool = Field(
        default=False,
        description="Development-only exception permitting plain HTTP artifact acquisition.",
    )
    allow_private_networks: bool = Field(
        default=False,
        description="Development-only exception permitting acquisition from private/non-global addresses.",
    )
    allowed_acquisition_hosts: Optional[list[str]] = Field(
        default=None,
        max_length=100,
        description="Optional exact or *.suffix hostname allowlist enforced on every acquisition redirect.",
    )
    allowed_acquisition_ports: Optional[list[int]] = Field(
        default=None,
        max_length=20,
        description="Additional acquisition ports; HTTPS/443 is always allowed and HTTP/80 requires allow_insecure_http.",
    )
    max_acquisition_redirects: int = Field(default=5, ge=0, le=5)

    @model_validator(mode="after")
    def validate_artifact_acquisition_limits(self):
        if self.complete_artifact_download and self.max_artifact_bytes < self.max_download_bytes:
            raise ValueError(
                "max_artifact_bytes must be greater than or equal to max_download_bytes "
                "when complete_artifact_download is enabled"
            )
        return self
    approval_receipt_id: Optional[str] = Field(
        default=None,
        description="Optional durable approval receipt to validate and stamp on the queued Model Intake scan.",
    )


class ModelIntakeResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: str = Field(default="auto", pattern="^(auto|huggingface|http|s3|gcs|azure|oci|mlflow)$")
    ref: str
    revision: Optional[str] = None
    filename: Optional[str] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=15, ge=1, le=60)


class ModelIntakeAutomaticReviewRequest(BaseModel):
    """Minimal-input technical review request.

    The automatic workflow may generate and bind technical evidence, but it is
    deliberately unable to create approvals, policy exceptions, or an
    admission. Those remain identity-bound operator actions.
    """

    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=4000)
    intended_environment: str = Field(
        default="production",
        pattern="^(development|test|staging|production)$",
    )
    revision: Optional[str] = Field(default=None, max_length=400)


class ModelIntakeAdmissionVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    admission_package: dict[str, Any]
    expected_artifact_sha256: str = Field(pattern="^[0-9a-fA-F]{64}$")
    expected_repository_snapshot_sha256: Optional[str] = Field(default=None, pattern="^[0-9a-fA-F]{64}$")
    require_registered_active_admission: Literal[True] = True


class ModelIntakeAdmissionRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=3, max_length=2000)


class ModelIntakeReassessmentEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trigger_type: str
    requested_action: str = Field(default="reassess", pattern="^(reassess|revoke)$")
    actor: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=3, max_length=2000)
    artifact_sha256: Optional[str] = Field(default=None, pattern="^[0-9a-fA-F]{64}$")
    statement_sha256: Optional[str] = Field(default=None, pattern="^[0-9a-fA-F]{64}$")
    all_active: bool = False
    confirm_all_active: bool = False
    approval_receipt_id: Optional[str] = None
    evidence_digest: Optional[str] = Field(default=None, pattern="^[0-9a-fA-F]{64}$")
    metadata_json: dict[str, Any] = Field(default_factory=dict)

    @field_validator("trigger_type")
    @classmethod
    def validate_trigger_type(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in REASSESSMENT_TRIGGERS:
            raise ValueError("unsupported Model Intake reassessment trigger")
        return normalized


class ModelIntakeRetentionCleanupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool = True
    retention_days: int = Field(default=30, ge=1, le=3650)
    max_total_bytes: Optional[int] = Field(default=None, ge=0, le=10_000_000_000_000)
    plan_sha256: Optional[str] = Field(default=None, pattern="^[0-9a-fA-F]{64}$")
    confirm_delete: bool = False
    actor: Optional[str] = Field(default=None, max_length=200)
    reason: Optional[str] = Field(default=None, max_length=2000)
    approval_receipt_id: Optional[str] = None


class ModelIntakeTrustAnchorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: Optional[str] = None
    public_key_pem: Optional[str] = None
    public_key_sha256: Optional[str] = None
    policy_profile: Optional[str] = "production"
    purpose: str = Field(
        default="publisher_signature",
        pattern="^(publisher_signature|upstream_attestation|runtime_runner|evaluation_runner|data_plane_runner|approval_signer|admission_signer)$",
    )
    environment: str = Field(default="production", pattern="^(development|test|staging|production)$")
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    issuer_constraint: Optional[str] = None
    subject_constraint: Optional[str] = None
    builder_id_constraint: Optional[str] = None
    source: str = Field(default="operator", min_length=1, max_length=120)
    version: str = Field(default="1", min_length=1, max_length=80)
    owner: Optional[str] = None
    is_active: bool = True


class ModelSubmissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=4000)
    source_kind: str = Field(default="auto", pattern="^(auto|huggingface|http|s3|gcs|azure|oci|mlflow)$")
    intended_environment: str = Field(pattern="^(development|test|staging|production)$")
    intended_use: dict[str, Any] = Field(default_factory=dict)
    expected_artifact_sha256: Optional[str] = Field(default=None, pattern="^[0-9a-fA-F]{64}$")
    publisher_signature: Optional[dict[str, Any]] = None
    upstream_attestation: Optional[dict[str, Any]] = None
    declared_metadata: dict[str, Any] = Field(default_factory=dict)


class ModelSubmissionStaticRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: str


class ModelRunnerEvidenceReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signature_envelope: dict[str, Any]


class ModelRunnerJobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: Literal["calibration", "runtime", "conversion"] = "runtime"
    deployment_bundle: dict[str, Any]
    known_answer_inputs: list[str] = Field(default_factory=list, max_length=94)
    known_answer_embedding_sha256: Optional[str] = Field(default=None, pattern="^[0-9a-fA-F]{64}$")
    vcpu_count: int = Field(default=2, ge=1, le=32)
    memory_mib: int = Field(default=4096, ge=256, le=262144)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    output_bytes: Optional[int] = Field(default=None, ge=64 * 1024**2, le=500 * 1024**3)


class ModelRunnerStorageCleanupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool = True
    force_inactive_scratch: bool = False


class ModelIntakeAgentSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objective: str = Field(min_length=3, max_length=2000)
    max_iterations: int = Field(default=10, ge=1, le=30)
    action_budget: int = Field(default=20, ge=1, le=100)


class ModelIntakeAgentReplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reply: str = Field(min_length=1, max_length=64000)


class ModelLoaderProfileResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_manifest: dict[str, Any]
    artifact_path: str = Field(min_length=1, max_length=2000)
    runtime_image_digest: str = Field(pattern="^sha256:[0-9a-fA-F]{64}$")
    reviewed_custom_code_sha256: Optional[str] = Field(default=None, pattern="^[0-9a-fA-F]{64}$")


class ModelEvidenceFreezeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment_bundle: dict[str, Any]


class ModelApprovalCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_manifest_id: str
    approval_type: str = Field(pattern="^(model_security_reviewer|ml_platform_reviewer|release_manager|legal_reviewer|privacy_reviewer|data_owner|risk_acceptance)$")
    decision: str = Field(pattern="^(approve|reject)$")
    reason: str = Field(min_length=3, max_length=2000)
    expires_days: int = Field(default=30, ge=1, le=365)
    restrictions: list[str] = Field(default_factory=list, max_length=50)


class ModelPolicyDecisionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_manifest_id: str


class ModelPromotionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_decision_id: str
    idempotency_key: str = Field(min_length=16, max_length=200)


class ModelAdmissionV2VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    admission_package: dict[str, Any]
    expected_bundle_sha256: str = Field(pattern="^[0-9a-fA-F]{64}$")
    expected_environment: str = Field(pattern="^(development|test|staging|production)$")
    expected_components: dict[str, str] = Field(default_factory=dict)
    require_registered_active_admission: Literal[True] = True




def _import_model_intake_helpers():
    try:
        from scanner_tools.model_intake import normalize_model_artifact_reference, parse_huggingface_ref
    except ModuleNotFoundError as exc:
        if exc.name != "scanner_tools":
            raise
        from scanner.scanner_tools.model_intake import normalize_model_artifact_reference, parse_huggingface_ref
    return normalize_model_artifact_reference, parse_huggingface_ref


def _is_hf_ref(ref: str) -> bool:
    parsed = urllib.parse.urlparse(ref)
    host = (parsed.hostname or "").lower().rstrip(".")
    return parsed.scheme == "hf" or host == "huggingface.co" or host.endswith(".huggingface.co")


def _detect_model_intake_platform(ref: str, metadata: dict[str, Any] | None = None) -> str:
    metadata = metadata or {}
    platform_hint = str(
        metadata.get("artifact_platform")
        or metadata.get("storage_provider")
        or metadata.get("registry_provider")
        or ""
    ).strip().lower().replace("-", "_")
    if platform_hint in {"huggingface", "http", "s3", "gcs", "azure", "azure_blob", "oci", "mlflow"}:
        return "azure" if platform_hint == "azure_blob" else platform_hint

    raw = str(ref or "").strip()
    lowered = raw.lower()
    parsed = urllib.parse.urlparse(raw)
    host = (parsed.hostname or "").lower().rstrip(".")

    if _is_hf_ref(raw) or _looks_like_hf_repo_id(raw):
        return "huggingface"
    if lowered.startswith("oci://"):
        return "oci"
    if lowered.startswith(("mlflow://", "models:/", "runs:/")):
        return "mlflow"
    if parsed.scheme == "s3" or _is_s3_hostname(host):
        return "s3"
    if parsed.scheme in {"gs", "gcs"} or host == "storage.googleapis.com" or host.endswith(".storage.googleapis.com"):
        return "gcs"
    if parsed.scheme == "azure" or _is_azure_blob_hostname(host):
        return "azure"
    return "http"


def _validate_model_intake_admission_request_authority(request: ModelIntakeScanRequest) -> None:
    if request.intake_mode != "admission":
        return
    forbidden = [
        field
        for field in sorted(MODEL_INTAKE_ADMISSION_FORBIDDEN_FIELDS)
        if _model_intake_value_is_nonempty(getattr(request, field, None))
    ]
    if request.require_deployment_approval is False:
        forbidden.append("require_deployment_approval")
    forbidden.extend(_model_intake_forbidden_metadata_paths(request.metadata_json))
    if forbidden:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "model_intake_admission_requester_authority_forbidden",
                "message": (
                    "Admission trust, policy exceptions, and approval state are server-owned. "
                    "Submit publisher leaf evidence only, or use preflight for untrusted declarations."
                ),
                "fields": sorted(set(forbidden)),
            },
        )


def _validate_model_intake_trust_anchor_request(req: ModelIntakeTrustAnchorRequest) -> None:
    if not req.name.strip():
        raise HTTPException(status_code=422, detail="name is required")
    if not (str(req.public_key_pem or "").strip() or str(req.public_key_sha256 or "").strip()):
        raise HTTPException(status_code=422, detail="public_key_pem or public_key_sha256 is required")
    sha = str(req.public_key_sha256 or "").strip()
    if sha and not re.fullmatch(r"[a-fA-F0-9]{64}", sha):
        raise HTTPException(status_code=422, detail="public_key_sha256 must be a 64-character SHA-256 hex digest")
    if req.valid_until and req.valid_from and req.valid_until <= req.valid_from:
        raise HTTPException(status_code=422, detail="valid_until must be later than valid_from")


async def _expand_model_intake_policy_profile_requirements(request: ModelIntakeScanRequest) -> ModelIntakeScanRequest:
    requested_profile = str(request.policy_profile or "").strip().lower() or None
    metadata = dict(request.metadata_json or {})
    metadata["intake_mode"] = request.intake_mode
    if requested_profile:
        metadata["requested_policy_profile"] = requested_profile

    if request.intake_mode == "preflight":
        request = _sanitize_model_intake_preflight_authority(request)
        metadata = dict(request.metadata_json or {})
        metadata["admission_eligible"] = False
        metadata["policy_requirements_enforced"] = False
        return request.model_copy(update={
            "metadata_json": metadata,
            "require_signed_admission": False,
        })

    profile_key = (
        os.environ.get("MODEL_INTAKE_ADMISSION_POLICY_PROFILE", "production").strip().lower()
        or "production"
    )
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT * FROM policy_profiles
            WHERE is_active = true
              AND product_area = 'model_intake'
              AND (active_from IS NULL OR active_from <= NOW())
              AND (active_until IS NULL OR active_until > NOW())
              AND (lower(environment) = $1 OR lower(name) = $1)
            ORDER BY updated_at DESC NULLS LAST, created_at DESC
            LIMIT 1
            """,
            profile_key,
        )
    profile = row_to_dict(row) if row else None
    if profile is None and profile_key in POLICY_PROFILES:
        profile = {
            **POLICY_PROFILES[profile_key],
            "environment": profile_key,
            "product_area": "model_intake",
            "required_trust_anchor_ids": [],
        }
    if not profile or not bool(profile.get("strict_model_intake")):
        raise HTTPException(
            status_code=503,
            detail=(
                f"Model Intake admission policy '{profile_key}' is missing, inactive, or not strict; "
                "configure an active strict_model_intake profile"
            ),
        )
    provider_governance_paths = _model_intake_forbidden_metadata_paths(metadata)
    metadata = _strip_model_intake_governance_metadata(metadata)
    if provider_governance_paths:
        metadata["ignored_provider_governance_fields"] = provider_governance_paths
    metadata["admission_eligible"] = True
    metadata["server_policy_profile"] = profile_key
    governed = request.model_copy(update={
        "policy_profile": profile_key,
        "policy_exceptions": None,
        "signature_trusted_keys": None,
        "signature_trusted_key_sha256": None,
        "attestation_trusted_keys": None,
        "attestation_trusted_key_sha256": None,
        "allowed_attestation_predicate_types": None,
        "required_attestation_builder_ids": None,
        "trust_anchor_ids": None,
        "deployment_approved": False,
        "require_deployment_approval": True,
        "metadata_json": metadata,
    })
    return _apply_model_intake_policy_profile_requirements(governed, profile)


async def _expand_model_intake_saved_trust_anchors(request: ModelIntakeScanRequest) -> ModelIntakeScanRequest:
    anchor_ids = [uuid.UUID(item) for item in _str_list(request.trust_anchor_ids)]
    async with _pool().acquire() as conn:
        environment = str(request.policy_profile or "production").lower()
        if request.intake_mode == "preflight":
            # Public preflight cannot select trust roots. The server supplies
            # every currently active, environment/profile-scoped publisher or
            # attestation anchor after requester trust material was stripped.
            rows = await conn.fetch(
                """
                SELECT * FROM model_intake_trust_anchors
                WHERE is_active = true
                  AND revoked_at IS NULL
                  AND valid_from <= NOW()
                  AND (valid_until IS NULL OR valid_until > NOW())
                  AND environment = $1
                  AND (policy_profile IS NULL OR lower(policy_profile) = $1)
                  AND purpose IN ('publisher_signature','upstream_attestation')
                ORDER BY purpose,name,id
                """,
                environment,
            )
        else:
            if not anchor_ids:
                return request
            rows = await conn.fetch(
                """
                SELECT * FROM model_intake_trust_anchors
                WHERE id = ANY($1::uuid[])
                  AND is_active = true
                  AND revoked_at IS NULL
                  AND valid_from <= NOW()
                  AND (valid_until IS NULL OR valid_until > NOW())
                  AND environment = $2
                  AND purpose IN ('publisher_signature','upstream_attestation')
                """,
                anchor_ids,
                environment,
            )
            if len(rows) != len(set(anchor_ids)):
                raise HTTPException(status_code=400, detail="One or more selected Model Intake trust anchors were not found or are inactive")
    if not rows:
        return request
    return _merge_model_intake_trust_anchor_material(request, [row_to_dict(row) for row in rows])


def _model_intake_policy_bundle_sha256() -> str:
    try:
        return str(
            _model_policy_bundle_identity(
                os.getenv("MODEL_INTAKE_POLICY_BUNDLE_SHA256", "")
            )["bundle_sha256"]
        )
    except _ModelAdmissionContractError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _model_intake_uuid(value: str, label: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid {label}") from exc


def _model_intake_required_static_checks(
    summary: dict[str, Any],
    model_intake: dict[str, Any] | None = None,
) -> dict[str, bool]:
    """Checks that a persisted scan must prove before becoming admission evidence."""
    return {
        "acquisition_complete": summary.get("acquisition_complete") is True,
        "inspection_complete": _model_intake_effective_inspection_complete(
            model_intake or {}, summary,
        ),
        "repository_manifest_complete": summary.get("repository_manifest_complete") is True,
        "repository_snapshot_complete": summary.get("repository_snapshot_complete") is True,
        "generated_evidence_pass": summary.get("generated_evidence_status") == "PASS",
        "checksum_verified": summary.get("checksum_status") == "verified",
    }


def _model_intake_static_evidence_status(
    model_intake: dict[str, Any],
    summary: dict[str, Any],
    findings: list[Any],
    required_static_checks: dict[str, bool],
) -> str:
    severity = {str(item.get("severity") or "").lower() for item in findings if isinstance(item, dict)}
    supply_chain = model_intake.get("supply_chain") if isinstance(model_intake.get("supply_chain"), dict) else {}
    license_compliance = (
        supply_chain.get("license_compliance")
        if isinstance(supply_chain.get("license_compliance"), dict)
        else {}
    )
    license_status = str(license_compliance.get("policy_status") or "")
    if license_status == "BLOCK":
        return "FAIL"
    if severity.intersection({"critical", "high"}):
        return "FAIL"
    if all(required_static_checks.values()):
        return "WARNING" if license_status == "REVIEW_REQUIRED" else "PASS"
    generated = model_intake.get("generated_evidence") if isinstance(model_intake.get("generated_evidence"), dict) else {}
    required_warning_names = set(generated.get("required_non_pass") or [])
    warning_results = [
        item for item in generated.get("results") or []
        if isinstance(item, dict) and item.get("scanner", {}).get("name") in required_warning_names
    ]
    warning_review = (
        summary.get("generated_evidence_status") == "REVIEW_REQUIRED"
        and bool(required_warning_names)
        and len(warning_results) == len(required_warning_names)
        and all(item.get("execution", {}).get("status") == "WARNING" for item in warning_results)
    )
    other_checks_pass = all(
        passed for name, passed in required_static_checks.items() if name != "generated_evidence_pass"
    )
    return "WARNING" if warning_review and other_checks_pass else "INCOMPLETE"


def _model_intake_finding_summary(value: Any) -> list[dict[str, Any]]:
    """Keep bounded finding identity without copying matched source or secrets."""
    if not isinstance(value, list):
        return []
    summaries: list[dict[str, Any]] = []
    for item in value[:100]:
        if not isinstance(item, dict):
            continue
        summary: dict[str, Any] = {}
        for key in (
            "id", "rule_id", "severity", "classification", "call", "package",
            "installed_version", "severity_source", "import_name", "evidence_class",
            "operator", "license", "tool_severity", "evidence_scope",
        ):
            text = str(item.get(key) or "").strip()
            if text:
                summary[key] = text[:240]
        path = str(item.get("path") or "").strip().replace("\\", "/")
        if path and not path.startswith("/") and ".." not in path.split("/"):
            summary["path"] = path[:500]
        line = item.get("line")
        if isinstance(line, int) and not isinstance(line, bool) and line > 0:
            summary["line"] = line
        message = str(item.get("message") or "").strip()
        if message:
            summary["message"] = re.sub(r"\s+", " ", message)[:500]
        if summary:
            summaries.append(summary)
    return summaries


def _model_intake_repository_manifest_summary(snapshot: Any) -> dict[str, Any]:
    """Persist a bounded, content-free inventory of the exact reviewed files."""
    snapshot = _model_intake_json_object(snapshot)
    raw_files = snapshot.get("files") if isinstance(snapshot.get("files"), list) else []
    files: list[dict[str, Any]] = []
    seen: set[str] = set()
    invalid_entries = 0
    for item in raw_files:
        if not isinstance(item, dict):
            invalid_entries += 1
            continue
        path = _model_intake_safe_relative_path(item.get("path"))
        digest = str(item.get("sha256") or "").lower()
        size = item.get("size_bytes")
        if (
            not path or path in seen or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(size, int) or isinstance(size, bool) or size < 0
        ):
            invalid_entries += 1
            continue
        seen.add(path)
        if len(files) < 2_000:
            files.append({"path": path, "sha256": digest, "size_bytes": size})
    return {
        "complete": snapshot.get("complete") is True,
        "repository": str(snapshot.get("repository") or "")[:300] or None,
        "revision": str(snapshot.get("revision") or "")[:200] or None,
        "snapshot_sha256": snapshot.get("snapshot_sha256"),
        "manifest_sha256": _model_intake_json_object(snapshot.get("repository_manifest")).get("manifest_sha256"),
        "total_files": len(raw_files),
        "reported_files": len(files),
        "truncated": len(files) < len(raw_files) - invalid_entries,
        "invalid_entries": invalid_entries,
        "files": files,
    }


def _model_intake_scanner_result_summaries(generated_evidence: Any) -> list[dict[str, Any]]:
    """Normalize generated scanner output for both source and conversion scans."""
    generated = _model_intake_json_object(generated_evidence)
    summaries: list[dict[str, Any]] = []
    for item in generated.get("results") or []:
        if not isinstance(item, dict):
            continue
        scanner = item.get("scanner") if isinstance(item.get("scanner"), dict) else {}
        execution = item.get("execution") if isinstance(item.get("execution"), dict) else {}
        summary = item.get("summary") if isinstance(item.get("summary"), dict) else {}
        subject = item.get("subject") if isinstance(item.get("subject"), dict) else {}
        findings = item.get("findings") if isinstance(item.get("findings"), list) else []
        summary_count = summary.get("finding_count")
        finding_count = (
            summary_count
            if isinstance(summary_count, int) and not isinstance(summary_count, bool) and summary_count >= 0
            else len(findings)
        )
        finding_summaries = _model_intake_finding_summary(findings)
        normalized = {
            "name": str(scanner.get("name") or "unknown"),
            "version": scanner.get("version"),
            "status": execution.get("status"),
            "required": bool(execution.get("required")),
            "applicability": execution.get("applicability"),
            "finding_count": finding_count,
            "findings_reported_count": len(finding_summaries),
            "findings_truncated": finding_count > len(finding_summaries),
            "coverage": _model_intake_content_free_coverage(item.get("coverage")),
            "findings": finding_summaries,
            "rules_sha256": (
                scanner.get("rules_sha256")
                or execution.get("rules_sha256")
            ),
            "database_sha256": (
                scanner.get("database_sha256")
                or execution.get("database_sha256")
            ),
        }
        subject_digest = str(subject.get("sha256") or "").lower()
        subject_filename = _model_intake_safe_relative_path(subject.get("filename"))
        subject_summary = {
            "kind": str(subject.get("kind") or "")[:80] or None,
            "filename": subject_filename,
            "sha256": subject_digest if re.fullmatch(r"[0-9a-f]{64}", subject_digest) else None,
            "complete": subject.get("complete") if isinstance(subject.get("complete"), bool) else None,
        }
        if any(value is not None for value in subject_summary.values()):
            normalized["subject"] = subject_summary
        for key in (
            "target_scope", "adapter_kind", "duration_ms", "timeout_seconds", "exit_code",
            "reason", "license_scan_mode", "raw_result_digest",
        ):
            if execution.get(key) is not None:
                normalized[key] = execution.get(key)
        if execution.get("error"):
            normalized["error"] = str(execution["error"])[:500]
        elif summary.get("error"):
            # Parser-contract errors are generated by ShakerScan, not model
            # content. Preserve the bounded reason so INCOMPLETE is actionable.
            normalized["error"] = re.sub(
                r"[^A-Za-z0-9_:. ,+\-]", "?", str(summary["error"])
            )[:500]
        execution_contract = [
            str(value)[:500] for value in execution.get("argv_contract") or []
        ][:30]
        if execution_contract:
            normalized["execution_contract"] = execution_contract
        content_free_summary = _model_intake_content_free_coverage(summary)
        scanned_files = _model_intake_safe_file_list(summary.get("scanned_files"))
        skipped_files = _model_intake_safe_file_list(summary.get("skipped_files"))
        if scanned_files:
            content_free_summary["scanned_files"] = scanned_files
        if skipped_files:
            content_free_summary["skipped_files"] = skipped_files
        if content_free_summary:
            normalized["summary"] = content_free_summary
        summaries.append(normalized)
    return summaries


def _model_intake_snapshot_custom_code_sha256(model_intake: dict[str, Any]) -> str | None:
    """Derive the reviewed-code identity only from a complete authoritative snapshot."""
    snapshot = model_intake.get("repository_snapshot") if isinstance(model_intake.get("repository_snapshot"), dict) else {}
    if snapshot.get("complete") is not True:
        return None
    files = snapshot.get("files") if isinstance(snapshot.get("files"), list) else []
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            raise HTTPException(status_code=409, detail="Repository snapshot entry is invalid")
        path = Path(str(item.get("path") or ""))
        digest = str(item.get("sha256") or "").lower()
        normalized = path.as_posix()
        if path.is_absolute() or not path.parts or ".." in path.parts or normalized in seen:
            raise HTTPException(status_code=409, detail="Repository snapshot custom-code path is unsafe")
        seen.add(normalized)
        if path.suffix.lower() != ".py":
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise HTTPException(status_code=409, detail="Repository snapshot custom-code digest is invalid")
        entries.append({"path": normalized, "sha256": digest})
    if not entries:
        return None
    return hashlib.sha256(
        json.dumps(sorted(entries, key=lambda entry: entry["path"]), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


async def _transition_model_intake_submission(
    conn: Any,
    submission_id: uuid.UUID,
    *,
    new_state: str,
    event_type: str,
    actor: str,
    reason: str,
    metadata: dict[str, Any] | None = None,
) -> str:
    row = await conn.fetchrow(
        "SELECT state FROM model_intake_submissions WHERE id=$1 FOR UPDATE",
        submission_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Model submission not found")
    previous_state = str(row["state"])
    if not _model_intake_transition_is_allowed(previous_state, new_state):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "model_intake_state_transition_invalid",
                "previous_state": previous_state,
                "requested_state": new_state,
            },
        )
    await conn.execute(
        "UPDATE model_intake_submissions SET state=$2,updated_at=NOW() WHERE id=$1",
        submission_id,
        new_state,
    )
    await conn.execute(
        """
        INSERT INTO model_intake_submission_events
            (submission_id,event_type,actor,reason,previous_state,new_state,metadata_json)
        VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)
        """,
        submission_id,
        event_type,
        actor,
        reason,
        previous_state,
        new_state,
        json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"), default=str),
    )
    return previous_state


async def _reset_model_intake_for_new_evidence(
    conn: Any,
    submission_id: uuid.UUID,
    *,
    actor: str,
    evidence_type: str,
    evidence_id: str,
) -> dict[str, int]:
    invalidated = await conn.fetch(
        """
        UPDATE model_intake_admissions
        SET status='reassessment_required',updated_at=NOW()
        WHERE submission_id=$1 AND status='active'
        RETURNING id,statement_sha256
        """,
        submission_id,
    )
    for admission in invalidated:
        await conn.execute(
            """
            INSERT INTO model_intake_admission_events
                (admission_id,event_type,actor,reason,previous_status,new_status,evidence_digest,metadata_json)
            VALUES ($1,'authoritative_evidence_changed',$2,$3,'active','reassessment_required',$4,$5::jsonb)
            """,
            admission["id"],
            actor,
            f"New {evidence_type} evidence requires a fresh frozen manifest and decision",
            admission["statement_sha256"],
            json.dumps({"evidence_type": evidence_type, "evidence_id": evidence_id}),
        )
    binding_result = await conn.execute(
        """
        UPDATE model_intake_deployment_bindings
        SET verifier_status='STALE',observed_bundle_sha256=NULL,observed_at=NULL
        WHERE submission_id=$1 AND verifier_status <> 'STALE'
        """,
        submission_id,
    )
    try:
        stale_bindings = int(str(binding_result).rsplit(" ", 1)[-1])
    except ValueError:
        stale_bindings = 0
    await _transition_model_intake_submission(
        conn,
        submission_id,
        new_state="evidence_ready",
        event_type="authoritative_evidence_attached",
        actor=actor,
        reason=f"Attached {evidence_type} evidence and invalidated downstream deployment authority",
        metadata={
            "evidence_type": evidence_type,
            "evidence_id": evidence_id,
            "admissions_invalidated": len(invalidated),
            "deployment_bindings_staled": stale_bindings,
        },
    )
    return {
        "admissions_invalidated": len(invalidated),
        "deployment_bindings_staled": stale_bindings,
    }


def _model_intake_untrusted_runner_claims(envelope: dict[str, Any]) -> dict[str, Any]:
    try:
        payload = base64.b64decode(str(envelope.get("payload") or ""), validate=True)
        value = json.loads(payload)
    except (ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


async def _persist_model_intake_runner_evidence(
    conn: Any,
    submission_uuid: uuid.UUID,
    signature_envelope: dict[str, Any],
    *,
    actor: str,
) -> dict[str, Any]:
    """Verify and persist one runner receipt inside the caller's transaction."""
    untrusted = _model_intake_untrusted_runner_claims(signature_envelope)
    evidence_type = str(untrusted.get("evidence_type") or "")
    policy = _MODEL_RUNNER_EVIDENCE_POLICY.get(evidence_type)
    if not policy:
        raise HTTPException(status_code=422, detail="Unsupported runner evidence type")
    _provenance, purpose = policy
    submission = await conn.fetchrow(
        "SELECT id,requested_environment FROM model_intake_submissions WHERE id=$1 FOR UPDATE",
        submission_uuid,
    )
    if not submission:
        raise HTTPException(status_code=404, detail="Model submission not found")
    anchors = await conn.fetch(
        """
        SELECT public_key_pem,builder_id_constraint FROM model_intake_trust_anchors
        WHERE is_active=true AND revoked_at IS NULL AND purpose=$1 AND environment=$2
          AND valid_from<=NOW() AND (valid_until IS NULL OR valid_until>NOW())
        """,
        purpose,
        submission["requested_environment"],
    )
    verified = _verify_model_runner_envelope(
        signature_envelope,
        expected_submission_id=str(submission_uuid),
        expected_environment=submission["requested_environment"],
        trusted_public_keys=[str(item["public_key_pem"] or "") for item in anchors if item["public_key_pem"]],
        trusted_builder_ids={str(item["builder_id_constraint"] or "") for item in anchors if item["builder_id_constraint"]},
    )
    if not verified["verified"]:
        raise HTTPException(status_code=409, detail=verified)
    payload = verified["payload"]
    bindings = {
        key: payload[key]
        for key in (
            "deployment_bundle_sha256", "model_artifact_sha256",
            "repository_snapshot_sha256", "custom_code_sha256", "tokenizer_sha256", "configuration_sha256", "runtime_image_digest",
            "retrieval_application_digest", "index_schema_digest",
            "loader_profile_sha256",
            "source_deployment_bundle_sha256", "source_model_artifact_sha256",
            "source_repository_snapshot_sha256",
        )
        if key in payload
    }
    inserted = await conn.fetchrow(
        """
        INSERT INTO model_intake_evidence_records
            (submission_id,evidence_type,schema_version,provenance_class,producer_id,
             producer_version,builder_id,invocation_id,subject_bindings,payload_sha256,
             signature_envelope,status,started_at,finished_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11::jsonb,$12,$13,$14,$15)
        ON CONFLICT (producer_id,invocation_id) DO NOTHING
        RETURNING *
        """,
        submission_uuid,
        evidence_type,
        payload["schema_version"],
        verified["provenance_class"],
        payload["builder_id"],
        str(payload.get("runner_version") or "unknown"),
        payload["builder_id"],
        payload["invocation_id"],
        json.dumps(bindings),
        verified["payload_sha256"],
        json.dumps(signature_envelope),
        payload["status"],
        datetime.fromisoformat(payload["started_at"].replace("Z", "+00:00")),
        datetime.fromisoformat(payload["finished_at"].replace("Z", "+00:00")),
        datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00")),
    )
    duplicate = inserted is None
    if duplicate:
        inserted = await conn.fetchrow(
            "SELECT * FROM model_intake_evidence_records WHERE producer_id=$1 AND invocation_id=$2",
            payload["builder_id"],
            payload["invocation_id"],
        )
        if not inserted or inserted["payload_sha256"] != verified["payload_sha256"]:
            raise HTTPException(status_code=409, detail="Runner invocation replay changed payload")
    derived_evaluation = None
    if evidence_type == "runtime_execution":
        evaluation_report = _derive_model_runner_embedding_evaluation(payload, verified["payload_sha256"])
        evaluation_producer = f"{payload['builder_id']}#embedding-evaluator-v1"
        evaluation_invocation = f"{payload['invocation_id']}:embedding-evaluation"
        derived_evaluation = await conn.fetchrow(
            """
            INSERT INTO model_intake_evidence_records
                (submission_id,evidence_type,schema_version,provenance_class,producer_id,
                 producer_version,builder_id,invocation_id,subject_bindings,input_manifest_sha256,
                 payload_sha256,payload_json,status,started_at,finished_at,expires_at)
            VALUES ($1,'embedding_evaluation',$2,'GENERATED_EVALUATION',$3,'1',$4,$5,
                    $6::jsonb,$7,$8,$9::jsonb,$10,$11,$12,$13)
            ON CONFLICT (producer_id,invocation_id) DO NOTHING
            RETURNING *
            """,
            submission_uuid,
            evaluation_report["schema_version"],
            evaluation_producer,
            payload["builder_id"],
            evaluation_invocation,
            json.dumps(bindings),
            verified["payload_sha256"],
            evaluation_report["evidence_sha256"],
            json.dumps(evaluation_report),
            evaluation_report["status"],
            datetime.fromisoformat(payload["started_at"].replace("Z", "+00:00")),
            datetime.fromisoformat(payload["finished_at"].replace("Z", "+00:00")),
            datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00")),
        )
        if derived_evaluation is None:
            derived_evaluation = await conn.fetchrow(
                "SELECT * FROM model_intake_evidence_records WHERE producer_id=$1 AND invocation_id=$2",
                evaluation_producer,
                evaluation_invocation,
            )
            if not derived_evaluation or derived_evaluation["payload_sha256"] != evaluation_report["evidence_sha256"]:
                raise HTTPException(status_code=409, detail="Derived evaluation invocation replay changed payload")
    invalidation = (
        {"admissions_invalidated": 0, "deployment_bindings_staled": 0}
        if duplicate
        else await _reset_model_intake_for_new_evidence(
            conn,
            submission_uuid,
            actor=actor,
            evidence_type=evidence_type,
            evidence_id=str(inserted["id"]),
        )
    )
    return {
        "evidence": row_to_dict(inserted),
        "derived_embedding_evaluation": row_to_dict(derived_evaluation) if derived_evaluation else None,
        "verified": True,
        "verified_by": actor,
        "downstream_invalidation": invalidation,
        "deployable": False,
    }


def _model_intake_conversion_output_usable(receipt_payload: dict[str, Any]) -> bool:
    """Return whether a verified receipt produced an equivalent target.

    Overall receipt status also covers attempted network operations and signer
    trust.  Those controls must remain visible and can block admission, but
    they must not discard a content-addressed conversion whose tensor and
    embedding equivalence checks passed.  Registering that output only makes
    it available for strict rescanning and runtime evidence; it never approves
    or promotes it.
    """
    observations = (
        receipt_payload.get("observations")
        if isinstance(receipt_payload.get("observations"), dict) else {}
    )
    phases = observations.get("phases") if isinstance(observations.get("phases"), dict) else {}
    required_phases = {
        "import", "deserialize_convert", "tensor_equivalence",
        "embedding_equivalence", "teardown",
    }
    return bool(
        receipt_payload.get("evidence_type") == "conversion_equivalence"
        and all(observations.get(field) for field in (
            "target_artifact_sha256",
            "target_repository_snapshot_sha256",
            "target_tokenizer_sha256",
            "target_configuration_sha256",
        ))
        and observations.get("tensor_inventory_equivalent") is True
        and observations.get("numeric_equivalence_status") == "PASS"
        and observations.get("embedding_equivalence_status") == "PASS"
        and all(phases.get(phase) == "PASS" for phase in required_phases)
    )


async def _register_and_rescan_converted_snapshot(
    submission_uuid: uuid.UUID,
    receipt_payload: dict[str, Any],
    *,
    actor: str,
) -> dict[str, Any]:
    """Register and strictly rescan a verified Firecracker conversion output."""
    observations = receipt_payload.get("observations") if isinstance(receipt_payload.get("observations"), dict) else {}
    if not _model_intake_conversion_output_usable(receipt_payload):
        return {"status": "NOT_APPLICABLE", "reason": "conversion_equivalence_not_proven"}
    artifact_sha = str(receipt_payload.get("model_artifact_sha256") or "")
    snapshot_sha = str(receipt_payload.get("repository_snapshot_sha256") or "")
    materialized = await asyncio.to_thread(
        _model_intake_converted_snapshot_materialization,
        artifact_sha256=artifact_sha,
        repository_snapshot_sha256=snapshot_sha,
    )
    expected_identities = {
        "target_artifact_sha256": artifact_sha,
        "target_repository_snapshot_sha256": snapshot_sha,
        "target_custom_code_sha256": materialized["custom_code_sha256"],
        "target_tokenizer_sha256": materialized["tokenizer_sha256"],
        "target_configuration_sha256": materialized["configuration_sha256"],
    }
    mismatches = [key for key, value in expected_identities.items() if observations.get(key) != value]
    if mismatches:
        raise HTTPException(status_code=409, detail={
            "error": "converted_snapshot_identity_mismatch",
            "fields": sorted(mismatches),
        })
    generated = await asyncio.to_thread(
        _scan_materialized_model_snapshot,
        Path(materialized["container_subject_path"]),
        artifact_relative_path=materialized["artifact_path"],
        snapshot_sha256=snapshot_sha,
        profile="strict",
    )
    generated_status = str(generated.get("status") or "INCOMPLETE")
    generated_severity = {
        str(finding.get("severity") or "").lower()
        for scanner_result in generated.get("results") or [] if isinstance(scanner_result, dict)
        for finding in scanner_result.get("findings") or [] if isinstance(finding, dict)
    }
    static_status = "FAIL" if generated_severity.intersection({"critical", "high"}) else {
        "PASS": "PASS",
        "REVIEW_REQUIRED": "WARNING",
        "FAIL": "FAIL",
    }.get(generated_status, "INCOMPLETE")
    runtime_resolution = _resolve_model_loader_profile(
        materialized["profile_manifest"],
        artifact_path=materialized["artifact_path"],
        runtime_image_digest=str(receipt_payload["runtime_image_digest"]),
        reviewed_custom_code_sha256=materialized["custom_code_sha256"],
    )
    if runtime_resolution.get("status") != "READY" or not isinstance(runtime_resolution.get("profile"), dict):
        static_status = "INCOMPLETE"
    report_base = {
        "schema_version": "model-intake-conversion-static-rescan/v1",
        "source_conversion_receipt_sha256": hashlib.sha256(
            json.dumps(receipt_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "model_artifact_sha256": artifact_sha,
        "repository_snapshot_sha256": snapshot_sha,
        "custom_code_sha256": materialized["custom_code_sha256"],
        "tokenizer_sha256": materialized["tokenizer_sha256"],
        "configuration_sha256": materialized["configuration_sha256"],
        "generated_evidence": generated,
        "status": static_status,
    }
    invocation = f"{receipt_payload['invocation_id']}:converted-static-rescan"
    bindings = {
        "model_artifact_sha256": artifact_sha,
        "repository_snapshot_sha256": snapshot_sha,
        "custom_code_sha256": materialized["custom_code_sha256"],
        "tokenizer_sha256": materialized["tokenizer_sha256"],
        "configuration_sha256": materialized["configuration_sha256"],
    }
    async with _pool().acquire() as conn, conn.transaction():
        verified_conversion = await conn.fetchrow(
            """
            SELECT id FROM model_intake_evidence_records
            WHERE submission_id=$1 AND evidence_type='conversion_equivalence'
              AND invocation_id=$2
            """,
            submission_uuid,
            receipt_payload["invocation_id"],
        )
        if not verified_conversion:
            raise HTTPException(status_code=409, detail="Verified conversion evidence is unavailable")
        source_static = await conn.fetchrow(
            """
            SELECT id,payload_json FROM model_intake_evidence_records
            WHERE submission_id=$1 AND evidence_type='static_analysis'
              AND COALESCE(payload_json #>> '{subject_identity,converted}','false') <> 'true'
            ORDER BY created_at DESC LIMIT 1
            """,
            submission_uuid,
        )
        source_payload = _model_intake_json_object(
            source_static["payload_json"] if source_static else {}
        )
        report = {
            **report_base,
            # The converted target is rescanned as a complete exact snapshot.
            # Keep the same normalized report surface as the source scan so a
            # latest-record query cannot erase scanner findings, licenses, or
            # rule/database identities after conversion.
            "required_static_checks": {
                "acquisition_complete": True,
                "inspection_complete": static_status in {"PASS", "WARNING"},
                "repository_manifest_complete": True,
                "repository_snapshot_complete": True,
                "generated_evidence_pass": generated_status == "PASS",
                "checksum_verified": True,
            },
            "checks": generated.get("statuses") or {},
            "subject_identity": {
                "artifact_sha256": artifact_sha,
                "repository_snapshot_sha256": snapshot_sha,
                "repository_manifest_sha256": snapshot_sha,
                "repository": materialized.get("profile_manifest", {}).get("repository"),
                "revision": materialized.get("profile_manifest", {}).get("revision"),
                "artifact_name": materialized.get("artifact_path"),
                "converted": True,
            },
            "repository_file_manifest": _model_intake_repository_manifest_summary({
                **_model_intake_json_object(materialized.get("profile_manifest")),
                "complete": True,
                "snapshot_sha256": snapshot_sha,
            }),
            "scan_findings": _model_intake_finding_summary(
                [
                    finding
                    for scanner in generated.get("results") or []
                    if isinstance(scanner, dict)
                    for finding in scanner.get("findings") or []
                    if isinstance(finding, dict)
                ]
            ),
            "scanner_results": _model_intake_scanner_result_summaries(generated),
            "runtime_dependencies": _model_intake_json_object(
                generated.get("runtime_dependencies")
            ),
            "vulnerability_summary": _model_intake_json_object(
                generated.get("vulnerability_summary")
            ),
            "vulnerability_inventory": [
                item for item in generated.get("vulnerability_inventory") or []
                if isinstance(item, dict)
            ][:1000],
            # Conversion changes the weight serialization, not the repository
            # terms. Preserve the source policy result while the converted
            # snapshot's native license scanner still contributes findings.
            "license_compliance": _model_intake_json_object(
                source_payload.get("license_compliance")
            ),
            "source_static_evidence_id": str(source_static["id"]) if source_static else None,
        }
        report_sha = hashlib.sha256(
            json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        for subject_kind, digest, size, manifest_sha, metadata in (
            ("artifact", artifact_sha, materialized["artifact_size_bytes"], snapshot_sha, {"converted": True}),
            ("repository_snapshot", snapshot_sha, materialized["repository_size_bytes"], snapshot_sha, {"converted": True}),
            ("custom_code", materialized["custom_code_sha256"], None, snapshot_sha, {"converted": True}),
            ("tokenizer", materialized["tokenizer_sha256"], None, snapshot_sha, {"converted": True}),
            ("configuration", materialized["configuration_sha256"], None, snapshot_sha, {"converted": True}),
        ):
            if not digest:
                continue
            await conn.execute(
                """
                INSERT INTO model_intake_subjects
                    (submission_id,subject_kind,immutable_uri,sha256,size_bytes,manifest_sha256,source_revision,metadata_json)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
                ON CONFLICT (submission_id,subject_kind,sha256) DO NOTHING
                """,
                submission_uuid,
                subject_kind,
                f"conversion://sha256/{snapshot_sha}/{subject_kind}",
                digest,
                size,
                manifest_sha,
                snapshot_sha,
                json.dumps({
                    **metadata,
                    "registered_by": actor,
                    "conversion_evidence_id": str(verified_conversion["id"]),
                    "source_model_artifact_sha256": receipt_payload.get("source_model_artifact_sha256"),
                    "source_repository_snapshot_sha256": receipt_payload.get("source_repository_snapshot_sha256"),
                }),
            )
        evidence = await conn.fetchrow(
            """
            INSERT INTO model_intake_evidence_records
                (submission_id,evidence_type,schema_version,provenance_class,producer_id,
                 producer_version,builder_id,invocation_id,subject_bindings,input_manifest_sha256,
                 payload_sha256,payload_json,status,started_at,finished_at,expires_at)
            VALUES ($1,'static_analysis',$2,'GENERATED_STATIC','shakerscan-conversion-static-rescan',
                    $3,$4,$5,$6::jsonb,$7,$8,$9::jsonb,$10,NOW(),NOW(),NOW()+INTERVAL '30 days')
            ON CONFLICT (producer_id,invocation_id) DO NOTHING RETURNING *
            """,
            submission_uuid,
            report["schema_version"],
            os.getenv("SCANNER_VERSION", "unknown"),
            os.getenv("GIT_COMMIT", "shakerscan-api"),
            invocation,
            json.dumps(bindings),
            report["source_conversion_receipt_sha256"],
            report_sha,
            json.dumps(report),
            static_status,
        )
        duplicate = evidence is None
        if duplicate:
            evidence = await conn.fetchrow(
                "SELECT * FROM model_intake_evidence_records WHERE producer_id=$1 AND invocation_id=$2",
                "shakerscan-conversion-static-rescan",
                invocation,
            )
            if not evidence or evidence["payload_sha256"] != report_sha:
                raise HTTPException(status_code=409, detail="Converted static rescan replay changed payload")
        invalidation = (
            {"admissions_invalidated": 0, "deployment_bindings_staled": 0}
            if duplicate
            else await _reset_model_intake_for_new_evidence(
                conn,
                submission_uuid,
                actor=actor,
                evidence_type="static_analysis",
                evidence_id=str(evidence["id"]),
            )
        )
    return {
        "status": static_status,
        "evidence": row_to_dict(evidence),
        "generated_evidence": generated,
        "next_runtime_subjects": {
            "model_artifact_sha256": artifact_sha,
            "repository_snapshot_sha256": snapshot_sha,
            "custom_code_sha256": materialized["custom_code_sha256"],
            "tokenizer_sha256": materialized["tokenizer_sha256"],
            "configuration_sha256": materialized["configuration_sha256"],
            "runtime_image_digest": receipt_payload["runtime_image_digest"],
            "loader_profile_sha256": (
                runtime_resolution["profile"]["profile_sha256"]
                if runtime_resolution.get("status") == "READY" else None
            ),
        },
        "runtime_loader_profile": runtime_resolution,
        "downstream_invalidation": invalidation,
    }


def _model_intake_runner_http(method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    base = os.getenv("MODEL_INTAKE_RUNNER_URL", "").strip().rstrip("/")
    token = os.getenv("MODEL_INTAKE_RUNNER_INTERNAL_TOKEN", "")
    if not base or len(token) < 32:
        raise RuntimeError("model_intake_runner_service_not_configured")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() if payload is not None else None
    request = urllib.request.Request(
        f"{base}{path}",
        data=encoded,
        method=method,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Shakerscan-Runner-Token": token,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(4_000_001)
    except urllib.error.HTTPError as exc:
        detail = exc.read(32_000).decode("utf-8", "replace")
        raise RuntimeError(f"runner_service_rejected:{exc.code}:{detail}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"runner_service_unavailable:{type(exc).__name__}") from exc
    if len(raw) > 4_000_000:
        raise RuntimeError("runner_service_response_too_large")
    decoded = json.loads(raw)
    if not isinstance(decoded, dict):
        raise RuntimeError("runner_service_response_invalid")
    return decoded


def _model_intake_snapshot_materialization(
    scan_result: dict[str, Any],
    *,
    artifact_sha256: str,
    repository_snapshot_sha256: str,
) -> dict[str, Any]:
    model = scan_result.get("model_intake") if isinstance(scan_result.get("model_intake"), dict) else {}
    snapshot = model.get("repository_snapshot") if isinstance(model.get("repository_snapshot"), dict) else {}
    if snapshot.get("complete") is not True or snapshot.get("snapshot_sha256") != repository_snapshot_sha256:
        raise HTTPException(status_code=409, detail="Exact complete repository snapshot is unavailable")
    files = snapshot.get("files") if isinstance(snapshot.get("files"), list) else []
    if not files or len(files) > 10_000:
        raise HTTPException(status_code=409, detail="Repository snapshot file inventory is invalid")
    canonical_files: list[dict[str, Any]] = []
    selected_path: str | None = None
    normalized: list[tuple[Path, str, int]] = []
    for entry in files:
        if not isinstance(entry, dict):
            raise HTTPException(status_code=409, detail="Repository snapshot entry is invalid")
        relative = Path(str(entry.get("path") or ""))
        digest = str(entry.get("sha256") or "").lower()
        size_value = entry.get("size_bytes")
        size = int(size_value if size_value is not None else -1)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts or not re.fullmatch(r"[0-9a-f]{64}", digest) or size < 0:
            raise HTTPException(status_code=409, detail="Repository snapshot entry is unsafe")
        canonical_files.append({"path": relative.as_posix(), "size_bytes": size, "sha256": digest})
        normalized.append((relative, digest, size))
        if digest == artifact_sha256:
            selected_path = relative.as_posix()
    canonical = {
        "provider": str(snapshot.get("repository_manifest", {}).get("provider") or "huggingface"),
        "repository": str(snapshot.get("repository") or ""),
        "revision": str(snapshot.get("revision") or ""),
        "files": sorted(canonical_files, key=lambda item: item["path"]),
    }
    canonical_bytes_value = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(canonical_bytes_value).hexdigest() != repository_snapshot_sha256:
        raise HTTPException(status_code=409, detail="Repository snapshot canonical digest mismatch")
    if not selected_path:
        raise HTTPException(status_code=409, detail="Deployment artifact is absent from repository snapshot")

    container_root = (_results_dir() / "model-intake-runner-subjects").resolve()
    subject = (container_root / repository_snapshot_sha256).resolve()
    manifest_dir = (container_root / "manifests").resolve()
    if container_root not in subject.parents:
        raise HTTPException(status_code=409, detail="Runner subject path escaped its root")
    source_root = (_results_dir() / "model-intake-quarantine" / "sha256").resolve()
    if not subject.exists():
        temporary = container_root / f".{repository_snapshot_sha256}.{uuid.uuid4().hex}.tmp"
        temporary.mkdir(parents=True, mode=0o700)
        try:
            for relative, digest, size in normalized:
                source = (source_root / digest[:2] / digest).resolve(strict=True)
                if source_root not in source.parents or not source.is_file() or source.stat().st_size != size:
                    raise HTTPException(status_code=409, detail=f"Quarantine object unavailable for {relative.as_posix()}")
                with source.open("rb") as handle:
                    observed = hashlib.file_digest(handle, "sha256").hexdigest()
                if observed != digest:
                    raise HTTPException(status_code=409, detail=f"Quarantine object digest mismatch for {relative.as_posix()}")
                target = temporary / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                target.chmod(0o400)
            os.replace(temporary, subject)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{repository_snapshot_sha256}.json"
    if not manifest_path.exists():
        temporary_manifest = manifest_dir / f".{repository_snapshot_sha256}.{uuid.uuid4().hex}.tmp"
        temporary_manifest.write_bytes(canonical_bytes_value)
        temporary_manifest.chmod(0o400)
        os.replace(temporary_manifest, manifest_path)

    host_root = os.getenv("MODEL_INTAKE_RUNNER_HOST_RESULTS_ROOT", "").strip()
    if not host_root or not Path(host_root).is_absolute():
        raise HTTPException(status_code=503, detail="MODEL_INTAKE_RUNNER_HOST_RESULTS_ROOT is not configured")
    relative_subject = subject.relative_to(_results_dir().resolve())
    relative_manifest = manifest_path.relative_to(_results_dir().resolve())
    semantic = model.get("metadata") if isinstance(model.get("metadata"), dict) else {}
    python_files = [item[0].as_posix() for item in normalized if item[0].suffix.lower() == ".py"]
    custom_code_entries = sorted([
        {"path": relative.as_posix(), "sha256": digest}
        for relative, digest, _size in normalized
        if relative.suffix.lower() == ".py"
    ], key=lambda entry: entry["path"])
    custom_code_sha256 = (
        hashlib.sha256(
            json.dumps(custom_code_entries, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if custom_code_entries else None
    )
    try:
        components = _model_intake_component_identities(canonical_files)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    profile_manifest = {
        **canonical,
        "library_name": str(semantic.get("library_name") or "transformers"),
        "custom_code_required": bool(python_files),
        "python_files": python_files,
        "architectures": semantic.get("architectures") if isinstance(semantic.get("architectures"), list) else [],
    }
    return {
        "subject_path": str(Path(host_root) / relative_subject),
        "repository_manifest_path": str(Path(host_root) / relative_manifest),
        "artifact_path": selected_path,
        "custom_code_sha256": custom_code_sha256,
        "tokenizer_sha256": components["tokenizer_sha256"],
        "configuration_sha256": components["configuration_sha256"],
        "profile_manifest": profile_manifest,
    }


def _model_intake_converted_snapshot_materialization(
    *,
    artifact_sha256: str,
    repository_snapshot_sha256: str,
) -> dict[str, Any]:
    """Independently verify and map one Firecracker-exported snapshot."""
    conversion_root = (_results_dir() / "model-intake-conversions").resolve()
    subject_candidate = conversion_root / repository_snapshot_sha256
    manifest_candidate = conversion_root / f"{repository_snapshot_sha256}.manifest.json"
    if not subject_candidate.exists() or not manifest_candidate.exists():
        raise HTTPException(status_code=409, detail="Converted snapshot or manifest is unavailable")
    subject = subject_candidate.resolve(strict=True)
    manifest_path = manifest_candidate.resolve(strict=True)
    if subject.parent != conversion_root or manifest_path.parent != conversion_root:
        raise HTTPException(status_code=409, detail="Converted snapshot escaped its content-addressed root")
    if not subject.is_dir() or not manifest_path.is_file() or manifest_path.stat().st_size > 20_000_000:
        raise HTTPException(status_code=409, detail="Converted snapshot or manifest is unavailable")
    manifest_bytes = manifest_path.read_bytes()
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=409, detail="Converted repository manifest is invalid") from exc
    if not isinstance(manifest, dict) or manifest.get("provider") != "shakerscan-conversion":
        raise HTTPException(status_code=409, detail="Converted repository manifest provider is invalid")
    if hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != repository_snapshot_sha256:
        raise HTTPException(status_code=409, detail="Converted repository snapshot digest mismatch")
    files = manifest.get("files") if isinstance(manifest.get("files"), list) else []
    if not files or len(files) > 10_000:
        raise HTTPException(status_code=409, detail="Converted repository inventory is invalid")
    normalized: list[tuple[Path, str, int]] = []
    selected_path: str | None = None
    seen: set[str] = set()
    total_bytes = 0
    for entry in files:
        if not isinstance(entry, dict):
            raise HTTPException(status_code=409, detail="Converted repository entry is invalid")
        relative = Path(str(entry.get("path") or ""))
        digest = str(entry.get("sha256") or "").lower()
        size = int(entry.get("size_bytes") if entry.get("size_bytes") is not None else -1)
        relative_text = relative.as_posix()
        if (
            relative.is_absolute() or not relative.parts or ".." in relative.parts
            or relative_text in seen or not re.fullmatch(r"[0-9a-f]{64}", digest) or size < 0
        ):
            raise HTTPException(status_code=409, detail="Converted repository entry is unsafe")
        seen.add(relative_text)
        total_bytes += size
        if total_bytes > int(os.getenv("MODEL_INTAKE_RUNNER_MAX_INPUT_BYTES", str(128 * 1024**3))):
            raise HTTPException(status_code=409, detail="Converted repository exceeds the configured quota")
        path = (subject / relative).resolve(strict=True)
        if subject not in path.parents or not path.is_file() or path.is_symlink() or path.stat().st_size != size:
            raise HTTPException(status_code=409, detail=f"Converted repository member is invalid: {relative_text}")
        with path.open("rb") as handle:
            observed = hashlib.file_digest(handle, "sha256").hexdigest()
        if observed != digest:
            raise HTTPException(status_code=409, detail=f"Converted repository member digest mismatch: {relative_text}")
        normalized.append((relative, digest, size))
        if digest == artifact_sha256:
            selected_path = relative_text
    observed_paths = {
        path.relative_to(subject).as_posix()
        for path in subject.rglob("*") if path.is_file() and not path.is_symlink()
    }
    if observed_paths != seen or not selected_path:
        raise HTTPException(status_code=409, detail="Converted repository inventory is incomplete or lacks the artifact")
    custom_entries = sorted(
        ({"path": relative.as_posix(), "sha256": digest} for relative, digest, _ in normalized if relative.suffix.lower() == ".py"),
        key=lambda item: item["path"],
    )
    custom_code_sha256 = (
        hashlib.sha256(json.dumps(custom_entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if custom_entries else None
    )
    canonical_files = [
        {"path": relative.as_posix(), "size_bytes": size, "sha256": digest}
        for relative, digest, size in normalized
    ]
    try:
        components = _model_intake_component_identities(canonical_files)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    host_root = os.getenv("MODEL_INTAKE_RUNNER_HOST_RESULTS_ROOT", "").strip()
    if not host_root or not Path(host_root).is_absolute():
        raise HTTPException(status_code=503, detail="MODEL_INTAKE_RUNNER_HOST_RESULTS_ROOT is not configured")
    relative_subject = subject.relative_to(_results_dir().resolve())
    relative_manifest = manifest_path.relative_to(_results_dir().resolve())
    python_files = [relative.as_posix() for relative, _digest, _size in normalized if relative.suffix.lower() == ".py"]
    return {
        "subject_path": str(Path(host_root) / relative_subject),
        "container_subject_path": str(subject),
        "repository_manifest_path": str(Path(host_root) / relative_manifest),
        "container_repository_manifest_path": str(manifest_path),
        "artifact_path": selected_path,
        "custom_code_sha256": custom_code_sha256,
        "tokenizer_sha256": components["tokenizer_sha256"],
        "configuration_sha256": components["configuration_sha256"],
        "artifact_size_bytes": next(size for relative, digest, size in normalized if digest == artifact_sha256),
        "repository_size_bytes": total_bytes,
        "profile_manifest": {
            **manifest,
            "library_name": "transformers",
            "custom_code_required": bool(python_files),
            "python_files": python_files,
            "architectures": [],
        },
    }


async def _execute_model_intake_agent_action(
    conn: Any,
    submission_uuid: uuid.UUID,
    name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    if name == "inspect_submission":
        if arguments:
            raise ValueError("inspect_submission takes no arguments")
        submission = await conn.fetchrow(
            """SELECT id,scan_id,requested_environment,source_kind,source_reference_hash,
                      expected_artifact_sha256,intended_use,state,created_at,updated_at
               FROM model_intake_submissions WHERE id=$1""",
            submission_uuid,
        )
        if not submission:
            raise ValueError("submission not found")
        subjects = await conn.fetch(
            """SELECT subject_kind,sha256,size_bytes,manifest_sha256,source_revision,created_at
               FROM model_intake_subjects WHERE submission_id=$1 ORDER BY created_at""",
            submission_uuid,
        )
        evidence = await conn.fetch(
            """SELECT id,evidence_type,provenance_class,producer_id,builder_id,status,
                      subject_bindings,payload_sha256,started_at,finished_at,expires_at,created_at
               FROM model_intake_evidence_records WHERE submission_id=$1 ORDER BY created_at""",
            submission_uuid,
        )
        runner_jobs = await conn.fetch(
            """SELECT id,operation,state,request_sha256,request_json,evidence_record_id,
                      error_json,created_at,started_at,finished_at
               FROM model_intake_runner_jobs WHERE submission_id=$1 ORDER BY created_at""",
            submission_uuid,
        )
        return {
            "submission": row_to_dict(submission),
            "subjects": [row_to_dict(row) for row in subjects],
            "evidence": [row_to_dict(row) for row in evidence],
            "runner_jobs": [row_to_dict(row) for row in runner_jobs],
            "authority": "read_only_non_admission_evidence",
        }
    if name == "inspect_readiness":
        if arguments:
            raise ValueError("inspect_readiness takes no arguments")
        runner = (
            await asyncio.to_thread(_model_intake_runner_http, "GET", "/health", None)
            if os.getenv("MODEL_INTAKE_RUNNER_URL", "").strip()
            else await asyncio.to_thread(_model_firecracker_readiness)
        )
        return {
            "scanners": await asyncio.to_thread(_model_scanner_adapter_readiness),
            "providers": await asyncio.to_thread(_model_provider_readiness),
            "runner": runner,
        }
    if name == "validate_runner_plan":
        allowed = {"operation", "deployment_bundle", "known_answer_embedding_sha256"}
        if set(arguments) - allowed:
            raise ValueError("validate_runner_plan has unsupported arguments")
        operation = str(arguments.get("operation") or "runtime")
        if operation not in {"calibration", "runtime", "conversion"}:
            raise ValueError("runner operation is unsupported")
        try:
            bundle = _build_model_deployment_bundle(
                arguments.get("deployment_bundle"), require_data_plane=False
            )
        except _ModelAdmissionContractError as exc:
            return {"status": "BLOCKED", "reason": str(exc), "deployable": False}
        submission = await conn.fetchrow(
            """SELECT s.requested_environment,s.scan_id,sc.result FROM model_intake_submissions s
               LEFT JOIN scans sc ON sc.id=s.scan_id WHERE s.id=$1""",
            submission_uuid,
        )
        if not submission:
            raise ValueError("submission not found")
        blockers: list[str] = []
        if bundle["target_environment"] != submission["requested_environment"]:
            blockers.append("environment_mismatch")
        subjects = await conn.fetch(
            "SELECT subject_kind,sha256 FROM model_intake_subjects WHERE submission_id=$1",
            submission_uuid,
        )
        subject_pairs = {(str(row["subject_kind"]), str(row["sha256"])) for row in subjects}
        if ("artifact", bundle["model_artifact_sha256"]) not in subject_pairs:
            blockers.append("model_artifact_subject_mismatch")
        if ("repository_snapshot", bundle["repository_snapshot_sha256"]) not in subject_pairs:
            blockers.append("repository_snapshot_subject_mismatch")
        result = _model_intake_json_object(submission["result"])
        try:
            try:
                materialized = await asyncio.to_thread(
                    _model_intake_snapshot_materialization,
                    result,
                    artifact_sha256=bundle["model_artifact_sha256"],
                    repository_snapshot_sha256=bundle["repository_snapshot_sha256"],
                )
            except HTTPException as source_error:
                if source_error.status_code != 409:
                    raise
                materialized = await asyncio.to_thread(
                    _model_intake_converted_snapshot_materialization,
                    artifact_sha256=bundle["model_artifact_sha256"],
                    repository_snapshot_sha256=bundle["repository_snapshot_sha256"],
                )
            for field in ("custom_code_sha256", "tokenizer_sha256", "configuration_sha256"):
                if bundle.get(field) != materialized[field]:
                    blockers.append(f"{field}_mismatch")
            resolver = _resolve_model_conversion_profile if operation == "conversion" else _resolve_model_loader_profile
            resolution = resolver(
                materialized["profile_manifest"],
                artifact_path=materialized["artifact_path"],
                runtime_image_digest=bundle["runtime_image_digest"],
                reviewed_custom_code_sha256=materialized["custom_code_sha256"],
            )
            if resolution.get("status") != "READY":
                blockers.append(f"loader_profile:{resolution.get('reason') or resolution.get('status')}")
        except (HTTPException, OSError, ValueError) as exc:
            blockers.append(f"complete_snapshot_or_selected_artifact_missing:{str(exc)[:300]}")
            resolution = None
        known_digest = str(arguments.get("known_answer_embedding_sha256") or "").lower()
        if operation == "runtime" and not re.fullmatch(r"[0-9a-f]{64}", known_digest):
            blockers.append("known_answer_embedding_digest_required")
        return {
            "status": "READY" if not blockers else "BLOCKED",
            "blockers": blockers,
            "deployment_bundle_sha256": bundle["bundle_sha256"],
            "loader_profile": resolution,
            "next_endpoint": (
                f"POST /model-intake/submissions/{submission_uuid}/runner-jobs"
                if not blockers else None
            ),
            "deployable": False,
        }
    if name == "draft_embedding_test_plan":
        if set(arguments) - {"use_case", "languages"}:
            raise ValueError("draft_embedding_test_plan has unsupported arguments")
        return _model_intake_embedding_test_plan(arguments)
    if name == "recommend_follow_up":
        if set(arguments) != {"action", "rationale"}:
            raise ValueError("recommend_follow_up requires action and rationale")
        action = str(arguments.get("action") or "")
        allowed = {
            "runtime", "conversion", "manual_custom_code_review", "embedding_baseline",
            "data_plane_evaluation", "block", "abstain",
        }
        rationale = str(arguments.get("rationale") or "").strip()
        if action not in allowed or not rationale or len(rationale) > 2000:
            raise ValueError("follow-up recommendation is outside the bounded catalog")
        return {
            "recorded": True,
            "action": action,
            "rationale": rationale,
            "executed": False,
            "authority": "operator_review_required",
        }
    raise ValueError("unknown planner action")


def _model_intake_evidence_matches_bundle(
    evidence_type: str,
    bindings: dict[str, Any],
    bundle: dict[str, Any],
) -> bool:
    if evidence_type == "static_analysis":
        return (
            bindings.get("model_artifact_sha256") == bundle["model_artifact_sha256"]
            and bindings.get("repository_snapshot_sha256") == bundle["repository_snapshot_sha256"]
        )
    if evidence_type == "conversion_equivalence":
        # The conversion receipt's deployment/profile digests bind the source
        # conversion job, not the target runtime loader. Its target component
        # identities and runtime image must match the bundle being frozen.
        return all((
            bindings.get("model_artifact_sha256") == bundle["model_artifact_sha256"],
            bindings.get("repository_snapshot_sha256") == bundle["repository_snapshot_sha256"],
            bindings.get("custom_code_sha256") == bundle.get("custom_code_sha256"),
            bindings.get("tokenizer_sha256") == bundle["tokenizer_sha256"],
            bindings.get("configuration_sha256") == bundle["configuration_sha256"],
            bindings.get("runtime_image_digest") == bundle["runtime_image_digest"],
            bool(bindings.get("source_model_artifact_sha256")),
            bool(bindings.get("source_repository_snapshot_sha256")),
        ))
    return (
        bindings.get("deployment_bundle_sha256") == bundle["bundle_sha256"]
        and bindings.get("model_artifact_sha256") == bundle["model_artifact_sha256"]
        and bindings.get("repository_snapshot_sha256") == bundle["repository_snapshot_sha256"]
        and bindings.get("runtime_image_digest") == bundle["runtime_image_digest"]
        and bindings.get("loader_profile_sha256") == bundle["loader_profile_sha256"]
    )


def _resolve_huggingface_model_intake(request: ModelIntakeResolveRequest) -> dict[str, Any]:
    _, parse_huggingface_ref = _import_model_intake_helpers()
    metadata = dict(request.metadata_json or {})
    if request.revision:
        metadata["revision"] = request.revision
    if request.filename:
        metadata["huggingface_file"] = request.filename
    hf_ref = parse_huggingface_ref(request.ref, metadata)
    repo_id = str(hf_ref.get("repo_id") or "")
    if not repo_id:
        raise HTTPException(status_code=400, detail="Hugging Face reference must include a model repo, such as org/model")

    warnings: list[str] = []
    model_info: dict[str, Any] = {}
    try:
        model_info = _hf_api_model_info(repo_id, str(hf_ref.get("revision") or "main"), request.timeout_seconds)
    except Exception as exc:
        warnings.append(f"Could not fetch Hugging Face model metadata: {type(exc).__name__}: {exc}")

    candidates = _hf_file_candidates(model_info) if model_info else []
    requested_filename = request.filename or hf_ref.get("filename")
    if not model_info and not requested_filename:
        warnings.append("Hugging Face metadata is required to choose a model artifact. Enter a direct artifact file path or retry when the Hub is reachable.")
        metadata_out = _model_intake_provider_resolution_failed_metadata(
            metadata,
            provider="huggingface",
            error_code="provider_resolution_failed:model_metadata_unavailable",
        )
        metadata_out["provider_resolution"].update({
            "requested_repository": repo_id,
            "requested_revision": hf_ref.get("revision") or metadata.get("revision") or "main",
        })
        return {
            "platform": "huggingface",
            "normalized_ref": request.ref,
            "repository": repo_id,
            "revision": hf_ref.get("revision"),
            "selected_file": None,
            "candidate_files": [],
            "metadata_json": {key: value for key, value in metadata_out.items() if value not in (None, "", [], {})},
            "warnings": warnings,
            "scan_payload": None,
        }
    selected = next((item for item in candidates if item["path"] == requested_filename), None) if requested_filename else None
    selected = selected or (candidates[0] if candidates else None)
    if selected:
        hf_ref = parse_huggingface_ref(request.ref, {
            **metadata,
            "revision": model_info.get("sha") or hf_ref.get("revision") or "main",
            "huggingface_file": selected["path"],
        })
    elif not hf_ref.get("filename"):
        warnings.append("No model artifact file was selected. Choose a .safetensors, .onnx, .gguf, .tflite, or reviewed legacy artifact.")

    if selected and selected.get("extension") in MODEL_INTAKE_RISKY_EXTENSIONS:
        warnings.append("Selected artifact uses a pickle-like or executable serialization format and should be reviewed before deployment.")
    if str(hf_ref.get("revision") or "main") == "main" and not model_info.get("sha"):
        warnings.append("Reference is not pinned to an immutable commit yet.")
    if model_info.get("gated") or model_info.get("private"):
        warnings.append("This model may require authenticated Hub access from the scanner worker.")

    repository_manifest = _hf_repository_manifest(
        model_info,
        repo_id,
        str(model_info.get("sha") or hf_ref.get("revision") or "main"),
    )
    if not repository_manifest.get("complete"):
        warnings.append("Repository inventory is incomplete or contains unsafe/colliding paths; production intake must fail closed.")
    if repository_manifest.get("custom_code_required"):
        warnings.append("Repository contains custom executable model code; scan and sandbox every executable file before approval.")

    provider_metadata = _hf_metadata_from_model_info(
        model_info,
        repo_id,
        str(hf_ref.get("revision") or "main"),
        selected,
    )
    if model_info:
        metadata_out = {**provider_metadata, **metadata}
        for key in _MODEL_INTAKE_PROVIDER_AUTHORITY_KEYS:
            if key in provider_metadata:
                metadata_out[key] = provider_metadata[key]
        metadata_out["python_files"] = list(repository_manifest.get("python_files") or [])
        metadata_out["custom_code_required"] = repository_manifest.get("custom_code_required")
        metadata_out["auto_map"] = repository_manifest.get("auto_map")
        metadata_out["provider_resolution"] = {
            "provider": "huggingface",
            "status": "PASS",
            "repository": repo_id,
            "revision": repository_manifest.get("revision"),
            "manifest_sha256": repository_manifest.get("manifest_sha256"),
        }
    else:
        metadata_out = _model_intake_provider_resolution_failed_metadata(
            metadata,
            provider="huggingface",
            error_code="provider_resolution_failed:model_metadata_unavailable",
        )
        metadata_out["provider_resolution"].update({
            "requested_repository": repo_id,
            "requested_revision": hf_ref.get("revision") or "main",
            "requested_file": requested_filename,
        })
    artifact_url = str(hf_ref.get("resolve_url") or request.ref).strip()
    model_card_url = str(metadata_out.get("model_card_url") or "") or None
    selected_size = int(selected.get("size_bytes") or 0) if selected else 0
    acquisition_limit = min(
        500_000_000_000,
        max(10_000_000, math.ceil(selected_size * 1.05)),
    )
    repository_files = repository_manifest.get("files") if isinstance(repository_manifest, dict) else []
    repository_size = sum(
        int(item.get("size_bytes") or 0)
        for item in repository_files if isinstance(item, dict)
    )
    repository_limit = min(
        2_000_000_000_000,
        max(50_000_000_000, math.ceil(repository_size * 1.05)),
    )
    scan_payload = {
        "artifact_url": artifact_url,
        "name": f"Hugging Face: {repo_id}",
        "metadata_json": metadata_out,
        "expected_sha256": selected.get("sha256") if selected else metadata_out.get("sha256"),
        "model_card_url": model_card_url,
        "require_deployment_approval": True,
        "require_signature": True,
        "require_hash": True,
        "require_model_governance": True,
        "max_download_bytes": acquisition_limit,
        "max_artifact_bytes": max(10_000_000_000, acquisition_limit),
        "complete_repository_snapshot": True,
        "max_repository_bytes": repository_limit,
        "run_generated_scanners": True,
        "run_dynamic_sandbox": True,
        "timeout_seconds": 20,
    }
    return {
        "platform": "huggingface",
        "normalized_ref": artifact_url,
        "repository": repo_id,
        "revision": hf_ref.get("revision"),
        "selected_file": selected,
        "candidate_files": candidates[:25],
        "metadata_json": metadata_out,
        "warnings": warnings,
        "scan_payload": scan_payload,
    }


def _model_intake_runner_readiness_snapshot() -> dict[str, Any]:
    """Readiness from the configured runner, or this host when none is set."""
    if os.getenv("MODEL_INTAKE_RUNNER_URL", "").strip():
        try:
            snapshot = _model_intake_runner_http("GET", "/health", None)
        except Exception:
            return {"status": "NOT_READY", "ready": False, "verified_component_sha256": {}}
    else:
        snapshot = _model_firecracker_readiness()
    if snapshot.get("ready") is True:
        try:
            expected_inputs = _model_intake_guest_rootfs_inputs_sha256()
        except OSError:
            expected_inputs = ""
        observed_inputs = str(snapshot.get("rootfs_inputs_sha256") or "")
        if not expected_inputs or observed_inputs != expected_inputs:
            checks = dict(snapshot.get("checks") or {})
            checks["current_rootfs_inputs"] = False
            snapshot = {
                **snapshot,
                "status": "NOT_READY",
                "ready": False,
                "checks": checks,
                "reason": (
                    "The installed microVM rootfs was built from a different ShakerScan guest source. "
                    "Reinstall the Model Intake runner before qualifying models."
                ),
                "expected_rootfs_inputs_sha256": expected_inputs or None,
            }
    return snapshot


_MODEL_INTAKE_STAGE_LOCK = threading.Lock()


_MODEL_INTAKE_STAGE_STATE: dict[str, Any] = {"status": "idle"}


def _model_intake_stage_dir() -> Path:
    return Path(os.getenv("MODEL_INTAKE_RUNNER_STAGE_DIR", "/runner-stage"))


def _model_intake_stage_manifest(stage_dir: Path) -> dict[str, Any] | None:
    """Verify both staged inputs against the server-written manifest.

    A file merely existing is not trusted evidence.  This also rejects symlink
    substitution before the privileged host installer consumes the paths.
    """
    manifest_path = stage_dir / "stage-manifest.json"
    kernel = stage_dir / "vmlinux"
    rootfs = stage_dir / "rootfs.ext4"
    try:
        if any(path.is_symlink() for path in (stage_dir, manifest_path, kernel, rootfs)):
            return None
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != "model-intake-runner-stage/v1":
            return None
        artifacts = raw.get("artifacts") if isinstance(raw.get("artifacts"), dict) else {}
        for name, path in (("kernel", kernel), ("rootfs", rootfs)):
            expected = artifacts.get(name) if isinstance(artifacts.get(name), dict) else {}
            if not path.is_file() or path.stat().st_size != int(expected.get("bytes") or -1):
                return None
            if _sha256_file(path) != str(expected.get("sha256") or ""):
                return None
        if artifacts["kernel"]["sha256"] != MODEL_INTAKE_GUEST_KERNEL_SHA256:
            return None
        if raw.get("rootfs_inputs_sha256") != _model_intake_guest_rootfs_inputs_sha256():
            return None
        return raw
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def _model_intake_stage_run() -> None:
    """Produce the two large runner inputs so the root step stays seconds long.

    Everything here is unprivileged relative to the host: fetching a pinned
    kernel and building a container image. The privileged install -- systemd
    unit, cgroup parent, /srv/jailer -- stays an explicit operator action.
    """
    stage_dir = _model_intake_stage_dir()
    try:
        stage_dir.mkdir(parents=True, exist_ok=True)
        stage_dir.chmod(0o700)
        (stage_dir / "stage-manifest.json").unlink(missing_ok=True)
        kernel_path = stage_dir / "vmlinux"
        _model_intake_stage_set(status="running", phase="kernel", error=None)
        if kernel_path.is_file() and _sha256_file(kernel_path) == MODEL_INTAKE_GUEST_KERNEL_SHA256:
            _model_intake_stage_log("kernel already staged and verified")
        else:
            _model_intake_stage_log(f"fetching {MODEL_INTAKE_GUEST_KERNEL_URL}")
            temporary = kernel_path.with_suffix(".partial")
            with urllib.request.urlopen(MODEL_INTAKE_GUEST_KERNEL_URL, timeout=120) as response:
                with temporary.open("wb") as handle:
                    shutil.copyfileobj(response, handle, 1024 * 1024)
            observed = _sha256_file(temporary)
            if observed != MODEL_INTAKE_GUEST_KERNEL_SHA256:
                temporary.unlink(missing_ok=True)
                raise RuntimeError(
                    f"kernel digest mismatch: expected {MODEL_INTAKE_GUEST_KERNEL_SHA256}, got {observed}"
                )
            temporary.replace(kernel_path)
            _model_intake_stage_log("kernel verified against its pinned digest")

        _model_intake_stage_set(phase="guest_rootfs")
        rootfs_path = stage_dir / "rootfs.ext4"
        script = Path("/workspace/scripts/build-model-intake-guest-rootfs.sh")
        if not script.is_file():
            raise RuntimeError("guest rootfs builder is unavailable in this runtime")
        rootfs_inputs_sha256 = _model_intake_guest_rootfs_inputs_sha256()
        _model_intake_stage_log("building the guest image (this pulls CPU PyTorch; expect minutes)")
        process = subprocess.Popen(
            ["bash", str(script), str(rootfs_path)],
            cwd="/workspace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert process.stdout is not None
        for line in process.stdout:
            _model_intake_stage_log(line.rstrip())
        if process.wait() != 0:
            raise RuntimeError("guest rootfs build failed; see the staging log")
        if _model_intake_guest_rootfs_inputs_sha256() != rootfs_inputs_sha256:
            rootfs_path.unlink(missing_ok=True)
            raise RuntimeError(
                "guest rootfs source changed during the build; staged output was discarded, retry staging"
            )

        artifacts = {
            "kernel": {
                "path": str(kernel_path),
                "sha256": _sha256_file(kernel_path),
                "bytes": kernel_path.stat().st_size,
            },
            "rootfs": {
                "path": str(rootfs_path),
                "sha256": _sha256_file(rootfs_path),
                "bytes": rootfs_path.stat().st_size,
            },
        }
        _write_model_intake_stage_manifest(
            stage_dir,
            artifacts,
            rootfs_inputs_sha256=rootfs_inputs_sha256,
        )
        _model_intake_stage_set(
            status="ready",
            phase="complete",
            artifacts=artifacts,
            integrity_verified=True,
        )
        _model_intake_stage_log("staging complete")
    except Exception as exc:  # noqa: BLE001 - surfaced to the operator as failed state
        _model_intake_stage_set(status="failed", phase="failed", error=f"{type(exc).__name__}: {exc}")
        _model_intake_stage_log(f"staging failed: {type(exc).__name__}: {exc}")


def _import_embedding_hint_readers():
    try:
        from scanner_tools.model_intake import (
            collect_embedding_configuration_hints,
            merge_embedding_configuration_hints,
        )
    except ModuleNotFoundError as exc:
        if exc.name != "scanner_tools":
            raise
        from scanner.scanner_tools.model_intake import (
            collect_embedding_configuration_hints,
            merge_embedding_configuration_hints,
        )
    return collect_embedding_configuration_hints, merge_embedding_configuration_hints


def _call_model_intake_signer(
    policy_decision_id: str,
    idempotency_key: str,
    requested_by_subject: str,
) -> dict[str, Any]:
    url = os.getenv(
        "MODEL_INTAKE_SIGNER_URL",
        "http://model-intake-signer:8091/internal/model-intake/admissions/issue",
    ).strip()
    token = os.getenv("MODEL_INTAKE_SIGNER_INTERNAL_TOKEN", "")
    if not url or len(token) < 32:
        raise RuntimeError("model_intake_signer_not_configured")
    payload = json.dumps({
        "policy_decision_id": policy_decision_id,
        "idempotency_key": idempotency_key,
        "requested_by_subject": requested_by_subject,
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Shakerscan-Signer-Token": token,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read(2_000_001)
    except urllib.error.HTTPError as exc:
        detail = exc.read(32_000).decode("utf-8", "replace")
        raise RuntimeError(f"signer_rejected:{exc.code}:{detail}") from exc
    if len(raw) > 2_000_000:
        raise RuntimeError("signer_response_too_large")
    decoded = json.loads(raw)
    if not isinstance(decoded, dict) or decoded.get("status") != "active":
        raise RuntimeError("signer_response_invalid")
    return decoded


async def _verify_model_intake_admission_v2_request(
    request: ModelAdmissionV2VerifyRequest,
    http_request: Request,
) -> tuple[dict[str, Any], ResolvedScanContract]:
    _model_intake_authenticated_subject(http_request)
    async with _pool().acquire() as conn:
        anchors = await conn.fetch(
            """
            SELECT public_key_pem,builder_id_constraint FROM model_intake_trust_anchors
            WHERE is_active=true AND revoked_at IS NULL AND purpose='admission_signer'
              AND environment=$1 AND valid_from<=NOW()
              AND (valid_until IS NULL OR valid_until>NOW())
            """,
            request.expected_environment,
        )
    trusted_keys = [str(item["public_key_pem"] or "") for item in anchors if item["public_key_pem"]]
    trusted_builders = {
        str(item["builder_id_constraint"] or "")
        for item in anchors
        if item["builder_id_constraint"]
    }
    env_keys = os.getenv("MODEL_INTAKE_ADMISSION_V2_TRUSTED_PUBLIC_KEYS", "").strip()
    if env_keys:
        trusted_keys.extend(_model_admission_trusted_keys(env_keys))
    env_builders = {
        item.strip()
        for item in os.getenv("MODEL_INTAKE_ADMISSION_V2_TRUSTED_BUILDERS", "").split(",")
        if item.strip()
    }
    trusted_builders.update(env_builders)
    result = _verify_model_admission_v2(
        request.admission_package,
        trusted_public_keys=trusted_keys,
        trusted_builder_ids=trusted_builders,
        expected_bundle_sha256=request.expected_bundle_sha256.lower(),
        expected_environment=request.expected_environment,
        expected_components=request.expected_components,
    )
    if not result.get("verified"):
        raise HTTPException(status_code=409, detail=result)
    async with _pool().acquire() as conn:
        admission = await conn.fetchrow(
            """
            SELECT * FROM model_intake_admissions
            WHERE statement_sha256=$1 AND schema_version='model-intake-admission/v2'
            """,
            result["statement_sha256"],
        )
        if not admission or admission["status"] != "active":
            blocker = "admission_not_registered" if not admission else f"admission_{admission['status']}"
            raise HTTPException(
                status_code=409,
                detail={**result, "verified": False, "status": "FAIL", "blockers": [blocker]},
            )
        if admission["deployment_bundle_sha256"] != request.expected_bundle_sha256.lower():
            raise HTTPException(status_code=409, detail="Registered deployment bundle differs")
    result["registry"] = {
        "admission_id": str(admission["id"]),
        "status": admission["status"],
        "schema_version": admission["schema_version"],
    }
    return result, admission


async def _expire_model_intake_admissions(conn: Any) -> None:
    await conn.execute(
        """UPDATE model_intake_admissions
           SET status='expired', updated_at=NOW()
           WHERE status IN ('active','reassessment_required') AND expires_at <= NOW()"""
    )


async def _enrich_model_intake_scan_request(request: ModelIntakeScanRequest) -> ModelIntakeScanRequest:
    """Resolve provider authority or preserve an explicit incomplete result."""
    artifact_ref = (request.artifact_url or "").strip()
    metadata = dict(request.metadata_json or {})
    if _detect_model_intake_platform(artifact_ref, metadata) != "huggingface":
        return request

    try:
        # Caller metadata must not enter the provider's authoritative output;
        # it is merged later only as untrusted declarations.
        resolve_request = ModelIntakeResolveRequest(
            platform="huggingface",
            ref=artifact_ref if _is_hf_ref(artifact_ref) else f"https://huggingface.co/{artifact_ref}",
            revision=metadata.get("revision") if isinstance(metadata.get("revision"), str) else None,
            filename=metadata.get("huggingface_file") if isinstance(metadata.get("huggingface_file"), str) else None,
            metadata_json={},
            timeout_seconds=min(max(int(request.timeout_seconds or 20), 1), 60),
        )
        resolved = await asyncio.to_thread(_resolve_huggingface_model_intake, resolve_request)
    except Exception as exc:
        logger.warning("Could not auto-enrich Hugging Face model intake request: %s: %s", type(exc).__name__, exc)
        error_code = f"provider_resolution_failed:{type(exc).__name__}"
        return request.model_copy(update={
            "metadata_json": _model_intake_provider_resolution_failed_metadata(
                metadata,
                provider="huggingface",
                error_code=error_code,
            ),
        })

    scan_payload = resolved.get("scan_payload") if isinstance(resolved.get("scan_payload"), dict) else {}
    resolved_metadata = scan_payload.get("metadata_json") if isinstance(scan_payload.get("metadata_json"), dict) else {}
    merged_metadata = {**resolved_metadata, **metadata}
    # Provider-derived identity and inventory fields are authoritative. Request
    # metadata may add declarations, but it must never replace the pinned Hub
    # revision, selected path, or complete file manifest produced by the
    # hardened resolver.
    for key in (
        "huggingface_repo",
        "revision",
        "huggingface_file",
        "huggingface_file_inventory",
        "repository_manifest",
        "source_repo",
    ):
        if key in resolved_metadata:
            merged_metadata[key] = resolved_metadata[key]
    authoritative_manifest = (
        resolved_metadata.get("repository_manifest")
        if isinstance(resolved_metadata.get("repository_manifest"), dict)
        else {}
    )
    merged_metadata["python_files"] = list(authoritative_manifest.get("python_files") or [])
    merged_metadata["custom_code_required"] = authoritative_manifest.get("custom_code_required")
    merged_metadata["auto_map"] = authoritative_manifest.get("auto_map")
    merged_metadata["provider_resolution"] = {
        "provider": "huggingface",
        "status": "PASS",
        "repository": resolved_metadata.get("huggingface_repo"),
        "revision": resolved_metadata.get("revision"),
        "manifest_sha256": authoritative_manifest.get("manifest_sha256"),
    }
    expected_sha = request.expected_sha256 or scan_payload.get("expected_sha256") or merged_metadata.get("sha256")
    model_card_url = request.model_card_url or scan_payload.get("model_card_url") or merged_metadata.get("model_card_url")
    artifact_url = scan_payload.get("artifact_url") or request.artifact_url
    name = request.name or scan_payload.get("name")

    return request.model_copy(update={
        "artifact_url": artifact_url,
        "name": name,
        "metadata_json": merged_metadata,
        "expected_sha256": expected_sha,
        "model_card_url": model_card_url,
    })


def _model_intake_artifact_size_bytes(
    model_intake: Mapping[str, Any],
    summary: Mapping[str, Any],
) -> int | None:
    """Return the authoritative observed artifact size for subject binding.

    New reports publish ``artifact_size_bytes`` directly.  The artifact fetch
    receipt is retained as a compatibility source for complete scans created
    before that field existed.  Declared/caller metadata is intentionally not
    accepted for Firecracker resource sizing.
    """
    artifact = model_intake.get("artifact")
    fetch = artifact.get("fetch") if isinstance(artifact, Mapping) else None
    candidates = [summary.get("artifact_size_bytes")]
    if isinstance(fetch, Mapping) and fetch.get("complete") is True and not fetch.get("truncated"):
        candidates.extend((fetch.get("bytes_total"), fetch.get("bytes_observed")))
    for value in candidates:
        if isinstance(value, bool):
            continue
        try:
            size = int(value)
        except (TypeError, ValueError):
            continue
        if size > 0:
            return size
    return None


def _model_intake_automatic_review_payload(row: Any) -> dict[str, Any]:
    """Return the public automatic-review shape with decoded JSONB fields.

    asyncpg intentionally returns JSON/JSONB values as JSON strings in this
    service.  Most Model Intake internals decode those values before use, but
    the automatic-review endpoints previously passed the raw row straight to
    the browser.  A completed review therefore changed ``timeline_json`` and
    ``pending_controls`` from the documented arrays into strings and crashed
    the whole Model Intake page when React called ``.map`` on them.

    Keep the decoding local to this resource instead of changing
    :func:`row_to_dict`, whose raw-JSON behavior is relied on by older API
    surfaces.
    """
    payload = row_to_dict(row)
    payload["timeline_json"] = _model_intake_auto_timeline(payload.get("timeline_json"))
    payload["pending_controls"] = _model_intake_present_pending_controls(
        payload.get("pending_controls")
    )
    error = _decode_json_value(payload.get("error_json"))
    payload["error_json"] = dict(error) if isinstance(error, Mapping) else None
    bundle = _decode_json_value(payload.get("deployment_bundle_json"))
    payload["deployment_bundle_json"] = (
        dict(bundle) if isinstance(bundle, Mapping) else None
    )
    controller_progress = int(payload.get("progress") or 0)
    effective_progress = controller_progress
    effective_step = str(payload.get("current_step") or "model_review")
    if str(payload.get("state") or "") == "static_scan_pending":
        try:
            scan_progress = max(0, min(100, int(payload.get("static_scan_progress") or 0)))
        except (TypeError, ValueError):
            scan_progress = 0
        effective_progress = max(controller_progress, min(44, 5 + scan_progress * 39 // 100))
        scan_phase = str(payload.get("static_scan_phase") or "").strip()
        if scan_phase:
            effective_step = scan_phase
    runner_state_field = {
        "conversion_running": "conversion_job_state",
        "calibration_running": "calibration_job_state",
        "runtime_running": "runtime_job_state",
    }.get(str(payload.get("state") or ""))
    active_runner_job_state = (
        str(payload.get(runner_state_field) or "") if runner_state_field else ""
    )
    payload["active_runner_job_state"] = active_runner_job_state or None
    if active_runner_job_state == "pending":
        effective_step = f"{effective_step}_queued"
    state = str(payload.get("state") or "")
    outcome = str(payload.get("technical_outcome") or "").upper()
    workflow_terminal = state in {
        "technical_review_complete", "attention_required", "failed", "cancelled",
    }
    controls_complete = state == "technical_review_complete" and outcome == "PASS"
    payload["progress_semantics"] = "workflow_lifecycle_percentage"
    payload["workflow_terminal"] = workflow_terminal
    payload["required_technical_controls_complete"] = controls_complete
    payload["required_technical_controls_status"] = (
        "complete" if controls_complete else "incomplete" if workflow_terminal else "pending"
    )
    payload["effective_progress"] = effective_progress
    payload["effective_current_step"] = effective_step
    return payload


def _model_intake_evidence_export(scan_payload: dict[str, Any], *, generated_at: Optional[datetime] = None) -> dict[str, Any]:
    result = _decode_json_value(scan_payload.get("result")) or {}
    model_intake = result.get("model_intake") if isinstance(result, dict) else {}
    model_intake = model_intake if isinstance(model_intake, dict) else {}
    summary = model_intake.get("summary") if isinstance(model_intake.get("summary"), dict) else {}
    checks = model_intake.get("checks") if isinstance(model_intake.get("checks"), dict) else {}
    aibom = model_intake.get("aibom") if isinstance(model_intake.get("aibom"), dict) else {}
    supply_chain = model_intake.get("supply_chain") if isinstance(model_intake.get("supply_chain"), dict) else {}
    generated_evaluation = model_intake.get("generated_evaluation") if isinstance(model_intake.get("generated_evaluation"), dict) else {}
    runtime_destinations = model_intake.get("runtime_destinations") if isinstance(model_intake.get("runtime_destinations"), list) else []
    artifact_ref = str(summary.get("artifact_ref") or scan_payload.get("target_url") or "")
    artifact = {
        "name": summary.get("artifact_name"),
        "label": _short_url_label(artifact_ref),
        "artifact_ref_hash": hashlib.sha256(artifact_ref.encode("utf-8", "ignore")).hexdigest() if artifact_ref else None,
        "source_kind": summary.get("source_kind"),
        "extension": summary.get("extension"),
        "sha256": summary.get("sha256"),
        "sha256_scope": summary.get("sha256_scope"),
        "expected_sha256": summary.get("expected_sha256"),
        "format_posture": summary.get("format_posture"),
    }
    trust_summary = {
        "checksum_status": summary.get("checksum_status"),
        "checksum_match": summary.get("checksum_match"),
        "checksum_policy_status": summary.get("checksum_policy_status"),
        "signature_verification_status": summary.get("signature_verification_status"),
        "signature_verified": summary.get("signature_verified"),
        "signature_valid": summary.get("signature_valid"),
        "signature_trusted_root": summary.get("signature_trusted_root"),
        "signature_key_fingerprint": summary.get("signature_key_fingerprint"),
        "signature_trust_anchors_configured": summary.get("signature_trust_anchors_configured"),
        "signature_verifier": summary.get("signature_verifier"),
        "signature_cryptographically_verified": summary.get("signature_cryptographically_verified"),
    }
    policy_summary = {
        "strict_governance": summary.get("strict_governance"),
        "deployment_environment": summary.get("deployment_environment"),
        "deployment_approved": summary.get("deployment_approved"),
        "license_policy_status": summary.get("license_policy_status"),
        "sbom_policy_status": summary.get("sbom_policy_status"),
        "malware_policy_status": summary.get("malware_policy_status"),
        "eval_policy_status": summary.get("eval_policy_status"),
        "generated_evaluation_status": summary.get("generated_evaluation_status"),
        "approval_policy_status": summary.get("approval_policy_status"),
        "aibom_completeness": summary.get("aibom_completeness"),
    }
    evidence_hashes = {
        "summary_hash": _content_free_hash(summary),
        "checks_hash": _content_free_hash(_model_intake_status_map(checks)),
        "aibom_hash": _content_free_hash(aibom),
        "supply_chain_hash": _content_free_hash(supply_chain),
        "runtime_destinations_hash": _content_free_hash(runtime_destinations),
        "generated_evaluation_hash": _content_free_hash(generated_evaluation),
    }
    runtime_summary = {
        "destination_count": len(runtime_destinations),
        "roles": sorted({
            str(item.get("role") or item.get("kind") or "unknown")
            for item in runtime_destinations
            if isinstance(item, dict)
        }),
        "hash": evidence_hashes["runtime_destinations_hash"],
    }
    generated = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    scan_id = str(scan_payload.get("id") or "")
    export_core = {
        "scan_id": scan_id,
        "artifact_ref_hash": artifact.get("artifact_ref_hash"),
        "trust_summary": trust_summary,
        "policy_summary": policy_summary,
        "check_statuses": _model_intake_status_map(checks),
        "evidence_hashes": evidence_hashes,
    }
    return {
        "schema_version": "2026-07-06.model-intake-evidence-export.v1",
        "generated_at": generated.isoformat(),
        "export_hash": _content_free_hash(export_core),
        "content_included": False,
        "artifact_included": False,
        "metadata_included": False,
        "signature_material_included": False,
        "scan": {
            "id": scan_id,
            "status": scan_payload.get("status"),
            "created_at": _iso_or_none(scan_payload.get("created_at")),
            "completed_at": _iso_or_none(scan_payload.get("completed_at")),
            "score": scan_payload.get("score"),
            "grade": scan_payload.get("grade"),
            "findings_count": scan_payload.get("findings_count"),
        },
        "artifact": artifact,
        "trust_summary": trust_summary,
        "policy_summary": policy_summary,
        "check_statuses": _model_intake_status_map(checks),
        "runtime_destinations": runtime_summary,
        "evidence_hashes": evidence_hashes,
        "replay_plan": {
            "type": "api_read_replay",
            "content_included": False,
            "scan_result_path": f"/scans/{scan_id}/result" if scan_id else None,
            "deployment_decision_path": f"/scans/{scan_id}/deployment-decision" if scan_id else None,
            "model_intake_rescan_path": f"/model-intake/targets/{scan_payload.get('target_id')}/rescan" if scan_payload.get("target_id") else None,
            "finding_filter_path": f"/findings?scan_id={scan_id}&source_type=model_intake" if scan_id else None,
        },
    }


def _prepare_model_intake_rescan_options(raw_options: Any) -> tuple[dict[str, Any], str | None, bool]:
    """Drop stale authority and force legacy target rechecks back to preflight."""
    options = dict(raw_options) if isinstance(raw_options, dict) else {}
    approval_receipt_id = str(options.pop("approval_receipt_id", "") or "").strip() or None
    for key in ("scope_receipt_id", "approved_by", "risk_tier", "runtime_scope_guard"):
        options.pop(key, None)
    authority_bearing = bool(
        approval_receipt_id
        or options.get("allow_insecure_http")
        or options.get("allow_private_networks")
        or options.get("allowed_acquisition_hosts")
        or options.get("allowed_acquisition_ports")
    )
    options["intake_mode"] = "preflight"
    options["require_signed_admission"] = False
    options["run_kind"] = "model_intake"
    return options, approval_receipt_id, authority_bearing
POLICY_PROFILES: dict[str, dict[str, Any]] = {
    "development": {
        "name": "development-ai-v1",
        "minimum_block_severity": "critical",
        "expires_days": 14,
        "allow_active_exceptions": True,
        "strict_model_intake": False,
    },
    "staging": {
        "name": "staging-ai-v1",
        "minimum_block_severity": "high",
        "expires_days": 21,
        "allow_active_exceptions": True,
        "strict_model_intake": False,
    },
    "production": {
        "name": "production-ai-v1",
        "minimum_block_severity": "high",
        "expires_days": 30,
        "allow_active_exceptions": True,
        "strict_model_intake": True,
    },
}


def _is_s3_hostname(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host == "s3.amazonaws.com" or (
        host.endswith(".amazonaws.com")
        and (host.startswith("s3.") or host.startswith("s3-") or ".s3." in host or ".s3-" in host)
    )


def _is_azure_blob_hostname(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host.endswith(".blob.core.windows.net") and host != "blob.core.windows.net"


def _looks_like_hf_repo_id(value: str) -> bool:
    parts = value.split("/")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    return len(parts) == 2 and all(part and all(char in allowed for char in part) for part in parts)




def _model_intake_value_is_nonempty(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _model_intake_forbidden_metadata_paths(value: Any, path: str = "metadata_json") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if str(key).strip().lower() in MODEL_INTAKE_ADMISSION_FORBIDDEN_METADATA_KEYS:
                paths.append(child_path)
            paths.extend(_model_intake_forbidden_metadata_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(_model_intake_forbidden_metadata_paths(child, f"{path}[{index}]"))
    return paths


def _strip_model_intake_governance_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_model_intake_governance_metadata(child)
            for key, child in value.items()
            if str(key).strip().lower() not in MODEL_INTAKE_ADMISSION_FORBIDDEN_METADATA_KEYS
        }
    if isinstance(value, list):
        return [_strip_model_intake_governance_metadata(child) for child in value]
    return value


def _sanitize_model_intake_preflight_authority(request: ModelIntakeScanRequest) -> ModelIntakeScanRequest:
    metadata = dict(request.metadata_json or {})
    governance_paths = _model_intake_forbidden_metadata_paths(metadata)
    declared = {
        "provenance_class": "DECLARED_UNTRUSTED",
        "signature_trusted_key_count": len(_str_list(request.signature_trusted_keys)),
        "signature_trusted_fingerprint_count": len(_str_list(request.signature_trusted_key_sha256)),
        "attestation_trusted_key_count": len(_str_list(request.attestation_trusted_keys)),
        "attestation_trusted_fingerprint_count": len(_str_list(request.attestation_trusted_key_sha256)),
        "trust_anchor_id_count": len(_str_list(request.trust_anchor_ids)),
        "deployment_approval_declared": bool(request.deployment_approved),
        "policy_exception_count": len(request.policy_exceptions or []),
        "governance_fields": governance_paths,
    }
    if any(
        value
        for key, value in declared.items()
        if key != "provenance_class"
    ):
        metadata["declared_trust_material"] = declared
    metadata = _strip_model_intake_governance_metadata(metadata)
    return request.model_copy(update={
        "metadata_json": metadata,
        "signature_trusted_keys": None,
        "signature_trusted_key_sha256": None,
        "attestation_trusted_keys": None,
        "attestation_trusted_key_sha256": None,
        "allowed_attestation_predicate_types": None,
        "required_attestation_builder_ids": None,
        "trust_anchor_ids": None,
        "deployment_approved": False,
        "require_deployment_approval": False,
        "policy_exceptions": None,
    })


def _merge_model_intake_trust_anchor_material(
    request: ModelIntakeScanRequest,
    anchors: list[dict[str, Any]],
) -> ModelIntakeScanRequest:
    # The caller is never a trust-root source. Only the server-selected durable
    # anchors passed to this function may populate trusted material.
    signature_keys: list[str] = []
    signature_fingerprints: list[str] = []
    attestation_keys: list[str] = []
    attestation_fingerprints: list[str] = []
    required_builder_ids: list[str] = []
    selected: list[dict[str, str]] = []
    for anchor in anchors:
        pem = str(anchor.get("public_key_pem") or "").strip()
        fingerprint = str(anchor.get("public_key_sha256") or "").strip()
        purpose = str(anchor.get("purpose") or "publisher_signature")
        target_keys = attestation_keys if purpose == "upstream_attestation" else signature_keys
        target_fingerprints = (
            attestation_fingerprints if purpose == "upstream_attestation" else signature_fingerprints
        )
        if pem and pem not in target_keys:
            target_keys.append(pem)
        if fingerprint and fingerprint not in target_fingerprints:
            target_fingerprints.append(fingerprint)
        builder_id = str(anchor.get("builder_id_constraint") or "").strip()
        if purpose == "upstream_attestation" and builder_id and builder_id not in required_builder_ids:
            required_builder_ids.append(builder_id)
        selected.append({
            "id": str(anchor.get("id") or ""),
            "name": str(anchor.get("name") or ""),
            "policy_profile": str(anchor.get("policy_profile") or ""),
            "purpose": purpose,
            "environment": str(anchor.get("environment") or ""),
            "version": str(anchor.get("version") or ""),
        })
    metadata = dict(request.metadata_json or {})
    if selected:
        metadata["selected_trust_anchors"] = selected
    return request.model_copy(update={
        "signature_trusted_keys": signature_keys or None,
        "signature_trusted_key_sha256": signature_fingerprints or None,
        "attestation_trusted_keys": attestation_keys or None,
        "attestation_trusted_key_sha256": attestation_fingerprints or None,
        "required_attestation_builder_ids": required_builder_ids or None,
        "metadata_json": metadata,
    })


def _apply_model_intake_policy_profile_requirements(
    request: ModelIntakeScanRequest,
    profile: dict[str, Any] | None,
) -> ModelIntakeScanRequest:
    if not profile:
        return request
    if str(profile.get("product_area") or "").strip().lower() != "model_intake":
        return request
    if not bool(profile.get("strict_model_intake")):
        return request
    required_ids = _str_list(_decode_json_value(profile.get("required_trust_anchor_ids")))
    # Strict admission accepts only anchors selected by the server-owned policy.
    merged_ids = list(dict.fromkeys(required_ids))
    metadata = dict(request.metadata_json or {})
    metadata["strict_governance"] = True
    metadata["policy_required_trust_anchor_ids"] = required_ids
    metadata["policy_required_trust_anchor_profile"] = str(
        profile.get("name") or profile.get("environment") or request.policy_profile or ""
    )
    metadata["policy_requirements_enforced"] = True
    updates: dict[str, Any] = {
        "trust_anchor_ids": merged_ids,
        "metadata_json": metadata,
        "complete_artifact_download": True,
        # Admission evidence is repository-scoped. Unsupported providers must
        # return UNSUPPORTED/INCOMPLETE instead of treating one URL as a
        # complete deployable model bundle.
        "complete_repository_snapshot": True,
        "run_generated_scanners": True,
        # None means the complete registered scanner set. A requester-provided
        # subset must never weaken a strict server-side profile.
        "generated_scanner_names": None,
        "run_dynamic_sandbox": True,
        "require_dynamic_sandbox": True,
        "run_generated_evaluation": True,
        "require_generated_evaluation": True,
        "require_signed_admission": True,
        "require_hash": True,
        "require_signature": True,
        "require_signature_verification": True,
        "require_cryptographic_signature_verification": True,
        "require_attestation_verification": True,
        "require_model_governance": True,
        "require_deployment_approval": True,
    }
    return request.model_copy(update=updates)


def _model_intake_effective_inspection_complete(
    model_intake: dict[str, Any],
    summary: dict[str, Any],
) -> bool:
    """Distinguish bounded in-memory bytes from conclusive artifact review.

    Complete acquisitions are streamed to quarantine and may be much larger
    than the bounded prefix retained in worker memory.  The old summary flag
    treated every such artifact as incompletely inspected even when a
    safetensors header proved all tensor bounds against the full byte length,
    or a complete archive walk covered the quarantined object.  That turned
    ordinary review warnings into ``INCOMPLETE`` and made the corporate report
    contradict its own coverage evidence.

    Only recognize the two formats for which the existing scanner records a
    conclusive full-object invariant.  ONNX/GGUF bounded hints remain
    incomplete unless the worker actually observed their whole payload.
    """
    if summary.get("inspection_complete") is True:
        return True
    if summary.get("acquisition_complete") is not True:
        return False
    artifact = _model_intake_json_object(model_intake.get("artifact"))
    archive = _model_intake_json_object(artifact.get("archive"))
    if archive.get("is_archive") is True and archive.get("complete") is True:
        return True
    supply_chain = _model_intake_json_object(model_intake.get("supply_chain"))
    format_inspection = _model_intake_json_object(supply_chain.get("format_inspection"))
    safetensors = _model_intake_json_object(format_inspection.get("safetensors_header"))
    return bool(
        safetensors.get("validation_complete") is True
        and safetensors.get("valid") is True
        and safetensors.get("payload_bounds_checked") is True
        and safetensors.get("payload_coverage_complete") is True
    )


def _model_intake_content_free_coverage(value: Any) -> dict[str, Any]:
    """Keep report-friendly counts/digests without copying paths, URLs, or scanner payloads."""
    if not isinstance(value, dict):
        return {}
    denied_fragments = {"path", "url", "name", "content", "source", "sample", "match"}
    return {
        str(key): item
        for key, item in value.items()
        if isinstance(item, (bool, int, float)) or item is None
        or (isinstance(item, str) and bool(re.fullmatch(r"[0-9a-fA-F]{64}", item)))
        if not any(fragment in str(key).lower() for fragment in denied_fragments)
    }


def _model_intake_safe_relative_path(value: Any) -> str | None:
    text = str(value or "").strip().replace("\\", "/")
    candidate = Path(text)
    if not text or candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        return None
    normalized = candidate.as_posix()
    return normalized[:500] if normalized else None


def _model_intake_safe_file_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    files: list[str] = []
    seen: set[str] = set()
    for item in value[:10_000]:
        normalized = _model_intake_safe_relative_path(item)
        if normalized and normalized not in seen:
            seen.add(normalized)
            files.append(normalized)
    return files


def _model_intake_transition_is_allowed(previous_state: str, new_state: str) -> bool:
    return new_state in _MODEL_INTAKE_SUBMISSION_TRANSITIONS.get(previous_state, set())


def _hf_api_model_info(repo_id: str, revision: str | None, timeout_seconds: int) -> dict[str, Any]:
    suffix = f"/revision/{urllib.parse.quote(revision, safe='')}" if revision and revision != "main" else ""
    # `blobs=true` asks the Hub to include file metadata, including LFS sha256/size
    # for hosted large model artifacts. Without it, `siblings` only contains names.
    query = urllib.parse.urlencode({"blobs": "true"})
    url = f"https://huggingface.co/api/models/{urllib.parse.quote(repo_id, safe='/')}{suffix}?{query}"
    raw, _fetch = _model_download_http(
        url,
        HF_MODEL_INFO_MAX_BYTES + 1,
        timeout_seconds,
        headers={"Accept": "application/json"},
        policy=_model_acquisition_policy({"allowed_acquisition_hosts": ["huggingface.co"]}),
    )
    if len(raw) > HF_MODEL_INFO_MAX_BYTES:
        raise RuntimeError(f"Hugging Face model metadata exceeded {HF_MODEL_INFO_MAX_BYTES} byte cap")
    return json.loads(raw.decode("utf-8"))


def _hf_file_candidates(model_info: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for sibling in model_info.get("siblings") or []:
        path = str(sibling.get("rfilename") or sibling.get("path") or "")
        score = _hf_candidate_score(path)
        if not path or score <= 0:
            continue
        ext = Path(path).suffix.lower()
        lfs = sibling.get("lfs") if isinstance(sibling.get("lfs"), dict) else {}
        candidates.append({
            "path": path,
            "extension": ext,
            "format_posture": "safer_static_format" if ext in MODEL_INTAKE_SAFER_EXTENSIONS else "unsafe_or_review_required",
            "risk": "lower" if ext in MODEL_INTAKE_SAFER_EXTENSIONS else "higher",
            "size_bytes": sibling.get("size") or lfs.get("size"),
            "sha256": lfs.get("sha256"),
            "blob_id": sibling.get("blobId"),
            "score": score,
        })
    return sorted(candidates, key=lambda item: (-int(item.get("score") or 0), str(item.get("path") or "")))


def _hf_repository_manifest(
    model_info: dict[str, Any],
    repo_id: str | None = None,
    revision: str | None = None,
    limit: int = MODEL_INTAKE_REPOSITORY_MANIFEST_MAX_FILES,
) -> dict[str, Any]:
    siblings = model_info.get("siblings") if isinstance(model_info.get("siblings"), list) else []
    inventory: list[dict[str, Any]] = []
    invalid_paths: list[dict[str, str]] = []
    duplicate_paths: list[str] = []
    case_collisions: list[list[str]] = []
    observed_paths: set[str] = set()
    case_paths: dict[str, str] = {}
    for sibling in siblings[:limit]:
        raw_path = str(sibling.get("rfilename") or sibling.get("path") or "")
        path, error = _hf_repo_path_status(raw_path)
        if error or not path:
            invalid_paths.append({"path": raw_path[:512], "reason": error or "invalid_path"})
            continue
        if path in observed_paths:
            duplicate_paths.append(path)
            continue
        observed_paths.add(path)
        folded = path.casefold()
        if folded in case_paths and case_paths[folded] != path:
            case_collisions.append([case_paths[folded], path])
        else:
            case_paths[folded] = path
        inventory.append(_hf_repo_file_record(sibling, path))
    inventory.sort(key=lambda item: str(item.get("path") or ""))
    canonical_subject = {
        "provider": "huggingface",
        "repository": repo_id,
        "revision": revision or model_info.get("sha"),
        "files": [
            {
                key: item.get(key)
                for key in ("path", "size_bytes", "sha256", "blob_id")
                if item.get(key) not in (None, "")
            }
            for item in inventory
        ],
    }
    manifest_sha256 = hashlib.sha256(
        json.dumps(canonical_subject, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    executable_files = [item["path"] for item in inventory if item.get("executable")]
    python_files = [item["path"] for item in inventory if "python_source" in item.get("categories", [])]
    auto_map = (
        model_info.get("config", {}).get("auto_map")
        if isinstance(model_info.get("config"), dict)
        else None
    )
    tags = model_info.get("tags") if isinstance(model_info.get("tags"), list) else []
    custom_code_required = bool(auto_map or python_files or "custom_code" in tags)
    total_size = sum(int(item.get("size_bytes") or 0) for item in inventory)
    complete = (
        bool(siblings)
        and len(siblings) <= limit
        and len(inventory) + len(invalid_paths) + len(duplicate_paths) == len(siblings)
        and not invalid_paths
        and not duplicate_paths
        and not case_collisions
    )
    return {
        "schema_version": "model-intake-repository-manifest/v1",
        "provider": "huggingface",
        "repository": repo_id,
        "revision": revision or model_info.get("sha"),
        "manifest_sha256": manifest_sha256,
        "complete": complete,
        "files_discovered": len(siblings),
        "files_recorded": len(inventory),
        "total_declared_bytes": total_size,
        "truncated_by_limit": len(siblings) > limit,
        "invalid_paths": invalid_paths[:100],
        "duplicate_paths": duplicate_paths[:100],
        "case_collisions": case_collisions[:100],
        "executable_files": executable_files,
        "python_files": python_files,
        "custom_code_required": custom_code_required,
        "auto_map": auto_map,
        "files": inventory,
    }


def _hf_metadata_from_model_info(model_info: dict[str, Any], repo_id: str, revision: str, selected: dict[str, Any] | None) -> dict[str, Any]:
    card_data = model_info.get("cardData") if isinstance(model_info.get("cardData"), dict) else {}
    tags = model_info.get("tags") if isinstance(model_info.get("tags"), list) else []
    datasets = card_data.get("datasets") or [tag.removeprefix("dataset:") for tag in tags if isinstance(tag, str) and tag.startswith("dataset:")]
    base_model = card_data.get("base_model") or card_data.get("base_models")
    license_ref = card_data.get("license") or next((tag.removeprefix("license:") for tag in tags if isinstance(tag, str) and tag.startswith("license:")), None)
    evals = card_data.get("model-index") or card_data.get("eval_results") or card_data.get("eval_results_v2")
    sha = model_info.get("sha") or revision
    repository_manifest = _hf_repository_manifest(model_info, repo_id, str(sha))
    file_inventory = repository_manifest["files"]
    tokenizer_files = _hf_files_named(model_info, MODEL_INTAKE_TOKENIZER_FILES)
    dependency_files = _hf_files_named(model_info, MODEL_INTAKE_DEPENDENCY_FILES)
    model_card_file = next(
        (
            str(item.get("path"))
            for item in file_inventory
            if isinstance(item, dict) and Path(str(item.get("path") or "")).name.lower() == "readme.md"
        ),
        None,
    )
    metadata: dict[str, Any] = {
        "huggingface_repo": repo_id,
        "revision": sha,
        "source_repo": f"https://huggingface.co/{repo_id}",
        "model_card_url": (
            f"https://huggingface.co/{repo_id}/resolve/{sha}/{urllib.parse.quote(model_card_file, safe='/')}"
            if model_card_file else None
        ),
        "publisher": repo_id.split("/", 1)[0],
        "pipeline_tag": model_info.get("pipeline_tag") or card_data.get("pipeline_tag"),
        "library_name": model_info.get("library_name") or card_data.get("library_name"),
        "tags": tags[:50],
        "gated": model_info.get("gated"),
        "private": model_info.get("private"),
        "huggingface_file_inventory": file_inventory,
        "repository_manifest": repository_manifest,
    }
    if license_ref:
        metadata["license"] = license_ref
    if datasets:
        metadata["training_data_ref"] = datasets
    if base_model:
        metadata["base_model"] = base_model
    if tokenizer_files:
        metadata["tokenizer"] = tokenizer_files
    if dependency_files:
        metadata["package_dependencies"] = {
            "source": "huggingface_repo_files",
            "files": dependency_files,
        }
    if evals:
        metadata["security_evals"] = {"source": "huggingface_model_card", "results": evals}
    if selected:
        metadata["huggingface_file"] = selected.get("path")
        if selected.get("sha256"):
            metadata["sha256"] = selected.get("sha256")
            metadata["sha256_source"] = "huggingface_lfs"
            metadata["sha256_scope"] = "full_artifact"
        if selected.get("size_bytes"):
            metadata["artifact_size_bytes"] = selected.get("size_bytes")
    return {key: value for key, value in metadata.items() if value not in (None, "", [], {})}






def _model_intake_stage_set(**fields: Any) -> None:
    with _MODEL_INTAKE_STAGE_LOCK:
        _MODEL_INTAKE_STAGE_STATE.update(fields)


def _model_intake_stage_log(line: str) -> None:
    with _MODEL_INTAKE_STAGE_LOCK:
        log = _MODEL_INTAKE_STAGE_STATE.setdefault("log", [])
        log.append(line[:500])
        del log[:-_MODEL_INTAKE_STAGE_LOG_LINES]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _model_intake_guest_rootfs_inputs_sha256(workspace: Path = Path("/workspace")) -> str:
    digest = hashlib.sha256()
    for relative in MODEL_INTAKE_GUEST_ROOTFS_INPUTS:
        path = workspace / relative
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _write_model_intake_stage_manifest(
    stage_dir: Path,
    artifacts: dict[str, Any],
    *,
    rootfs_inputs_sha256: str,
) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", rootfs_inputs_sha256):
        raise ValueError("rootfs input snapshot digest is invalid")
    manifest = {
        "schema_version": "model-intake-runner-stage/v1",
        "artifacts": artifacts,
        "kernel_source": {
            "url": MODEL_INTAKE_GUEST_KERNEL_URL,
            "sha256": MODEL_INTAKE_GUEST_KERNEL_SHA256,
        },
        "rootfs_builder": "scripts/build-model-intake-guest-rootfs.sh",
        "rootfs_inputs_sha256": rootfs_inputs_sha256,
    }
    temporary = stage_dir / "stage-manifest.json.partial"
    temporary.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(stage_dir / "stage-manifest.json")




def _model_intake_provider_resolution_failed_metadata(
    metadata: dict[str, Any],
    *,
    provider: str,
    error_code: str,
) -> dict[str, Any]:
    declared_authority = {
        key: metadata[key]
        for key in sorted(_MODEL_INTAKE_PROVIDER_AUTHORITY_KEYS)
        if key in metadata
    }
    sanitized = {
        key: value
        for key, value in metadata.items()
        if key not in _MODEL_INTAKE_PROVIDER_AUTHORITY_KEYS
    }
    sanitized.update({
        "provider_resolution": {
            "provider": provider,
            "status": "INCOMPLETE",
            "error_code": error_code,
            "caller_authority_discarded": bool(declared_authority),
            "discarded_declarations_sha256": (
                hashlib.sha256(
                    json.dumps(declared_authority, sort_keys=True, separators=(",", ":"), default=str).encode()
                ).hexdigest()
                if declared_authority else None
            ),
        },
        "repository_manifest": {
            "schema_version": "model-intake-repository-manifest/v1",
            "provider": provider,
            "complete": False,
            "files_discovered": 0,
            "files_recorded": 0,
            "files": [],
            "python_files": [],
            "custom_code_required": None,
            "inventory_status": "INCOMPLETE",
            "error": error_code,
        },
        "huggingface_file_inventory": [],
        "python_files": [],
        "custom_code_required": None,
    })
    return sanitized


def _model_intake_auto_timeline(value: Any) -> list[dict[str, Any]]:
    decoded = _decode_json_value(value)
    return [item for item in decoded if isinstance(item, dict)] if isinstance(decoded, list) else []


def _model_intake_present_pending_controls(value: Any) -> list[dict[str, Any]]:
    """Keep security findings and license follow-up distinct in review cards.

    Static evidence carries both scanner findings and the native license
    inventory.  Treating a missing LICENSE/NOTICE file as a generic static-code
    warning made the automatic card disagree with the normalized report and
    obscured the actionable Semgrep/AST results.  This presentation transform
    preserves the underlying evidence and status while giving license evidence
    its own concise follow-up.  It also repairs already-completed reviews when
    they are read, without rewriting their frozen records.
    """
    decoded = _decode_json_value(value)
    controls = [dict(item) for item in decoded if isinstance(item, Mapping)] if isinstance(decoded, list) else []
    presented: list[dict[str, Any]] = []
    for control in controls:
        if str(control.get("control") or "") != "static_analysis":
            presented.append(control)
            continue
        items = [dict(item) for item in control.get("items") or [] if isinstance(item, Mapping)]
        license_items: list[dict[str, Any]] = []
        security_items: list[dict[str, Any]] = []
        for item in items:
            scanners = {str(name) for name in item.get("scanners") or []}
            if "shakerscan-license-inventory" in scanners:
                license_items.append(item)
            else:
                security_items.append(item)
        if security_items or not license_items:
            static_control = dict(control)
            if items:
                static_control["items"] = security_items
            presented.append(static_control)
        if license_items:
            presented.append({
                "control": "license_compliance",
                "status": "REVIEW",
                "summary": "License evidence needs review.",
                "action": "Open the License BOM for detected terms, missing source text, obligations, and evidence.",
                "items": license_items,
            })
    return presented


def _model_intake_status_map(value: Any) -> dict[str, Any]:
    mapping = value if isinstance(value, dict) else {}
    out: dict[str, Any] = {}
    for key, item in mapping.items():
        if isinstance(item, dict):
            out[str(key)] = item.get("status")
        elif isinstance(item, bool) or item is None:
            out[str(key)] = item
        elif isinstance(item, (str, int, float)):
            out[str(key)] = item
        else:
            out[str(key)] = str(type(item).__name__)
    return out










_MODEL_INTAKE_SUBMISSION_TRANSITIONS: dict[str, set[str]] = {
    "submitted": {"scanning", "evidence_ready", "blocked", "cancelled"},
    "scanning": {"evidence_ready", "blocked", "cancelled"},
    "evidence_ready": {"evidence_ready", "awaiting_approval", "blocked", "cancelled"},
    "evidence_frozen": {"evidence_ready", "awaiting_approval", "blocked", "cancelled"},
    "awaiting_approval": {"evidence_ready", "awaiting_approval", "policy_decided", "blocked", "cancelled"},
    "policy_decided": {"evidence_ready", "admitted", "blocked", "cancelled"},
    "admitted": {"evidence_ready", "promoted", "blocked"},
    "promoted": {"evidence_ready", "blocked"},
    "blocked": {"evidence_ready", "cancelled"},
    "cancelled": set(),
}


def _hf_candidate_score(path: str) -> int:
    name = Path(path).name.lower()
    ext = Path(path).suffix.lower()
    if name in MODEL_INTAKE_COMMON_ARTIFACTS:
        return 120
    if ext == ".safetensors":
        return 100
    if ext == ".onnx":
        return 90
    if ext == ".gguf":
        return 85
    if ext == ".tflite":
        return 80
    if ext in MODEL_INTAKE_RISKY_EXTENSIONS:
        return 45
    return 0


def _hf_repo_path_status(raw_path: str) -> tuple[str | None, str | None]:
    path = str(raw_path or "")
    if not path or "\x00" in path or "\\" in path or path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return None, "invalid_or_absolute_path"
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None, "non_normalized_path"
    normalized = "/".join(parts)
    if len(normalized.encode("utf-8")) > 4096:
        return None, "path_too_long"
    return normalized, None


def _hf_repo_file_record(sibling: dict[str, Any], path: str) -> dict[str, Any]:
    lfs = sibling.get("lfs") if isinstance(sibling.get("lfs"), dict) else {}
    name = Path(path).name.lower()
    ext = Path(path).suffix.lower()
    categories: list[str] = []
    if _hf_candidate_score(path) > 0:
        categories.append("model_artifact")
    if name in MODEL_INTAKE_TOKENIZER_FILES:
        categories.append("tokenizer")
    if name in MODEL_INTAKE_DEPENDENCY_FILES:
        categories.append("dependency")
    if name in MODEL_INTAKE_METADATA_FILES or name.endswith("_config.json"):
        categories.append("metadata")
    if ext in MODEL_INTAKE_EXECUTABLE_EXTENSIONS:
        categories.append("executable")
    if ext == ".py":
        categories.append("python_source")
    if not categories:
        categories.append("other")
    item = {
        "path": path,
        "size_bytes": sibling.get("size") or lfs.get("size"),
        "sha256": lfs.get("sha256"),
        "blob_id": sibling.get("blobId"),
        "categories": categories,
        "executable": "executable" in categories,
        "source": "huggingface_model_info",
    }
    return {key: value for key, value in item.items() if value not in (None, "", [], {})}


def _hf_files_named(model_info: dict[str, Any], names: set[str]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for item in _hf_repo_file_inventory(model_info):
        name = Path(str(item.get("path") or "")).name.lower()
        if name in names:
            matches.append(item)
    return matches










def _hf_repo_file_inventory(
    model_info: dict[str, Any],
    limit: int = MODEL_INTAKE_REPOSITORY_MANIFEST_MAX_FILES,
) -> list[dict[str, Any]]:
    return list(_hf_repository_manifest(model_info, limit=limit).get("files") or [])
async def _model_intake_auto_runner_memory_ready(
    review: Mapping[str, Any], memory_mib: int,
) -> bool:
    """Retry sampled/unknown memory pressure briefly; reject fixed capacity gaps."""
    readiness = await asyncio.to_thread(_model_intake_runner_readiness_snapshot)
    plan = _model_runner_memory_admission(readiness, memory_mib)
    if plan.get("sufficient") is True:
        return True
    total_mib = plan.get("host_memory_total_mib")
    reserve_mib = plan.get("host_reserve_mib")
    fixed_capacity_gap = (
        isinstance(total_mib, int)
        and isinstance(reserve_mib, int)
        and memory_mib + reserve_mib > total_mib
    )
    if not fixed_capacity_gap and _model_intake_auto_runner_readiness_grace_active(review):
        return False
    raise RuntimeError(
        "The Firecracker host does not have enough verified memory for this exact model: "
        f"{plan.get('reason')}. Move the runner to a larger KVM host or free memory and start a new review."
    )
def _model_intake_auto_runner_readiness_grace_active(
    review: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> bool:
    """Retry a briefly unavailable runner without turning one probe into a terminal result."""
    entered_at = review.get("updated_at")
    if not isinstance(entered_at, datetime):
        return False
    if entered_at.tzinfo is None:
        entered_at = entered_at.replace(tzinfo=timezone.utc)
    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    return checked_at - entered_at < _MODEL_INTAKE_AUTO_RUNNER_READINESS_GRACE
_MODEL_INTAKE_AUTO_RUNNER_READINESS_GRACE = timedelta(minutes=2)
