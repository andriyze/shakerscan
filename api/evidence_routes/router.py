"""Evidence routes.

Extracted verbatim from the api.py monolith. Covers the evidence instance
ledger, content-addressed object reads, content-free export manifests and
bundles, and the approval-gated retention sweep with its immutable preview.

Retention deletion is the one genuinely destructive path in this module. Its
storage seams (``local_evidence_path``, ``_delete_remote_evidence_objects``)
stay patchable from both this module and the composition root so a stubbed test
can never fall through to real filesystem or object-store deletion.
"""

from __future__ import annotations

import asyncio
import asyncpg
import os
import secrets
from collections import Counter
import io
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Callable, Optional, Sequence
import uuid

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

try:
    from action_scope import _decode_json_value
    from api_utils import _direct_query_value, _optional_uuid
    from evidence_storage import delete_remote_evidence_object, local_evidence_path
    from finding_routes import router as _finding_routes
    from serialization import row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..action_scope import _decode_json_value
    from ..api_utils import _direct_query_value, _optional_uuid
    from ..evidence_storage import delete_remote_evidence_object, local_evidence_path
    from ..finding_routes import router as _finding_routes
    from ..serialization import row_to_dict


try:
    EVIDENCE_RETENTION_PREVIEW_TTL_SECONDS = max(
        60,
        min(3600, int(os.environ.get("EVIDENCE_RETENTION_PREVIEW_TTL_SECONDS", "600"))),
    )
except (TypeError, ValueError):
    EVIDENCE_RETENTION_PREVIEW_TTL_SECONDS = 600


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


def configure_evidence_router(
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


def _get(name: str) -> Any:
    """Resolve an injected collaborator that still lives in the composition root."""
    return _dep(name)()


EVIDENCE_RETENTION_PREVIEW_SCHEMA_VERSION = 1


def _validate_evidence_retention_preview_payload(payload: dict[str, Any], *, allow_consumed: bool = False) -> None:
    if payload.get("schema_version") != EVIDENCE_RETENTION_PREVIEW_SCHEMA_VERSION:
        raise HTTPException(status_code=409, detail="Retention preview uses an unsupported schema; run a new preview")
    expected_hash = _evidence_retention_preview_hash(payload)
    if not secrets.compare_digest(str(payload.get("preview_hash") or ""), expected_hash):
        raise HTTPException(status_code=409, detail="Retention preview is invalid; run a new preview")
    criteria = payload.get("criteria")
    if not isinstance(criteria, dict) or criteria.get("scope") != "target" or not criteria.get("target_id"):
        raise HTTPException(status_code=409, detail="Retention preview scope is invalid; run a new preview")
    if str(payload.get("target_id") or "") != str(criteria.get("target_id") or ""):
        raise HTTPException(status_code=409, detail="Retention preview target binding is invalid; run a new preview")
    if not isinstance(payload.get("candidates"), list):
        raise HTTPException(status_code=409, detail="Retention preview candidate set is invalid; run a new preview")
    status = str(payload.get("status") or "")
    if status in {"executing", "consumed"} and allow_consumed:
        return
    if payload.get("policy_hash") != _evidence_retention_policy_hash():
        raise HTTPException(status_code=409, detail="Retention policy changed after preview; run a new preview")
    if status != "ready":
        raise HTTPException(status_code=409, detail="Retention preview is no longer executable; run a new preview")
    expires_at = _parse_hypothesis_time(payload.get("expires_at"))
    if not expires_at or expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=409, detail="Retention preview expired; run a new preview")


def _evidence_retention_policy_hash() -> str:
    encoded = json.dumps(
        {
            "schema_version": EVIDENCE_RETENTION_PREVIEW_SCHEMA_VERSION,
            "policy_days": EVIDENCE_RETENTION_DAYS,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _evidence_retention_preview_hash(payload: dict[str, Any]) -> str:
    material = {
        "schema_version": payload.get("schema_version"),
        "issued_at": payload.get("issued_at"),
        "expires_at": payload.get("expires_at"),
        "criteria": payload.get("criteria"),
        "policy_hash": payload.get("policy_hash"),
        "candidates": payload.get("candidates"),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _results_dir() -> Any:
    return _dep("results_dir")()


def _record_export_event(*a: Any, **k: Any) -> Any:
    return _get("_record_export_event")(*a, **k)


async def _validate_approval_receipt_for_action(*a: Any, **k: Any) -> Any:
    return await _get("_validate_approval_receipt_for_action")(*a, **k)


async def _record_command_result(*a: Any, **k: Any) -> Any:
    return await _get("_record_command_result")(*a, **k)


async def _record_evidence_instance(*a: Any, **k: Any) -> Any:
    return await _get("_record_evidence_instance")(*a, **k)


def _redact_agent_payload(*a: Any, **k: Any) -> Any:
    return _get("_redact_agent_payload")(*a, **k)


def _parse_hypothesis_time(*a: Any, **k: Any) -> Any:
    return _get("_parse_hypothesis_time")(*a, **k)



class EvidenceInstanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: Optional[str] = None
    evidence_object_id: Optional[str] = None
    scan_id: Optional[str] = None
    target_id: Optional[str] = None
    concrete_url: Optional[str] = None
    object_id: Optional[str] = None
    payload_variant: Optional[str] = None
    request_response_refs: list[str] = Field(default_factory=list)
    principal_pair: dict[str, Any] = Field(default_factory=dict)
    proof_observation: dict[str, Any] = Field(default_factory=dict)
    campaign_action_id: Optional[str] = None
    tool_receipt_id: Optional[str] = None
    redaction_profile: str = "redact_sensitive_v1"
    hash: Optional[str] = None
    retention_policy: str = Field(default="standard", pattern="^(standard|short|audit|legal_hold|sensitive)$")
    proof_state: str = Field(default="unverified", pattern="^(verified|suspected|unverified|refuted|inconclusive)$")
    evidence_strength: Optional[str] = Field(default=None, pattern="^(claimed|signal|reproduced|cross_principal_verified)$")
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = None


__all__ = ["configure_evidence_router", "router"]
@router.get("/evidence/instances")
async def list_evidence_instances(
    finding_id: Optional[str] = Query(None),
    tool_receipt_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    summary_only: bool = Query(False),
):
    """List concrete evidence instances split from canonical findings."""
    try:
        finding_uuid = _optional_uuid(finding_id)
        tool_receipt_uuid = _optional_uuid(tool_receipt_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="finding_id and tool_receipt_id must be UUIDs when provided") from exc
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT *
            FROM evidence_instances
            WHERE ($2::uuid IS NULL OR finding_id = $2)
              AND ($3::uuid IS NULL OR tool_receipt_id = $3)
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
            finding_uuid,
            tool_receipt_uuid,
        )
    return {
        "evidence_instances": [
            _public_evidence_instance_summary(row) if summary_only else _public_evidence_instance_row(row)
            for row in rows
        ],
        "count": len(rows),
        "execution_enabled": False,
    }


@router.get("/evidence/instances/{instance_id}")
async def get_evidence_instance(instance_id: str):
    """Return one full, redacted proof observation for on-demand inspection."""
    try:
        instance_uuid = uuid.UUID(instance_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="instance_id must be a UUID") from exc
    async with _pool().acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM evidence_instances WHERE id = $1", instance_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Evidence instance not found")
    return _public_evidence_instance_row(row)


@router.post("/evidence/instances")
async def record_evidence_instance(req: EvidenceInstanceRequest):
    """Record a concrete evidence instance without changing finding state."""
    async with _pool().acquire() as conn:
        return await _record_evidence_instance(conn, req)


@router.get("/evidence/export-manifest")
async def evidence_export_manifest(
    finding_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    retention_class: Optional[str] = Query(None, pattern="^(standard|short|audit|legal_hold|sensitive)$"),
    limit: int = Query(200, ge=1, le=1000),
):
    """Return a content-free manifest for evidence export/audit."""
    retention_class = _direct_query_value(retention_class)
    try:
        finding_uuid = _optional_uuid(finding_id)
        scan_uuid = _optional_uuid(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="finding_id and scan_id must be UUIDs when provided") from exc
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT *
            FROM evidence_objects
            WHERE ($2::uuid IS NULL OR finding_id = $2)
              AND ($3::uuid IS NULL OR scan_id = $3)
              AND ($4::text IS NULL OR retention_class = $4)
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
            finding_uuid,
            scan_uuid,
            retention_class,
        )
    manifest = _evidence_export_manifest(rows)
    manifest["filters"] = {
        "finding_id": str(finding_uuid) if finding_uuid else None,
        "scan_id": str(scan_uuid) if scan_uuid else None,
        "retention_class": retention_class,
        "limit": limit,
    }
    return manifest


@router.get("/evidence/export-bundle")
async def evidence_export_bundle(
    finding_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    retention_class: Optional[str] = Query(None, pattern="^(standard|short|audit|legal_hold|sensitive)$"),
    limit: int = Query(200, ge=1, le=1000),
    record_event: bool = Query(False, description="Persist a content-free export event for deliberate audit logging."),
    export_format: str = Query("json", alias="format", pattern="^(json|zip)$"),
):
    """Return a content-free export bundle descriptor or metadata zip."""
    retention_class = _direct_query_value(retention_class)
    record_event = bool(_direct_query_value(record_event))
    export_format = str(_direct_query_value(export_format) or "json")
    try:
        finding_uuid = _optional_uuid(finding_id)
        scan_uuid = _optional_uuid(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="finding_id and scan_id must be UUIDs when provided") from exc
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT *
            FROM evidence_objects
            WHERE ($2::uuid IS NULL OR finding_id = $2)
              AND ($3::uuid IS NULL OR scan_id = $3)
              AND ($4::text IS NULL OR retention_class = $4)
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
            finding_uuid,
            scan_uuid,
            retention_class,
        )
    filters = {
        "finding_id": str(finding_uuid) if finding_uuid else None,
        "scan_id": str(scan_uuid) if scan_uuid else None,
        "retention_class": retention_class,
        "limit": limit,
    }
    manifest = _evidence_export_manifest(rows)
    manifest["filters"] = filters
    bundle = _evidence_export_bundle_descriptor(manifest, filters=filters)
    if record_event:
        async with _pool().acquire() as conn:
            bundle["export_event"] = await _record_export_event(
                conn,
                export_kind="evidence_export_bundle",
                command="evidence.export_bundle",
                bundle=bundle,
                filters=filters,
                created_by="api",
            )
    archive = _evidence_export_archive_descriptor(manifest, bundle, filters=filters)
    if export_format == "zip":
        archive_bytes = _evidence_export_archive_bytes(manifest, bundle)
        headers = {
            "Content-Disposition": f"attachment; filename=\"{archive['filename']}\"",
            "X-ShakerScan-Bundle-Hash": str(bundle.get("bundle_hash") or ""),
            "X-ShakerScan-Archive-SHA256": archive["archive_sha256"],
        }
        event = bundle.get("export_event")
        if isinstance(event, dict) and event.get("id"):
            headers["X-ShakerScan-Export-Event-Id"] = str(event["id"])
        return Response(content=archive_bytes, media_type=archive["media_type"], headers=headers)
    bundle["archive"] = archive
    return bundle


@router.post("/evidence/retention/sweep")
async def evidence_retention_sweep(req: EvidenceRetentionSweepRequest):
    return await _evidence_retention_sweep(req, pool=_pool())


@router.get("/evidence/retention/executions")
async def list_evidence_retention_executions(
    target_id: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
):
    """List durable unfinished deletion intents so an operator can resume after reload."""
    try:
        target_uuid = _optional_uuid(target_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="target_id must be a UUID") from exc
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM evidence_retention_previews
            WHERE status='executing'
              AND ($1::uuid IS NULL OR target_id=$1)
            ORDER BY execution_started_at DESC NULLS LAST, created_at DESC
            LIMIT $2
            """,
            target_uuid,
            limit,
        )
    executions = [
        _public_evidence_retention_execution(_evidence_retention_preview_payload(row))
        for row in rows
    ]
    return {"executions": executions, "count": len(executions), "execution_enabled": False}


@router.get("/evidence/{evidence_id}")
async def get_evidence_object(evidence_id: str):
    """A single durable evidence object (content already redaction-profiled)."""
    try:
        eid = uuid.UUID(evidence_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid evidence id")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM evidence_objects WHERE id = $1", eid)
    if not row:
        raise HTTPException(status_code=404, detail="Evidence object not found")
    return _finding_routes._public_evidence_object_row(row)
def _public_evidence_instance_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    payload["request_response_refs"] = _decode_json_value(payload.get("request_response_refs")) or []
    for key in ("principal_pair", "proof_observation", "metadata_json"):
        payload[key] = _redact_agent_payload(_decode_json_value(payload.get(key)) or {})
    payload["execution_enabled"] = False
    payload["findings_updated"] = 0
    return payload


def _public_evidence_instance_summary(row: Any) -> dict[str, Any]:
    """Bound list payloads while retaining the fields needed to triage evidence.

    Full proof observations can contain multiple request/response comparisons and
    body samples.  They remain available from the instance detail endpoint, but
    should not be repeated across a 200-row browse response.
    """
    payload = _public_evidence_instance_row(row)
    proof = payload.get("proof_observation") or {}
    family_proof = proof.get("family_proof") if isinstance(proof, dict) else {}
    if not isinstance(family_proof, dict):
        family_proof = {}
    comparisons = proof.get("comparisons") if isinstance(proof, dict) else []
    payload["proof_observation"] = {
        key: proof.get(key)
        for key in (
            "objective", "expected_signal", "falsifier", "family", "cwe",
            "verdict", "reason", "promotable", "proof_basis", "contract_id",
            "schema_version",
        )
        if proof.get(key) is not None
    }
    if family_proof:
        payload["proof_observation"]["family_proof"] = {
            key: family_proof.get(key)
            for key in (
                "family", "cwe", "verdict", "reason", "promotable",
                "proof_source", "reproduction_count", "restoration_verified",
            )
            if family_proof.get(key) is not None
        }
    payload["comparison_count"] = len(comparisons) if isinstance(comparisons, list) else 0
    payload["proof_payload_included"] = False
    # These can also be large and are not rendered by the browse table.
    payload["request_response_refs"] = []
    payload["principal_pair"] = {}
    payload["metadata_json"] = {}
    return payload


def _evidence_export_manifest(rows: Sequence[Any], *, generated_at: Optional[datetime] = None) -> dict[str, Any]:
    generated = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    objects = [_evidence_manifest_entry(row) for row in rows]
    retention_counts = Counter(str(item.get("retention_class") or "unknown") for item in objects)
    storage_counts = Counter(str(item.get("storage_status") or "unknown") for item in objects)
    integrity_counts = Counter(str(item.get("storage_integrity") or "not_checked") for item in objects)
    manifest_hash = hashlib.sha256(
        json.dumps(objects, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "2026-07-06.evidence-export-manifest.v1",
        "generated_at": generated.isoformat(),
        "object_count": len(objects),
        "manifest_hash": manifest_hash,
        "retention_policy_days": EVIDENCE_RETENTION_DAYS,
        "retention_counts": dict(retention_counts),
        "storage_counts": dict(storage_counts),
        "integrity_counts": dict(integrity_counts),
        "content_included": False,
        "objects": objects,
    }


def _evidence_export_bundle_descriptor(
    manifest: dict[str, Any],
    *,
    filters: Optional[dict[str, Any]] = None,
    generated_at: Optional[datetime] = None,
) -> dict[str, Any]:
    generated = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    objects = manifest.get("objects") if isinstance(manifest.get("objects"), list) else []
    finding_ids = sorted({str(item.get("finding_id")) for item in objects if item.get("finding_id")})
    scan_ids = sorted({str(item.get("scan_id")) for item in objects if item.get("scan_id")})
    evidence_reads = []
    for item in objects:
        object_id = item.get("id")
        if not object_id:
            continue
        evidence_reads.append({
            "evidence_object_id": str(object_id),
            "api_path": f"/evidence/{object_id}",
            "content_sha256": item.get("content_sha256"),
            "storage_uri": item.get("storage_uri"),
            "storage_integrity": item.get("storage_integrity"),
            "retention_class": item.get("retention_class"),
        })
    replay_plan = {
        "type": "api_read_replay",
        "content_included": False,
        "evidence_object_reads": evidence_reads,
        "finding_evidence_reads": [
            {"finding_id": finding_id, "api_path": f"/findings/{finding_id}/evidence"}
            for finding_id in finding_ids
        ],
    }
    bundle_core = {
        "manifest_hash": manifest.get("manifest_hash"),
        "object_count": manifest.get("object_count"),
        "filters": filters or {},
        "replay_plan": replay_plan,
    }
    bundle_hash = hashlib.sha256(
        json.dumps(bundle_core, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "2026-07-06.evidence-export-bundle.v1",
        "generated_at": generated.isoformat(),
        "bundle_hash": bundle_hash,
        "manifest_hash": manifest.get("manifest_hash"),
        "object_count": manifest.get("object_count", len(objects)),
        "content_included": False,
        "filters": filters or {},
        "retention_counts": manifest.get("retention_counts") or {},
        "storage_counts": manifest.get("storage_counts") or {},
        "integrity_counts": manifest.get("integrity_counts") or {},
        "finding_ids": finding_ids,
        "scan_ids": scan_ids,
        "files": [
            {
                "name": "evidence-export-manifest.json",
                "kind": "manifest",
                "sha256": manifest.get("manifest_hash"),
                "content_included": False,
            },
            {
                "name": "evidence-export-replay-plan.json",
                "kind": "replay_plan",
                "sha256": hashlib.sha256(
                    json.dumps(replay_plan, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
                "content_included": False,
            },
        ],
        "replay_plan": replay_plan,
    }


def _evidence_export_archive_bytes(manifest: dict[str, Any], bundle: dict[str, Any]) -> bytes:
    """Build a deterministic content-free metadata archive for evidence export."""
    files = {
        "evidence-export-manifest.json": manifest,
        "evidence-export-bundle.json": bundle,
        "evidence-export-replay-plan.json": bundle.get("replay_plan") or {},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            payload = json.dumps(files[name], sort_keys=True, indent=2, default=str).encode("utf-8")
            info = zipfile.ZipInfo(name)
            info.date_time = (2026, 7, 6, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, payload)
    return buf.getvalue()


def _evidence_export_archive_descriptor(
    manifest: dict[str, Any],
    bundle: dict[str, Any],
    *,
    filters: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    archive_bytes = _evidence_export_archive_bytes(manifest, bundle)
    bundle_hash = str(bundle.get("bundle_hash") or "evidence-export")
    safe_suffix = re.sub(r"[^a-fA-F0-9]", "", bundle_hash)[:12] or "metadata"
    query = dict(filters or bundle.get("filters") or {})
    query["format"] = "zip"
    query = {k: v for k, v in query.items() if v is not None}
    files = []
    for name, payload in (
        ("evidence-export-manifest.json", manifest),
        ("evidence-export-bundle.json", bundle),
        ("evidence-export-replay-plan.json", bundle.get("replay_plan") or {}),
    ):
        encoded = json.dumps(payload, sort_keys=True, indent=2, default=str).encode("utf-8")
        files.append({
            "name": name,
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "size_bytes": len(encoded),
            "content_included": False,
        })
    return {
        "schema_version": "2026-07-06.evidence-export-archive.v1",
        "filename": f"shakerscan-evidence-export-{safe_suffix}.zip",
        "media_type": "application/zip",
        "content_included": False,
        "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "size_bytes": len(archive_bytes),
        "download_api_path": f"/evidence/export-bundle?{urllib.parse.urlencode(query)}",
        "files": files,
    }


async def _evidence_retention_sweep(req: EvidenceRetentionSweepRequest, *, pool: asyncpg.Pool):
    """Preview or execute exact, target-scoped evidence retention cleanup."""
    supplied_fields = set(getattr(req, "model_fields_set", set()))
    if req.dry_run:
        if req.preview_id:
            raise HTTPException(status_code=400, detail="preview_id is only valid when executing a retention sweep")
        if not req.target_id:
            raise HTTPException(status_code=400, detail="target_id is required for a retention preview")
        try:
            target_uuid = uuid.UUID(str(req.target_id))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="target_id must be a UUID") from exc
        effective_req = req.model_copy(update={"target_id": str(target_uuid)})
        current = datetime.now(timezone.utc)
        expires = current + timedelta(seconds=EVIDENCE_RETENTION_PREVIEW_TTL_SECONDS)
        preview_id = uuid.uuid4()
        async with pool.acquire() as conn:
            async with conn.transaction():
                target = await conn.fetchrow("SELECT id, url FROM targets WHERE id=$1 FOR SHARE", target_uuid)
                if not target:
                    raise HTTPException(status_code=404, detail="Target not found")
                rows = await conn.fetch(
                    """
                    SELECT eo.*
                    FROM evidence_objects eo
                    LEFT JOIN findings f ON f.id = eo.finding_id
                    LEFT JOIN scans s ON s.id = eo.scan_id
                    WHERE ($2::text IS NULL OR eo.retention_class = $2)
                      AND eo.retention_class IN ('short', 'sensitive', 'standard', 'audit')
                      AND eo.created_at <= $4::timestamptz - (
                          CASE
                              WHEN $5::int IS NULL THEN
                                  CASE eo.retention_class
                                      WHEN 'short' THEN 30
                                      WHEN 'sensitive' THEN 90
                                      WHEN 'standard' THEN 365
                                      WHEN 'audit' THEN 2555
                                  END
                              WHEN eo.retention_class = 'sensitive' THEN GREATEST($5::int, 90)
                              WHEN eo.retention_class = 'audit' THEN GREATEST($5::int, 2555)
                              ELSE $5::int
                          END * INTERVAL '1 day'
                      )
                      AND eo.retention_delete_pending_at IS NULL
                      AND (eo.finding_id IS NOT NULL OR eo.scan_id IS NOT NULL)
                      AND (eo.finding_id IS NULL OR f.target_id = $1)
                      AND (eo.scan_id IS NULL OR s.target_id = $1)
                      AND (f.target_id = $1 OR s.target_id = $1)
                      AND (f.id IS NULL OR f.status <> 'active')
                    ORDER BY eo.created_at ASC, eo.id ASC
                    LIMIT $3
                    """,
                    target_uuid,
                    effective_req.retention_class,
                    effective_req.limit,
                    current,
                    effective_req.older_than_days,
                )
                candidates = _evidence_retention_candidates(
                    rows,
                    now=current,
                    older_than_days=effective_req.older_than_days,
                    retention_class_filter=effective_req.retention_class,
                )
                candidates = await _enrich_evidence_retention_candidates(
                    conn,
                    candidates,
                    delete_local_files=effective_req.delete_local_files,
                )
                payload = {
                    "preview_id": str(preview_id),
                    "target_id": str(target_uuid),
                    "schema_version": EVIDENCE_RETENTION_PREVIEW_SCHEMA_VERSION,
                    "issued_at": current.isoformat(),
                    "expires_at": expires.isoformat(),
                    "criteria": _evidence_retention_criteria(effective_req),
                    "policy_hash": _evidence_retention_policy_hash(),
                    "candidates": _evidence_retention_candidate_snapshot(candidates),
                    "status": "ready",
                }
                payload["preview_hash"] = _evidence_retention_preview_hash(payload)
                await conn.execute(
                    """
                    INSERT INTO evidence_retention_previews (
                        id, target_id, schema_version, criteria_json,
                        candidate_snapshot_json, preview_hash, policy_hash,
                        status, created_at, expires_at
                    ) VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,'ready',$8,$9)
                    """,
                    preview_id,
                    target_uuid,
                    EVIDENCE_RETENTION_PREVIEW_SCHEMA_VERSION,
                    json.dumps(payload["criteria"], sort_keys=True),
                    json.dumps(payload["candidates"], sort_keys=True),
                    payload["preview_hash"],
                    payload["policy_hash"],
                    current,
                    expires,
                )
        remote_candidate_count = sum(1 for item in candidates if item.get("remote_object"))
        return {
            "dry_run": True,
            "target_id": str(target_uuid),
            "candidate_count": len(candidates),
            "deleted_count": 0,
            "delete_local_files": effective_req.delete_local_files,
            "local_files": {"deleted": [], "missing": [], "errors": []},
            "remote_objects": {
                "candidate_count": remote_candidate_count,
                "deleted_count": 0,
                "missing_count": 0,
                "failed_count": 0,
                "preserved_count": remote_candidate_count,
                "delete_supported": True,
                "deleted": [],
                "missing": [],
                "errors": [],
            },
            "retention_policy_days": EVIDENCE_RETENTION_DAYS,
            "candidates": candidates,
            "execution_enabled": False,
            "preview_bound": True,
            "preview_status": "ready",
            "preview_id": str(preview_id),
            "preview_hash": payload["preview_hash"],
            "preview_issued_at": payload["issued_at"],
            "preview_expires_at": payload["expires_at"],
            "preview_criteria": payload["criteria"],
            "preview_candidate_count": len(payload["candidates"]),
        }

    changed_execution_fields = supplied_fields.intersection(EVIDENCE_RETENTION_PREVIEW_FIELDS)
    if changed_execution_fields:
        changed = ", ".join(sorted(changed_execution_fields))
        raise HTTPException(
            status_code=409,
            detail=f"Execution accepts only dry_run=false, preview_id, and approval_receipt_id; remove: {changed}",
        )
    if not req.preview_id:
        raise HTTPException(status_code=409, detail="A fresh retention preview is required before deletion")
    try:
        preview_uuid = uuid.UUID(str(req.preview_id))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="Retention preview ID is invalid; run a new preview") from exc

    async with pool.acquire() as conn:
        preview_row = await conn.fetchrow(
            "SELECT * FROM evidence_retention_previews WHERE id=$1",
            preview_uuid,
        )
        if not preview_row:
            raise HTTPException(status_code=409, detail="Retention preview was not found; run a new preview")
        preview_payload = _evidence_retention_preview_payload(preview_row)
        _validate_evidence_retention_preview_payload(preview_payload, allow_consumed=True)
        if preview_payload["status"] == "consumed":
            if preview_payload.get("approval_receipt_id") != str(req.approval_receipt_id or ""):
                raise HTTPException(status_code=409, detail="Retention preview was already used with another approval receipt")
            stored = dict(preview_payload.get("result") or {})
            stored["idempotent_replay"] = True
            return stored

        effective_req = _evidence_retention_request_from_preview(preview_payload)
        target_uuid = uuid.UUID(str(effective_req.target_id))
        target = await conn.fetchrow("SELECT id, url FROM targets WHERE id=$1", target_uuid)
        if not target:
            raise HTTPException(status_code=409, detail="Retention preview target no longer exists; run a new preview")
        approval_id = str(req.approval_receipt_id or "")
        expected_context = {
            "preview_id": str(preview_uuid),
            "preview_hash": preview_payload["preview_hash"],
            "target_id": str(target_uuid),
        }

        expected_snapshot = preview_payload["candidates"]
        try:
            candidate_ids = sorted(
                uuid.UUID(str(item["id"]))
                for item in expected_snapshot
                if isinstance(item, dict) and item.get("id")
            )
            if len(candidate_ids) != len(expected_snapshot):
                raise ValueError("missing candidate id")
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=409,
                detail="Retention preview candidate set is invalid; run a new preview",
            ) from exc

        locked_identity_keys: list[str] = []
        locked_blob_keys: list[str] = []
        drift_detail: str | None = None
        try:
            locked_identity_keys = await _acquire_evidence_retention_identity_locks(
                conn,
                _evidence_retention_identity_lock_keys(expected_snapshot),
            )
            locked_blob_keys = await _acquire_evidence_retention_blob_locks(
                conn,
                _evidence_retention_blob_lock_keys(expected_snapshot),
            )

            if preview_payload["status"] == "ready":
                # Validate after potentially waiting for blob writers. This keeps a
                # short-lived, exact-preview approval from expiring while queued on
                # locks and then being used anyway.
                approval_context = await _validate_approval_receipt_for_action(
                    conn,
                    req.approval_receipt_id,
                    target_id=target_uuid,
                    target_url=str(target["url"] or ""),
                    action_name="evidence.retention_sweep",
                    command="evidence.retention_sweep",
                    risk_tier="dangerous",
                    always_require_receipt=True,
                    require_target_binding=True,
                    required_action_name="evidence.retention_sweep",
                    required_action_context=expected_context,
                    require_expiry=True,
                    created_not_before=preview_payload["issued_at"],
                    expires_no_later_than=preview_payload["expires_at"],
                )
            else:
                approval_context = {
                    "approval_receipt_id": preview_payload.get("approval_receipt_id"),
                    "scope_receipt_id": preview_payload.get("scope_receipt_id"),
                }

            response: dict[str, Any] | None = None
            async with conn.transaction():
                locked_row = await conn.fetchrow(
                    "SELECT * FROM evidence_retention_previews WHERE id=$1 FOR UPDATE",
                    preview_uuid,
                )
                if not locked_row:
                    drift_detail = "Retention preview disappeared; run a new preview"
                else:
                    locked_payload = _evidence_retention_preview_payload(locked_row)
                    _validate_evidence_retention_preview_payload(locked_payload, allow_consumed=True)
                    if locked_payload["status"] == "consumed":
                        if locked_payload.get("approval_receipt_id") != approval_id:
                            drift_detail = "Retention preview was already used with another approval receipt"
                        else:
                            response = dict(locked_payload.get("result") or {})
                            response["idempotent_replay"] = True
                    elif locked_payload["status"] == "executing":
                        if locked_payload.get("approval_receipt_id") != approval_id:
                            drift_detail = "Retention preview is already executing with another approval receipt"
                    else:
                        # Repeat validation after the preview row lock is held. The
                        # first validation writes a durable blocked record; this one
                        # closes the expiry race immediately before intent commit.
                        approval_context = await _validate_approval_receipt_for_action(
                            conn,
                            req.approval_receipt_id,
                            target_id=target_uuid,
                            target_url=str(target["url"] or ""),
                            action_name="evidence.retention_sweep",
                            command="evidence.retention_sweep",
                            risk_tier="dangerous",
                            always_require_receipt=True,
                            require_target_binding=True,
                            required_action_name="evidence.retention_sweep",
                            required_action_context=expected_context,
                            require_expiry=True,
                            created_not_before=locked_payload["issued_at"],
                            expires_no_later_than=locked_payload["expires_at"],
                            record_blocked=False,
                        )
                        rows = []
                        if candidate_ids:
                            rows = await conn.fetch(
                                """
                                SELECT * FROM evidence_objects
                                WHERE id = ANY($1::uuid[])
                                ORDER BY id
                                FOR UPDATE
                                """,
                                candidate_ids,
                            )
                        links_match = await _evidence_retention_links_match_target(
                            conn,
                            rows,
                            target_id=target_uuid,
                        ) if rows else not candidate_ids
                        candidates = _evidence_retention_candidates(
                            rows,
                            older_than_days=effective_req.older_than_days,
                            retention_class_filter=effective_req.retention_class,
                        )
                        candidates = await _enrich_evidence_retention_candidates(
                            conn,
                            candidates,
                            delete_local_files=effective_req.delete_local_files,
                        )
                        actual_snapshot = _evidence_retention_candidate_snapshot(candidates)
                        pending_elsewhere = any(
                            row.get("retention_delete_pending_at")
                            and str(row.get("retention_delete_preview_id") or "") != str(preview_uuid)
                            for row in rows
                        )
                        if not links_match or pending_elsewhere or actual_snapshot != expected_snapshot:
                            drift_detail = (
                                "Evidence eligibility, ownership, or storage references changed after preview; "
                                "no deletion was attempted. Run a new preview"
                            )
                            await conn.execute(
                                """
                                UPDATE evidence_retention_previews
                                SET status='stale', result_json=$2::jsonb
                                WHERE id=$1 AND status='ready'
                                """,
                                preview_uuid,
                                json.dumps({"reason": "candidate_snapshot_changed"}),
                            )
                        else:
                            already_used = await conn.fetchval(
                                """
                                SELECT id FROM evidence_retention_previews
                                WHERE approval_receipt_id=$1 AND id<>$2
                                LIMIT 1
                                """,
                                uuid.UUID(approval_id),
                                preview_uuid,
                            )
                            if already_used:
                                raise HTTPException(
                                    status_code=409,
                                    detail="Approval receipt was already used for another retention preview",
                                )
                            if candidate_ids:
                                marked = await conn.fetch(
                                    """
                                    UPDATE evidence_objects
                                    SET retention_delete_preview_id=$1,
                                        retention_delete_pending_at=NOW()
                                    WHERE id = ANY($2::uuid[])
                                      AND retention_delete_pending_at IS NULL
                                    RETURNING id
                                    """,
                                    preview_uuid,
                                    candidate_ids,
                                )
                                if {row["id"] for row in marked} != set(candidate_ids):
                                    raise HTTPException(
                                        status_code=409,
                                        detail="Evidence deletion intent conflicted with another operation; run a new preview",
                                    )
                            await conn.execute(
                                """
                                UPDATE evidence_retention_previews
                                SET status='executing', approval_receipt_id=$2,
                                    scope_receipt_id=$3, execution_started_at=NOW()
                                WHERE id=$1 AND status='ready'
                                """,
                                preview_uuid,
                                uuid.UUID(approval_id),
                                str(approval_context.get("scope_receipt_id") or "") or None,
                            )

            if response is not None:
                return response
            if drift_detail:
                raise HTTPException(status_code=409, detail=drift_detail)

            # The exact deletion intent is now durable. External side effects run
            # outside SQL transactions; retries of an `executing` preview safely
            # resume and treat already-missing content-addressed blobs as success.
            runtime_candidates: list[dict[str, Any]] = []
            consistency_errors: list[dict[str, str]] = []
            guard_detail: str | None = None
            remote_result: dict[str, Any] = {"deleted": [], "missing": [], "errors": [], "deleted_ids": []}
            file_result: dict[str, Any] = {"deleted": [], "missing": [], "errors": [], "deleted_ids": []}
            # The committed `executing` row is the deletion linearization point:
            # ownership and active-finding protection were checked while that
            # intent was recorded. A retry must finish the same intent even if a
            # finding resurfaces later; staling it after a blob may already have
            # been deleted would leave a durable row pointing at missing content.
            # Evidence-row and advisory locks still prevent the candidate itself
            # from being replaced while the irreversible side effect runs.
            async with conn.transaction():
                current_rows = []
                if candidate_ids:
                    current_rows = await conn.fetch(
                        """
                        SELECT * FROM evidence_objects
                        WHERE id = ANY($1::uuid[])
                        ORDER BY id
                        FOR UPDATE
                        """,
                        candidate_ids,
                    )
                rows_by_id = {str(row["id"]): row for row in current_rows}
                safe_candidates: list[dict[str, Any]] = []
                for snapshot in expected_snapshot:
                    item_id = str(snapshot.get("id") or "")
                    row = rows_by_id.get(item_id)
                    if not row:
                        consistency_errors.append({"evidence_object_id": item_id, "error": "row_missing_during_execution"})
                        continue
                    if (
                        not _evidence_retention_row_matches_snapshot(row, snapshot)
                        or str(row.get("retention_delete_preview_id") or "") != str(preview_uuid)
                        or not row.get("retention_delete_pending_at")
                    ):
                        consistency_errors.append({"evidence_object_id": item_id, "error": "row_changed_during_execution"})
                        continue
                    candidate = dict(snapshot)
                    candidate["storage_backend"] = _evidence_storage_backend(str(candidate.get("storage_uri") or ""))
                    candidate["remote_object"] = candidate["storage_backend"] == "s3"
                    candidate["local_file"] = candidate["storage_backend"] == "local"
                    safe_candidates.append(candidate)
                if consistency_errors:
                    guard_detail = (
                        "Evidence row identity changed after deletion intent; "
                        "no new blob deletion was attempted"
                    )
                    await conn.execute(
                        """
                        UPDATE evidence_objects
                        SET retention_delete_preview_id=NULL,
                            retention_delete_pending_at=NULL
                        WHERE retention_delete_preview_id=$1
                        """,
                        preview_uuid,
                    )
                    await conn.execute(
                        """
                        UPDATE evidence_retention_previews
                        SET status='stale', result_json=$2::jsonb
                        WHERE id=$1 AND status='executing'
                        """,
                        preview_uuid,
                        json.dumps({"reason": "execution_guard_changed", "errors": consistency_errors}),
                    )
                else:
                    # Use the approved snapshot consequences verbatim. In
                    # particular, preserve_shared may never become delete_* at
                    # runtime even if another reference disappears.
                    runtime_candidates = safe_candidates
                    remote_result, file_result = await _run_evidence_retention_deletion_io(
                        [item for item in runtime_candidates if item.get("planned_blob_action") == "delete_remote"],
                        [item for item in runtime_candidates if item.get("planned_blob_action") == "delete_local"],
                    )
            if guard_detail:
                raise HTTPException(status_code=409, detail=guard_detail)
            remote_success_ids = set(remote_result.get("deleted_ids") or [])
            local_success_ids = set(file_result.get("deleted_ids") or [])
            deletable: list[uuid.UUID] = []
            for item in runtime_candidates:
                item_id = str(item.get("id") or "")
                action = str(item.get("planned_blob_action") or "row_only")
                if action == "delete_remote" and item_id not in remote_success_ids:
                    continue
                if action == "delete_local" and item_id not in local_success_ids:
                    continue
                deletable.append(uuid.UUID(item_id))

            async with conn.transaction():
                final_row = await conn.fetchrow(
                    "SELECT * FROM evidence_retention_previews WHERE id=$1 FOR UPDATE",
                    preview_uuid,
                )
                if not final_row:
                    raise HTTPException(status_code=409, detail="Retention execution intent disappeared")
                final_payload = _evidence_retention_preview_payload(final_row)
                _validate_evidence_retention_preview_payload(final_payload, allow_consumed=True)
                if final_payload["status"] == "consumed":
                    if final_payload.get("approval_receipt_id") != approval_id:
                        raise HTTPException(status_code=409, detail="Retention preview was consumed by another approval")
                    stored = dict(final_payload.get("result") or {})
                    stored["idempotent_replay"] = True
                    return stored
                if final_payload["status"] != "executing" or final_payload.get("approval_receipt_id") != approval_id:
                    raise HTTPException(status_code=409, detail="Retention execution intent is no longer valid")

                deleted_rows = []
                if deletable:
                    deleted_rows = await conn.fetch(
                        """
                        DELETE FROM evidence_objects
                        WHERE id = ANY($1::uuid[])
                          AND retention_delete_preview_id=$2
                        RETURNING id
                        """,
                        sorted(deletable),
                        preview_uuid,
                    )
                deleted_ids = sorted(str(row["id"]) for row in deleted_rows)
                await conn.execute(
                    """
                    UPDATE evidence_objects
                    SET retention_delete_preview_id=NULL,
                        retention_delete_pending_at=NULL
                    WHERE retention_delete_preview_id=$1
                    """,
                    preview_uuid,
                )
                deleted_count = len(deleted_ids)
                remote_candidate_count = sum(1 for item in runtime_candidates if item.get("remote_object"))
                remote_success_count = len(remote_success_ids)
                storage_failed = bool(
                    remote_result.get("errors")
                    or file_result.get("errors")
                    or consistency_errors
                    or deleted_count != len(expected_snapshot)
                )
                command_status = "partial" if storage_failed else "completed"
                command_result = await _record_command_result(
                    conn,
                    command="evidence.retention_sweep",
                    status=command_status,
                    risk_tier="dangerous",
                    target_id=target_uuid,
                    scope_receipt_id=str(approval_context.get("scope_receipt_id") or "") or None,
                    approval_receipt_id=req.approval_receipt_id,
                    evidence_object_ids=deleted_ids,
                    operator_message=(
                        f"Swept {deleted_count} of {len(expected_snapshot)} previewed evidence object(s); "
                        f"{len(file_result.get('deleted', []))} local file(s) removed; "
                        f"{len(remote_result.get('deleted', [])) + len(remote_result.get('missing', []))} "
                        "remote blob(s) retired"
                    ),
                    result_json={
                        "target_id": str(target_uuid),
                        "preview_id": str(preview_uuid),
                        "preview_hash": final_payload["preview_hash"],
                        "candidate_count": len(expected_snapshot),
                        "deleted_count": deleted_count,
                        "remote_candidate_count": remote_candidate_count,
                        "remote_success_count": remote_success_count,
                        "remote_failed_count": len(remote_result.get("errors", [])),
                        "local_failed_count": len(file_result.get("errors", [])),
                        "consistency_failed_count": len(consistency_errors),
                    },
                    next_action="/settings/arsenal?tab=timeline",
                )
                response = {
                    "dry_run": False,
                    "target_id": str(target_uuid),
                    "candidate_count": len(expected_snapshot),
                    "deleted_count": deleted_count,
                    "delete_local_files": effective_req.delete_local_files,
                    "local_files": {
                        "deleted": file_result.get("deleted", []),
                        "missing": file_result.get("missing", []),
                        "errors": file_result.get("errors", []),
                    },
                    "remote_objects": {
                        "candidate_count": remote_candidate_count,
                        "deleted_count": len(remote_result.get("deleted", [])),
                        "missing_count": len(remote_result.get("missing", [])),
                        "failed_count": len(remote_result.get("errors", [])),
                        "preserved_count": max(0, remote_candidate_count - remote_success_count),
                        "delete_supported": True,
                        "deleted": remote_result.get("deleted", []),
                        "missing": remote_result.get("missing", []),
                        "errors": remote_result.get("errors", []),
                    },
                    "consistency_errors": consistency_errors,
                    "retention_policy_days": EVIDENCE_RETENTION_DAYS,
                    "candidates": runtime_candidates,
                    "execution_enabled": True,
                    "preview_bound": True,
                    "preview_status": "consumed",
                    "preview_id": str(preview_uuid),
                    "preview_hash": final_payload["preview_hash"],
                    "preview_issued_at": final_payload["issued_at"],
                    "preview_expires_at": final_payload["expires_at"],
                    "preview_criteria": final_payload["criteria"],
                    "preview_candidate_count": len(expected_snapshot),
                    "operation_id": command_result["id"],
                    "idempotent_replay": False,
                }
                await conn.execute(
                    """
                    UPDATE evidence_retention_previews
                    SET status='consumed', operation_id=$2,
                        result_json=$3::jsonb, consumed_at=NOW()
                    WHERE id=$1 AND status='executing'
                    """,
                    preview_uuid,
                    uuid.UUID(str(command_result["id"])),
                    json.dumps(response, default=str, sort_keys=True),
                )
            return response
        finally:
            await _release_evidence_retention_blob_locks(conn, locked_blob_keys)
            await _release_evidence_retention_identity_locks(conn, locked_identity_keys)


def _public_evidence_retention_execution(payload: dict[str, Any]) -> dict[str, Any]:
    """Content-free recovery descriptor for a durable executing intent."""
    candidates = list(payload.get("candidates") or [])
    remote_count = sum(1 for item in candidates if item.get("planned_blob_action") == "delete_remote")
    return {
        "dry_run": False,
        "target_id": payload["target_id"],
        "candidate_count": len(candidates),
        "deleted_count": 0,
        "delete_local_files": bool((payload.get("criteria") or {}).get("delete_local_files", True)),
        "local_files": {"deleted": [], "missing": [], "errors": []},
        "remote_objects": {
            "candidate_count": remote_count,
            "deleted_count": 0,
            "missing_count": 0,
            "failed_count": 0,
            "preserved_count": remote_count,
            "delete_supported": True,
            "deleted": [],
            "missing": [],
            "errors": [],
        },
        "retention_policy_days": EVIDENCE_RETENTION_DAYS,
        "candidates": candidates,
        "execution_enabled": True,
        "preview_bound": True,
        "preview_status": payload["status"],
        "preview_id": payload["preview_id"],
        "preview_hash": payload["preview_hash"],
        "preview_issued_at": payload["issued_at"],
        "preview_expires_at": payload["expires_at"],
        "preview_criteria": payload["criteria"],
        "preview_candidate_count": len(candidates),
        "approval_receipt_id": payload.get("approval_receipt_id"),
        "execution_started_at": payload.get("execution_started_at"),
        "idempotent_replay": False,
    }
EVIDENCE_RETENTION_DAYS = {
    "short": 30,
    "sensitive": 90,
    "standard": 365,
    "audit": 2555,
    "legal_hold": None,
}


EVIDENCE_RETENTION_PREVIEW_FIELDS = (
    "target_id",
    "older_than_days",
    "retention_class",
    "limit",
    "delete_local_files",
)


def _evidence_retention_criteria(req: EvidenceRetentionSweepRequest) -> dict[str, Any]:
    """Canonical destructive scope persisted with a retention preview."""
    return {
        "scope": "target",
        "target_id": str(req.target_id or ""),
        "older_than_days": req.older_than_days,
        "retention_class": req.retention_class,
        "limit": int(req.limit),
        "delete_local_files": bool(req.delete_local_files),
    }


def _evidence_retention_candidate_snapshot(candidates: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Content-free identity snapshot used to detect preview drift before deletion."""
    snapshots: list[dict[str, Any]] = []
    for candidate in candidates:
        created_at = _parse_hypothesis_time(candidate.get("created_at"))
        snapshots.append({
            "id": str(candidate.get("id") or ""),
            "finding_id": str(candidate.get("finding_id")) if candidate.get("finding_id") else None,
            "scan_id": str(candidate.get("scan_id")) if candidate.get("scan_id") else None,
            "object_type": str(candidate.get("object_type") or ""),
            "content_sha256": str(candidate.get("content_sha256") or ""),
            "size_bytes": int(candidate.get("size_bytes") or 0),
            "storage_uri": str(candidate.get("storage_uri") or ""),
            "retention_class": str(candidate.get("retention_class") or ""),
            "created_at": created_at.isoformat() if created_at else None,
            "retention_days": int(candidate.get("retention_days") or 0),
            "shared_reference_count": int(candidate.get("shared_reference_count") or 0),
            "planned_blob_action": str(candidate.get("planned_blob_action") or "row_only"),
        })
    return sorted(snapshots, key=lambda item: item["id"])


def _evidence_retention_blob_lock_keys(candidates: Sequence[dict[str, Any]]) -> list[str]:
    # Lock every candidate hash, including previewed preserve_shared objects.
    # A runtime recheck must never widen a preserved consequence into deletion.
    return sorted({
        str(candidate.get("content_sha256") or "")
        for candidate in candidates
        if candidate.get("content_sha256")
    })


def _evidence_retention_identity_lock_keys(candidates: Sequence[dict[str, Any]]) -> list[str]:
    return sorted({
        f"{candidate.get('finding_id')}:{candidate.get('object_type')}"
        for candidate in candidates
        if candidate.get("finding_id") and candidate.get("object_type")
    })


async def _acquire_evidence_retention_identity_locks(conn, keys: Sequence[str]) -> list[str]:
    acquired: list[str] = []
    for key in sorted(set(str(item) for item in keys if item)):
        await conn.fetchval(
            "SELECT pg_advisory_lock(hashtextextended($1, 0))",
            f"evidence-row:{key}",
        )
        acquired.append(key)
    return acquired


async def _release_evidence_retention_identity_locks(conn, keys: Sequence[str]) -> None:
    for key in reversed(list(keys)):
        try:
            await conn.fetchval(
                "SELECT pg_advisory_unlock(hashtextextended($1, 0))",
                f"evidence-row:{key}",
            )
        except Exception:
            pass


async def _acquire_evidence_retention_blob_locks(conn, keys: Sequence[str]) -> list[str]:
    acquired: list[str] = []
    for key in sorted(set(str(item) for item in keys if item)):
        await conn.fetchval(
            "SELECT pg_advisory_lock(hashtextextended($1, 0))",
            f"evidence-blob:{key}",
        )
        acquired.append(key)
    return acquired


async def _release_evidence_retention_blob_locks(conn, keys: Sequence[str]) -> None:
    for key in reversed(list(keys)):
        try:
            await conn.fetchval(
                "SELECT pg_advisory_unlock(hashtextextended($1, 0))",
                f"evidence-blob:{key}",
            )
        except Exception:
            # Closing/resetting the session releases any remaining advisory locks.
            pass


def _evidence_retention_row_matches_snapshot(row: Any, snapshot: dict[str, Any]) -> bool:
    payload = row_to_dict(row)
    created_at = _parse_hypothesis_time(payload.get("created_at"))
    normalized = {
        "id": str(payload.get("id") or ""),
        "finding_id": str(payload.get("finding_id")) if payload.get("finding_id") else None,
        "scan_id": str(payload.get("scan_id")) if payload.get("scan_id") else None,
        "object_type": str(payload.get("object_type") or ""),
        "content_sha256": str(payload.get("content_sha256") or ""),
        "size_bytes": int(payload.get("size_bytes") or 0),
        "storage_uri": str(payload.get("storage_uri") or ""),
        "retention_class": str(payload.get("retention_class") or ""),
        "created_at": created_at.isoformat() if created_at else None,
    }
    return all(normalized[key] == snapshot.get(key) for key in normalized)


def _evidence_retention_request_from_preview(payload: dict[str, Any]) -> EvidenceRetentionSweepRequest:
    criteria = dict(payload.get("criteria") or {})
    return EvidenceRetentionSweepRequest(
        dry_run=False,
        target_id=criteria.get("target_id"),
        older_than_days=criteria.get("older_than_days"),
        retention_class=criteria.get("retention_class"),
        limit=criteria.get("limit", 200),
        delete_local_files=criteria.get("delete_local_files", True),
    )


def _evidence_storage_backend(storage_uri: str) -> str:
    value = str(storage_uri or "")
    if value.startswith("local:evidence_objects/"):
        return "local"
    if value.startswith("s3:evidence_objects/"):
        return "s3"
    if value.startswith("inline:"):
        return "inline"
    if not value:
        return "none"
    return "unknown"


def _evidence_manifest_entry(row: Any) -> dict[str, Any]:
    payload = _finding_routes._public_evidence_object_row(row)
    content = payload.pop("content", None)
    payload["content_included"] = False
    payload["content_available"] = content is not None
    return payload


def _evidence_retention_candidates(
    rows: Sequence[Any],
    *,
    now: Optional[datetime] = None,
    older_than_days: Optional[int] = None,
    retention_class_filter: Optional[str] = None,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for row in rows:
        candidate = _evidence_retention_candidate(
            row,
            now=now,
            older_than_days=older_than_days,
            retention_class_filter=retention_class_filter,
        )
        if candidate:
            candidates.append(candidate)
    return candidates


async def _enrich_evidence_retention_candidates(
    conn,
    candidates: Sequence[dict[str, Any]],
    *,
    delete_local_files: bool,
) -> list[dict[str, Any]]:
    """Bind shared-reference counts and the exact blob consequence into a preview."""
    enriched = [dict(candidate) for candidate in candidates]
    candidate_uri_counts = Counter(
        str(item.get("storage_uri") or "") for item in enriched if item.get("storage_uri")
    )
    total_uri_counts: dict[str, int] = {}
    if candidate_uri_counts:
        rows = await conn.fetch(
            """
            SELECT storage_uri, COUNT(*) AS reference_count
            FROM evidence_objects
            WHERE storage_uri = ANY($1::text[])
            GROUP BY storage_uri
            """,
            sorted(candidate_uri_counts),
        )
        total_uri_counts = {
            str(row["storage_uri"]): int(row["reference_count"] or 0)
            for row in rows if row["storage_uri"]
        }
    for candidate in enriched:
        storage_uri = str(candidate.get("storage_uri") or "")
        outside_references = max(
            0,
            total_uri_counts.get(storage_uri, 0) - candidate_uri_counts.get(storage_uri, 0),
        ) if storage_uri else 0
        backend = str(candidate.get("storage_backend") or _evidence_storage_backend(storage_uri))
        if outside_references:
            action = "preserve_shared"
        elif backend == "s3":
            action = "delete_remote"
        elif backend == "local" and delete_local_files:
            action = "delete_local"
        elif backend == "local":
            action = "preserve_local"
        else:
            action = "row_only"
        candidate["shared_reference_count"] = outside_references
        candidate["planned_blob_action"] = action
    return enriched


async def _evidence_retention_links_match_target(
    conn,
    rows: Sequence[Any],
    *,
    target_id: uuid.UUID,
) -> bool:
    """Lock linked owners and fail closed if scope or finding protection drifted."""
    finding_ids = sorted({
        uuid.UUID(str(row["finding_id"]))
        for row in rows if row.get("finding_id")
    })
    scan_ids = sorted({
        uuid.UUID(str(row["scan_id"]))
        for row in rows if row.get("scan_id")
    })
    findings: dict[uuid.UUID, Any] = {}
    scans: dict[uuid.UUID, Any] = {}
    if finding_ids:
        finding_rows = await conn.fetch(
            """
            SELECT id, target_id, status
            FROM findings
            WHERE id = ANY($1::uuid[])
            ORDER BY id
            FOR SHARE
            """,
            finding_ids,
        )
        findings = {row["id"]: row for row in finding_rows}
    if scan_ids:
        scan_rows = await conn.fetch(
            """
            SELECT id, target_id
            FROM scans
            WHERE id = ANY($1::uuid[])
            ORDER BY id
            FOR SHARE
            """,
            scan_ids,
        )
        scans = {row["id"]: row for row in scan_rows}
    for raw_row in rows:
        row = row_to_dict(raw_row)
        finding_id = uuid.UUID(str(row["finding_id"])) if row.get("finding_id") else None
        scan_id = uuid.UUID(str(row["scan_id"])) if row.get("scan_id") else None
        if not finding_id and not scan_id:
            return False
        if finding_id:
            finding = findings.get(finding_id)
            if (
                not finding
                or finding["target_id"] != target_id
                or str(finding["status"] or "") == "active"
            ):
                return False
        if scan_id:
            scan = scans.get(scan_id)
            if not scan or scan["target_id"] != target_id:
                return False
    return True


async def _run_evidence_retention_deletion_io(
    remote_candidates: Sequence[dict[str, Any]],
    local_candidates: Sequence[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run blocking blob I/O without releasing locks while threads are alive.

    Cancelling an ``asyncio.to_thread`` await does not stop its worker thread.
    Shield the aggregate task and, if the request is cancelled, wait until every
    underlying deletion call has actually returned before propagating cancellation
    to the transaction/lock cleanup path.
    """

    async def run_all() -> tuple[dict[str, Any], dict[str, Any]]:
        remote_result, local_result = await asyncio.gather(
            asyncio.to_thread(_delete_remote_evidence_objects, remote_candidates),
            asyncio.to_thread(_delete_local_evidence_files, local_candidates),
        )
        return remote_result, local_result

    work = asyncio.create_task(run_all())
    try:
        return await asyncio.shield(work)
    except asyncio.CancelledError:
        # A second cancellation may arrive during shutdown. Keep shielding until
        # the threads are truly done; only then may the caller release advisory
        # locks or roll back its row-lock transaction.
        while not work.done():
            try:
                await asyncio.shield(work)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if work.done():
            try:
                work.result()
            except Exception:
                pass
        raise
def _evidence_retention_candidate(
    row: Any,
    *,
    now: Optional[datetime] = None,
    older_than_days: Optional[int] = None,
    retention_class_filter: Optional[str] = None,
) -> dict[str, Any] | None:
    payload = row_to_dict(row)
    retention_class = str(payload.get("retention_class") or "standard").strip().lower() or "standard"
    if retention_class_filter and retention_class != retention_class_filter:
        return None
    if retention_class == "legal_hold":
        return None
    created_at = _parse_hypothesis_time(payload.get("created_at"))
    if not created_at:
        return None
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    age_days = max(0, int((current - created_at).total_seconds() // 86400))
    class_days = EVIDENCE_RETENTION_DAYS.get(retention_class)
    if class_days is None:
        # legal_hold or an unknown class: never sweep (fail-closed).
        return None
    if older_than_days is not None:
        # An operator override may only make retention MORE conservative for
        # compliance-sensitive classes; it can never delete something younger
        # than the class's own retention floor.
        threshold = (
            max(int(older_than_days), int(class_days))
            if retention_class in EVIDENCE_RETENTION_PROTECTED_CLASSES
            else int(older_than_days)
        )
    else:
        threshold = int(class_days)
    if age_days < threshold:
        return None
    storage_uri = str(payload.get("storage_uri") or "")
    storage_backend = _evidence_storage_backend(storage_uri)
    return {
        "id": str(payload.get("id")),
        "scan_id": str(payload.get("scan_id")) if payload.get("scan_id") else None,
        "finding_id": str(payload.get("finding_id")) if payload.get("finding_id") else None,
        "object_type": payload.get("object_type"),
        "content_sha256": payload.get("content_sha256"),
        "size_bytes": payload.get("size_bytes") or 0,
        "storage_uri": storage_uri,
        "retention_class": retention_class,
        "created_at": payload.get("created_at"),
        "age_days": age_days,
        "retention_days": threshold,
        "storage_backend": storage_backend,
        "local_file": bool(local_evidence_path(_results_dir(), storage_uri)),
        "remote_object": storage_backend == "s3",
        "remote_deletion_supported": storage_backend == "s3",
    }


def _delete_local_evidence_files(candidates: Sequence[dict[str, Any]]) -> dict[str, Any]:
    deleted: list[str] = []
    missing: list[str] = []
    errors: list[dict[str, str]] = []
    deleted_ids: set[str] = set()
    by_uri: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        by_uri.setdefault(str(candidate.get("storage_uri") or ""), []).append(candidate)
    for storage_uri, group in by_uri.items():
        candidate = group[0]
        path = local_evidence_path(_results_dir(), str(candidate.get("storage_uri") or ""))
        if not path:
            continue
        try:
            path.unlink()
            deleted.append(str(path))
            deleted_ids.update(str(item.get("id")) for item in group if item.get("id"))
        except FileNotFoundError:
            missing.append(str(path))
            deleted_ids.update(str(item.get("id")) for item in group if item.get("id"))
        except OSError as exc:
            errors.append({"path": str(path), "error": f"{type(exc).__name__}: {exc}"})
    return {"deleted": deleted, "missing": missing, "errors": errors, "deleted_ids": sorted(deleted_ids)}


def _delete_remote_evidence_objects(candidates: Sequence[dict[str, Any]]) -> dict[str, Any]:
    deleted: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []
    errors: list[dict[str, Any]] = []
    deleted_ids: set[str] = set()
    by_uri: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        by_uri.setdefault(str(candidate.get("storage_uri") or ""), []).append(candidate)
    for storage_uri, group in by_uri.items():
        candidate = group[0]
        if not candidate.get("remote_object"):
            continue
        result = delete_remote_evidence_object(storage_uri)
        result["evidence_object_id"] = str(candidate.get("id") or "")
        status = str(result.get("status") or "")
        if result.get("deleted"):
            deleted_ids.update(str(item.get("id")) for item in group if item.get("id"))
            item = {
                "evidence_object_ids": sorted(str(item.get("id")) for item in group if item.get("id")),
                "storage_uri": storage_uri,
            }
            if status == "missing":
                missing.append(item)
            else:
                deleted.append(item)
        else:
            errors.append(result)
    return {
        "deleted": deleted,
        "missing": missing,
        "errors": errors,
        "deleted_ids": sorted(deleted_ids),
    }
EVIDENCE_RETENTION_PROTECTED_CLASSES = frozenset({"audit", "sensitive"})
class EvidenceRetentionSweepRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool = True
    target_id: Optional[str] = None
    older_than_days: Optional[int] = Field(default=None, ge=0, le=3650)
    retention_class: Optional[str] = Field(default=None, pattern="^(standard|short|audit|legal_hold|sensitive)$")
    limit: int = Field(default=200, ge=1, le=1000)
    delete_local_files: bool = True
    approval_receipt_id: Optional[str] = None
    preview_id: Optional[str] = None


def _evidence_retention_preview_payload(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    criteria = _decode_json_value(payload.get("criteria_json")) or {}
    candidates = _decode_json_value(payload.get("candidate_snapshot_json")) or []
    issued_at = _parse_hypothesis_time(payload.get("created_at"))
    expires_at = _parse_hypothesis_time(payload.get("expires_at"))
    return {
        "preview_id": str(payload.get("id") or ""),
        "target_id": str(payload.get("target_id") or ""),
        "schema_version": int(payload.get("schema_version") or 0),
        "issued_at": issued_at.isoformat() if issued_at else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "criteria": criteria if isinstance(criteria, dict) else {},
        "policy_hash": str(payload.get("policy_hash") or ""),
        "candidates": candidates if isinstance(candidates, list) else [],
        "preview_hash": str(payload.get("preview_hash") or ""),
        "status": str(payload.get("status") or ""),
        "approval_receipt_id": str(payload.get("approval_receipt_id")) if payload.get("approval_receipt_id") else None,
        "scope_receipt_id": str(payload.get("scope_receipt_id")) if payload.get("scope_receipt_id") else None,
        "operation_id": str(payload.get("operation_id")) if payload.get("operation_id") else None,
        "execution_started_at": (
            parsed.isoformat()
            if (parsed := _parse_hypothesis_time(payload.get("execution_started_at")))
            else None
        ),
        "result": _decode_json_value(payload.get("result_json")) or {},
    }
