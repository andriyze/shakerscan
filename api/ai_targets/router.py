"""AI Gate routes: targets, principals, scans, transcripts, surfaces, and ops routing.

Extracted verbatim from the api.py monolith. Owns the AI Gate surface — target
and principal management, queueing AI safety scans, transcripts and their purge,
the AI surface inventory and attempts, campaign history and exports, connectivity
and MCP readiness probes, runtime risk, finding retest, scan replay, and the
natural-language operations router.

Collaborators that are still hubs inside api.py are injected by the composition
root as lazily-resolved callables, so the dependency direction stays app ->
router and existing test patches of those names keep working.
"""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
import re
from typing import Annotated, Any, Callable, Literal, Mapping, Optional, Sequence, Union
import urllib.parse
import uuid

import asyncpg
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from api_utils import (
        SEVERITY_ORDER, _clean_string_list, _content_free_hash, _direct_query_value,
        _int_or_none, _iso_or_none, _json_safe_row, _optional_uuid, _parse_iso_datetime,
        _record_map, _row_value, _severity_sort_value, _short_url_label, _uuid_or_400,
        extract_root_domain, utc_now, utc_now_iso,
    )
    import asm_inventory
    from ai_assurance import build_agent_blast_radius, build_ai_inventory, run_mcp_live_readiness_probe
    from ai_demo_scenarios import get_ai_test_scenarios
    from ai_gate.targets.rest_json import (
        append_query_params as ai_append_query_params,
        build_headers as ai_build_headers,
        build_url as ai_build_url,
        extract_response_text as ai_extract_response_text,
        replace_placeholders as ai_replace_placeholders,
    )
    from finding_routes import router as _finding_routes
    from redaction import redact_sensitive
    from request_models import ScanAdvancedLimits, ScanPublicCompatibilityOptions, ScanRequest
    from retest_contract import parse_json_field
    from runtime.credential_migration import (
        LegacyCredentialMigrationError, sync_legacy_ai_principal_credential,
        sync_legacy_ai_target_credential,
    )
    from runtime.credential_store import CredentialStoreError, PostgresCredentialProfileStore
    from secret_store import decrypt_secret, encrypt_secret
    from serialization import _decode_json_value, _json_object, _str_list, row_to_dict
    from targets import router as _targets_router
    from targets.router import AsmImproveRequest, AsmPolicyUpdate
except ModuleNotFoundError:  # package import in host-side tests
    from ..api_utils import (
        SEVERITY_ORDER, _clean_string_list, _content_free_hash, _direct_query_value,
        _int_or_none, _iso_or_none, _json_safe_row, _optional_uuid, _parse_iso_datetime,
        _record_map, _row_value, _severity_sort_value, _short_url_label, _uuid_or_400,
        extract_root_domain, utc_now, utc_now_iso,
    )
    from .. import asm_inventory
    from ..ai_assurance import build_agent_blast_radius, build_ai_inventory, run_mcp_live_readiness_probe
    from ..ai_demo_scenarios import get_ai_test_scenarios
    from ..ai_gate.targets.rest_json import (
        append_query_params as ai_append_query_params,
        build_headers as ai_build_headers,
        build_url as ai_build_url,
        extract_response_text as ai_extract_response_text,
        replace_placeholders as ai_replace_placeholders,
    )
    from ..finding_routes import router as _finding_routes
    from ..request_models import ScanAdvancedLimits, ScanPublicCompatibilityOptions, ScanRequest
    from ..retest_contract import parse_json_field
    from ..runtime.credential_migration import (
        LegacyCredentialMigrationError, sync_legacy_ai_principal_credential,
        sync_legacy_ai_target_credential,
    )
    from ..runtime.credential_store import CredentialStoreError, PostgresCredentialProfileStore
    from ..secret_store import decrypt_secret, encrypt_secret
    from ..serialization import _decode_json_value, _json_object, _str_list, row_to_dict
    from ..targets import router as _targets_router
    from ..targets.router import AsmImproveRequest, AsmPolicyUpdate
    from scanner.redaction import redact_sensitive


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


def configure_ai_targets_router(
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

# Cross-domain calls go through the owning module so a patch or later change on
# that module is seen here, instead of freezing a binding at import time.
def _mask_ai_target_secret(*a: Any, **k: Any) -> Any:
    return _targets_router._mask_ai_target_secret(*a, **k)


async def asm_gaps(*a: Any, **k: Any) -> Any:
    return await _targets_router.asm_gaps(*a, **k)


async def asm_improve(*a: Any, **k: Any) -> Any:
    return await _targets_router.asm_improve(*a, **k)


async def asm_set_policy(*a: Any, **k: Any) -> Any:
    return await _targets_router.asm_set_policy(*a, **k)


async def get_finding_record(*a: Any, **k: Any) -> Any:
    return await _finding_routes.get_finding_record(*a, **k)


async def mark_retest_enqueue_failed(*a: Any, **k: Any) -> Any:
    return await _finding_routes.mark_retest_enqueue_failed(*a, **k)


# Hub collaborators that still live in api.py, injected and resolved lazily.

def get_redis(*a: Any, **k: Any) -> Any:
    return _dep("get_redis")(*a, **k)


def enqueue_job(*a: Any, **k: Any) -> Any:
    return _dep("enqueue_job")(*a, **k)

def _load_effective_ai_settings(*a: Any, **k: Any) -> Any:
    return _dep("load_effective_ai_settings")(*a, **k)

def _sanitize_scan_options(*a: Any, **k: Any) -> Any:
    return _dep("sanitize_scan_options")(*a, **k)

def _ai_ops_execute_enabled(*a: Any, **k: Any) -> Any:
    return _dep("ai_ops_execute_enabled")(*a, **k)

def _legacy_credential_migration_http_error(*a: Any, **k: Any) -> Any:
    return _dep("legacy_credential_migration_http_error")(*a, **k)

async def submit_scan(*a: Any, **k: Any) -> Any:
    return await _dep("submit_scan")(*a, **k)

async def _validate_approval_receipt_for_action(*a: Any, **k: Any) -> Any:
    return await _dep("validate_approval_receipt_for_action")(*a, **k)

async def _record_command_result(*a: Any, **k: Any) -> Any:
    return await _dep("record_command_result")(*a, **k)


import copy
import logging

logger = logging.getLogger("shakerscan.api.ai_targets")
QUEUE_NAME = os.environ.get("SCAN_QUEUE_NAME", "scan_jobs")


@router.get("/ai/test-scenarios")
async def list_ai_test_scenarios(include_demo: bool = Query(False)):
    """Return scenario templates for AI Gate and model-intake workflows."""
    settings = _load_effective_ai_settings()
    return get_ai_test_scenarios(include_demo=bool(include_demo and settings.get("demo_mode_enabled")))


@router.post("/ai/demo/run")
async def run_ai_honey_demo(request: AIDemoRunRequest):
    """Queue a small Honey AI Gate demo suite when demo mode is enabled."""
    settings = _load_effective_ai_settings()
    if not settings.get("demo_mode_enabled"):
        raise HTTPException(status_code=403, detail="AI demo mode is disabled in settings")

    scenario_ids = request.scenario_ids or list(AI_DEMO_DEFAULT_SCENARIOS)
    scenario_ids = [str(item).strip() for item in scenario_ids if str(item).strip()]
    if not scenario_ids:
        raise HTTPException(status_code=400, detail="At least one demo scenario is required")
    if len(scenario_ids) > 10:
        raise HTTPException(status_code=400, detail="Demo run is limited to 10 scenarios")

    scanner_base_url = str(settings.get("demo_honey_scanner_url") or "").strip()
    if not scanner_base_url:
        raise HTTPException(status_code=400, detail="Configure a Honey scanner URL before running the demo")

    public_base_url = str(settings.get("demo_honey_public_url") or scanner_base_url).strip()
    registry = await _fetch_honey_ai_gate_registry(scanner_base_url)
    scenarios = {
        str(scenario.get("id")): scenario
        for scenario in registry.get("scenarios", [])
        if isinstance(scenario, dict) and scenario.get("id")
    }
    missing = [scenario_id for scenario_id in scenario_ids if scenario_id not in scenarios]
    if missing:
        raise HTTPException(status_code=400, detail=f"Honey registry does not include scenarios: {', '.join(missing)}")

    surface_config = {
        "rag": ("rag", "$.answer", "shaker-rag-lite"),
        "agent": ("agent_trace", "$", "shaker-agent-abuse"),
        "mcp": ("mcp_trace", "$.result", "shaker-mcp-security"),
    }
    run_id = f"demo-{utc_now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    queued: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    async with _pool().acquire() as conn:
        for scenario_id in scenario_ids:
            target_id: Any = None
            scenario = scenarios[scenario_id]
            try:
                surface = str(scenario.get("surface") or "rag")
                target_type, response_path, probe_pack = surface_config.get(surface, surface_config["rag"])
                metadata = copy.deepcopy(scenario.get("metadata_json") or {})
                expected = scenario.get("expected_shakerscan_findings") or []
                metadata.update({
                    "shakerscan_demo": True,
                    "demo_run_id": run_id,
                    "calibration_run": run_id,
                    "honey_scenario_id": scenario_id,
                    "expected_shakerscan_findings": expected,
                    "safe_fixture": scenario.get("safe_fixture") is True,
                })
                endpoint_url = _demo_target_url(
                    str(scenario.get("target_url") or ""),
                    scanner_base_url,
                    run_id,
                    scenario_id,
                )
                request_template = _normalize_ai_request_template(
                    _demo_request_template_with_prompt(scenario.get("target_template"), surface),
                    method=str(scenario.get("method") or "POST"),
                    target_type=target_type,
                )

                async with conn.transaction():
                    target_id = await conn.fetchval("""
                        INSERT INTO ai_targets (
                            name, target_type, endpoint_url, method, headers_template,
                            request_template, response_path, streaming_mode, rate_limit_rps,
                            token_budget, request_budget, production_mode, metadata_json, is_active
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'json', 10, 4000, $8, false, $9, true)
                        RETURNING id
                    """,
                        f"Honey demo {scenario_id}",
                        target_type,
                        endpoint_url,
                        _normalize_ai_method(str(scenario.get("method") or "POST")),
                        json.dumps({"Content-Type": "application/json", "Accept": "application/json"}),
                        json.dumps(request_template),
                        response_path,
                        request.request_budget,
                        json.dumps(metadata),
                    )
                    await conn.execute("""
                        INSERT INTO ai_target_credentials (
                            ai_target_id, auth_kind, header_name, secret_value,
                            secret_preview, metadata_json, rotated_at
                        ) VALUES ($1, 'none', NULL, NULL, NULL, '{}'::jsonb, NOW())
                    """,
                        target_id,
                    )

                scan = await _queue_ai_target_scan(
                    str(target_id),
                    AITargetScanRequest(
                        probe_pack=probe_pack,
                        scan_profile=request.scan_profile,
                        environment="development",
                        ai_judge_enabled=False,
                        semantic_judge_enabled=False,
                    ),
                )
                queued.append({
                    "scenario_id": scenario_id,
                    "name": scenario.get("name") or scenario_id,
                    "surface": surface,
                    "safe_fixture": scenario.get("safe_fixture") is True,
                    "expected_findings": expected,
                    "target_id": str(target_id),
                    "scan_id": scan["scan_id"],
                    "ui_url": scan["ui_url"],
                    "probe_pack": probe_pack,
                    "scan_profile": request.scan_profile,
                })
            except Exception as exc:
                logger.warning("Honey demo scenario %s failed to queue", scenario_id, exc_info=True)
                if target_id:
                    reason = f"Honey demo queue failed: {type(exc).__name__}: {exc}"
                    await conn.execute(
                        "UPDATE ai_targets SET is_active = false, updated_at = NOW() WHERE id = $1",
                        target_id,
                    )
                    await conn.execute(
                        """
                        UPDATE scans
                        SET status = 'failed',
                            error_message = $2,
                            completed_at = COALESCE(completed_at, NOW()),
                            updated_at = NOW()
                        WHERE ai_target_id = $1 AND status = 'pending'
                        """,
                        target_id,
                        reason[:1000],
                    )
                failed.append({
                    "scenario_id": scenario_id,
                    "name": scenario.get("name") or scenario_id,
                    "target_id": str(target_id) if target_id else None,
                    "error": f"{type(exc).__name__}: {exc}",
                })

    return {
        "run_id": run_id,
        "honey_registry_url": f"{public_base_url}/api/ai-gate/scenarios",
        "queued": queued,
        "failed": failed,
    }


@router.get("/ai/inventory")
async def get_ai_inventory(
    root_domain: Optional[str] = None,
    include_inactive: bool = False,
    include_resolved: bool = False,
    limit_scans: int = Query(150, ge=1, le=300),
):
    """Return AI assets, discovered AI-surface candidates, and blast-radius summaries."""
    AI_INVENTORY_INPUT_CAP = 500
    async with _pool().acquire() as conn:
        targets_query = """
            SELECT
                id, url, name, root_domain, is_active, discovery_source,
                last_score, last_grade, last_scanned_at, total_scans,
                active_findings_count, created_at, updated_at
            FROM targets
            WHERE ($1::boolean = true OR is_active = true)
              AND ($2::text IS NULL OR root_domain = $2::text)
            ORDER BY updated_at DESC
            LIMIT 500
        """
        targets = [row_to_dict(row) for row in await conn.fetch(targets_query, include_inactive, root_domain)]

        ai_query = """
            SELECT
                id, name, target_type, endpoint_url, method, streaming_mode,
                production_mode, rate_limit_rps, token_budget, request_budget,
                last_scanned_at, last_scan_id, metadata_json, is_active,
                created_at, updated_at
            FROM ai_targets
            WHERE ($1::boolean = true OR is_active = true)
              AND ($2::text IS NULL OR LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY production_mode DESC, updated_at DESC
            LIMIT 500
        """
        ai_targets = [row_to_dict(row) for row in await conn.fetch(ai_query, include_inactive, root_domain)]

        scans_query = """
            SELECT
                s.id, s.target_id, s.ai_target_id, s.target_url, s.status,
                s.scan_type, s.run_kind, s.result, s.created_at, s.completed_at,
                t.root_domain
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.result IS NOT NULL
              AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
              AND (
                $1::text IS NULL
                OR t.root_domain = $1::text
                OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($1::text) || '%'
              )
            ORDER BY s.created_at DESC
            LIMIT $2
        """
        scans = [row_to_dict(row) for row in await conn.fetch(scans_query, root_domain, limit_scans)]

        findings_query = """
            SELECT
                f.id, f.ai_target_id, f.scan_id, f.title, f.severity, f.status,
                f.source, f.tool, f.last_seen_at, ait.endpoint_url as ai_target_url
            FROM findings f
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE f.ai_target_id IS NOT NULL
              AND ($1::boolean = true OR f.status = 'active')
              AND ($2::text IS NULL OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY f.last_seen_at DESC NULLS LAST
            LIMIT 500
        """
        findings = [
            row_to_dict(row)
            for row in await conn.fetch(findings_query, include_resolved, root_domain)
        ]

    inventory = build_ai_inventory(
        targets=targets,
        ai_targets=ai_targets,
        scans=scans,
        findings=findings,
    )
    # Surface input-list truncation so a capped inventory is not read as complete
    # (mirrors the candidate-list truncation flag inside build_ai_inventory).
    truncated_inputs = [
        name for name, rows in (
            ("targets", targets), ("ai_targets", ai_targets), ("findings", findings),
        ) if len(rows) >= AI_INVENTORY_INPUT_CAP
    ]
    summary = inventory.get("summary")
    if isinstance(summary, dict):
        summary["inputs_truncated"] = bool(truncated_inputs) or bool(summary.get("candidates_truncated"))
        if truncated_inputs:
            summary["truncated_inputs"] = truncated_inputs
            summary["input_cap"] = AI_INVENTORY_INPUT_CAP
    return inventory


@router.get("/ai/targets")
async def list_ai_targets(
    include_inactive: bool = False,
    include_demo: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List saved AI Gate targets."""
    async with _pool().acquire() as conn:
        query = "SELECT * FROM ai_targets"
        params: list[Any] = []
        conditions: list[str] = []
        if not include_inactive:
            conditions.append("is_active = true")
        if not include_demo:
            conditions.append(f"NOT {_ai_demo_target_sql_predicate()}")
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC LIMIT $1 OFFSET $2"
        params.extend([limit, offset])
        targets = await conn.fetch(query, *params)
        count_query = "SELECT COUNT(*) FROM ai_targets"
        if conditions:
            count_query += " WHERE " + " AND ".join(conditions)
        total = await conn.fetchval(count_query)
        target_ids = [row["id"] for row in targets]
        credentials = []
        if target_ids:
            credentials = await conn.fetch(
                "SELECT * FROM ai_target_credentials WHERE ai_target_id = ANY($1::uuid[])",
                target_ids,
            )

    credential_by_target = {row["ai_target_id"]: row for row in credentials}
    return {
        "targets": [_ai_target_response(row, credential_by_target.get(row["id"])) for row in targets],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/ai/targets/{target_id}/campaign-history")
async def get_ai_target_campaign_history(target_id: str, limit: int = Query(12, ge=1, le=50)):
    """Return longitudinal AI Gate campaign history for one saved target."""
    try:
        target_uuid = uuid.UUID(target_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid AI target id")

    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT id FROM ai_targets WHERE id = $1", target_uuid)
        if not target:
            raise HTTPException(status_code=404, detail="AI Gate target not found")
        rows = await conn.fetch(
            """
            SELECT id, ai_target_id, target_url, options, result, run_kind, status,
                   score, grade, findings_count, created_at, completed_at
            FROM scans
            WHERE ai_target_id = $1
              AND status = 'completed'
              AND run_kind LIKE 'ai_%'
              AND result IS NOT NULL
            ORDER BY COALESCE(completed_at, created_at) DESC, created_at DESC
            LIMIT $2
            """,
            target_uuid,
            limit,
        )
    return _build_ai_target_campaign_history(str(target_uuid), list(rows), limit=limit)


@router.get("/ai/targets/{target_id}/campaign-history/export")
async def get_ai_target_campaign_history_export(target_id: str, limit: int = Query(12, ge=1, le=50)):
    """Return a content-free AI Gate target history export with readiness trends."""
    try:
        target_uuid = uuid.UUID(target_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid AI target id")

    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT id FROM ai_targets WHERE id = $1", target_uuid)
        if not target:
            raise HTTPException(status_code=404, detail="AI Gate target not found")
        rows = await conn.fetch(
            """
            SELECT id, ai_target_id, target_url, options, result, run_kind, status,
                   score, grade, findings_count, created_at, completed_at
            FROM scans
            WHERE ai_target_id = $1
              AND status = 'completed'
              AND run_kind LIKE 'ai_%'
              AND result IS NOT NULL
            ORDER BY COALESCE(completed_at, created_at) DESC, created_at DESC
            LIMIT $2
            """,
            target_uuid,
            limit,
        )
    history = _build_ai_target_campaign_history(str(target_uuid), list(rows), limit=limit)
    return _build_ai_target_campaign_history_export(history)


@router.post("/ai/targets")
async def create_ai_target(request: AITargetCreate):
    """Create an AI Gate target."""
    target_type = _normalize_ai_target_type(request.target_type)
    endpoint_url = _normalize_ai_endpoint_url(request.endpoint_url)
    method = _normalize_ai_method(request.method)
    streaming_mode = _normalize_ai_streaming_mode(request.streaming_mode)
    headers_template = _normalize_ai_headers_template(request.headers_template)
    request_template = _normalize_ai_request_template(
        request.request_template,
        method=method,
        target_type=target_type,
    )
    credential = _build_ai_credential_db_record(request.credential)
    target_name = request.name or urllib.parse.urlparse(endpoint_url).hostname or endpoint_url

    async with _pool().acquire() as conn:
        existing = await conn.fetchrow("SELECT id FROM ai_targets WHERE endpoint_url = $1", endpoint_url)
        if existing:
            raise HTTPException(status_code=409, detail="AI target already exists for this endpoint_url")

        async with conn.transaction():
            target_id = await conn.fetchval("""
                INSERT INTO ai_targets (
                    name, target_type, endpoint_url, method, headers_template,
                    request_template, response_path, streaming_mode, rate_limit_rps,
                    token_budget, request_budget, production_mode, metadata_json, is_active
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                RETURNING id
            """,
                target_name,
                target_type,
                endpoint_url,
                method,
                json.dumps(headers_template),
                json.dumps(request_template),
                request.response_path,
                streaming_mode,
                request.rate_limit_rps,
                request.token_budget,
                request.request_budget,
                request.production_mode,
                json.dumps(request.metadata_json or {}),
                request.is_active,
            )
            credential_id = await conn.fetchval("""
                INSERT INTO ai_target_credentials (
                    ai_target_id, auth_kind, header_name, secret_value,
                    secret_preview, metadata_json, rotated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
                RETURNING id
            """,
                target_id,
                credential["auth_kind"],
                credential["header_name"],
                credential["secret_value"],
                credential["secret_preview"],
                json.dumps(credential["metadata_json"]),
            )
            await _sync_ai_target_credential_profile(conn, credential_id)

        target = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", target_id)
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            target_id,
        )
    return {"target": _ai_target_response(target, credential_row)}


@router.patch("/ai/targets/{target_id}")
async def update_ai_target(target_id: str, request: AITargetUpdate):
    """Update an AI Gate target."""
    payload = request.model_dump(exclude_unset=True)
    async with _pool().acquire() as conn:
        existing = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", uuid.UUID(target_id))
        if not existing:
            raise HTTPException(status_code=404, detail="AI target not found")
        existing_credential = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            uuid.UUID(target_id),
        )

        update_data: dict[str, Any] = {}
        if "name" in payload:
            update_data["name"] = payload["name"] or existing["name"]
        if "endpoint_url" in payload and payload["endpoint_url"] is not None:
            update_data["endpoint_url"] = _normalize_ai_endpoint_url(payload["endpoint_url"])
        effective_method = _normalize_ai_method(payload.get("method") or existing["method"])
        if "method" in payload:
            update_data["method"] = effective_method
        if "headers_template" in payload:
            update_data["headers_template"] = json.dumps(_normalize_ai_headers_template(payload.get("headers_template")))
        if "request_template" in payload:
            update_data["request_template"] = json.dumps(
                _normalize_ai_request_template(
                    payload.get("request_template"),
                    method=effective_method,
                    target_type=existing["target_type"],
                )
            )
        if "response_path" in payload:
            update_data["response_path"] = payload.get("response_path") or None
        if "streaming_mode" in payload and payload["streaming_mode"] is not None:
            update_data["streaming_mode"] = _normalize_ai_streaming_mode(payload["streaming_mode"])
        for key in ("rate_limit_rps", "token_budget", "request_budget"):
            if key in payload:
                update_data[key] = payload[key]
        if "production_mode" in payload:
            update_data["production_mode"] = bool(payload["production_mode"])
        if "metadata_json" in payload:
            update_data["metadata_json"] = json.dumps(payload.get("metadata_json") or {})
        if "is_active" in payload:
            update_data["is_active"] = bool(payload["is_active"])

        async with conn.transaction():
            if update_data:
                assignments = []
                values = []
                for idx, (key, value) in enumerate(update_data.items(), start=1):
                    assignments.append(f"{key} = ${idx}")
                    values.append(value)
                assignments.append("updated_at = NOW()")
                values.append(uuid.UUID(target_id))
                await conn.execute(
                    f"UPDATE ai_targets SET {', '.join(assignments)} WHERE id = ${len(values)}",
                    *values,
                )

            if request.credential is not None:
                credential = _build_ai_credential_db_record(
                    request.credential,
                    dict(existing_credential) if existing_credential else None,
                )
                await conn.execute("""
                    INSERT INTO ai_target_credentials (
                        ai_target_id, auth_kind, header_name, secret_value,
                        secret_preview, metadata_json, rotated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
                    ON CONFLICT (ai_target_id) DO UPDATE SET
                        auth_kind = EXCLUDED.auth_kind,
                        header_name = EXCLUDED.header_name,
                        secret_value = EXCLUDED.secret_value,
                        secret_preview = EXCLUDED.secret_preview,
                        metadata_json = EXCLUDED.metadata_json,
                        rotated_at = NOW(),
                        updated_at = NOW()
                """,
                    uuid.UUID(target_id),
                    credential["auth_kind"],
                    credential["header_name"],
                    credential["secret_value"],
                    credential["secret_preview"],
                    json.dumps(credential["metadata_json"]),
                )
                credential_id = await conn.fetchval(
                    "SELECT id FROM ai_target_credentials WHERE ai_target_id=$1",
                    uuid.UUID(target_id),
                )
                await _sync_ai_target_credential_profile(conn, credential_id)

            if "is_active" in update_data:
                credential_ids = await conn.fetch(
                    "SELECT id FROM ai_target_credentials WHERE ai_target_id=$1",
                    uuid.UUID(target_id),
                )
                principal_ids = await conn.fetch(
                    "SELECT id FROM ai_target_principals WHERE ai_target_id=$1",
                    uuid.UUID(target_id),
                )
                for row in credential_ids:
                    await _sync_ai_target_credential_profile(conn, row["id"])
                for row in principal_ids:
                    await _sync_ai_principal_credential_profile(conn, row["id"])

        target = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", uuid.UUID(target_id))
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            uuid.UUID(target_id),
        )
    return {"target": _ai_target_response(target, credential_row)}


@router.delete("/ai/targets/{target_id}")
async def delete_ai_target(target_id: str):
    """Deactivate an AI Gate target."""
    async with _pool().acquire() as conn:
        async with conn.transaction():
            target_uuid = uuid.UUID(target_id)
            result = await conn.execute("""
                UPDATE ai_targets
                SET is_active = false, updated_at = NOW()
                WHERE id = $1
            """, target_uuid)
            if result != "UPDATE 0":
                credential_ids = await conn.fetch(
                    "SELECT id FROM ai_target_credentials WHERE ai_target_id=$1",
                    target_uuid,
                )
                principal_ids = await conn.fetch(
                    "SELECT id FROM ai_target_principals WHERE ai_target_id=$1",
                    target_uuid,
                )
                for row in credential_ids:
                    await _sync_ai_target_credential_profile(conn, row["id"])
                for row in principal_ids:
                    await _sync_ai_principal_credential_profile(conn, row["id"])
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="AI target not found")
    return {"status": "deleted", "target_id": target_id}


@router.get("/ai/targets/{target_id}/principals")
async def list_ai_target_principals(target_id: str, include_inactive: bool = False):
    """List non-secret principal identities configured for one AI Gate target."""
    async with _pool().acquire() as conn:
        target_exists = await conn.fetchval(
            "SELECT 1 FROM ai_targets WHERE id = $1",
            uuid.UUID(target_id),
        )
        if not target_exists:
            raise HTTPException(status_code=404, detail="AI target not found")
        query = """
            SELECT * FROM ai_target_principals
            WHERE ai_target_id = $1
        """
        if not include_inactive:
            query += " AND is_active = true"
        query += " ORDER BY role, label"
        rows = await conn.fetch(query, uuid.UUID(target_id))

    return {
        "target_id": target_id,
        "principals": [_sanitize_ai_principal(row) for row in rows],
    }


@router.post("/ai/targets/{target_id}/principals")
async def create_ai_target_principal(target_id: str, request: AITargetPrincipalCreate):
    """Create a principal credential for cross-user RAG and agent authorization tests."""
    label = _normalize_ai_principal_label(request.label)
    role = _normalize_ai_principal_role(request.role)
    credential = _build_ai_credential_db_record(request.credential)
    principal_metadata = {**(credential["metadata_json"] or {}), **(request.metadata_json or {})}
    async with _pool().acquire() as conn:
        try:
            async with conn.transaction():
                target_exists = await conn.fetchval(
                    "SELECT 1 FROM ai_targets WHERE id = $1",
                    uuid.UUID(target_id),
                )
                if not target_exists:
                    raise HTTPException(status_code=404, detail="AI target not found")
                principal_id = await conn.fetchval("""
                    INSERT INTO ai_target_principals (
                        ai_target_id, label, role, tenant_id, auth_kind, header_name,
                        secret_value, secret_preview, metadata_json, is_active, rotated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                    RETURNING id
                """,
                    uuid.UUID(target_id),
                    label,
                    role,
                    str(request.tenant_id or "").strip() or None,
                    credential["auth_kind"],
                    credential["header_name"],
                    credential["secret_value"],
                    credential["secret_preview"],
                    json.dumps(principal_metadata),
                    request.is_active,
                )
                await _sync_ai_principal_credential_profile(conn, principal_id)
        except Exception as exc:
            if isinstance(exc, HTTPException):
                raise
            if "unique" in str(exc).lower():
                raise HTTPException(status_code=409, detail="Principal label already exists for this AI target") from exc
            if isinstance(exc, LegacyCredentialMigrationError):
                raise _legacy_credential_migration_http_error(exc) from exc
            raise
        row = await conn.fetchrow("SELECT * FROM ai_target_principals WHERE id = $1", principal_id)
    return {"principal": _sanitize_ai_principal(row)}


@router.patch("/ai/targets/{target_id}/principals/{principal_id}")
async def update_ai_target_principal(
    target_id: str,
    principal_id: str,
    request: AITargetPrincipalUpdate,
):
    """Update a principal credential without returning its raw secret."""
    payload = request.model_dump(exclude_unset=True)
    async with _pool().acquire() as conn:
        try:
            async with conn.transaction():
                principal_uuid = uuid.UUID(principal_id)
                target_uuid = uuid.UUID(target_id)
                existing = await conn.fetchrow(
                    """SELECT * FROM ai_target_principals
                       WHERE id = $1 AND ai_target_id = $2 FOR UPDATE""",
                    principal_uuid,
                    target_uuid,
                )
                if not existing:
                    raise HTTPException(status_code=404, detail="AI target principal not found")

                update_data: dict[str, Any] = {}
                if "label" in payload and payload["label"] is not None:
                    update_data["label"] = _normalize_ai_principal_label(payload["label"])
                if "role" in payload and payload["role"] is not None:
                    update_data["role"] = _normalize_ai_principal_role(payload["role"])
                if "tenant_id" in payload:
                    update_data["tenant_id"] = str(payload.get("tenant_id") or "").strip() or None
                if "metadata_json" in payload:
                    update_data["metadata_json"] = json.dumps(payload.get("metadata_json") or {})
                if "is_active" in payload:
                    update_data["is_active"] = bool(payload["is_active"])

                if request.credential is not None:
                    credential = _build_ai_credential_db_record(request.credential, dict(existing))
                    update_data.update({
                        "auth_kind": credential["auth_kind"],
                        "header_name": credential["header_name"],
                        "secret_value": credential["secret_value"],
                        "secret_preview": credential["secret_preview"],
                        "metadata_json": json.dumps(
                            {
                                **(_decode_json_value(existing.get("metadata_json")) or {}),
                                **(credential["metadata_json"] or {}),
                                **(
                                    payload.get("metadata_json")
                                    if isinstance(payload.get("metadata_json"), dict)
                                    else {}
                                ),
                            }
                        ),
                        "rotated_at": datetime.now(timezone.utc),
                    })

                if update_data:
                    assignments = []
                    values = []
                    for idx, (key, value) in enumerate(update_data.items(), start=1):
                        assignments.append(f"{key} = ${idx}")
                        values.append(value)
                    assignments.append("updated_at = NOW()")
                    values.extend([principal_uuid, target_uuid])
                    await conn.execute(
                        f"""
                        UPDATE ai_target_principals
                        SET {', '.join(assignments)}
                        WHERE id = ${len(values) - 1} AND ai_target_id = ${len(values)}
                        """,
                        *values,
                    )
                await _sync_ai_principal_credential_profile(conn, principal_uuid)
                row = await conn.fetchrow(
                    "SELECT * FROM ai_target_principals WHERE id = $1 AND ai_target_id = $2",
                    principal_uuid,
                    target_uuid,
                )
        except LegacyCredentialMigrationError as exc:
            raise _legacy_credential_migration_http_error(exc) from exc
    return {"principal": _sanitize_ai_principal(row)}


@router.delete("/ai/targets/{target_id}/principals/{principal_id}")
async def delete_ai_target_principal(target_id: str, principal_id: str):
    """Deactivate a principal credential."""
    async with _pool().acquire() as conn:
        async with conn.transaction():
            principal_uuid = uuid.UUID(principal_id)
            result = await conn.execute("""
                UPDATE ai_target_principals
                SET is_active = false, updated_at = NOW()
                WHERE id = $1 AND ai_target_id = $2
            """,
                principal_uuid,
                uuid.UUID(target_id),
            )
            if result != "UPDATE 0":
                await _sync_ai_principal_credential_profile(conn, principal_uuid)
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="AI target principal not found")
    return {"status": "deleted", "target_id": target_id, "principal_id": principal_id}


@router.post("/ai/targets/{target_id}/scan")
async def scan_ai_target(target_id: str, request: AITargetScanRequest):
    """Queue an AI Gate scan for a saved AI target."""
    return await _queue_ai_target_scan(target_id, request)


@router.post("/ai/targets/{target_id}/test")
async def test_ai_target_connectivity(target_id: str, request: AITargetConnectivityTestRequest):
    """Send one sanitized preflight request to validate AI target wiring before a scan."""
    async with _pool().acquire() as conn:
        target_row = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", uuid.UUID(target_id))
        if not target_row:
            raise HTTPException(status_code=404, detail="AI target not found")
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            uuid.UUID(target_id),
        )

    _reject_api_side_ai_credential_preflight(credential_row)

    target = row_to_dict(target_row)
    for key in ("headers_template", "request_template", "metadata_json"):
        target[key] = _decode_json_value(target.get(key)) or {}
    target["credential"] = _anonymous_ai_runtime_credential()

    result = await asyncio.to_thread(
        _run_ai_target_connectivity_probe,
        target,
        prompt=request.prompt,
        timeout_seconds=request.timeout_seconds,
    )
    return {
        "target_id": target_id,
        "target_name": target.get("name"),
        "target_type": target.get("target_type"),
        **result,
    }


@router.post("/ai/targets/{target_id}/mcp/live-readiness")
async def test_ai_target_mcp_live_readiness(target_id: str, request: AIMCPLiveReadinessRequest):
    """Run safe live MCP/OAuth metadata readiness checks for an MCP target."""
    async with _pool().acquire() as conn:
        target_row = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", uuid.UUID(target_id))
        if not target_row:
            raise HTTPException(status_code=404, detail="AI target not found")
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            uuid.UUID(target_id),
        )

    _reject_api_side_ai_credential_preflight(credential_row)

    target = row_to_dict(target_row)
    for key in ("headers_template", "request_template", "metadata_json"):
        target[key] = _decode_json_value(target.get(key)) or {}
    target["credential"] = _anonymous_ai_runtime_credential()

    result = await asyncio.to_thread(
        run_mcp_live_readiness_probe,
        target,
        timeout_seconds=request.timeout_seconds,
    )
    return {
        "target_id": target_id,
        "target_name": target.get("name"),
        "target_type": target.get("target_type"),
        **result,
    }


@router.get("/ai/targets/{target_id}/runtime-risk")
async def get_ai_target_runtime_risk(target_id: str):
    """Return blast-radius risk for one AI target from metadata and active findings."""
    async with _pool().acquire() as conn:
        target_row = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", uuid.UUID(target_id))
        if not target_row:
            raise HTTPException(status_code=404, detail="AI target not found")
        findings = [
            row_to_dict(row)
            for row in await conn.fetch(
                """
                SELECT id, ai_target_id, status, severity, title, source, tool, last_seen_at
                FROM findings
                WHERE ai_target_id = $1 AND status = 'active'
                ORDER BY last_seen_at DESC NULLS LAST
                LIMIT 100
                """,
                uuid.UUID(target_id),
            )
        ]

    target = row_to_dict(target_row)
    target["metadata_json"] = _decode_json_value(target.get("metadata_json")) or {}
    return {
        "target_id": target_id,
        "target_name": target.get("name"),
        "target_type": target.get("target_type"),
        "blast_radius": build_agent_blast_radius(target, findings),
    }


@router.get("/ai/scans/{scan_id}/transcript")
async def get_ai_scan_transcript(scan_id: str, request: Request, include_sensitive: bool = False):
    """Return AI Gate transcripts for a completed scan.

    Transcripts are redacted at response time by default (they routinely contain
    the exact secrets/PII the probes were hunting for). Raw bodies are returned
    only when the operator has enabled AI_TRANSCRIPT_ALLOW_SENSITIVE and the
    caller asks with include_sensitive=true; that access is audit-logged.
    """
    async with _pool().acquire() as conn:
        scan = await conn.fetchrow(
            "SELECT result, run_kind FROM scans WHERE id = $1",
            uuid.UUID(scan_id),
        )
    if not scan or scan["run_kind"] not in {"ai_api", "ai_widget", "ai_rag", "ai_trace", "ai_mcp"}:
        raise HTTPException(status_code=404, detail="AI scan not found")
    result = _decode_json_value(scan["result"]) or {}
    ai_gate = result.get("ai_gate") if isinstance(result, dict) else None
    transcripts = ai_gate.get("transcripts") if isinstance(ai_gate, dict) else None
    if not transcripts:
        raise HTTPException(status_code=404, detail="Transcript not available")
    retention = ai_gate.get("transcript_retention") if isinstance(ai_gate, dict) else {}
    sensitivity_label = (retention or {}).get("transcript_sensitivity")

    available = _ai_transcript_sensitive_allowed()
    reveal = bool(include_sensitive) and available
    if reveal:
        client_host = getattr(getattr(request, "client", None), "host", "unknown")
        logger.warning(
            "AI transcript RAW (unredacted) access: scan_id=%s client=%s sensitivity=%s count=%s",
            scan_id, client_host, sensitivity_label, len(transcripts),
        )
        response_transcripts = transcripts
        redaction_applied = False
    else:
        response_transcripts = redact_sensitive(transcripts, redact_strings=True, scrub_text=True)
        redaction_applied = True

    retention_out = dict(retention or {})
    retention_out.update({
        "redaction_applied": redaction_applied,
        "include_sensitive_available": available,
    })
    return {
        "scan_id": scan_id,
        "transcripts": response_transcripts,
        "transcript_retention": retention_out,
        "sensitivity_label": sensitivity_label,
        "redaction_applied": redaction_applied,
        "include_sensitive": reveal,
        "include_sensitive_available": available,
    }


@router.delete("/ai/scans/{scan_id}/transcript")
async def purge_ai_scan_transcript(scan_id: str):
    """Purge stored AI Gate transcript bodies while preserving scan and finding metadata."""
    async with _pool().acquire() as conn:
        scan = await conn.fetchrow(
            "SELECT result, run_kind FROM scans WHERE id = $1",
            uuid.UUID(scan_id),
        )
        if not scan or scan["run_kind"] not in {"ai_api", "ai_widget", "ai_rag", "ai_trace", "ai_mcp"}:
            raise HTTPException(status_code=404, detail="AI scan not found")
        result = _decode_json_value(scan["result"]) or {}
        ai_gate = result.get("ai_gate") if isinstance(result, dict) else None
        if not isinstance(ai_gate, dict):
            raise HTTPException(status_code=404, detail="AI Gate result not available")
        transcripts = ai_gate.get("transcripts")
        purged_count = len(transcripts) if isinstance(transcripts, list) else 0
        ai_gate["transcripts"] = []
        retention = ai_gate.get("transcript_retention") if isinstance(ai_gate.get("transcript_retention"), dict) else {}
        retention.update({
            "purged": True,
            "purged_at": datetime.now(timezone.utc).isoformat(),
            "purged_transcript_count": purged_count,
            "redaction_applied": True,
            "include_sensitive_available": False,
        })
        ai_gate["transcript_retention"] = retention
        result["ai_gate"] = ai_gate
        await conn.execute(
            "UPDATE scans SET result = $1 WHERE id = $2",
            json.dumps(result),
            uuid.UUID(scan_id),
        )
    return {"scan_id": scan_id, "purged": True, "purged_transcript_count": purged_count}


@router.post("/ai/surfaces/sync")
async def sync_ai_surfaces():
    """Upsert the durable AI surface inventory from saved AI targets and backfill
    the attempt ledger from completed AI Gate scans (mirrors the DAST endpoint
    inventory + attempt ledger). Idempotent; safe to call repeatedly."""
    surfaces_upserted = 0
    attempts_written = 0
    async with _pool().acquire() as conn:
        # Durable inventory: include every AI target ever registered (active or
        # soft-deleted) so the ledger does not silently drop historical surfaces.
        targets = await conn.fetch("SELECT * FROM ai_targets")
        target_to_surface: dict[Any, Any] = {}
        for t in targets:
            md = _decode_json_value(t["metadata_json"]) or {}
            cred = await conn.fetchrow("SELECT auth_kind FROM ai_target_credentials WHERE ai_target_id=$1", t["id"])
            tools = md.get("tool_inventory") if isinstance(md.get("tool_inventory"), list) else []
            row = await conn.fetchrow(
                """
                INSERT INTO ai_surfaces
                    (ai_target_id, surface_type, endpoint_url, auth_kind, owner, environment,
                     risk_tier, data_classification, tools_count, metadata_json, last_seen, updated_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),NOW())
                ON CONFLICT (ai_target_id) DO UPDATE SET
                    surface_type=EXCLUDED.surface_type, endpoint_url=EXCLUDED.endpoint_url,
                    auth_kind=EXCLUDED.auth_kind, owner=EXCLUDED.owner, environment=EXCLUDED.environment,
                    risk_tier=EXCLUDED.risk_tier, data_classification=EXCLUDED.data_classification,
                    tools_count=EXCLUDED.tools_count, metadata_json=EXCLUDED.metadata_json,
                    last_seen=NOW(), updated_at=NOW()
                RETURNING id
                """,
                t["id"], t["target_type"] or "api_chat", t["endpoint_url"],
                (cred["auth_kind"] if cred else None),
                md.get("asset_owner") or md.get("owner"),
                md.get("environment") or md.get("deployment_environment"),
                md.get("risk_tier"), md.get("data_classification"),
                len(tools), json.dumps(md),
            )
            target_to_surface[t["id"]] = row["id"]
            surfaces_upserted += 1

        # Backfill the attempt ledger from ALL completed AI Gate scans, paginated,
        # so larger/older installs are not silently truncated at 500 rows. A hard
        # safety cap bounds one sync; if it is hit the ledger is reported partial.
        BACKFILL_BATCH = 1000
        MAX_BACKFILL_SCANS = 100_000
        offset = 0
        attempts_skipped_no_surface = 0
        partial = False
        while True:
            scans = await conn.fetch(
                """
                SELECT id, ai_target_id, options, result, created_at, completed_at
                FROM scans
                WHERE run_kind LIKE 'ai_%' AND status = 'completed' AND ai_target_id IS NOT NULL
                ORDER BY completed_at DESC NULLS LAST, id
                LIMIT $1 OFFSET $2
                """,
                BACKFILL_BATCH, offset,
            )
            if not scans:
                break
            for s in scans:
                surface_id = target_to_surface.get(s["ai_target_id"])
                if not surface_id:
                    attempts_skipped_no_surface += 1
                    continue
                opts = _decode_json_value(s["options"]) or {}
                res = _decode_json_value(s["result"]) or {}
                findings = res.get("findings") if isinstance(res, dict) else []
                findings = findings if isinstance(findings, list) else []
                crit_high = sum(1 for f in findings if str(f.get("severity") or "").lower() in ("critical", "high"))
                families = sorted({
                    str(f.get("family") or f.get("category"))
                    for f in findings if (f.get("family") or f.get("category"))
                })
                ai_gate = res.get("ai_gate") if isinstance(res.get("ai_gate"), dict) else {}
                decision = ai_gate.get("decision") if isinstance(ai_gate.get("decision"), dict) else {}
                await conn.execute(
                    """
                    INSERT INTO ai_surface_attempts
                        (surface_id, scan_id, probe_pack, scan_profile, environment, families,
                         status, proof_state, findings_count, critical_high_count, started_at, completed_at)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                    ON CONFLICT (surface_id, scan_id) DO UPDATE SET
                        findings_count=EXCLUDED.findings_count, critical_high_count=EXCLUDED.critical_high_count,
                        families=EXCLUDED.families, status=EXCLUDED.status, proof_state=EXCLUDED.proof_state,
                        completed_at=EXCLUDED.completed_at
                    """,
                    surface_id, s["id"],
                    opts.get("probe_pack") or opts.get("ai_probe_pack"),
                    opts.get("scan_profile") or opts.get("ai_scan_profile"),
                    opts.get("environment") or (decision.get("environment") if isinstance(decision, dict) else None),
                    families, "completed",
                    str(decision.get("decision")) if isinstance(decision, dict) and decision.get("decision") else None,
                    len(findings), crit_high, s["created_at"], s["completed_at"],
                )
                attempts_written += 1
            offset += len(scans)
            if len(scans) < BACKFILL_BATCH:
                break
            if offset >= MAX_BACKFILL_SCANS:
                partial = True
                break

        await conn.execute(
            """
            UPDATE ai_surfaces s SET last_tested = sub.mx
            FROM (SELECT surface_id, MAX(completed_at) mx FROM ai_surface_attempts GROUP BY surface_id) sub
            WHERE s.id = sub.surface_id AND sub.mx IS NOT NULL
            """
        )
    return {
        "surfaces_upserted": surfaces_upserted,
        "attempts_written": attempts_written,
        "attempts_skipped_no_surface": attempts_skipped_no_surface,
        "scans_scanned": offset,
        "partial": partial,
    }


@router.get("/ai/surfaces")
async def list_ai_surfaces():
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT s.*,
                   COALESCE(a.attempt_count, 0) AS attempt_count,
                   a.last_attempt_at,
                   COALESCE(a.total_findings, 0) AS total_findings,
                   COALESCE(a.total_crit_high, 0) AS total_crit_high
            FROM ai_surfaces s
            LEFT JOIN (
                SELECT surface_id, COUNT(*) AS attempt_count, MAX(completed_at) AS last_attempt_at,
                       SUM(findings_count) AS total_findings, SUM(critical_high_count) AS total_crit_high
                FROM ai_surface_attempts GROUP BY surface_id
            ) a ON a.surface_id = s.id
            ORDER BY s.updated_at DESC
            """
        )
    return {"ai_surfaces": [row_to_dict(r) for r in rows]}


@router.get("/ai/surfaces/{surface_id}/attempts")
async def list_ai_surface_attempts(surface_id: str):
    async with _pool().acquire() as conn:
        surface = await conn.fetchrow("SELECT * FROM ai_surfaces WHERE id=$1", uuid.UUID(surface_id))
        if not surface:
            raise HTTPException(status_code=404, detail="AI surface not found")
        rows = await conn.fetch(
            "SELECT * FROM ai_surface_attempts WHERE surface_id=$1 ORDER BY completed_at DESC NULLS LAST",
            uuid.UUID(surface_id),
        )
    return {"surface": row_to_dict(surface), "attempts": [row_to_dict(r) for r in rows]}


@router.post("/ai/ops/route")
async def ai_ops_route(request: AIOpsRouterRequest):
    """Map natural-language DAST/ASM operations to safe API calls.

    This is a deterministic router for agents, not a free-form LLM executor.
    Active/state-changing actions dry-run unless the caller explicitly requests execution, provides
    the required confirmations, and the gated-execution policy is enabled. Standard installs enable
    it; AI_OPS_ROUTER_EXECUTE_ENABLED=false disables it globally.
    """
    plan = _build_ai_ops_router_plan(request)
    if plan["dry_run"]:
        return plan

    call = plan.get("planned_api_call") or {}
    method = call.get("method")
    path = str(call.get("path") or "")
    body = call.get("body") if isinstance(call.get("body"), dict) else {}
    executed: dict[str, Any]

    if (
        (plan["intent"] == "run_full_coverage" or str(plan["intent"]).startswith("run_dast_"))
        and method == "POST"
        and path == "/scans"
    ):
        public_scan_options = {
            key: value
            for key, value in (body.get("options") or {}).items()
            if key in ScanPublicCompatibilityOptions.model_fields
        }
        result = await submit_scan(
            ScanRequest(
                target=body["target"],
                budget_profile=body.get("budget_profile"),
                policy=body.get("policy"),
                advanced=(
                    ScanAdvancedLimits(**body["advanced"])
                    if isinstance(body.get("advanced"), dict) else None
                ),
                approval_receipt_id=body.get("approval_receipt_id"),
                options=ScanPublicCompatibilityOptions(**public_scan_options),
            )
        )
        executed = {
            "scan_id": result.get("scan_id"),
            "job_id": result.get("job_id"),
            "status": result.get("status"),
            "ui_link": f"/scans/{result.get('scan_id')}" if result.get("scan_id") else None,
            "result": result,
        }
    elif plan["intent"] == "enable_continuous_asm" and method == "PUT" and request.target_id:
        result = await asm_set_policy(request.target_id, AsmPolicyUpdate(**body))
        executed = {
            "target_id": request.target_id,
            "status": "updated",
            "ui_link": f"/asm?target_id={request.target_id}",
            "result": result,
        }
    elif plan["intent"] == "explain_asm_gaps" and method == "GET" and request.target_id:
        result = await asm_gaps(request.target_id)
        executed = {
            "target_id": request.target_id,
            "status": "read",
            "ui_link": f"/asm?target_id={request.target_id}",
            "result": result,
        }
    elif plan["intent"] == "increase_api_endpoint_budget" and method == "POST" and request.target_id:
        result = await asm_improve(request.target_id, AsmImproveRequest(**body))
        executed = {
            "scan_id": result.get("scan_id"),
            "job_id": result.get("job_id"),
            "campaign_id": result.get("campaign_id"),
            "status": result.get("status"),
            "ui_link": f"/scans/{result.get('scan_id')}" if result.get("scan_id") else f"/asm?target_id={request.target_id}",
            "result": result,
        }
    elif str(plan["intent"]).startswith("focused_asm_") and method == "POST" and request.target_id:
        result = await asm_improve(request.target_id, AsmImproveRequest(**body))
        executed = {
            "scan_id": result.get("scan_id"),
            "job_id": result.get("job_id"),
            "campaign_id": result.get("campaign_id"),
            "status": result.get("status"),
            "ui_link": f"/scans/{result.get('scan_id')}" if result.get("scan_id") else f"/asm?target_id={request.target_id}",
            "result": result,
        }
    else:
        raise HTTPException(status_code=400, detail="Unsupported planned API call")

    plan["dry_run"] = False
    plan["executed"] = executed
    return plan


@router.post("/ai/findings/{finding_id:path}/retest")
async def retest_ai_finding(finding_id: str, request: AIFindingRetestRequest | None = None):
    """Queue a focused AI Gate replay for one AI Gate finding."""
    request = request or AIFindingRetestRequest()
    r = get_redis()
    try:
        r.ping()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"AI Gate scan queue unavailable: {e}")

    scan_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    verification_id = uuid.uuid4()

    async with _pool().acquire() as conn:
        finding = await get_finding_record(conn, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        finding_data = dict(finding)
        if not (finding_data.get("source") == "ai_gate" or finding_data.get("ai_target_id")):
            raise HTTPException(status_code=400, detail="Finding is not an AI Gate finding")
        if not finding_data.get("ai_target_id"):
            raise HTTPException(status_code=400, detail="AI Gate finding is missing ai_target_id")

        target_row = await conn.fetchrow(
            "SELECT * FROM ai_targets WHERE id = $1",
            finding_data["ai_target_id"],
        )
        if not target_row:
            raise HTTPException(status_code=404, detail="AI target not found")
        if not target_row["is_active"]:
            raise HTTPException(status_code=409, detail="AI target is inactive")
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            finding_data["ai_target_id"],
        )
        principal_rows = await conn.fetch(
            """
            SELECT * FROM ai_target_principals
            WHERE ai_target_id = $1 AND is_active = true
            ORDER BY role, label
            """,
            finding_data["ai_target_id"],
        )
        credential_profile_ref, principal_refs = await _resolve_ai_gate_credential_refs(
            conn,
            target_id=finding_data["ai_target_id"],
            credential_row=credential_row,
            principal_rows=list(principal_rows),
        )
        credentials_selected = bool(credential_profile_ref) or any(
            item.get("credential_profile_ref") for item in principal_refs
        )
        approval_context = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=target_row["endpoint_url"],
            target_id=finding_data["ai_target_id"] if credentials_selected else None,
            action_name="ai_gate.finding_replay",
            risk_tier="credential" if credentials_selected else "active",
            always_require_receipt=credentials_selected,
            require_target_binding=credentials_selected,
            require_expiry=credentials_selected,
        )
        original_scan = None
        if finding_data.get("scan_id"):
            original_scan = await conn.fetchrow(
                "SELECT options FROM scans WHERE id = $1",
                finding_data["scan_id"],
            )

        target = row_to_dict(target_row)
        for key in ("headers_template", "request_template", "metadata_json"):
            target[key] = _decode_json_value(target.get(key)) or {}
        original_options = _ai_scan_options_from_row(original_scan)
        worker_options, storage_options, replay_plan = _build_ai_finding_retest_scan_options(
            target=target,
            credential_profile_ref=credential_profile_ref,
            finding=finding_data,
            original_scan_options=original_options,
            request=request,
            verification_id=verification_id,
            principal_refs=principal_refs,
        )
        if credentials_selected:
            worker_options["credential_action_name"] = "ai_gate.finding_replay"
        if approval_context:
            worker_options.update(approval_context)
            storage_options.update(approval_context)
            replay_plan["approval_receipt_id"] = approval_context.get("approval_receipt_id")
            replay_plan["scope_receipt_id"] = approval_context.get("scope_receipt_id")

        production_scan = bool(target.get("production_mode")) or storage_options.get("ai_environment") == "production"
        confirmed = bool((storage_options.get("production_confirmation") or {}).get("confirmed"))
        if production_scan and not confirmed:
            raise HTTPException(
                status_code=409,
                detail="Focused AI Gate replay targets production. Re-submit with confirm_production=true.",
            )

        run_kind = storage_options["run_kind"]
        await conn.execute("""
            INSERT INTO scans (
                id, target_id, ai_target_id, target_url, job_id, status,
                options, scan_type, run_kind, subject_ref
            ) VALUES ($1, NULL, $2, $3, $4, 'pending', $5, 'ai_gate', $6, $7)
        """,
            uuid.UUID(scan_id),
            finding_data["ai_target_id"],
            target["endpoint_url"],
            job_id,
            json.dumps(storage_options),
            run_kind,
            f"ai_finding_retest:{finding_data['id']}",
        )
        await conn.execute("""
            INSERT INTO finding_verifications (
                id, finding_id, scan_id, target_id, job_id, requested_by, status,
                finding_type, target_url, original_url, replay_commands,
                verification_mode, ai_plan, message
            ) VALUES (
                $1, $2, $3, NULL, $4, $5, 'queued',
                'ai_gate', $6, $7, $8,
                'ai_driven', $9, $10
            )
        """,
            verification_id,
            finding_data["id"],
            uuid.UUID(scan_id),
            job_id,
            request.requested_by or "api",
            target["endpoint_url"],
            finding_data.get("url"),
            json.dumps([{
                "description": "Focused AI Gate replay",
                "scan_id": scan_id,
                **replay_plan,
            }]),
            json.dumps(replay_plan),
            "Queued focused AI Gate replay",
        )
        await conn.execute("""
            UPDATE findings
            SET last_verification_status = 'queued',
                last_verification_verdict = NULL,
                updated_at = NOW()
            WHERE id = $1
        """, finding_data["id"])
        command_result = await _record_command_result(
            conn,
            command="ai_gate.finding_replay",
            status="queued",
            risk_tier="active",
            scan_id=scan_id,
            finding_ids=[str(finding_data["id"])],
            scope_receipt_id=storage_options.get("scope_receipt_id"),
            approval_receipt_id=storage_options.get("approval_receipt_id"),
            operator_message=f"Queued AI Gate replay for finding {finding_data.get('title') or finding_data['id']}",
            result_json={
                "finding_id": str(finding_data["id"]),
                "verification_id": str(verification_id),
                "ai_target_id": str(finding_data["ai_target_id"]),
                "scan_id": scan_id,
                "job_id": job_id,
                "mode": request.mode,
                "probe_id": replay_plan.get("probe_id"),
                "probe_family": replay_plan.get("probe_family"),
            },
            next_action=f"/scans/{scan_id}",
            created_by=request.requested_by or "api",
        )

    job_data = {
        "job_id": job_id,
        "scan_id": scan_id,
        "target": target["endpoint_url"],
        "options": worker_options,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        enqueue_job(r, QUEUE_NAME, job_data)
        r.hset(
            f"job:{job_id}",
            mapping={
                "status": "queued",
                "target": target["endpoint_url"],
                "scan_id": scan_id,
                "verification_id": str(verification_id),
                "finding_id": str(finding_data["id"]),
            },
        )
        r.expire(f"job:{job_id}", 86400)
    except Exception as e:
        async with _pool().acquire() as conn:
            await mark_retest_enqueue_failed(
                conn,
                verification_id=verification_id,
                finding_id=finding_data["id"],
                error_message=f"AI Gate replay queue enqueue failed: {type(e).__name__}: {e}",
            )
        raise HTTPException(status_code=503, detail=f"AI Gate scan queue unavailable: {e}")

    response = {
        "retest_id": str(verification_id),
        "job_id": job_id,
        "scan_id": scan_id,
        "status": "queued",
        "mode": request.mode,
        "finding_id": str(finding_data["id"]),
        "finding_type": "ai_gate",
        "target_url": target["endpoint_url"],
        "probe_id": replay_plan.get("probe_id"),
        "probe_family": replay_plan.get("probe_family"),
        "ui_url": f"/scans/{scan_id}",
    }
    if storage_options.get("approval_receipt_id"):
        response["approval_receipt_id"] = storage_options.get("approval_receipt_id")
        response["scope_receipt_id"] = storage_options.get("scope_receipt_id")
    response["operation_id"] = command_result["id"]
    return response


@router.get("/ai/scans/{scan_id}/campaign-history")
async def get_ai_scan_campaign_history(scan_id: str, limit: int = Query(6, ge=2, le=12)):
    """Compare a completed AI Gate scan against recent same-target campaign runs."""
    async with _pool().acquire() as conn:
        current_scan = await conn.fetchrow(
            """
            SELECT id, ai_target_id, target_url, options, result, run_kind, status,
                   score, grade, findings_count, created_at, completed_at
            FROM scans
            WHERE id = $1
            """,
            uuid.UUID(scan_id),
        )
        if not current_scan:
            raise HTTPException(status_code=404, detail="AI Gate scan not found")
        if not str(current_scan["run_kind"] or "").startswith("ai_") or not current_scan["ai_target_id"]:
            raise HTTPException(status_code=400, detail="Scan is not an AI Gate target scan")
        if current_scan["status"] != "completed":
            raise HTTPException(status_code=409, detail="Only completed AI Gate scans have campaign history")

        rows = await conn.fetch(
            """
            SELECT id, ai_target_id, target_url, options, result, run_kind, status,
                   score, grade, findings_count, created_at, completed_at
            FROM scans
            WHERE ai_target_id = $1
              AND status = 'completed'
              AND run_kind LIKE 'ai_%'
              AND result IS NOT NULL
            ORDER BY COALESCE(completed_at, created_at) DESC, created_at DESC
            LIMIT 40
            """,
            current_scan["ai_target_id"],
        )
    return _build_ai_campaign_history(current_scan, list(rows), limit=limit)


@router.post("/ai/scans/{scan_id}/replay")
async def replay_ai_scan(scan_id: str, request: AIScanReplayRequest | None = None):
    """Queue a focused replay/rerun from a completed AI Gate scan campaign."""
    request = request or AIScanReplayRequest()
    r = get_redis()
    try:
        r.ping()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"AI Gate scan queue unavailable: {e}")

    new_scan_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    async with _pool().acquire() as conn:
        original_scan = await conn.fetchrow(
            """
            SELECT id, ai_target_id, target_url, options, result, run_kind, status
            FROM scans
            WHERE id = $1
            """,
            uuid.UUID(scan_id),
        )
        if not original_scan:
            raise HTTPException(status_code=404, detail="AI Gate scan not found")
        if not str(original_scan["run_kind"] or "").startswith("ai_") or not original_scan["ai_target_id"]:
            raise HTTPException(status_code=400, detail="Scan is not an AI Gate target scan")
        if original_scan["status"] != "completed":
            raise HTTPException(status_code=409, detail="Only completed AI Gate scans can be replayed")

        original_result = _decode_json_value(original_scan["result"]) or {}
        replay_plan = _build_ai_scan_replay_plan(original_result, request)

        target_row = await conn.fetchrow(
            "SELECT * FROM ai_targets WHERE id = $1",
            original_scan["ai_target_id"],
        )
        if not target_row:
            raise HTTPException(status_code=404, detail="AI target not found")
        if not target_row["is_active"]:
            raise HTTPException(status_code=409, detail="AI target is inactive")
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            original_scan["ai_target_id"],
        )
        principal_rows = await conn.fetch(
            """
            SELECT * FROM ai_target_principals
            WHERE ai_target_id = $1 AND is_active = true
            ORDER BY role, label
            """,
            original_scan["ai_target_id"],
        )
        credential_profile_ref, principal_refs = await _resolve_ai_gate_credential_refs(
            conn,
            target_id=original_scan["ai_target_id"],
            credential_row=credential_row,
            principal_rows=list(principal_rows),
        )
        credentials_selected = bool(credential_profile_ref) or any(
            item.get("credential_profile_ref") for item in principal_refs
        )
        approval_context = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=target_row["endpoint_url"],
            target_id=original_scan["ai_target_id"] if credentials_selected else None,
            action_name="ai_gate.campaign_replay",
            risk_tier="credential" if credentials_selected else "active",
            always_require_receipt=credentials_selected,
            require_target_binding=credentials_selected,
            require_expiry=credentials_selected,
        )

        target = row_to_dict(target_row)
        for key in ("headers_template", "request_template", "metadata_json"):
            target[key] = _decode_json_value(target.get(key)) or {}
        original_options = _ai_scan_options_from_row(original_scan)
        original_confirmation = original_options.get("production_confirmation")
        original_confirmed = isinstance(original_confirmation, dict) and original_confirmation.get("confirmed") is True

        scan_request = AITargetScanRequest(
            probe_pack=str(original_options.get("ai_probe_pack") or replay_plan.get("probe_pack") or "shaker-ai-smoke"),
            scan_profile=str(original_options.get("ai_scan_profile") or replay_plan.get("scan_profile") or "smoke"),
            environment=str(original_options.get("ai_environment") or replay_plan.get("environment") or "preview"),
            confirm_production=bool(request.confirm_production or original_confirmed),
            ai_judge_enabled=original_options.get("ai_judge_enabled"),
            semantic_judge_enabled=original_options.get("semantic_judge_enabled"),
        )
        worker_options, storage_options = _build_ai_worker_options(
            target=target,
            credential_profile_ref=credential_profile_ref,
            request=scan_request,
            principal_refs=principal_refs,
        )
        if credentials_selected:
            worker_options["credential_action_name"] = "ai_gate.campaign_replay"
        metadata_json = worker_options["ai_target"].setdefault("metadata_json", {})
        if replay_plan.get("probe_ids"):
            worker_options["ai_focus_probe_ids"] = replay_plan["probe_ids"]
            storage_options["ai_focus_probe_ids"] = replay_plan["probe_ids"]
            metadata_json["ai_focus_probe_ids"] = replay_plan["probe_ids"]
        if replay_plan.get("probe_family"):
            worker_options["ai_focus_probe_family"] = replay_plan["probe_family"]
            storage_options["ai_focus_probe_family"] = replay_plan["probe_family"]
            metadata_json["ai_focus_probe_family"] = replay_plan["probe_family"]

        replay_plan = {
            **replay_plan,
            "source_scan_id": scan_id,
            "requested_by": request.requested_by or "api",
            "queued_scan_id": new_scan_id,
        }
        worker_options["ai_scan_replay"] = replay_plan
        storage_options["ai_scan_replay"] = replay_plan
        if approval_context:
            worker_options.update(approval_context)
            storage_options.update(approval_context)
            replay_plan["approval_receipt_id"] = approval_context.get("approval_receipt_id")
            replay_plan["scope_receipt_id"] = approval_context.get("scope_receipt_id")
        production_scan = bool(target.get("production_mode")) or storage_options.get("ai_environment") == "production"
        confirmed = bool((storage_options.get("production_confirmation") or {}).get("confirmed"))
        if production_scan and not confirmed:
            raise HTTPException(
                status_code=409,
                detail="AI Gate scan replay targets production. Re-submit with confirm_production=true.",
            )

        run_kind = storage_options["run_kind"]
        await conn.execute("""
            INSERT INTO scans (
                id, target_id, ai_target_id, target_url, job_id, status,
                options, scan_type, run_kind, subject_ref
            ) VALUES ($1, NULL, $2, $3, $4, 'pending', $5, 'ai_gate', $6, $7)
        """,
            uuid.UUID(new_scan_id),
            original_scan["ai_target_id"],
            target["endpoint_url"],
            job_id,
            json.dumps(storage_options),
            run_kind,
            f"ai_scan_replay:{scan_id}",
        )
        command_result = await _record_command_result(
            conn,
            command="ai_gate.campaign_replay",
            status="queued",
            risk_tier="active",
            scan_id=new_scan_id,
            scope_receipt_id=storage_options.get("scope_receipt_id"),
            approval_receipt_id=storage_options.get("approval_receipt_id"),
            operator_message=f"Queued AI Gate campaign replay for {target['endpoint_url']}",
            result_json={
                "source_scan_id": scan_id,
                "queued_scan_id": new_scan_id,
                "job_id": job_id,
                "ai_target_id": str(original_scan["ai_target_id"]),
                "mode": replay_plan.get("mode"),
                "probe_ids": replay_plan.get("probe_ids") or [],
                "probe_family": replay_plan.get("probe_family"),
                "transcript": replay_plan.get("transcript"),
            },
            next_action=f"/scans/{new_scan_id}",
            created_by=request.requested_by or "api",
        )

    job_data = {
        "job_id": job_id,
        "scan_id": new_scan_id,
        "target": target["endpoint_url"],
        "options": worker_options,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        enqueue_job(r, QUEUE_NAME, job_data)
        r.hset(
            f"job:{job_id}",
            mapping={
                "status": "queued",
                "target": target["endpoint_url"],
                "scan_id": new_scan_id,
                "source_scan_id": scan_id,
            },
        )
        r.expire(f"job:{job_id}", 86400)
    except Exception as e:
        async with _pool().acquire() as conn:
            await conn.execute(
                "UPDATE scans SET status='failed', error_message=$2, completed_at=NOW() WHERE id=$1",
                uuid.UUID(new_scan_id),
                f"AI Gate scan replay queue enqueue failed: {type(e).__name__}: {e}",
            )
        raise HTTPException(status_code=503, detail=f"AI Gate scan queue unavailable: {e}")

    response = {
        "scan_id": new_scan_id,
        "job_id": job_id,
        "status": "queued",
        "source_scan_id": scan_id,
        "mode": replay_plan.get("mode"),
        "probe_ids": replay_plan.get("probe_ids") or [],
        "probe_family": replay_plan.get("probe_family"),
        "transcript": replay_plan.get("transcript"),
        "target_url": target["endpoint_url"],
        "ui_url": f"/scans/{new_scan_id}",
    }
    if storage_options.get("approval_receipt_id"):
        response["approval_receipt_id"] = storage_options.get("approval_receipt_id")
        response["scope_receipt_id"] = storage_options.get("scope_receipt_id")
    response["operation_id"] = command_result["id"]
    return response
AI_DEMO_DEFAULT_SCENARIOS = (
    "rag.safe.tenant_scoped_answer.v1",
    "rag.unsafe.cross_tenant_inventory.v1",
    "agent.unsafe.approval_bypass.v1",
    "mcp.unsafe.oauth_audience_wildcard.v1",
)


AI_TARGET_TYPES = {"api_chat", "widget", "rag", "agent_trace", "mcp_trace"}

AI_TARGET_METHODS = {"GET", "POST", "PUT", "PATCH"}

AI_STREAMING_MODES = {"json", "sse"}

AI_AUTH_KINDS = {
    "none",
    "bearer",
    "api_key_header",
    "custom_header",
    "basic_auth",
    "cookie",
    "multi_header",
    "query_param",
}

AI_PRINCIPAL_ROLES = {"attacker", "victim", "admin", "service", "observer"}

AI_PROBE_PACKS = {
    "shaker-ai-smoke",
    "shaker-owasp-llm",
    "shaker-agent-abuse",
    "shaker-mcp-security",
    "shaker-rag-lite",
}

AI_SCAN_PROFILES = {"smoke", "trace", "standard", "deep"}

AI_ENVIRONMENTS = {"preview", "staging", "production", "development"}

class AITargetCredential(BaseModel):
    auth_kind: str = "none"
    header_name: Optional[str] = None
    secret: Optional[str] = None
    metadata_json: Optional[dict[str, Any]] = None

AI_GATE_GENERIC_CREDENTIAL_CAPABILITY = "ai_gate.scan"

AI_GATE_GENERIC_AUTH_KINDS = {
    "authorization_header",
    "bearer_token",
    "api_key_header",
    "cookie",
    "basic_auth",
    "custom_headers",
    "query_parameter",
}


class AITargetCreate(BaseModel):
    name: Optional[str] = None
    target_type: str = "api_chat"
    endpoint_url: str
    method: str = "POST"
    headers_template: dict[str, Any] = Field(default_factory=dict)
    request_template: dict[str, Any] = Field(default_factory=dict)
    response_path: Optional[str] = "$.answer"
    streaming_mode: str = "json"
    rate_limit_rps: Optional[int] = Field(default=None, ge=1)
    token_budget: Optional[int] = Field(default=None, ge=1)
    request_budget: Optional[int] = Field(default=None, ge=1)
    production_mode: bool = False
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True
    credential: AITargetCredential = Field(default_factory=AITargetCredential)


class AITargetUpdate(BaseModel):
    name: Optional[str] = None
    endpoint_url: Optional[str] = None
    method: Optional[str] = None
    headers_template: Optional[dict[str, Any]] = None
    request_template: Optional[dict[str, Any]] = None
    response_path: Optional[str] = None
    streaming_mode: Optional[str] = None
    rate_limit_rps: Optional[int] = Field(default=None, ge=1)
    token_budget: Optional[int] = Field(default=None, ge=1)
    request_budget: Optional[int] = Field(default=None, ge=1)
    production_mode: Optional[bool] = None
    metadata_json: Optional[dict[str, Any]] = None
    is_active: Optional[bool] = None
    credential: Optional[AITargetCredential] = None


class AITargetPrincipalCreate(BaseModel):
    label: str
    role: str = "attacker"
    tenant_id: Optional[str] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True
    credential: AITargetCredential = Field(default_factory=AITargetCredential)


class AITargetPrincipalUpdate(BaseModel):
    label: Optional[str] = None
    role: Optional[str] = None
    tenant_id: Optional[str] = None
    metadata_json: Optional[dict[str, Any]] = None
    is_active: Optional[bool] = None
    credential: Optional[AITargetCredential] = None


class AITargetScanRequest(BaseModel):
    probe_pack: str = "shaker-ai-smoke"
    scan_profile: str = "smoke"
    environment: str = "preview"
    confirm_production: bool = False
    ai_judge_enabled: Optional[bool] = None
    semantic_judge_enabled: Optional[bool] = None
    approval_receipt_id: Optional[str] = Field(
        default=None,
        description="Optional durable approval receipt to validate and stamp on the queued AI Gate scan.",
    )


class AITargetConnectivityTestRequest(BaseModel):
    prompt: str = "ShakerScan connectivity check. Reply with a short safe response."
    timeout_seconds: int = Field(default=15, ge=1, le=60)


class AIMCPLiveReadinessRequest(BaseModel):
    timeout_seconds: int = Field(default=8, ge=1, le=30)


class AIDemoRunRequest(BaseModel):
    scenario_ids: Optional[list[str]] = None
    scan_profile: str = Field(default="smoke", pattern="^(smoke|trace|standard|deep)$")
    request_budget: int = Field(default=1, ge=1, le=10)


class AIFindingRetestRequest(BaseModel):
    mode: str = Field(default="same_probe", pattern="^(same_probe|same_family|strict_replay)$")
    requested_by: Optional[str] = "api"
    confirm_production: bool = False
    approval_receipt_id: Optional[str] = Field(
        default=None,
        description="Optional durable approval receipt to validate and stamp on the queued AI Gate finding replay.",
    )


class AIScanReplayRequest(BaseModel):
    mode: str = Field(default="skipped", pattern="^(skipped|errors|family|transcript|all)$")
    probe_family: Optional[str] = None
    probe_id: Optional[str] = None
    transcript_index: Optional[int] = Field(default=None, ge=0)
    requested_by: Optional[str] = "api"
    confirm_production: bool = False
    approval_receipt_id: Optional[str] = Field(
        default=None,
        description="Optional durable approval receipt to validate and stamp on the queued AI Gate campaign replay.",
    )


def _normalize_ai_endpoint_url(raw: str) -> str:
    candidate = str(raw or "").strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="endpoint_url is required")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="endpoint_url must use http or https")
    return urllib.parse.urlunparse(parsed)


def _normalize_ai_target_type(value: str | None) -> str:
    candidate = str(value or "api_chat").strip()
    if candidate not in AI_TARGET_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"target_type must be one of: {', '.join(sorted(AI_TARGET_TYPES))}",
        )
    return candidate


def _normalize_ai_method(value: str | None) -> str:
    candidate = str(value or "POST").strip().upper()
    if candidate not in AI_TARGET_METHODS:
        raise HTTPException(status_code=400, detail="method must be GET, POST, PUT, or PATCH")
    return candidate


def _normalize_ai_streaming_mode(value: str | None) -> str:
    candidate = str(value or "json").strip().lower()
    if candidate not in AI_STREAMING_MODES:
        raise HTTPException(status_code=400, detail="streaming_mode must be json or sse")
    return candidate


def _normalize_ai_headers_template(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    headers: dict[str, str] = {}
    for key, header_value in value.items():
        if isinstance(key, str) and key.strip() and isinstance(header_value, str) and header_value.strip():
            headers[key.strip()] = header_value
    return headers


def _normalize_ai_request_template(value: Any, *, method: str, target_type: str) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="request_template must be a JSON object")
    if target_type != "widget" and method != "GET" and not _contains_prompt_placeholder(value):
        raise HTTPException(
            status_code=400,
            detail="request_template must contain a {{prompt}} placeholder for non-GET AI targets",
        )
    return value


def _build_ai_credential_db_record(
    credential: AITargetCredential,
    existing: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    auth_kind = str(credential.auth_kind or "none").strip()
    if auth_kind not in AI_AUTH_KINDS:
        raise HTTPException(
            status_code=400,
            detail=f"auth_kind must be one of: {', '.join(sorted(AI_AUTH_KINDS))}",
        )

    metadata = credential.metadata_json if isinstance(credential.metadata_json, dict) else {}
    header_name = str(credential.header_name or "").strip() or None
    secret = str(credential.secret or "").strip()
    existing_secret = (
        str(decrypt_secret(existing.get("secret_value")) or "")
        if existing and existing.get("auth_kind") == auth_kind
        else ""
    )

    if auth_kind == "none":
        return {
            "auth_kind": "none",
            "header_name": None,
            "secret_value": None,
            "secret_preview": None,
            "metadata_json": {},
        }

    if auth_kind == "bearer":
        header_name = "Authorization"
    elif auth_kind == "api_key_header":
        header_name = header_name or "X-API-Key"
    elif auth_kind == "basic_auth":
        header_name = "Authorization"
    elif auth_kind == "cookie":
        header_name = "Cookie"
    elif auth_kind == "custom_header" and not header_name:
        raise HTTPException(status_code=400, detail="header_name is required for custom_header auth")
    elif auth_kind == "query_param":
        header_name = header_name or str(metadata.get("param_name") or "").strip() or None
        if not header_name:
            raise HTTPException(status_code=400, detail="Parameter name is required for query_param auth")
        metadata = {**metadata, "param_name": header_name}

    if auth_kind == "multi_header":
        pairs = _normalize_multi_header_pairs(metadata.get("headers")) or _parse_multi_header_lines(secret)
        if not pairs and existing_secret:
            secret_value = existing_secret
            try:
                pairs = _normalize_multi_header_pairs(json.loads(existing_secret))
            except json.JSONDecodeError:
                pairs = []
        elif pairs:
            secret_value = json.dumps(pairs)
        else:
            raise HTTPException(status_code=400, detail="At least one header pair is required")
        return {
            "auth_kind": auth_kind,
            "header_name": None,
            "secret_value": encrypt_secret(secret_value),
            "secret_preview": f"{len(pairs)} header{'s' if len(pairs) != 1 else ''}",
            "metadata_json": {"headers": [{"name": pair["name"], "value": "***"} for pair in pairs]},
        }

    if not secret and existing_secret:
        secret = existing_secret
    if not secret:
        raise HTTPException(status_code=400, detail=f"secret is required for {auth_kind} auth")

    return {
        "auth_kind": auth_kind,
        "header_name": header_name,
        "secret_value": encrypt_secret(secret),
        "secret_preview": _mask_ai_target_secret(secret),
        "metadata_json": metadata,
    }


async def _sync_ai_target_credential_profile(conn: Any, profile_id: Any) -> None:
    try:
        await sync_legacy_ai_target_credential(conn, profile_id)
    except LegacyCredentialMigrationError as exc:
        raise _legacy_credential_migration_http_error(exc) from exc


async def _sync_ai_principal_credential_profile(conn: Any, profile_id: Any) -> None:
    try:
        await sync_legacy_ai_principal_credential(conn, profile_id)
    except LegacyCredentialMigrationError as exc:
        raise _legacy_credential_migration_http_error(exc) from exc


def _normalize_ai_principal_role(value: Any) -> str:
    role = str(value or "attacker").strip().lower().replace("-", "_")
    if role not in AI_PRINCIPAL_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"role must be one of: {', '.join(sorted(AI_PRINCIPAL_ROLES))}",
        )
    return role


def _normalize_ai_principal_label(value: Any) -> str:
    label = str(value or "").strip()
    if not label:
        raise HTTPException(status_code=400, detail="principal label is required")
    if len(label) > 80:
        raise HTTPException(status_code=400, detail="principal label must be 80 characters or fewer")
    return label


def _sanitize_ai_principal(row: Any) -> dict[str, Any]:
    principal = row_to_dict(row)
    principal["metadata_json"] = _sanitize_scan_options(
        _decode_json_value(principal.get("metadata_json")) or {}
    )
    principal["credential"] = _sanitize_ai_credential(principal)
    for secret_key in ("secret_value", "secret_preview", "auth_kind", "header_name"):
        principal.pop(secret_key, None)
    return principal


async def _resolve_ai_gate_credential_refs(
    conn: Any,
    *,
    target_id: Any,
    credential_row: Any,
    principal_rows: list[Any],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    default_ref = await _resolve_ai_gate_credential_profile(
        conn, credential_row, target_id=target_id,
    )
    principal_refs: list[dict[str, Any]] = []
    for row in principal_rows:
        profile_ref = await _resolve_ai_gate_credential_profile(
            conn, row, target_id=target_id,
        )
        principal_refs.append(_ai_principal_ref(row, profile_ref))
    return default_ref, principal_refs


def _ai_target_response(target_row: Any, credential_row: Optional[Any] = None) -> dict[str, Any]:
    target = row_to_dict(target_row)
    for key in ("headers_template", "request_template", "metadata_json"):
        target[key] = _decode_json_value(target.get(key)) or {}
    credential = dict(credential_row) if credential_row else None
    target["credential"] = _sanitize_ai_credential(credential)
    return target


def _ai_demo_target_sql_predicate() -> str:
    return """(
        COALESCE(metadata_json->>'shakerscan_demo', '') = 'true'
        OR (metadata_json ? 'calibration_run' AND COALESCE(metadata_json->>'calibration_run', '') <> '')
        OR metadata_json ? 'honey_scenario_id'
        OR metadata_json ? 'safe_fixture'
        OR metadata_json ? 'expected_shakerscan_findings'
    )"""


def _demo_target_url(url: str, scanner_base_url: str, run_id: str, scenario_id: str) -> str:
    parsed = urllib.parse.urlparse(str(url or ""))
    if not parsed.path:
        raise HTTPException(status_code=400, detail=f"Honey scenario {scenario_id} has no target path")
    base = urllib.parse.urlparse(_normalize_demo_base_url(scanner_base_url))
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query["calibration_run"] = run_id
    query["calibration_scenario"] = scenario_id
    return urllib.parse.urlunparse((base.scheme, base.netloc, parsed.path, "", urllib.parse.urlencode(query), ""))


def _demo_request_template_with_prompt(template: Any, surface: str) -> dict[str, Any]:
    updated = copy.deepcopy(template) if isinstance(template, dict) else {}
    if surface in {"rag", "agent"}:
        updated["message"] = "{{prompt}}"
        updated.setdefault("session_id", "{{session_id}}")
    elif surface == "mcp":
        params = updated.setdefault("params", {})
        if not isinstance(params, dict):
            params = {}
            updated["params"] = params
        params["prompt"] = "{{prompt}}"
        updated.setdefault("id", "{{session_id}}")
    else:
        updated["message"] = "{{prompt}}"
    return updated


async def _fetch_honey_ai_gate_registry(base_url: str) -> dict[str, Any]:
    url = f"{_normalize_demo_base_url(base_url)}/api/ai-gate/scenarios"
    return await asyncio.to_thread(_fetch_json_url, url)


async def _queue_ai_target_scan(target_id: str, request: AITargetScanRequest) -> dict[str, Any]:
    if request.probe_pack not in AI_PROBE_PACKS:
        raise HTTPException(status_code=400, detail=f"probe_pack must be one of: {', '.join(sorted(AI_PROBE_PACKS))}")
    if request.scan_profile not in AI_SCAN_PROFILES:
        raise HTTPException(status_code=400, detail=f"scan_profile must be one of: {', '.join(sorted(AI_SCAN_PROFILES))}")
    if request.environment not in AI_ENVIRONMENTS:
        raise HTTPException(status_code=400, detail=f"environment must be one of: {', '.join(sorted(AI_ENVIRONMENTS))}")

    r = get_redis()
    job_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())

    command_result: dict[str, Any] | None = None
    async with _pool().acquire() as conn:
        target_row = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", uuid.UUID(target_id))
        if not target_row:
            raise HTTPException(status_code=404, detail="AI target not found")
        if not target_row["is_active"]:
            raise HTTPException(status_code=409, detail="AI target is inactive")
        reason = _ai_production_confirmation_reason(
            bool(target_row["production_mode"]), request.environment, request.confirm_production
        )
        if reason:
            raise HTTPException(
                status_code=409,
                detail=f"{reason}. Re-submit with confirm_production=true.",
            )
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            uuid.UUID(target_id),
        )
        principal_rows = await conn.fetch(
            """
            SELECT * FROM ai_target_principals
            WHERE ai_target_id = $1 AND is_active = true
            ORDER BY role, label
            """,
            uuid.UUID(target_id),
        )
        credential_profile_ref, principal_refs = await _resolve_ai_gate_credential_refs(
            conn,
            target_id=target_id,
            credential_row=credential_row,
            principal_rows=list(principal_rows),
        )
        credentials_selected = bool(credential_profile_ref) or any(
            item.get("credential_profile_ref") for item in principal_refs
        )
        approval_context = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=target_row["endpoint_url"],
            target_id=target_id if credentials_selected else None,
            action_name="ai_gate.scan",
            risk_tier="credential" if credentials_selected else "active",
            always_require_receipt=credentials_selected,
            require_target_binding=credentials_selected,
            require_expiry=credentials_selected,
        )

        target = row_to_dict(target_row)
        for key in ("headers_template", "request_template", "metadata_json"):
            target[key] = _decode_json_value(target.get(key)) or {}
        worker_options, storage_options = _build_ai_worker_options(
            target=target,
            credential_profile_ref=credential_profile_ref,
            request=request,
            principal_refs=principal_refs,
        )
        if credentials_selected:
            worker_options["credential_action_name"] = "ai_gate.scan"
        if approval_context:
            worker_options.update(approval_context)
            storage_options.update(approval_context)
        run_kind = storage_options["run_kind"]

        await conn.execute("""
            INSERT INTO scans (
                id, target_id, ai_target_id, target_url, job_id, status,
                options, scan_type, run_kind, subject_ref
            ) VALUES ($1, NULL, $2, $3, $4, 'pending', $5, 'ai_gate', $6, $7)
        """,
            uuid.UUID(scan_id),
            uuid.UUID(target_id),
            target["endpoint_url"],
            job_id,
            json.dumps(storage_options),
            run_kind,
            f"ai_target:{target_id}",
        )
        command_result = await _record_command_result(
            conn,
            command="ai_gate.scan",
            status="queued",
            risk_tier="credential" if credentials_selected else "active",
            scan_id=scan_id,
            scope_receipt_id=storage_options.get("scope_receipt_id"),
            approval_receipt_id=storage_options.get("approval_receipt_id"),
            operator_message=f"Queued AI Gate {request.scan_profile} scan for {target.get('name') or target['endpoint_url']}",
            result_json={
                "target": target["endpoint_url"],
                "ai_target_id": target_id,
                "job_id": job_id,
                "probe_pack": request.probe_pack,
                "scan_profile": request.scan_profile,
                "environment": request.environment,
            },
            next_action=f"/scans/{scan_id}",
        )

    job_data = {
        "job_id": job_id,
        "scan_id": scan_id,
        "target": target["endpoint_url"],
        "options": worker_options,
        "submitted_at": utc_now_iso(),
    }
    enqueue_job(r, QUEUE_NAME, job_data)
    r.hset(f"job:{job_id}", mapping={"status": "queued", "target": target["endpoint_url"], "scan_id": scan_id})

    response = {
        "scan_id": scan_id,
        "job_id": job_id,
        "status": "queued",
        "target": target["endpoint_url"],
        "run_kind": run_kind,
        "ai_target_id": target_id,
        "probe_pack": request.probe_pack,
        "scan_profile": request.scan_profile,
        "ui_url": f"/scans/{scan_id}",
    }
    if storage_options.get("approval_receipt_id"):
        response["approval_receipt_id"] = storage_options.get("approval_receipt_id")
        response["scope_receipt_id"] = storage_options.get("scope_receipt_id")
    if command_result:
        response["operation_id"] = command_result["id"]
    return response


def _anonymous_ai_runtime_credential() -> dict[str, Any]:
    return {
        "auth_kind": "none",
        "header_name": None,
        "secret": None,
        "metadata_json": {},
    }


def _reject_api_side_ai_credential_preflight(row: Any) -> None:
    item = row_to_dict(row) if row else {}
    if str(item.get("auth_kind") or "none").strip().lower() == "none":
        return
    raise HTTPException(
        status_code=409,
        detail={
            "error": "credentialed_preflight_requires_worker",
            "message": (
                "Credentialed AI target checks must run through AI Gate Scan so the "
                "target-bound worker resolves the credential after approval."
            ),
            "next_action": "Queue an AI Gate Scan for this target.",
        },
    )


def _build_ai_worker_options(
    *,
    target: dict[str, Any],
    credential_profile_ref: dict[str, Any] | None,
    request: AITargetScanRequest,
    principal_refs: Optional[list[dict[str, Any]]] = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    probe_pack = request.probe_pack if request.probe_pack in AI_PROBE_PACKS else "shaker-ai-smoke"
    scan_profile = request.scan_profile if request.scan_profile in AI_SCAN_PROFILES else "smoke"
    environment = request.environment if request.environment in AI_ENVIRONMENTS else "preview"
    run_kind = _ai_target_run_kind(target["target_type"])
    metadata_json = dict(target.get("metadata_json") or {})
    metadata_json["scan_profile"] = scan_profile
    if request.ai_judge_enabled is not None:
        metadata_json["ai_judge_enabled"] = request.ai_judge_enabled
    if request.semantic_judge_enabled is not None:
        metadata_json["semantic_judge_enabled"] = request.semantic_judge_enabled
    production_scan = bool(target.get("production_mode")) or environment == "production"
    production_confirmation = None
    if production_scan:
        endpoint_hash = hashlib.sha256(
            str(target.get("endpoint_url") or "").strip().encode("utf-8")
        ).hexdigest()
        production_confirmation = {
            "confirmed": bool(request.confirm_production),
            "confirmed_at": datetime.now(timezone.utc).isoformat(),
            "environment": environment,
            "target_production_mode": bool(target.get("production_mode")),
            "target_id": str(target.get("id") or ""),
            "target_type": target.get("target_type"),
            "endpoint_hash": f"sha256:{endpoint_hash}",
            "probe_pack": probe_pack,
            "scan_profile": scan_profile,
        }
        metadata_json["production_confirmation"] = production_confirmation

    storage_options = {
        "run_kind": run_kind,
        "ai_enabled": True,
        "ai_target_id": target["id"],
        "ai_target_type": target["target_type"],
        "ai_target_name": target["name"],
        "ai_probe_pack": probe_pack,
        "ai_scan_profile": scan_profile,
        "ai_environment": environment,
        "ai_response_path": target.get("response_path"),
        "ai_streaming_mode": target.get("streaming_mode"),
        "ai_request_budget": target.get("request_budget"),
        "ai_token_budget": target.get("token_budget"),
    }
    if production_confirmation:
        storage_options["production_confirmation"] = production_confirmation
    admitted_principal_refs = [dict(row) for row in (principal_refs or [])]
    if admitted_principal_refs:
        metadata_json["principal_count"] = len(admitted_principal_refs)
        metadata_json["principal_roles"] = sorted(
            {
                str(item.get("role") or "")
                for item in admitted_principal_refs if item.get("role")
            }
        )
        storage_options["ai_principal_count"] = len(admitted_principal_refs)
        storage_options["ai_principal_roles"] = metadata_json["principal_roles"]
    worker_options = {
        **storage_options,
        "ai_target": {
            "id": target["id"],
            "name": target["name"],
            "target_type": target["target_type"],
            "endpoint_url": target["endpoint_url"],
            "method": target["method"],
            "headers_template": target.get("headers_template") or {},
            "request_template": target.get("request_template") or {},
            "response_path": target.get("response_path"),
            "streaming_mode": target.get("streaming_mode") or "json",
            "rate_limit_rps": target.get("rate_limit_rps"),
            "token_budget": target.get("token_budget"),
            "request_budget": target.get("request_budget"),
            "production_mode": target.get("production_mode"),
            "metadata_json": metadata_json,
            "credential_profile_ref": credential_profile_ref,
        },
    }
    if admitted_principal_refs:
        worker_options["ai_target"]["principal_refs"] = admitted_principal_refs
    return worker_options, storage_options


def _ai_scan_options_from_row(scan_row: Any) -> dict[str, Any]:
    if not scan_row:
        return {}
    options = scan_row.get("options") if isinstance(scan_row, dict) else scan_row["options"]
    return parse_json_field(options) or {}


def _build_ai_finding_retest_scan_options(
    *,
    target: dict[str, Any],
    credential_profile_ref: dict[str, Any] | None,
    finding: dict[str, Any],
    original_scan_options: dict[str, Any],
    request: AIFindingRetestRequest,
    verification_id: uuid.UUID,
    principal_refs: Optional[list[dict[str, Any]]] = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    context = _ai_finding_probe_context(finding)
    probe_id = context.get("probe_id")
    probe_family = context.get("probe_family")
    if request.mode in {"same_probe", "strict_replay"} and not probe_id:
        raise HTTPException(status_code=400, detail="AI Gate finding is missing probe_id context for focused replay")
    if request.mode == "same_family" and not probe_family:
        raise HTTPException(status_code=400, detail="AI Gate finding is missing probe_family context for family replay")

    original_confirmation = original_scan_options.get("production_confirmation")
    original_confirmed = isinstance(original_confirmation, dict) and original_confirmation.get("confirmed") is True
    scan_request = AITargetScanRequest(
        probe_pack=str(original_scan_options.get("ai_probe_pack") or "shaker-ai-smoke"),
        scan_profile=str(original_scan_options.get("ai_scan_profile") or "smoke"),
        environment=str(original_scan_options.get("ai_environment") or "preview"),
        confirm_production=bool(request.confirm_production or original_confirmed),
        ai_judge_enabled=original_scan_options.get("ai_judge_enabled"),
        semantic_judge_enabled=original_scan_options.get("semantic_judge_enabled"),
    )
    worker_options, storage_options = _build_ai_worker_options(
        target=target,
        credential_profile_ref=credential_profile_ref,
        request=scan_request,
        principal_refs=principal_refs,
    )

    focus_probe_ids = [probe_id] if request.mode in {"same_probe", "strict_replay"} and probe_id else []
    focus_probe_family = probe_family if request.mode == "same_family" else None
    metadata_json = worker_options["ai_target"].setdefault("metadata_json", {})
    if focus_probe_ids:
        worker_options["ai_focus_probe_ids"] = focus_probe_ids
        metadata_json["ai_focus_probe_ids"] = focus_probe_ids
    if focus_probe_family:
        worker_options["ai_focus_probe_family"] = focus_probe_family
        metadata_json["ai_focus_probe_family"] = focus_probe_family
    if request.mode == "strict_replay":
        metadata_json["strict_replay"] = True
        metadata_json["replay_previous_response"] = context["evidence"].get("response_excerpt")

    replay_plan = {
        "mode": request.mode,
        "finding_id": str(finding["id"]),
        "verification_id": str(verification_id),
        "probe_id": probe_id,
        "probe_family": probe_family,
        "source_finding_id": context.get("source_finding_id"),
        "probe_pack": scan_request.probe_pack,
        "scan_profile": scan_request.scan_profile,
        "environment": scan_request.environment,
    }
    worker_options["ai_finding_retest"] = replay_plan
    storage_options["ai_finding_retest"] = replay_plan
    return worker_options, storage_options, replay_plan


def _build_ai_scan_replay_plan(
    scan_result: dict[str, Any],
    request: AIScanReplayRequest,
) -> dict[str, Any]:
    ai_gate = scan_result.get("ai_gate") if isinstance(scan_result, dict) else {}
    if not isinstance(ai_gate, dict) or not ai_gate:
        raise HTTPException(status_code=400, detail="Scan does not contain an AI Gate result")
    coverage = ai_gate.get("coverage_matrix") if isinstance(ai_gate.get("coverage_matrix"), dict) else {}
    by_family = coverage.get("by_family") if isinstance(coverage.get("by_family"), dict) else {}
    skipped = coverage.get("skipped") if isinstance(coverage.get("skipped"), list) else []
    transcripts = ai_gate.get("transcripts") if isinstance(ai_gate.get("transcripts"), list) else []
    mode = request.mode or "skipped"
    focus_probe_ids: list[str] = []
    focus_family = (request.probe_family or "").strip() or None
    transcript_context: dict[str, Any] | None = None

    def _count(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    if mode == "skipped":
        focus_probe_ids = [
            str(item.get("probe_id"))
            for item in skipped
            if isinstance(item, dict) and item.get("probe_id")
        ]
        if not focus_probe_ids:
            raise HTTPException(status_code=400, detail="AI Gate scan has no skipped probe ids to replay")
    elif mode == "errors":
        error_families = [
            family
            for family, bucket in by_family.items()
            if isinstance(bucket, dict) and _count(bucket.get("errors")) > 0
        ]
        if not error_families:
            raise HTTPException(status_code=400, detail="AI Gate scan has no errored families to rerun")
        if len(error_families) == 1:
            focus_family = str(error_families[0])
        else:
            focus_probe_ids = [
                str(item.get("probe_id"))
                for item in skipped
                if isinstance(item, dict)
                and item.get("probe_id")
                and str(item.get("family") or "") in {str(f) for f in error_families}
            ]
            if not focus_probe_ids:
                focus_family = str(error_families[0])
    elif mode == "family":
        if not focus_family:
            raise HTTPException(status_code=400, detail="probe_family is required for family replay")
        if by_family and focus_family not in by_family:
            raise HTTPException(status_code=400, detail=f"Probe family {focus_family!r} was not planned in this scan")
    elif mode == "transcript":
        requested_probe_id = (request.probe_id or "").strip()
        selected_index = request.transcript_index
        selected_transcript: dict[str, Any] | None = None
        if requested_probe_id:
            for idx, item in enumerate(transcripts):
                if isinstance(item, dict) and str(item.get("probe_id") or "").strip() == requested_probe_id:
                    selected_transcript = item
                    selected_index = idx
                    break
            if selected_transcript is None:
                raise HTTPException(status_code=400, detail=f"Transcript probe_id {requested_probe_id!r} was not found in this scan")
        elif selected_index is not None:
            if selected_index >= len(transcripts):
                raise HTTPException(status_code=400, detail="transcript_index is out of range")
            candidate = transcripts[selected_index]
            selected_transcript = candidate if isinstance(candidate, dict) else None
        else:
            raise HTTPException(status_code=400, detail="probe_id or transcript_index is required for transcript replay")
        if not isinstance(selected_transcript, dict):
            raise HTTPException(status_code=400, detail="Selected transcript is not replayable")
        transcript_probe_id = str(selected_transcript.get("probe_id") or "").strip()
        if not transcript_probe_id:
            raise HTTPException(status_code=400, detail="Selected transcript is missing probe_id context")
        focus_probe_ids = [transcript_probe_id]
        turns = selected_transcript.get("turns")
        transcript_context = {
            "transcript_index": selected_index,
            "probe_id": transcript_probe_id,
            "probe_family": selected_transcript.get("probe_family") or selected_transcript.get("strategy_id"),
            "technique": selected_transcript.get("technique"),
            "status_code": selected_transcript.get("status_code"),
            "stop_reason": selected_transcript.get("stop_reason"),
            "turn_count": len(turns) if isinstance(turns, list) else selected_transcript.get("turn_count"),
            "had_error": bool(selected_transcript.get("error")),
        }
    elif mode == "all":
        focus_family = None
        focus_probe_ids = []
    else:
        raise HTTPException(status_code=400, detail="Unsupported AI Gate replay mode")

    summary = coverage.get("summary") if isinstance(coverage.get("summary"), dict) else {}
    return {
        "mode": mode,
        "probe_ids": focus_probe_ids,
        "probe_family": focus_family,
        "source_planned": summary.get("planned"),
        "source_executed": summary.get("executed"),
        "source_skipped": summary.get("skipped"),
        "source_errors": summary.get("errors"),
        "probe_pack": ai_gate.get("probe_pack"),
        "scan_profile": ai_gate.get("scan_profile"),
        "environment": (ai_gate.get("decision") or {}).get("environment") if isinstance(ai_gate.get("decision"), dict) else None,
        "transcript": transcript_context,
    }


def _build_ai_campaign_history(current_scan: Any, scan_rows: list[Any], *, limit: int = 6) -> dict[str, Any]:
    current_id = str(_row_value(current_scan, "id") or "")
    context = _ai_campaign_context_from_scan(current_scan)
    all_entries = [_ai_campaign_history_entry(row, current_scan_id=current_id) for row in scan_rows]

    def _matches_context(entry: dict[str, Any]) -> bool:
        return (
            (entry.get("probe_pack") or "") == context["probe_pack"]
            and (entry.get("scan_profile") or "") == context["scan_profile"]
            and (entry.get("environment") or "") == context["environment"]
        )

    comparable = [entry for entry in all_entries if _matches_context(entry)]
    if not any(entry["current"] for entry in comparable):
        comparable.insert(0, _ai_campaign_history_entry(current_scan, current_scan_id=current_id))
    comparable = comparable[:limit]
    current_entry = next((entry for entry in comparable if entry["current"]), _ai_campaign_history_entry(current_scan, current_scan_id=current_id))
    previous_entry = next((entry for entry in comparable if not entry["current"]), None)
    deltas = None
    if previous_entry:
        deltas = {
            "findings_count": current_entry["findings_count"] - previous_entry["findings_count"],
            "executed": current_entry["executed"] - previous_entry["executed"],
            "skipped": current_entry["skipped"] - previous_entry["skipped"],
            "errors": current_entry["errors"] - previous_entry["errors"],
            "coverage_pct": current_entry["coverage_pct"] - previous_entry["coverage_pct"],
            "decision_changed": current_entry.get("decision") != previous_entry.get("decision"),
        }
    return {
        "scan_id": current_id,
        "ai_target_id": str(_row_value(current_scan, "ai_target_id") or ""),
        "target_url": _row_value(current_scan, "target_url"),
        "context": {
            "probe_pack": context["probe_pack"] or None,
            "scan_profile": context["scan_profile"] or None,
            "environment": context["environment"] or None,
        },
        "runs": comparable,
        "previous_run": previous_entry,
        "deltas": deltas,
        "trend_series": {
            "overall": _ai_readiness_trend_points(comparable),
        },
        "total_same_target_runs": len(all_entries),
    }


def _build_ai_target_campaign_history(target_id: str, scan_rows: list[Any], *, limit: int = 12) -> dict[str, Any]:
    """Build target-level AI Gate campaign history grouped by probe/profile/environment."""
    entries = [_ai_campaign_history_entry(row) for row in scan_rows]
    entries = entries[:limit]
    contexts: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in entries:
        key = (
            str(entry.get("probe_pack") or ""),
            str(entry.get("scan_profile") or ""),
            str(entry.get("environment") or ""),
        )
        bucket = contexts.setdefault(
            key,
            {
                "probe_pack": entry.get("probe_pack"),
                "scan_profile": entry.get("scan_profile"),
                "environment": entry.get("environment"),
                "runs": [],
            },
        )
        bucket["runs"].append(entry)

    context_summaries: list[dict[str, Any]] = []
    for bucket in contexts.values():
        runs = bucket["runs"]
        latest = runs[0] if runs else None
        previous = runs[1] if len(runs) > 1 else None
        deltas = None
        if latest and previous:
            deltas = {
                "findings_count": latest["findings_count"] - previous["findings_count"],
                "executed": latest["executed"] - previous["executed"],
                "skipped": latest["skipped"] - previous["skipped"],
                "errors": latest["errors"] - previous["errors"],
                "coverage_pct": latest["coverage_pct"] - previous["coverage_pct"],
                "decision_changed": latest.get("decision") != previous.get("decision"),
            }
        context_summaries.append({
            "probe_pack": bucket["probe_pack"],
            "scan_profile": bucket["scan_profile"],
            "environment": bucket["environment"],
            "runs_count": len(runs),
            "latest_run": latest,
            "previous_run": previous,
            "deltas": deltas,
            "readiness_trend": _ai_readiness_trend(latest, previous),
            "trend_points": _ai_readiness_trend_points(runs),
        })

    latest_run = entries[0] if entries else None
    previous_run = entries[1] if len(entries) > 1 else None
    context_trend_series = [
        {
            "probe_pack": item.get("probe_pack"),
            "scan_profile": item.get("scan_profile"),
            "environment": item.get("environment"),
            "runs_count": item.get("runs_count"),
            "points": item.get("trend_points") or [],
        }
        for item in context_summaries
    ]
    return {
        "ai_target_id": str(target_id),
        "runs": entries,
        "contexts": context_summaries,
        "latest_run": latest_run,
        "readiness_trends": {
            "overall": _ai_readiness_trend(latest_run, previous_run),
            "contexts": [
                {
                    "probe_pack": item.get("probe_pack"),
                    "scan_profile": item.get("scan_profile"),
                    "environment": item.get("environment"),
                    "runs_count": item.get("runs_count"),
                    "trend": item.get("readiness_trend"),
                }
                for item in context_summaries
            ],
        },
        "trend_series": {
            "overall": _ai_readiness_trend_points(entries),
            "contexts": context_trend_series,
        },
        "summary": {
            "total_runs": len(entries),
            "contexts": len(context_summaries),
            "blocked_runs": sum(1 for entry in entries if entry.get("decision") == "block"),
            "errored_runs": sum(1 for entry in entries if entry.get("errors", 0) > 0),
            "budget_stopped_runs": sum(1 for entry in entries if entry.get("stopped_by_request_budget")),
        },
    }


def _build_ai_target_campaign_history_export(
    history: dict[str, Any],
    *,
    generated_at: Optional[datetime] = None,
) -> dict[str, Any]:
    generated = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    runs = history.get("runs") if isinstance(history.get("runs"), list) else []
    manifest_runs = [
        {
            "scan_id": item.get("id"),
            **(item.get("evidence_manifest_summary") or {}),
        }
        for item in runs
        if isinstance(item, dict)
        and isinstance(item.get("evidence_manifest_summary"), dict)
        and item.get("evidence_manifest_summary", {}).get("available")
    ]
    evidence_manifests = {
        "available_count": len(manifest_runs),
        "manifest_hashes": [item.get("manifest_hash") for item in manifest_runs if item.get("manifest_hash")],
        "transcripts_hashes": [
            ((item.get("evidence_hashes") or {}).get("transcripts_hash"))
            for item in manifest_runs
            if isinstance(item.get("evidence_hashes"), dict) and (item.get("evidence_hashes") or {}).get("transcripts_hash")
        ],
        "runs": manifest_runs,
    }
    export_core = {
        "ai_target_id": history.get("ai_target_id"),
        "summary": history.get("summary") or {},
        "readiness_trends": history.get("readiness_trends") or {},
        "trend_series": history.get("trend_series") or {},
        "run_ids": [item.get("id") for item in runs if isinstance(item, dict)],
        "evidence_manifest_hashes": evidence_manifests["manifest_hashes"],
    }
    export_hash = hashlib.sha256(
        json.dumps(export_core, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "2026-07-06.ai-target-campaign-history-export.v1",
        "generated_at": generated.isoformat(),
        "export_hash": export_hash,
        "content_included": False,
        "transcripts_included": False,
        "ai_target_id": history.get("ai_target_id"),
        "summary": history.get("summary") or {},
        "readiness_trends": history.get("readiness_trends") or {},
        "trend_series": history.get("trend_series") or {},
        "evidence_manifests": evidence_manifests,
        "contexts": history.get("contexts") or [],
        "runs": runs,
        "report_links": [
            {
                "scan_id": item.get("id"),
                "scan_url": item.get("ui_url"),
                "redteam_report_url": f"/scans/{item.get('id')}/ai-redteam-report" if item.get("id") else None,
            }
            for item in runs
            if isinstance(item, dict)
        ],
    }


def _run_ai_target_connectivity_probe(target: dict[str, Any], *, prompt: str, timeout_seconds: int) -> dict[str, Any]:
    method = str(target.get("method") or "POST").upper()
    if target.get("target_type") == "widget":
        return {
            "ok": False,
            "supported": False,
            "stage": "configuration",
            "error": "Widget connectivity requires a browser session and is validated during widget scans.",
        }

    replacements = {
        "prompt": prompt,
        "probe_id": "connectivity.preflight",
        "session_id": f"connectivity-{uuid.uuid4().hex[:12]}",
    }
    headers = ai_build_headers(target)
    headers.setdefault("User-Agent", "ShakerScan AI Gate connectivity check")
    endpoint_url = ai_build_url(str(target.get("endpoint_url") or ""), target)
    body = ai_replace_placeholders(target.get("request_template") or {}, replacements)
    request_url = ai_append_query_params(endpoint_url, body) if method == "GET" else endpoint_url
    data = None
    if method != "GET":
        data = json.dumps(body).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(request_url, data=data, headers=headers, method=method)
    started = utc_now()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - user-configured local scanner target
            raw_bytes = response.read(100_000)
            raw_text = raw_bytes.decode("utf-8", errors="replace")
            content_type = response.headers.get("Content-Type", "")
            response_text = ai_extract_response_text(raw_text, content_type, target.get("response_path"))
            status_code = int(response.status)
    except urllib.error.HTTPError as exc:
        raw_bytes = exc.read(100_000)
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        response_text = ai_extract_response_text(raw_text, content_type, target.get("response_path"))
        status_code = int(exc.code)
    except Exception as exc:  # noqa: BLE001 - surface precise connectivity errors to the operator
        elapsed_ms = round((utc_now() - started).total_seconds() * 1000, 1)
        return {
            "ok": False,
            "supported": True,
            "stage": "request",
            "error": str(exc),
            "request": {
                "method": method,
                "url": request_url,
                "headers": _mask_ai_headers_for_preview(headers),
                "body": body if method != "GET" else None,
            },
            "latency_ms": elapsed_ms,
        }

    elapsed_ms = round((utc_now() - started).total_seconds() * 1000, 1)
    response_path_ok = bool(str(response_text or "").strip())
    ok = 200 <= status_code < 400 and response_path_ok
    return {
        "ok": ok,
        "supported": True,
        "stage": "response_path" if not response_path_ok else "complete",
        "status_code": status_code,
        "latency_ms": elapsed_ms,
        "content_type": content_type,
        "response_path": target.get("response_path"),
        "response_path_ok": response_path_ok,
        "request": {
            "method": method,
            "url": request_url,
            "headers": _mask_ai_headers_for_preview(headers),
            "body": body if method != "GET" else None,
        },
        "response": {
            "excerpt": raw_text[:2000],
            "extracted_text": str(response_text or "")[:2000],
        },
    }


def _ai_transcript_sensitive_allowed() -> bool:
    """Admin gate for raw (unredacted) transcript access.

    ShakerScan has no user-auth layer, so the operator opts in explicitly via
    AI_TRANSCRIPT_ALLOW_SENSITIVE. When off (default), raw transcripts are never
    returned over the API regardless of the include_sensitive query param.
    """
    return str(os.environ.get("AI_TRANSCRIPT_ALLOW_SENSITIVE", "")).strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


class AIOpsRouterRequest(BaseModel):
    """Natural-language DAST/ASM intent planner for AI agents.

    Execution is intentionally conservative: active or state-changing intents dry-run by default
    and require request confirmation plus the gated-execution policy before this API queues work.
    Standard installs enable the policy; AI_OPS_ROUTER_EXECUTE_ENABLED=false disables it globally.
    """

    prompt: Optional[str] = None
    utterance: Optional[str] = None
    target: Optional[str] = None
    target_id: Optional[str] = None
    execute: bool = False
    confirm_execution: bool = False
    confirm_authorized: bool = False
    confirm_high_risk: bool = False
    auth_context: dict[str, Any] = Field(default_factory=dict)


def _build_ai_ops_router_plan(request: AIOpsRouterRequest) -> dict[str, Any]:
    text = _ai_ops_prompt_text(request)
    lowered = text.lower()
    explicit_scan_match = re.search(
        r"\b(quick|standard|deep|full|aggressive|smart)\s+scan\b", lowered
    )
    missing: list[str] = []
    non_goals = [
        "no implicit Lab/deep upgrade",
        "no hidden shard or ASM implementation rows",
        "no active work without explicit authorization",
    ]
    authorization_assumption = (
        "The requester confirms they own or are authorized to test the target before execution."
    )
    intent = "unknown"
    planned_call: dict[str, Any] | None = None
    safety_preset = "safe"
    active_or_budget = False
    high_risk_families: list[str] = []
    active_families: list[str] = []
    rate_cap_changes: dict[str, Any] = {}
    explanation = "I could not map the request to a supported DAST/ASM operation."

    if not text:
        missing.append("prompt")
    elif "full coverage" in lowered or "scan all endpoint" in lowered:
        intent = "run_full_coverage"
        active_or_budget = True
        active_families = ["all"]
        safety_preset = "balanced"
        if not request.target:
            missing.append("target")
        planned_call = _ai_ops_call(
            "POST",
            "/scans",
            _ai_ops_scan_body(
                request.target or "<target>",
                budget_profile="thorough",
                active_testing=True,
                options={
                    "parallel": True,
                    "shard_strategy": "coverage",
                    "exploit_depth": False,
                },
            ),
        )
        explanation = "Plan a one-shot Full Coverage scan with discover-once dynamic fan-out."
    elif explicit_scan_match:
        # Product vocabulary is intentionally exact: "deep scan" is DAST, while "Deep Hunt" is
        # the separate /agent/hunt workflow. Exact named DAST requests take precedence over
        # more general family words that might also appear in the prompt.
        scan_type = explicit_scan_match.group(1)
        intent = f"run_dast_{scan_type}"
        active_or_budget = True  # queueing any scan is a state-changing operation
        if scan_type in {"full", "smart"}:
            safety_preset = "balanced"
            active_families = ["all"]
        elif scan_type == "aggressive":
            safety_preset = "lab"
            active_families = ["all"]
        else:
            safety_preset = "safe"
        if not request.target:
            missing.append("target")
        profile, active = {
            "quick": ("fast", False),
            "standard": ("balanced", False),
            "deep": ("thorough", False),
            "full": ("thorough", True),
            "aggressive": ("thorough", True),
            "smart": ("thorough", True),
        }[scan_type]
        planned_call = _ai_ops_call(
            "POST", "/scans",
            _ai_ops_scan_body(
                request.target or "<target>",
                budget_profile=profile,
                active_testing=active,
            ),
        )
        explanation = f"Plan the explicitly requested {scan_type} DAST scan."
    elif ("keep" in lowered and "covered" in lowered) or "enable asm" in lowered or "continuous asm" in lowered:
        intent = "enable_continuous_asm"
        active_or_budget = True
        safety_preset = "safe"
        if not request.target_id:
            missing.append("target_id")
        body = {
            "enabled": True,
            "config": {
                "batch_size": asm_inventory.DEFAULT_ASM_CONFIG["batch_size"],
                "stale_days": asm_inventory.DEFAULT_ASM_CONFIG["stale_days"],
                "recon_interval_hours": asm_inventory.DEFAULT_ASM_CONFIG["recon_interval_hours"],
                "exploit_depth": False,
            },
        }
        planned_call = _ai_ops_call("PUT", f"/targets/{request.target_id or '<target_id>'}/asm/policy", body)
        explanation = "Enable safe Continuous ASM defaults for the target."
    elif "untested" in lowered or "gaps" in lowered or "not tested" in lowered or "still needs" in lowered:
        intent = "explain_asm_gaps"
        safety_preset = "read_only"
        if not request.target_id:
            missing.append("target_id")
        planned_call = _ai_ops_call("GET", f"/targets/{request.target_id or '<target_id>'}/asm/gaps")
        explanation = "Read the ASM coverage gap summary without queueing work."
    elif "budget" in lowered and ("api" in lowered or "apis" in lowered or "endpoint" in lowered):
        intent = "increase_api_endpoint_budget"
        active_or_budget = True
        active_families = ["all"]
        safety_preset = "safe"
        if not request.target_id:
            missing.append("target_id")
        api_batch_size = min(200, max(100, int(asm_inventory.DEFAULT_ASM_CONFIG["batch_size"]) * 2))
        body = {"endpoint_filter": "api", "batch_size": api_batch_size, "exploit_depth": False}
        planned_call = _ai_ops_call(
            "POST",
            f"/targets/{request.target_id or '<target_id>'}/asm/improve",
            body,
        )
        rate_cap_changes = {
            "global_defaults_changed": False,
            "endpoint_filter": "api",
            "batch_size": api_batch_size,
        }
        explanation = (
            "Queue the next ASM improvement pass with extra batch budget scoped to API-like endpoints only; "
            "target-wide defaults stay unchanged."
        )
    else:
        family: str | None = None
        if "bola" in lowered or "idor" in lowered or "object authorization" in lowered:
            family = "bola"
        elif (
            "authentication" in lowered
            or "auth bypass" in lowered
            or "anonymous access" in lowered
            or "unauthenticated" in lowered
            or "access control" in lowered
        ):
            family = "auth"
        elif "sqli" in lowered or "sql injection" in lowered:
            family = "sqli"
        elif "xss" in lowered or "cross-site scripting" in lowered:
            family = "xss"
        if family:
            intent = f"focused_asm_{family}"
            active_or_budget = True
            active_families = [family]
            if not request.target_id:
                missing.append("target_id")
            body: dict[str, Any] = {"check_family": family}
            if family == "bola":
                high_risk_families = ["bola"]
                body["exploit_depth"] = True
                safety_preset = "lab"
                if not _ai_ops_has_auth_context(request, "primary"):
                    missing.append("primary_auth_context")
                if not _ai_ops_has_auth_context(request, "second_user"):
                    missing.append("second_user_auth_context")
            elif family == "auth":
                safety_preset = "balanced"
                if not _ai_ops_has_auth_context(request, "primary"):
                    missing.append("primary_auth_context")
            else:
                safety_preset = "balanced"
            planned_call = _ai_ops_call("POST", f"/targets/{request.target_id or '<target_id>'}/asm/improve", body)
            explanation = f"Queue a focused ASM endpoint batch for {family} only."
        elif "scan" in lowered and not any(
            phrase in lowered for phrase in ("deep hunt", "autonomous hunt", "investigate autonomously")
        ):
            # Only an otherwise-unqualified scan falls back to quick DAST. Keep this after ASM,
            # gap, budget, and focused-family routing so ordinary wording such as "scan for SQL
            # injection" cannot be swallowed by the generic DAST fallback.
            intent = "run_dast_quick"
            active_or_budget = True
            safety_preset = "safe"
            if not request.target:
                missing.append("target")
            planned_call = _ai_ops_call(
                "POST",
                "/scans",
                _ai_ops_scan_body(
                    request.target or "<target>",
                    budget_profile="fast",
                    active_testing=False,
                ),
            )
            explanation = "Plan the documented quick DAST default for an unqualified scan request."

    requires_confirmation = bool(active_or_budget or high_risk_families)
    execution_enabled = _ai_ops_execute_enabled()
    confirmation_ok = (
        request.execute
        and (not requires_confirmation or request.confirm_execution)
        and (not active_or_budget or request.confirm_authorized)
        and (not high_risk_families or request.confirm_high_risk)
    )
    execution_allowed = bool(
        request.execute
        and not missing
        and planned_call
        and (not requires_confirmation or (execution_enabled and confirmation_ok))
    )
    dry_run = not execution_allowed
    execution_blocked_reason = None
    if request.execute and dry_run:
        if missing:
            execution_blocked_reason = "missing_inputs"
        elif requires_confirmation and not execution_enabled:
            execution_blocked_reason = "AI_OPS_ROUTER_EXECUTE_ENABLED is not enabled"
        elif requires_confirmation and not confirmation_ok:
            execution_blocked_reason = "confirmation_required"
        else:
            execution_blocked_reason = "unsupported_intent"

    return {
        "intent": intent,
        "dry_run": dry_run,
        "execute_requested": bool(request.execute),
        "execution_allowed": execution_allowed,
        "execution_blocked_reason": execution_blocked_reason,
        "requires_confirmation": requires_confirmation,
        "safety_preset": safety_preset,
        "missing_inputs": list(dict.fromkeys(missing)),
        "planned_api_call": planned_call,
        "planned_api_calls": [planned_call] if planned_call else [],
        "explanation": explanation,
        "authorization_assumption": authorization_assumption if active_or_budget else None,
        "blast_radius": {
            "target": request.target,
            "target_id": request.target_id,
            "active_families": active_families,
            "high_risk_families": high_risk_families,
            "auth_states": ["configured target credentials"] if active_or_budget else [],
            "rate_cap_changes": rate_cap_changes,
        },
        "non_goals": non_goals,
    }
def _normalize_demo_base_url(value: Any, *, default: str = "") -> str:
    return _validate_demo_base_url(value, default=default)




















def _contains_prompt_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return "{{prompt}}" in value
    if isinstance(value, list):
        return any(_contains_prompt_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_prompt_placeholder(item) for item in value.values())
    return False


def _parse_multi_header_lines(raw: str | None) -> list[dict[str, str]]:
    if not raw:
        return []
    pairs: list[dict[str, str]] = []
    for line in raw.splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip() and value.strip():
            pairs.append({"name": name.strip(), "value": value.strip()})
    return pairs


def _normalize_multi_header_pairs(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    pairs: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        header_value = str(item.get("value") or "").strip()
        if name and header_value:
            pairs.append({"name": name, "value": header_value})
    return pairs


def _sanitize_ai_credential(row: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not row:
        return {
            "auth_kind": "none",
            "header_name": None,
            "secret_configured": False,
            "secret_preview": None,
            "metadata_json": {},
        }
    return {
        "auth_kind": row.get("auth_kind") or "none",
        "header_name": row.get("header_name"),
        "secret_configured": bool(row.get("secret_value")),
        "secret_preview": row.get("secret_preview"),
        "metadata_json": _decode_json_value(row.get("credential_metadata_json") or row.get("metadata_json") or {}),
    }


async def _resolve_ai_gate_credential_profile(
    conn: Any,
    row: Any,
    *,
    target_id: Any,
) -> dict[str, Any] | None:
    item = row_to_dict(row) if row else {}
    if str(item.get("auth_kind") or "none") == "none":
        return None
    profile_id = item.get("id")
    try:
        profile = await _generic_credential_store.get_profile(
            conn, profile_id=profile_id,
        )
    except CredentialStoreError as exc:
        raise HTTPException(
            status_code=409,
            detail="AI Gate credential migration is incomplete; restart the API and workers",
        ) from exc
    expires_at = profile.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not profile.is_active or (
        expires_at is not None and expires_at <= datetime.now(timezone.utc)
    ):
        raise HTTPException(status_code=409, detail="AI Gate credential is inactive or expired")
    if profile.target_kind != "api" or profile.target_id != str(target_id):
        raise HTTPException(status_code=409, detail="AI Gate credential target binding changed")
    if profile.auth_kind not in AI_GATE_GENERIC_AUTH_KINDS:
        raise HTTPException(
            status_code=409,
            detail="AI Gate credential authentication kind is not executable",
        )
    allowed = tuple(profile.allowed_capabilities)
    if allowed and AI_GATE_GENERIC_CREDENTIAL_CAPABILITY not in allowed:
        raise HTTPException(
            status_code=409,
            detail=f"AI Gate credential does not allow {AI_GATE_GENERIC_CREDENTIAL_CAPABILITY}",
        )
    return _generic_ai_credential_ref(profile)


def _ai_principal_ref(
    row: Any,
    credential_profile_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    principal = row_to_dict(row)
    metadata = _decode_json_value(principal.get("metadata_json")) or {}
    return {
        "id": principal.get("id"),
        "label": principal.get("label"),
        "role": principal.get("role"),
        "tenant_id": principal.get("tenant_id"),
        "auth_kind": (
            credential_profile_ref.get("auth_kind")
            if credential_profile_ref else "none"
        ),
        "credential_configured": credential_profile_ref is not None,
        "credential_profile_ref": credential_profile_ref,
        "metadata_json": _sanitize_scan_options(metadata),
    }


def _ai_target_run_kind(target_type: str) -> str:
    if target_type == "widget":
        return "ai_widget"
    if target_type == "rag":
        return "ai_rag"
    if target_type == "agent_trace":
        return "ai_trace"
    if target_type == "mcp_trace":
        return "ai_mcp"
    return "ai_api"


def _fetch_json_url(url: str, *, timeout: int = 15) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        logger.warning("Honey registry fetch failed with HTTP %s for %s", exc.code, url)
        raise HTTPException(status_code=502, detail=f"Honey registry returned HTTP {exc.code}: {body[:200]}") from exc
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError, UnicodeDecodeError) as exc:
        logger.warning("Honey registry fetch failed for %s", url, exc_info=True)
        raise HTTPException(status_code=502, detail=f"Unable to read Honey registry: {exc}") from exc


def _ai_production_confirmation_reason(
    production_mode: bool, environment: str | None, confirm_production: bool
) -> str | None:
    """Return a refusal reason when a production AI Gate scan lacks explicit
    confirmation, else None. Extracted so the gate is unit-testable (a regression
    that drops it would otherwise let active probes hit production unconfirmed)."""
    production_scan = bool(production_mode) or str(environment or "") == "production"
    if production_scan and not confirm_production:
        return (
            "This AI target is marked production"
            if production_mode
            else "This AI Gate scan targets the production environment"
        )
    return None


def _ai_finding_probe_context(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = parse_json_field(finding.get("evidence")) or {}
    probe_id = str(evidence.get("probe_id") or "").strip()
    probe_family = str(evidence.get("probe_family") or evidence.get("strategy_id") or "").strip()
    source_finding_id = str(evidence.get("source_finding_id") or "").strip()
    if not source_finding_id:
        raw_expected = evidence.get("expected_finding") or evidence.get("oracle_expected_finding")
        if probe_id and raw_expected:
            source_finding_id = f"{probe_id}:{str(raw_expected).split(':')[-1]}"
    if not probe_id and source_finding_id and ":" in source_finding_id:
        probe_id = source_finding_id.split(":", 1)[0]
    turns = evidence.get("turns")
    if not probe_family and isinstance(turns, list) and turns:
        first_turn = turns[0] if isinstance(turns[0], dict) else {}
        probe_family = str(first_turn.get("probe_family") or "").strip()
    return {
        "probe_id": probe_id,
        "probe_family": probe_family,
        "source_finding_id": source_finding_id,
        "evidence": evidence,
    }


def _ai_campaign_context_from_scan(scan_row: Any) -> dict[str, Any]:
    options = parse_json_field(_row_value(scan_row, "options")) or {}
    result = _decode_json_value(_row_value(scan_row, "result")) or {}
    ai_gate = result.get("ai_gate") if isinstance(result, dict) else {}
    ai_gate = ai_gate if isinstance(ai_gate, dict) else {}
    decision = ai_gate.get("decision") if isinstance(ai_gate.get("decision"), dict) else {}
    return {
        "probe_pack": str(options.get("ai_probe_pack") or ai_gate.get("probe_pack") or ""),
        "scan_profile": str(options.get("ai_scan_profile") or ai_gate.get("scan_profile") or ""),
        "environment": str(options.get("ai_environment") or decision.get("environment") or ""),
    }


def _ai_campaign_history_entry(scan_row: Any, *, current_scan_id: str | None = None) -> dict[str, Any]:
    result = _decode_json_value(_row_value(scan_row, "result")) or {}
    ai_gate = result.get("ai_gate") if isinstance(result, dict) else {}
    ai_gate = ai_gate if isinstance(ai_gate, dict) else {}
    coverage = ai_gate.get("coverage_matrix") if isinstance(ai_gate.get("coverage_matrix"), dict) else {}
    summary = coverage.get("summary") if isinstance(coverage.get("summary"), dict) else {}
    decision = ai_gate.get("decision") if isinstance(ai_gate.get("decision"), dict) else {}
    evidence_manifest = ai_gate.get("evidence_manifest") if isinstance(ai_gate.get("evidence_manifest"), dict) else {}
    evidence = evidence_manifest.get("evidence") if isinstance(evidence_manifest.get("evidence"), dict) else {}
    evidence_summary = _ai_campaign_evidence_manifest_summary(evidence_manifest)
    evidence_hashes = evidence_summary.get("evidence_hashes") if isinstance(evidence_summary.get("evidence_hashes"), dict) else {}
    context = _ai_campaign_context_from_scan(scan_row)

    def _num(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    planned = _num(summary.get("planned"))
    executed = _num(summary.get("executed"))
    scan_id = str(_row_value(scan_row, "id") or "")
    usage = ai_gate.get("usage") if isinstance(ai_gate.get("usage"), dict) else {}
    coverage_pct = round((executed / planned) * 100) if planned else 0
    findings_count = _num(_row_value(scan_row, "findings_count"))
    errors = _num(summary.get("errors"))
    skipped = _num(summary.get("skipped"))
    decision_value = decision.get("decision")
    readiness_penalty = (
        min(45, findings_count * 8)
        + min(30, errors * 15)
        + (15 if decision_value == "block" else 0)
        + (8 if summary.get("stopped_by_request_budget") or usage.get("stopped_by_request_budget") else 0)
    )
    readiness_score = max(0, min(100, coverage_pct - readiness_penalty))
    return {
        "id": scan_id,
        "ui_url": f"/scans/{scan_id}" if scan_id else None,
        "current": bool(current_scan_id and scan_id == current_scan_id),
        "status": _row_value(scan_row, "status"),
        "target_url": _row_value(scan_row, "target_url"),
        "created_at": _iso_or_none(_row_value(scan_row, "created_at")),
        "completed_at": _iso_or_none(_row_value(scan_row, "completed_at")),
        "score": _row_value(scan_row, "score"),
        "grade": _row_value(scan_row, "grade"),
        "findings_count": findings_count,
        "decision": decision_value,
        "rationale": decision.get("rationale"),
        "probe_pack": context["probe_pack"] or None,
        "scan_profile": context["scan_profile"] or None,
        "environment": context["environment"] or None,
        "planned": planned,
        "executed": executed,
        "skipped": skipped,
        "errors": errors,
        "with_transcripts": _num(summary.get("with_transcripts")),
        "with_findings": _num(summary.get("with_findings")),
        "coverage_pct": coverage_pct,
        "readiness_score": readiness_score,
        "stopped_by_request_budget": bool(summary.get("stopped_by_request_budget") or usage.get("stopped_by_request_budget")),
        "transcripts_hash": evidence_hashes.get("transcripts_hash") or evidence.get("transcripts_hash"),
        "manifest_hash": evidence_summary.get("manifest_hash") if evidence_summary.get("available") else evidence_manifest.get("manifest_hash"),
        "evidence_manifest_summary": evidence_summary,
    }


def _ai_readiness_trend_points(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    points: list[dict[str, Any]] = []
    for entry in reversed(entries):
        points.append({
            "scan_id": entry.get("id"),
            "completed_at": entry.get("completed_at") or entry.get("created_at"),
            "coverage_pct": entry.get("coverage_pct"),
            "readiness_score": entry.get("readiness_score"),
            "findings_count": entry.get("findings_count"),
            "errors": entry.get("errors"),
            "decision": entry.get("decision"),
            "stopped_by_request_budget": bool(entry.get("stopped_by_request_budget")),
        })
    return points


def _ai_readiness_trend(latest: dict[str, Any] | None, previous: dict[str, Any] | None) -> dict[str, Any]:
    def _num(row: dict[str, Any] | None, key: str) -> int:
        if not row:
            return 0
        try:
            return int(row.get(key) or 0)
        except (TypeError, ValueError):
            return 0

    if not latest:
        return {
            "state": "no_runs",
            "latest_run_id": None,
            "previous_run_id": None,
            "coverage_pct": None,
            "coverage_delta": None,
            "findings_delta": None,
            "errors_delta": None,
            "decision_changed": False,
        }
    coverage_delta = None
    findings_delta = None
    errors_delta = None
    decision_changed = False
    if previous:
        coverage_delta = _num(latest, "coverage_pct") - _num(previous, "coverage_pct")
        findings_delta = _num(latest, "findings_count") - _num(previous, "findings_count")
        errors_delta = _num(latest, "errors") - _num(previous, "errors")
        decision_changed = latest.get("decision") != previous.get("decision")
    if not previous:
        state = "baseline"
    elif _num(latest, "errors") > 0:
        state = "regressed"
    elif latest.get("decision") == "block":
        state = "blocked"
    elif (coverage_delta or 0) > 0 and (errors_delta or 0) <= 0:
        state = "improving"
    elif (coverage_delta or 0) < 0 or (errors_delta or 0) > 0:
        state = "regressed"
    else:
        state = "stable"
    return {
        "state": state,
        "latest_run_id": latest.get("id"),
        "previous_run_id": previous.get("id") if previous else None,
        "coverage_pct": latest.get("coverage_pct"),
        "coverage_delta": coverage_delta,
        "findings_count": latest.get("findings_count"),
        "findings_delta": findings_delta,
        "errors": latest.get("errors"),
        "errors_delta": errors_delta,
        "decision": latest.get("decision"),
        "decision_changed": decision_changed,
        "stopped_by_request_budget": bool(latest.get("stopped_by_request_budget")),
    }


def _mask_ai_headers_for_preview(headers: dict[str, str]) -> dict[str, str]:
    masked: dict[str, str] = {}
    for key, value in headers.items():
        normalized = key.lower()
        if normalized in {"authorization", "cookie", "x-api-key"} or "token" in normalized or "secret" in normalized:
            masked[key] = "***"
        else:
            masked[key] = value
    return masked


def _ai_ops_prompt_text(request: AIOpsRouterRequest) -> str:
    return str(request.prompt or request.utterance or "").strip()


def _ai_ops_has_auth_context(request: AIOpsRouterRequest, key: str) -> bool:
    ctx = request.auth_context if isinstance(request.auth_context, dict) else {}
    aliases = {
        "primary": ("primary", "has_primary", "has_primary_auth", "has_primary_auth_context"),
        "second_user": ("second_user", "user2", "has_second_user", "has_second_user_auth", "has_second_user_auth_context"),
    }
    return any(bool(ctx.get(alias)) for alias in aliases.get(key, (key,)))


def _ai_ops_call(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    call: dict[str, Any] = {"method": method, "path": path}
    if body is not None:
        call["body"] = body
    return call


def _ai_ops_scan_body(
    target: str,
    *,
    budget_profile: str,
    active_testing: bool,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "target": target,
        "budget_profile": budget_profile,
        "policy": {"active_testing": active_testing},
        "options": dict(options or {}),
    }
def _validate_demo_base_url(value: Any, *, default: str = "") -> str:
    raw = str(value or "").strip().rstrip("/")
    if not raw:
        raw = default.rstrip("/")
    if not raw:
        return ""
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Demo Honey URL must be an http(s) URL")
    return raw


_generic_credential_store = PostgresCredentialProfileStore()






def _generic_ai_credential_ref(profile: Any) -> dict[str, Any]:
    return {
        "profile_id": profile.profile_id,
        "profile_version": profile.current_version,
        "auth_kind": profile.auth_kind,
        "principal_slot": profile.principal_slot,
        "allowed_capabilities": list(profile.allowed_capabilities),
        "source": "credential_profiles",
        "secret_values_visible": False,
    }


def _ai_campaign_evidence_manifest_summary(evidence_manifest: Any) -> dict[str, Any]:
    """Return a content-free AI Gate evidence manifest summary for campaign exports."""
    manifest = evidence_manifest if isinstance(evidence_manifest, dict) else {}
    if not manifest:
        return {"available": False}

    def _dict_value(key: str) -> dict[str, Any]:
        value = manifest.get(key)
        return value if isinstance(value, dict) else {}

    probe_catalog = _dict_value("probe_catalog")
    detectors = _dict_value("detectors")
    judging = _dict_value("judging")
    evidence_hashes = _dict_value("evidence_hashes")
    budget = _dict_value("budget")
    sanitization = _dict_value("sanitization")
    summary = {
        "available": True,
        "schema_version": manifest.get("schema_version"),
        "target_snapshot_hash": manifest.get("target_snapshot_hash"),
        "probe_catalog": {
            "probe_pack": probe_catalog.get("probe_pack"),
            "scan_profile": probe_catalog.get("scan_profile"),
            "planned_count": probe_catalog.get("planned_count"),
            "executed_count": probe_catalog.get("executed_count"),
            "planned_hash": probe_catalog.get("planned_hash"),
            "executed_hash": probe_catalog.get("executed_hash"),
        },
        "detectors": {
            "version": detectors.get("version"),
            "control_catalog_hash": detectors.get("control_catalog_hash"),
        },
        "judging": {
            "semantic": {
                "enabled": (judging.get("semantic") or {}).get("enabled") if isinstance(judging.get("semantic"), dict) else None,
                "provider_configured": (judging.get("semantic") or {}).get("provider_configured") if isinstance(judging.get("semantic"), dict) else None,
                "model": (judging.get("semantic") or {}).get("model") if isinstance(judging.get("semantic"), dict) else None,
                "rubric_version": (judging.get("semantic") or {}).get("rubric_version") if isinstance(judging.get("semantic"), dict) else None,
                "prompt_hash": (judging.get("semantic") or {}).get("prompt_hash") if isinstance(judging.get("semantic"), dict) else None,
            },
            "rubric": {
                "enabled": (judging.get("rubric") or {}).get("enabled") if isinstance(judging.get("rubric"), dict) else None,
                "provider_configured": (judging.get("rubric") or {}).get("provider_configured") if isinstance(judging.get("rubric"), dict) else None,
                "model": (judging.get("rubric") or {}).get("model") if isinstance(judging.get("rubric"), dict) else None,
                "rubric_version": (judging.get("rubric") or {}).get("rubric_version") if isinstance(judging.get("rubric"), dict) else None,
                "prompt_hash": (judging.get("rubric") or {}).get("prompt_hash") if isinstance(judging.get("rubric"), dict) else None,
            },
        },
        "evidence_hashes": {
            "transcripts_hash": evidence_hashes.get("transcripts_hash"),
            "findings_hash": evidence_hashes.get("findings_hash"),
            "control_evidence_hash": evidence_hashes.get("control_evidence_hash"),
            "coverage_matrix_hash": evidence_hashes.get("coverage_matrix_hash"),
        },
        "budget": {
            "request_budget": budget.get("request_budget"),
            "request_count": budget.get("request_count"),
            "remaining_requests": budget.get("remaining_requests"),
            "stopped_by_request_budget": budget.get("stopped_by_request_budget"),
        },
        "sanitization": {
            "credentials_masked_in_manifest": sanitization.get("credentials_masked_in_manifest"),
            "headers_and_metadata_redacted_by_key": sanitization.get("headers_and_metadata_redacted_by_key"),
        },
    }
    summary["manifest_hash"] = str(manifest.get("manifest_hash") or hashlib.sha256(
        json.dumps(summary, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest())
    return summary
