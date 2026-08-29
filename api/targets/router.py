"""Target routes: inventory, credentials, principals, invariants, graph, and ASM.

Extracted verbatim from the api.py monolith. Owns the target surface — the flat
and grouped listings, root domains, canonical de-duplication, exact-target
credential profiles and principals, operator-approved invariant contracts, the
application graph, and the Continuous-ASM inventory, coverage, gaps, and
queueing actions.

Collaborators that are still hubs inside api.py are injected by the composition
root as lazily-resolved callables, so the dependency direction stays
app -> router and existing test patches of those names keep working.
"""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
import secrets
import contextvars
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
import re
from typing import Any, Callable, Literal, Mapping, Optional
import urllib.parse
import uuid

import asyncpg
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from api_utils import (
        LEGACY_SCAN_WRITE_FIELDS, SEVERITY_ORDER, _ARSENAL_CREATED_BY_CONTEXT,
        _QUEUE_HANDOFF_CONFIRMATION_KEY, _clean_string_list, _target_credential_profile_status,
        _content_free_hash, _direct_query_value, _graph_get, _graph_list,
        _int_or_none, _iso_or_none, _json_safe_row, _optional_uuid,
        _parse_graph_json, _parse_iso_datetime, _record_map, _row_value,
        _severity_sort_value, _short_url_label, _uuid_or_400,
        extract_root_domain, utc_now, utc_now_iso,
    )
    import asm_inventory
    import check_registry
    import invariant_contracts
    import invariant_proposals
    import parallel_scan
    from redaction import is_sensitive_key
    from request_models import (
        HypothesisRequest, ScanAdvancedLimits, ScanOptions,
        ScanPublicCompatibilityOptions, ScanPublicPlacement, _ScanRequestBase,
    )
    from runtime.credential_migration import (
        LegacyCredentialMigrationError, sync_legacy_web_credential,
        sync_legacy_web_credential_by_name,
    )
    from runtime.credential_store import CredentialStoreError
    from runtime.models import TargetBinding
    from scan.action_plan import ScanActionPlanError
    from scan.action_store import PostgresScanActionStore
    from scan.contracts import (
        bind_scan_scope_receipt, raw_scan_authentication_keys, resolve_scan_contract,
    )
    from action_scope import scope_origin_matches_target
    from asset_cohorts import target_cohort
    from scan.jobs import CanonicalScanJob, admitted_credential_profile_ids
    from scan.manifest_store import PostgresScanManifestStore
    from secret_store import decrypt_secret, encrypt_secret, encryption_enabled
    from serialization import _decode_json_value, _decode_jsonb_scalar, _json_object, _str_list, row_to_dict
    from target_dedupe import (
        TargetMergeBlockedError,
        canonical_target_key as _canonical_target_key,
        ensure_no_executing_retention_previews as _ensure_target_merge_safe,
        merge_target_group as _merge_target_group,
        plan_canonical_merges,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from ..api_utils import (
        LEGACY_SCAN_WRITE_FIELDS, SEVERITY_ORDER, _ARSENAL_CREATED_BY_CONTEXT,
        _QUEUE_HANDOFF_CONFIRMATION_KEY, _clean_string_list, _target_credential_profile_status,
        _content_free_hash, _direct_query_value, _graph_get, _graph_list,
        _int_or_none, _iso_or_none, _json_safe_row, _optional_uuid,
        _parse_graph_json, _parse_iso_datetime, _record_map, _row_value,
        _severity_sort_value, _short_url_label, _uuid_or_400,
        extract_root_domain, utc_now, utc_now_iso,
    )
    from .. import asm_inventory, check_registry, invariant_contracts, invariant_proposals, parallel_scan
    from ..runtime.credential_migration import (
        LegacyCredentialMigrationError, sync_legacy_web_credential,
        sync_legacy_web_credential_by_name,
    )
    from ..asset_cohorts import target_cohort
    from ..runtime.credential_store import CredentialStoreError
    from ..runtime.models import TargetBinding
    from ..scan.action_plan import ScanActionPlanError
    from ..scan.action_store import PostgresScanActionStore
    from ..scan.contracts import (
        bind_scan_scope_receipt, raw_scan_authentication_keys, resolve_scan_contract,
    )
    from ..action_scope import scope_origin_matches_target
    from ..scan.jobs import CanonicalScanJob, admitted_credential_profile_ids
    from ..scan.manifest_store import PostgresScanManifestStore
    from ..secret_store import decrypt_secret, encrypt_secret, encryption_enabled
    from ..serialization import _decode_json_value, _decode_jsonb_scalar, _json_object, _str_list, row_to_dict
    from ..target_dedupe import (
        TargetMergeBlockedError,
        canonical_target_key as _canonical_target_key,
        ensure_no_executing_retention_previews as _ensure_target_merge_safe,
        merge_target_group as _merge_target_group,
        plan_canonical_merges,
    )
    from scanner.redaction import is_sensitive_key
    from ..request_models import (
        HypothesisRequest, ScanAdvancedLimits, ScanOptions,
        ScanPublicCompatibilityOptions, ScanPublicPlacement, _ScanRequestBase,
    )


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


def configure_targets_router(
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

# Hub collaborators that still live in api.py. They are injected and resolved
# lazily rather than imported: several have hundreds of transitive dependencies
# inside the monolith, they are defined after routers are registered, and late
# resolution keeps existing test patches of these names effective.

def get_redis(*a: Any, **k: Any) -> Any:
    return _dep("get_redis")(*a, **k)

def enqueue_job(*a: Any, **k: Any) -> Any:
    return _dep("enqueue_job")(*a, **k)

import logging

logger = logging.getLogger("shakerscan.api.targets")

def _json_size_bytes(*a: Any, **k: Any) -> Any:
    return _dep("json_size_bytes")(*a, **k)

def _legacy_credential_migration_http_error(*a: Any, **k: Any) -> Any:
    return _dep("legacy_credential_migration_http_error")(*a, **k)

def _canonical_vulnerability_route(*a: Any, **k: Any) -> Any:
    return _dep("canonical_vulnerability_route")(*a, **k)

def _provision_same_origin_url(*a: Any, **k: Any) -> Any:
    return _dep("provision_same_origin_url")(*a, **k)

def _load_effective_automation_settings(*a: Any, **k: Any) -> Any:
    return _dep("load_effective_automation_settings")(*a, **k)

def _safe_default_asm_config(*a: Any, **k: Any) -> Any:
    return _dep("safe_default_asm_config")(*a, **k)

def _refuse_raw_target_authentication(scan_options: Any) -> None:
    """Refuse raw authentication in stored target options.

    A target's scan_options is inherited by every later scan and every ASM wave, so accepting
    authentication here writes a bearer header, cookie, login password or OAuth secret to JSONB in
    plaintext, outside the encrypted credential store. Canonical Scan admission already refuses to
    spend it, which makes the stored value both a secret at rest and a trap: the write succeeds and
    every scan afterwards fails. Refuse the write instead, using the same canonical vocabulary as
    the direct route and schedules.
    """
    raw_keys = raw_scan_authentication_keys(
        scan_options if isinstance(scan_options, Mapping) else None
    )
    if raw_keys:
        raise HTTPException(
            status_code=422,
            detail=(
                "target scan options reject raw authentication ("
                + ", ".join(raw_keys)
                + "); create an encrypted credential profile and pass "
                "credential_profile_ids with a target-bound approval receipt"
            ),
        )


def _sanitize_scan_options(*a: Any, **k: Any) -> Any:
    return _dep("sanitize_scan_options")(*a, **k)

def _redact_agent_payload(*a: Any, **k: Any) -> Any:
    return _dep("redact_agent_payload")(*a, **k)

def _redact_agent_text(*a: Any, **k: Any) -> Any:
    return _dep("redact_agent_text")(*a, **k)

async def _freeze_scan_target_binding(*a: Any, **k: Any) -> Any:
    return await _dep("freeze_scan_target_binding")(*a, **k)

def _compile_scan_template_work_manifest(*a: Any, **k: Any) -> Any:
    return _dep("compile_scan_template_work_manifest")(*a, **k)

async def _submit_scan(*a: Any, **k: Any) -> Any:
    return await _dep("submit_scan")(*a, **k)

async def _validate_approval_receipt_for_action(*a: Any, **k: Any) -> Any:
    return await _dep("validate_approval_receipt_for_action")(*a, **k)

async def _record_command_result(*a: Any, **k: Any) -> Any:
    return await _dep("record_command_result")(*a, **k)

async def _upsert_hypothesis(*a: Any, **k: Any) -> Any:
    return await _dep("upsert_hypothesis")(*a, **k)

def _hypothesis_situation_report(*a: Any, **k: Any) -> Any:
    return _dep("hypothesis_situation_report")(*a, **k)

def _compile_scan_admission_action_authority(*a: Any, **k: Any) -> Any:
    return _dep("compile_scan_admission_action_authority")(*a, **k)

def _compile_scan_admission_surface_work_manifests(*a: Any, **k: Any) -> Any:
    return _dep("compile_scan_admission_surface_work_manifests")(*a, **k)


def _public_hypothesis_row(*a: Any, **k: Any) -> Any:
    return _dep("public_hypothesis_row")(*a, **k)


def _model(name: str) -> Any:
    """Return a request model that still lives in the api module."""
    return _dep("model")(name)


QUEUE_NAME = os.environ.get("SCAN_QUEUE_NAME", "scan_jobs")


@router.get("/targets")
async def list_targets(
    include_inactive: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    """List all targets."""
    async with _pool().acquire() as conn:
        query = """
            SELECT t.id,
                   LEFT(t.url, 2049) AS url,
                   LEFT(t.name, 512) AS name,
                   LEFT(t.root_domain, 253) AS root_domain,
                   t.is_root, t.discovery_source, t.is_active, t.metadata_json,
                   t.last_scanned_at, t.last_score, t.last_grade,
                   t.total_scans, t.active_findings_count, t.created_at,
                   fs.total_active as active_findings,
                   COALESCE(origins.items, '[]'::jsonb) AS origins
            FROM targets t
            LEFT JOIN findings_summary fs ON t.id = fs.target_id
            LEFT JOIN LATERAL (
                SELECT jsonb_agg(item.target_url ORDER BY item.last_seen DESC) AS items
                FROM (
                    SELECT LEFT(s.target_url, 2049) AS target_url, MAX(s.created_at) AS last_seen
                    FROM scans s
                    WHERE s.target_id=t.id AND s.run_kind='web_dast'
                    GROUP BY LEFT(s.target_url, 2049)
                    ORDER BY MAX(s.created_at) DESC
                    LIMIT 32
                ) item
            ) origins ON true
            WHERE COALESCE(t.discovery_source, 'manual') <> 'model-intake'
        """
        params = []
        param_idx = 1

        if not include_inactive:
            query += f" AND t.is_active = true"

        query += f" ORDER BY t.updated_at DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM targets WHERE COALESCE(discovery_source, 'manual') <> 'model-intake'"
            + ("" if include_inactive else " AND is_active = true")
        )

    return {
        'targets': [_public_target_row(r) for r in rows],
        'total': total
    }


@router.post("/targets/dedupe")
async def dedupe_targets(
    payload: Optional[DedupeTargetsRequest] = None,
    dry_run: Optional[bool] = Query(default=None),
):
    """Merge web target rows that share a host across scheme/port variants
    into one survivor (active > most findings > most scans > https), reassigning all
    scans/findings/endpoints/graph/Deep Hunt/credentials/evidence/audit rows before deleting duplicates.
    Defaults to a dry run. JSON {"dry_run": false} and the backwards-compatible
    ?dry_run=false query both execute when they do not conflict; a true value in
    either input wins safely. Idempotent and per-group transactional."""
    # FastAPI replaces Query(...) during HTTP dispatch, but direct Python callers
    # (unit tests, local agents, internal adapters) receive the marker object.
    # Only a real bool is an explicit query override.
    query_dry_run = dry_run if isinstance(dry_run, bool) else None
    body_dry_run = payload.dry_run if payload else None
    if query_dry_run is None and body_dry_run is None:
        effective_dry_run = True
    elif query_dry_run is True or body_dry_run is True:
        effective_dry_run = True
    else:
        effective_dry_run = False
    async with _pool().acquire() as conn:
        plan = await plan_canonical_merges(conn)

        executed = 0
        if not effective_dry_run:
            try:
                # Preflight the full plan so a blocked later group cannot make an
                # API request appear to fail after earlier groups already merged.
                plan_target_ids = [
                    uuid.UUID(target["id"])
                    for item in plan
                    for target in (item["survivor"], *item["merged"])
                ]
                await _ensure_target_merge_safe(conn, plan_target_ids)
                for item in plan:
                    survivor_id = uuid.UUID(item["survivor"]["id"])
                    dupe_ids = [uuid.UUID(m["id"]) for m in item["merged"]]
                    async with conn.transaction():
                        await _merge_target_group(conn, survivor_id, dupe_ids)
                    executed += 1
            except TargetMergeBlockedError as exc:
                raise HTTPException(status_code=409, detail=exc.api_detail()) from exc

        return {
            "dry_run": effective_dry_run,
            "groups_found": len(plan),
            "targets_merged": sum(len(p["merged"]) for p in plan),
            "groups_executed": executed,
            "plan": plan,
        }


@router.get("/targets/grouped")
async def list_targets_grouped(
    include_inactive: bool = False,
    search: Optional[str] = None,
    discovery_source: Optional[str] = Query(None, pattern="^(manual|subfinder|gungnir-monitor|import|model-intake)$"),
    grade: Optional[str] = Query(None, pattern="^[A-Fa-f]$"),
    has_findings: Optional[bool] = None,
    sort_by: Optional[str] = Query("root_domain", pattern="^(root_domain|last_scanned_at|active_findings_count|last_score|created_at)$"),
    sort_order: Optional[str] = Query("asc", pattern="^(asc|desc)$")
):
    """List all targets grouped by root domain for hierarchical display."""
    async with _pool().acquire() as conn:
        query = """
            SELECT
                t.id,
                LEFT(t.url, 2049) AS url,
                LEFT(t.name, 512) AS name,
                LEFT(t.root_domain, 253) AS root_domain,
                t.is_root,
                t.discovery_source, t.is_active, t.metadata_json,
                t.last_scanned_at, t.last_score, t.last_grade,
                t.total_scans, t.active_findings_count,
                t.created_at
            FROM targets t
            WHERE 1=1
        """
        params = []
        param_idx = 1

        if not include_inactive:
            query += " AND t.is_active = true"

        # Model Intake subjects have their own workflow and must not appear as
        # web targets. Keep the explicit legacy source filter for API clients
        # that need to inspect historical rows during migration.
        if discovery_source != "model-intake":
            query += " AND COALESCE(t.discovery_source, 'manual') <> 'model-intake'"

        if search:
            query += f" AND (t.url ILIKE '%' || ${param_idx} || '%' OR t.name ILIKE '%' || ${param_idx} || '%' OR t.root_domain ILIKE '%' || ${param_idx} || '%')"
            params.append(search)
            param_idx += 1

        if discovery_source:
            query += f" AND t.discovery_source = ${param_idx}"
            params.append(discovery_source)
            param_idx += 1

        if grade:
            query += f" AND UPPER(t.last_grade) = UPPER(${param_idx})"
            params.append(grade)
            param_idx += 1

        if has_findings is not None:
            if has_findings:
                query += " AND t.active_findings_count > 0"
            else:
                query += " AND t.active_findings_count = 0"

        query += " ORDER BY t.root_domain, t.is_root DESC, t.url"

        rows = await conn.fetch(query, *params)
        # Collapse scheme/trailing-slash duplicate target rows so the grouped view
        # doesn't expose the same origin multiple times.
        rows = _dedupe_canonical_target_rows(rows)

        # Per-target ASM coverage and exact AI Investigator trust-tier counts.
        asm_by_target: dict[str, dict] = {}
        investigator_findings_by_target: dict[str, dict[str, int]] = {}
        target_ids = [row['id'] for row in rows]
        if target_ids:
            investigator_rows = await conn.fetch(
                """
                SELECT ids.target_id,
                       COALESCE(f.investigator_verified_count, 0) AS investigator_verified_count,
                       COALESCE(c.investigator_suspected_count, 0) AS investigator_suspected_count
                FROM unnest($1::uuid[]) AS ids(target_id)
                LEFT JOIN LATERAL (
                    SELECT COUNT(*) AS investigator_verified_count
                    FROM findings
                    WHERE target_id=ids.target_id AND status='active'
                      AND last_verification_verdict='exploited'
                      AND tool IN ('autonomous_workflow','bola')
                ) f ON true
                LEFT JOIN LATERAL (
                    SELECT COUNT(*) AS investigator_suspected_count
                    FROM investigation_candidates
                    WHERE target_id=ids.target_id AND plane='web'
                      AND status IN ('new','verification_queued','verifying','inconclusive','blocked')
                ) c ON true
                """,
                target_ids,
            )
            investigator_findings_by_target = {
                str(row['target_id']): {
                    'investigator_verified_count': int(row['investigator_verified_count'] or 0),
                    'investigator_suspected_count': int(row['investigator_suspected_count'] or 0),
                }
                for row in investigator_rows
            }
            asm_rows = await conn.fetch(
                """
                WITH inventory AS (
                    SELECT target_id,
                           COUNT(*) AS total,
                           COUNT(*) FILTER (WHERE test_status <> 'gone') AS testable,
                           COUNT(*) FILTER (WHERE test_status = 'tested') AS status_tested
                    FROM target_endpoints
                    WHERE target_id = ANY($1::uuid[])
                    GROUP BY target_id
                ),
                latest_attempt AS (
                    SELECT DISTINCT ON (te.id)
                        te.target_id,
                        te.id AS endpoint_id,
                        CASE
                            WHEN aea.status = 'completed'
                             AND lower(COALESCE(aea.scanner_telemetry_json->>'per_endpoint_telemetry', 'false')) <> 'true'
                            THEN 'partial'
                            ELSE aea.status
                        END AS status
                    FROM target_endpoints te
                    JOIN asm_endpoint_attempts aea ON aea.endpoint_id = te.id
                    WHERE te.target_id = ANY($1::uuid[]) AND te.test_status <> 'gone'
                    ORDER BY te.id, COALESCE(aea.completed_at, aea.started_at) DESC, aea.started_at DESC
                ),
                attempts AS (
                    SELECT target_id,
                           COUNT(*) AS attempted,
                           COUNT(*) FILTER (WHERE status = 'completed') AS completed
                    FROM latest_attempt
                    GROUP BY target_id
                )
                SELECT i.target_id, i.total, i.testable, i.status_tested,
                       COALESCE(a.attempted, 0) AS attempted,
                       COALESCE(a.completed, 0) AS attempt_completed
                FROM inventory i
                LEFT JOIN attempts a ON a.target_id = i.target_id
                """,
                target_ids,
            )
            for ar in asm_rows:
                total = int(ar['total'] or 0)
                testable = int(ar['testable'] or total)
                attempted = int(ar['attempted'] or 0)
                tested = int(ar['attempt_completed'] if attempted > 0 else (ar['status_tested'] or 0))
                denominator = testable
                asm_by_target[str(ar['target_id'])] = {
                    'total': total,
                    'tested': tested,
                    'untested': max(0, denominator - tested),
                    'coverage': round(tested / denominator, 4) if denominator else 0.0,
                    'coverage_basis': 'attempt_ledger' if attempted > 0 else 'endpoint_status',
                    'attempted': attempted,
                }

    def _attach_asm(target_data):
        if target_data:
            target_data['asm_coverage'] = asm_by_target.get(str(target_data['id']))
            target_data.update(investigator_findings_by_target.get(str(target_data['id']), {
                'investigator_verified_count': 0,
                'investigator_suspected_count': 0,
            }))
        return target_data

    # Group by root_domain
    grouped = {}
    for row in rows:
        rd = row['root_domain'] or 'unknown'
        if rd not in grouped:
            grouped[rd] = {
                'root_domain': rd,
                'root_target': None,
                'subdomains': []
            }

        target_data = _attach_asm(_public_target_row(row))
        if row['is_root']:
            grouped[rd]['root_target'] = target_data
        else:
            grouped[rd]['subdomains'].append(target_data)

    # Convert to list and add summary stats
    result = []
    for rd, data in grouped.items():
        data['subdomain_count'] = len(data['subdomains'])
        data['total_count'] = data['subdomain_count'] + (1 if data['root_target'] else 0)
        # Add aggregate stats for sorting
        root_findings = data['root_target']['active_findings_count'] if data['root_target'] else 0
        subdomain_findings = sum(s['active_findings_count'] for s in data['subdomains'])
        data['total_findings'] = root_findings + subdomain_findings
        data['best_score'] = data['root_target']['last_score'] if data['root_target'] and data['root_target']['last_score'] is not None else None
        data['latest_scan'] = data['root_target']['last_scanned_at'] if data['root_target'] else None
        data['earliest_created'] = data['root_target']['created_at'] if data['root_target'] else (
            min((s['created_at'] for s in data['subdomains']), default=None)
        )
        # Domain-level ASM coverage rollup across root + subdomains.
        cov_targets = ([data['root_target']] if data['root_target'] else []) + data['subdomains']
        cov_total = sum((t.get('asm_coverage') or {}).get('total', 0) for t in cov_targets)
        cov_tested = sum((t.get('asm_coverage') or {}).get('tested', 0) for t in cov_targets)
        data['asm_coverage'] = {
            'total': cov_total,
            'tested': cov_tested,
            'untested': cov_total - cov_tested,
            'coverage': round(cov_tested / cov_total, 4) if cov_total else 0.0,
        } if cov_total else None
        result.append(data)

    # Sort based on sort_by and sort_order
    reverse = sort_order == 'desc'

    def sort_key(x):
        if sort_by == 'root_domain':
            return x['root_domain'].lower()
        elif sort_by == 'last_scanned_at':
            return x['latest_scan'] or ''
        elif sort_by == 'active_findings_count':
            return x['total_findings']
        elif sort_by == 'last_score':
            # None values should sort last in ascending, first in descending
            score = x['best_score']
            if score is None:
                return -1 if reverse else 101
            return score
        elif sort_by == 'created_at':
            return x['earliest_created'] or ''
        return x['root_domain'].lower()

    result.sort(key=sort_key, reverse=reverse)

    return {
        'domains': result,
        'total_root_domains': len(result),
        'total_targets': sum(d['total_count'] for d in result)
    }


@router.get("/domains")
async def list_domains():
    """List unique root domains from DAST and AI targets."""
    async with _pool().acquire() as conn:
        rows = await conn.fetch("""
            SELECT DISTINCT root_domain
            FROM targets
            WHERE root_domain IS NOT NULL AND is_active = true
              AND char_length(btrim(root_domain)) BETWEEN 1 AND 253
              AND COALESCE(discovery_source, 'manual') <> 'model-intake'
            ORDER BY root_domain
        """)
        ai_rows = await conn.fetch("""
            SELECT endpoint_url
            FROM ai_targets
            WHERE endpoint_url IS NOT NULL AND is_active = true
        """)

    domains = {
        *(r['root_domain'].strip() for r in rows if r['root_domain']),
        *(extract_root_domain(r['endpoint_url']).strip() for r in ai_rows if r['endpoint_url'])
    }
    return {'domains': sorted(domain for domain in domains if 0 < len(domain) <= 253)}


@router.post("/targets")
async def create_target(request: TargetCreate):
    """Create a new target."""
    _refuse_raw_target_authentication(request.scan_options)
    scheme_inferred = "://" not in (request.url or "")
    try:
        normalized_target, target_note = normalize_target_url(request.url)
    except TargetNormalizationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not normalized_target:
        raise HTTPException(status_code=400, detail="Invalid target URL")
    root_domain = extract_root_domain(normalized_target)
    is_root = is_root_domain(normalized_target)
    requested_cohort = getattr(request, "cohort", None)

    async with _pool().acquire() as conn:
        try:
            # Canonical find-or-create: a scheme/trailing-slash variant of an existing
            # origin reuses that target instead of creating a duplicate. xmax = 0 is
            # true only for a freshly INSERTed row, so we can report created vs reused.
            row = await conn.fetchrow("""
                INSERT INTO targets (url, name, root_domain, is_root, scan_options, metadata_json, asm_enabled, asm_config)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (canonical_key) DO UPDATE SET url = targets.url
                RETURNING id, url, name, discovery_source, metadata_json,
                          root_domain, is_root, (xmax = 0) AS created
            """, normalized_target, request.name, root_domain, is_root,
                 json.dumps(_attach_target_note(request.scan_options or {}, request.url, target_note, scheme_inferred)),
                 json.dumps({"cohort": requested_cohort}) if requested_cohort else json.dumps({}),
                 _default_asm_enabled_for_new_web_target("manual"),
                 json.dumps(_default_asm_config_for_new_web_target("manual")))

            response = {
                'id': str(row['id']),
                'url': row['url'],
                # When a different origin reuses an existing host-level target,
                # report the stored target metadata rather than metadata derived
                # from the just-submitted origin.
                'root_domain': row['root_domain'],
                'is_root': row['is_root'],
                'cohort': target_cohort(
                    url=row['url'],
                    name=row.get('name'),
                    discovery_source=row.get('discovery_source'),
                    metadata=_decode_json_value(row.get('metadata_json')) or {},
                ),
                'status': 'created' if row['created'] else 'already_exists'
            }
            # Surface warning if path/query was stripped
            if target_note:
                response['warning'] = target_note
                response['original_url'] = request.url
            # Web identity is host-level, so a different scheme or port resolves to an existing
            # target rather than creating a new one. That merge is deliberate, but returning only
            # an id let a caller believe it had registered the origin it asked for: a scope receipt
            # and a Hunt were then bound to one application while the work ran against another on
            # the same host, and the result looked correct. Say so explicitly.
            if not scope_origin_matches_target(request.url, row['url']):
                response['origin_merged'] = True
                response['requested_url'] = request.url
                response['warning'] = (
                    f"{request.url} resolves to the existing host-level target {row['url']}; "
                    "web targets are identified by host, so scans, scope receipts and Hunts bound "
                    "to this id address that origin, not the one requested."
                )
            return response
        except asyncpg.UniqueViolationError:
            raise HTTPException(status_code=409, detail="Target already exists")


@router.get("/targets/{target_id}")
async def get_target(target_id: str):
    """Get target details."""
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        target = await conn.fetchrow("""
            SELECT t.*, fs.*, COALESCE(origins.items, '[]'::jsonb) AS origins
            FROM targets t
            LEFT JOIN findings_summary fs ON t.id = fs.target_id
            LEFT JOIN LATERAL (
                SELECT jsonb_agg(item.target_url ORDER BY item.last_seen DESC) AS items
                FROM (
                    SELECT s.target_url, MAX(s.created_at) AS last_seen
                    FROM scans s
                    WHERE s.target_id=t.id AND s.run_kind='web_dast'
                    GROUP BY s.target_url
                    ORDER BY MAX(s.created_at) DESC
                    LIMIT 32
                ) item
            ) origins ON true
            WHERE t.id = $1
        """, target_uuid)

        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        # Get recent scans (exclude child shard rows of parallel scans)
        scans = await conn.fetch("""
            SELECT id, status, score, grade, created_at, completed_at
            FROM scans
            WHERE target_id = $1 AND (scan_role IS NULL OR scan_role <> 'shard')
            ORDER BY created_at DESC LIMIT 10
        """, target_uuid)

    result = _public_target_row(target)
    result['recent_scans'] = [dict(s) for s in scans]
    return result


@router.patch("/targets/{target_id}")
async def update_target(target_id: str, request: TargetUpdate):
    """Update a target."""
    async with _pool().acquire() as conn:
        updates = []
        params = []
        param_idx = 1

        if request.name is not None:
            updates.append(f"name = ${param_idx}")
            params.append(request.name)
            param_idx += 1

        if request.is_active is not None:
            updates.append(f"is_active = ${param_idx}")
            params.append(request.is_active)
            param_idx += 1

        if request.scan_options is not None:
            _refuse_raw_target_authentication(request.scan_options)
            updates.append(f"scan_options = ${param_idx}")
            params.append(json.dumps(request.scan_options))
            param_idx += 1

        if request.metadata_json is not None:
            updates.append(f"metadata_json = COALESCE(metadata_json, '{{}}'::jsonb) || ${param_idx}::jsonb")
            params.append(json.dumps(request.metadata_json))
            param_idx += 1

        if request.cohort is not None:
            updates.append(f"metadata_json = COALESCE(metadata_json, '{{}}'::jsonb) || ${param_idx}::jsonb")
            params.append(json.dumps({"cohort": request.cohort}))
            param_idx += 1

        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")

        updates.append("updated_at = NOW()")
        params.append(uuid.UUID(target_id))

        query = f"UPDATE targets SET {', '.join(updates)} WHERE id = ${param_idx} RETURNING id"
        result = await conn.fetchval(query, *params)

        if not result:
            raise HTTPException(status_code=404, detail="Target not found")

    return {'id': target_id, 'status': 'updated'}


@router.get("/targets/{target_id}/credential-profiles")
async def list_target_credential_profiles(target_id: str, include_inactive: bool = False):
    """List target-scoped credential profiles without returning secret material."""
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", target_uuid):
            raise HTTPException(status_code=404, detail="Target not found")
        rows = await conn.fetch(
            """
            SELECT * FROM target_credential_profiles
            WHERE target_id = $1 AND ($2::boolean OR is_active = true)
            ORDER BY is_active DESC, lower(name)
            """,
            target_uuid,
            include_inactive,
        )
    profiles = [_public_target_credential_profile_row(row) for row in rows]
    return {"target_id": target_id, "profiles": profiles, "count": len(profiles)}


@router.post("/targets/{target_id}/credential-profiles")
async def create_target_credential_profile(target_id: str, request: TargetCredentialProfileCreate):
    """Create or rotate a named target credential profile."""
    target_uuid = _uuid_or_400(target_id, "target id")
    values = _target_credential_profile_values(
        name=request.name,
        auth_kind=request.auth_kind,
        secret=request.secret,
        expires_at=request.expires_at,
        metadata_json=request.metadata_json,
    )
    async with _pool().acquire() as conn:
        try:
            async with conn.transaction():
                if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", target_uuid):
                    raise HTTPException(status_code=404, detail="Target not found")
                row = await conn.fetchrow(
                    """
                    INSERT INTO target_credential_profiles (
                        target_id, name, auth_kind, secret_value, secret_preview,
                        expires_at, metadata_json, rotated_at
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,NOW())
                    ON CONFLICT (target_id, lower(name))
                    DO UPDATE SET
                        auth_kind = EXCLUDED.auth_kind,
                        secret_value = EXCLUDED.secret_value,
                        secret_preview = EXCLUDED.secret_preview,
                        expires_at = EXCLUDED.expires_at,
                        is_active = true,
                        metadata_json = target_credential_profiles.metadata_json || EXCLUDED.metadata_json,
                        rotated_at = NOW(),
                        updated_at = NOW()
                    RETURNING *
                    """,
                    target_uuid,
                    values["name"],
                    values["auth_kind"],
                    values["secret_value"],
                    values["secret_preview"],
                    values["expires_at"],
                    json.dumps(values["metadata_json"]),
                )
                await sync_legacy_web_credential(conn, row["id"])
        except (LegacyCredentialMigrationError, CredentialStoreError) as exc:
            raise _legacy_credential_migration_http_error(exc) from exc
    return {"profile": _public_target_credential_profile_row(row)}


@router.patch("/targets/{target_id}/credential-profiles/{profile_id}")
async def update_target_credential_profile(
    target_id: str,
    profile_id: str,
    request: TargetCredentialProfileUpdate,
):
    """Update profile metadata and optionally rotate its credential."""
    target_uuid = _uuid_or_400(target_id, "target id")
    profile_uuid = _uuid_or_400(profile_id, "credential profile id")
    async with _pool().acquire() as conn:
        try:
            async with conn.transaction():
                existing_row = await conn.fetchrow(
                    "SELECT * FROM target_credential_profiles WHERE id = $1 AND target_id = $2",
                    profile_uuid,
                    target_uuid,
                )
                if not existing_row:
                    raise HTTPException(status_code=404, detail="Credential profile not found")
                existing = row_to_dict(existing_row)
                next_kind = request.auth_kind or existing.get("auth_kind")
                if request.auth_kind and request.auth_kind != existing.get("auth_kind"):
                    raise HTTPException(
                        status_code=409,
                        detail="A migrated credential cannot change auth_kind; create a new generic profile",
                    )
                secret = request.secret
                rotated = secret is not None
                secret_value = existing.get("secret_value")
                secret_preview = existing.get("secret_preview")
                if rotated:
                    normalized_secret = _normalize_target_credential_secret(secret)
                    secret_value = encrypt_secret(normalized_secret)
                    secret_preview = _mask_ai_target_secret(normalized_secret)
                expires_at = existing.get("expires_at")
                if request.clear_expiry:
                    expires_at = None
                elif "expires_at" in request.model_fields_set:
                    expires_at = request.expires_at
                metadata = _decode_json_value(existing.get("metadata_json")) or {}
                if request.metadata_json is not None:
                    metadata.update(_redact_agent_payload(request.metadata_json))
                row = await conn.fetchrow(
                    """
                    UPDATE target_credential_profiles SET
                        name = $1, auth_kind = $2, secret_value = $3, secret_preview = $4,
                        expires_at = $5, is_active = $6, metadata_json = $7::jsonb,
                        rotated_at = CASE WHEN $8::boolean THEN NOW() ELSE rotated_at END,
                        updated_at = NOW()
                    WHERE id = $9 AND target_id = $10
                    RETURNING *
                    """,
                    _normalize_target_credential_profile_name(request.name or existing.get("name")),
                    next_kind,
                    secret_value,
                    secret_preview,
                    expires_at,
                    bool(request.is_active) if request.is_active is not None else bool(existing.get("is_active", True)),
                    json.dumps(metadata),
                    rotated,
                    profile_uuid,
                    target_uuid,
                )
                await sync_legacy_web_credential(conn, profile_uuid)
        except (LegacyCredentialMigrationError, CredentialStoreError) as exc:
            raise _legacy_credential_migration_http_error(exc) from exc
    return {"profile": _public_target_credential_profile_row(row)}


@router.post("/targets/{target_id}/credential-profiles/{profile_id}/rotate")
async def rotate_target_credential_profile(
    target_id: str,
    profile_id: str,
    request: TargetCredentialProfileRotate,
):
    """Rotate secret material while preserving the profile identity."""
    return await update_target_credential_profile(
        target_id,
        profile_id,
        TargetCredentialProfileUpdate(
            secret=request.secret,
            expires_at=request.expires_at,
            clear_expiry=request.clear_expiry,
            is_active=True,
        ),
    )


@router.delete("/targets/{target_id}/credential-profiles/{profile_id}")
async def delete_target_credential_profile(target_id: str, profile_id: str):
    """Deactivate a credential profile without deleting its audit history."""
    target_uuid = _uuid_or_400(target_id, "target id")
    profile_uuid = _uuid_or_400(profile_id, "credential profile id")
    async with _pool().acquire() as conn:
        try:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    UPDATE target_credential_profiles
                    SET is_active = false, updated_at = NOW()
                    WHERE id = $1 AND target_id = $2
                    RETURNING *
                    """,
                    profile_uuid,
                    target_uuid,
                )
                if row:
                    await sync_legacy_web_credential(conn, profile_uuid)
        except (LegacyCredentialMigrationError, CredentialStoreError) as exc:
            raise _legacy_credential_migration_http_error(exc) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Credential profile not found")
    return {"status": "deactivated", "profile": _public_target_credential_profile_row(row)}


@router.get("/targets/{target_id}/principals")
async def list_target_principals(target_id: str, include_inactive: bool = False):
    """List role/tenant principals configured for DAST/ASM authorization planning."""
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", target_uuid):
            raise HTTPException(status_code=404, detail="Target not found")
        rows = await conn.fetch(
            """
            SELECT p.*,
                   EXISTS (
                     SELECT 1 FROM target_credential_profiles cp
                     WHERE cp.target_id = p.target_id
                       AND lower(cp.name) = lower(p.credential_profile)
                       AND cp.is_active = true
                       AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
                   ) AS credential_configured
            FROM target_principals p
            WHERE target_id = $1 AND ($2::boolean OR is_active = true)
            ORDER BY is_active DESC, role, label
            """,
            target_uuid,
            include_inactive,
        )
    principals = [_public_target_principal_row(row) for row in rows]
    return {
        "target_id": target_id,
        "principals": principals,
        "count": len(principals),
        "execution_enabled": False,
    }


@router.post("/targets/{target_id}/principals")
async def create_target_principal(target_id: str, request: TargetPrincipalCreate):
    """Create or update a target principal identity without storing raw credentials."""
    target_uuid = _uuid_or_400(target_id, "target id")
    label = _normalize_target_principal_label(request.label)
    role = _normalize_target_principal_role(request.role)
    auth_state = _normalize_target_auth_state(request.auth_state)
    metadata = _redact_agent_payload(request.metadata_json or {})
    async with _pool().acquire() as conn:
        try:
            async with conn.transaction():
                if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", target_uuid):
                    raise HTTPException(status_code=404, detail="Target not found")
                row = await conn.fetchrow(
                    """
                    INSERT INTO target_principals (
                        target_id, label, role, tenant_id, auth_state, credential_profile,
                        is_active, metadata_json
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
                    ON CONFLICT (target_id, lower(label), COALESCE(tenant_id, ''), COALESCE(auth_state, ''))
                    DO UPDATE SET
                        role = EXCLUDED.role,
                        credential_profile = EXCLUDED.credential_profile,
                        is_active = EXCLUDED.is_active,
                        metadata_json = target_principals.metadata_json || EXCLUDED.metadata_json,
                        updated_at = NOW()
                    RETURNING *
                    """,
                    target_uuid,
                    label,
                    role,
                    request.tenant_id,
                    auth_state,
                    str(request.credential_profile or "").strip() or None,
                    bool(request.is_active),
                    json.dumps(metadata),
                )
                await sync_legacy_web_credential_by_name(
                    conn,
                    target_id=target_uuid,
                    profile_name=row["credential_profile"],
                )
        except asyncpg.UniqueViolationError as exc:
            raise _principal_slot_conflict() from exc
        except (LegacyCredentialMigrationError, CredentialStoreError) as exc:
            raise _legacy_credential_migration_http_error(exc) from exc
        row = await conn.fetchrow(
            """
            SELECT p.*, EXISTS (
              SELECT 1 FROM target_credential_profiles cp
              WHERE cp.target_id = p.target_id
                AND lower(cp.name) = lower(p.credential_profile)
                AND cp.is_active = true
                AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
            ) AS credential_configured
            FROM target_principals p WHERE p.id = $1
            """,
            row["id"],
        )
    return {
        "principal": _public_target_principal_row(row),
        "execution_enabled": False,
        "findings_created": 0,
    }


@router.post("/targets/{target_id}/principals/auto-provision")
async def auto_provision_target_principals(target_id: str, request: TargetPrincipalAutoProvisionRequest):
    """Self-register managed test principals via the target's OWN signup flow (opt-in).

    A real registration through the app's public signup -- never forged auth. Requires the target's
    metadata_json.auto_provisioning.enabled = true plus a current target-scoped credential-tier
    approval receipt. Secrets are encrypted through the normal credential-profile path and are
    never returned.
    """
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _AUTO_PROVISION_SEMAPHORE:
        async with _pool().acquire() as conn:
            target = await conn.fetchrow("SELECT id, url, is_active, metadata_json FROM targets WHERE id=$1", target_uuid)
            if not target or not target["is_active"]:
                raise HTTPException(status_code=404, detail="Active target not found")
            approval = await _validate_approval_receipt_for_action(
                conn,
                request.approval_receipt_id,
                target_url=str(target["url"]),
                target_id=target_uuid,
                action_name="target.principals.auto_provision",
                command="target.principals.auto_provision",
                risk_tier="credential",
                created_by=request.created_by,
                always_require_receipt=True,
            )
            provisioned = await _auto_provision_principals(conn, target_uuid, str(target["url"]), _auto_provisioning_config(dict(target)))
            command_result = await _record_command_result(
                conn,
                command="target.principals.auto_provision",
                status="completed",
                risk_tier="credential",
                operator_message=f"Provisioned or reused {len(provisioned)} managed test principals",
                scope_receipt_id=str((approval or {}).get("scope_receipt_id") or "") or None,
                approval_receipt_id=request.approval_receipt_id,
                result_json={"target_id": target_id, "principals": provisioned},
                created_by=request.created_by,
            )
    return {
        "target_id": target_id,
        "provisioned": provisioned,
        "count": len(provisioned),
        "command_result_id": command_result.get("id"),
        "note": "Managed test accounts registered via the app's own signup; credentials stored encrypted.",
    }


@router.patch("/targets/{target_id}/principals/{principal_id}")
async def update_target_principal(target_id: str, principal_id: str, request: TargetPrincipalUpdate):
    """Update target principal metadata without returning or accepting raw secrets."""
    target_uuid = _uuid_or_400(target_id, "target id")
    principal_uuid = _uuid_or_400(principal_id, "principal id")
    updates: list[str] = []
    values: list[Any] = []
    if request.label is not None:
        values.append(_normalize_target_principal_label(request.label))
        updates.append(f"label = ${len(values)}")
    if request.role is not None:
        values.append(_normalize_target_principal_role(request.role))
        updates.append(f"role = ${len(values)}")
    if request.tenant_id is not None:
        values.append(str(request.tenant_id).strip() or None)
        updates.append(f"tenant_id = ${len(values)}")
    if request.auth_state is not None:
        values.append(_normalize_target_auth_state(request.auth_state))
        updates.append(f"auth_state = ${len(values)}")
    if request.credential_profile is not None:
        values.append(str(request.credential_profile).strip() or None)
        updates.append(f"credential_profile = ${len(values)}")
    if request.metadata_json is not None:
        values.append(json.dumps(_redact_agent_payload(request.metadata_json or {})))
        updates.append(f"metadata_json = metadata_json || ${len(values)}::jsonb")
    if request.is_active is not None:
        values.append(bool(request.is_active))
        updates.append(f"is_active = ${len(values)}")
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    values.extend([principal_uuid, target_uuid])
    async with _pool().acquire() as conn:
        try:
            async with conn.transaction():
                previous = await conn.fetchrow(
                    "SELECT credential_profile FROM target_principals WHERE id=$1 AND target_id=$2",
                    principal_uuid,
                    target_uuid,
                )
                row = await conn.fetchrow(
                    f"""
                    UPDATE target_principals
                    SET {', '.join(updates)}, updated_at = NOW()
                    WHERE id = ${len(values) - 1} AND target_id = ${len(values)}
                    RETURNING *
                    """,
                    *values,
                )
                if row:
                    names = {
                        str(value or "").strip()
                        for value in (
                            previous["credential_profile"] if previous else None,
                            row["credential_profile"],
                        )
                        if str(value or "").strip()
                    }
                    for name in names:
                        await sync_legacy_web_credential_by_name(
                            conn, target_id=target_uuid, profile_name=name,
                        )
        except asyncpg.UniqueViolationError as exc:
            raise _principal_slot_conflict() from exc
        except (LegacyCredentialMigrationError, CredentialStoreError) as exc:
            raise _legacy_credential_migration_http_error(exc) from exc
        if not row:
            raise HTTPException(status_code=404, detail="Target principal not found")
        row = await conn.fetchrow(
            """
            SELECT p.*, EXISTS (
              SELECT 1 FROM target_credential_profiles cp
              WHERE cp.target_id = p.target_id
                AND lower(cp.name) = lower(p.credential_profile)
                AND cp.is_active = true
                AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
            ) AS credential_configured
            FROM target_principals p WHERE p.id = $1 AND p.target_id = $2
            """,
            principal_uuid,
            target_uuid,
        )
    return {"principal": _public_target_principal_row(row), "execution_enabled": False}


@router.delete("/targets/{target_id}/principals/{principal_id}")
async def delete_target_principal(target_id: str, principal_id: str):
    """Deactivate a target principal used for role/tenant planning."""
    target_uuid = _uuid_or_400(target_id, "target id")
    principal_uuid = _uuid_or_400(principal_id, "principal id")
    async with _pool().acquire() as conn:
        try:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    UPDATE target_principals
                    SET is_active = false, updated_at = NOW()
                    WHERE id = $1 AND target_id = $2
                    RETURNING *
                    """,
                    principal_uuid,
                    target_uuid,
                )
                if row:
                    await sync_legacy_web_credential_by_name(
                        conn,
                        target_id=target_uuid,
                        profile_name=row["credential_profile"],
                    )
        except (LegacyCredentialMigrationError, CredentialStoreError) as exc:
            raise _legacy_credential_migration_http_error(exc) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Target principal not found")
    return {
        "status": "deleted",
        "target_id": target_id,
        "principal_id": principal_id,
        "execution_enabled": False,
    }


@router.get("/targets/{target_id}/invariants")
async def list_target_invariant_contracts(target_id: str, include_drafts: bool = True):
    """List typed rules-of-the-game. Only approved rows are supplied to autonomous planners."""
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id=$1", target_uuid):
            raise HTTPException(status_code=404, detail="Target not found")
        rows = await conn.fetch(
            """
            SELECT * FROM target_invariant_contracts
            WHERE target_id=$1 AND status <> 'retired' AND ($2::boolean OR status='approved')
            ORDER BY CASE status WHEN 'approved' THEN 0 ELSE 1 END, updated_at DESC
            LIMIT 200
            """,
            target_uuid,
            include_drafts,
        )
    contracts = [_public_target_invariant_contract_row(row) for row in rows]
    return {
        "target_id": target_id,
        "contracts": contracts,
        "count": len(contracts),
        "approved_count": sum(1 for item in contracts if item.get("status") == "approved"),
        "draft_count": sum(1 for item in contracts if item.get("status") == "draft"),
        "execution_enabled": False,
        "findings_created": 0,
    }


@router.post("/targets/{target_id}/invariants/compile")
async def compile_target_invariant_rule(target_id: str, request: TargetInvariantCompileRequest):
    """Compile one short rule into reviewable drafts; never approve, execute, or create findings."""
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id=$1", target_uuid):
            raise HTTPException(status_code=404, detail="Target not found")
    try:
        compiled = invariant_contracts.compile_rule_text(
            _redact_agent_text(request.rule_text),
            method=request.method,
            path=request.path,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persisted: list[dict[str, Any]] = []
    if request.persist_drafts:
        if not request.approval_receipt_id:
            raise HTTPException(status_code=400, detail="approval_receipt_id is required to persist drafts")
        for candidate in compiled["candidates"]:
            fields = {
                key: value
                for key, value in candidate.items()
                if key in TargetInvariantContractCreate.model_fields
            }
            created = await create_target_invariant_contract(
                target_id,
                TargetInvariantContractCreate(
                    **fields,
                    source="compiled",
                    created_by=request.created_by,
                    approval_receipt_id=request.approval_receipt_id,
                ),
            )
            persisted.append(created["contract"])
    return {
        "target_id": target_id,
        **compiled,
        "persisted_drafts": persisted,
        "persisted_count": len(persisted),
        "approval_required": True,
        "planning_authority": False,
        "promotion_authority": False,
    }


@router.get("/targets/{target_id}/invariants/{contract_id}/verification-plan")
async def get_target_invariant_verification_plan(target_id: str, contract_id: str):
    """Explain the deterministic proof boundary and missing runtime bindings for one contract."""
    target_uuid = _uuid_or_400(target_id, "target id")
    contract_uuid = _uuid_or_400(contract_id, "invariant contract id")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM target_invariant_contracts WHERE id=$1 AND target_id=$2",
            contract_uuid,
            target_uuid,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Invariant contract not found")
    contract = _public_target_invariant_contract_row(row)
    return {
        "target_id": target_id,
        "contract_id": contract_id,
        "contract_status": contract.get("status"),
        "verification_plan": invariant_contracts.verification_plan(contract),
        "execution_enabled": False,
        "findings_created": 0,
    }


@router.post("/targets/{target_id}/invariants/hypotheses")
async def generate_target_invariant_hypotheses(
    target_id: str,
    request: TargetInvariantHypothesisRequest = None,
):
    """Turn approved invariants into deduped worklist leads without queueing or executing tests."""
    request = request or TargetInvariantHypothesisRequest()
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id=$1", target_uuid):
            raise HTTPException(status_code=404, detail="Target not found")
        rows = await conn.fetch(
            """
            SELECT * FROM target_invariant_contracts
            WHERE target_id=$1 AND status='approved'
            ORDER BY updated_at DESC
            LIMIT 200
            """,
            target_uuid,
        )
        records = []
        for row in rows:
            contract = _public_target_invariant_contract_row(row)
            records.append(await _upsert_hypothesis(
                conn,
                _invariant_hypothesis_request(target_id, contract, created_by=request.created_by),
            ))
    return {
        "target_id": target_id,
        "approved_contract_count": len(rows),
        "created": sum(1 for item in records if item.get("created")),
        "hypotheses": [item["hypothesis"] for item in records],
        "execution_enabled": False,
        "findings_created": 0,
        "runtime_proof_required": True,
    }


@router.post("/targets/{target_id}/invariants")
async def create_target_invariant_contract(target_id: str, request: TargetInvariantContractCreate):
    """Create a draft typed invariant. Drafts never enter planner context or proof decisions."""
    target_uuid = _uuid_or_400(target_id, "target id")
    if _json_size_bytes(request.expected_value) > 8_192:
        raise HTTPException(status_code=413, detail="expected_value exceeds 8192 bytes")
    if _json_size_bytes(request.conditions) > 16_384:
        raise HTTPException(status_code=413, detail="conditions exceeds 16384 bytes")
    if _json_size_bytes(request.metadata_json) > 16_384:
        raise HTTPException(status_code=413, detail="metadata_json exceeds 16384 bytes")
    try:
        contract = invariant_contracts.canonical_contract(request.model_dump(mode="python"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Requirements text and expected values can be pasted from tickets or API examples. Apply the
    # same secret scrubber used by agent context packs before either value reaches durable storage.
    contract["title"] = _redact_agent_text(contract["title"])
    contract["source_text"] = _redact_agent_text(contract["source_text"])
    contract["expected_value"] = _redact_agent_payload(contract["expected_value"])
    metadata = _redact_agent_payload(request.metadata_json or {})
    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT url FROM targets WHERE id=$1", target_uuid)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        approval = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=str(target["url"] or ""),
            target_id=target_uuid,
            action_name="target.invariant_contract.record",
            command="target.invariant_contract.record",
            risk_tier="active",
            created_by=request.created_by,
            always_require_receipt=True,
        )
        row = await conn.fetchrow(
            """
            INSERT INTO target_invariant_contracts (
                target_id, contract_version, contract_kind, title, source_text,
                subject_role, action, resource, method, path, field_name, operator,
                expected_value, expected_access, conditions, status, source,
                metadata_json, created_by
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15::jsonb,
                'draft',$16,$17::jsonb,$18
            ) RETURNING *
            """,
            target_uuid,
            contract["version"],
            contract["contract_kind"],
            contract["title"],
            contract["source_text"],
            contract["subject_role"],
            contract["action"],
            contract["resource"],
            contract["method"],
            contract["path"],
            contract["field_name"],
            contract["operator"],
            json.dumps(contract["expected_value"]),
            contract["expected_access"],
            json.dumps(contract["conditions"]),
            request.source,
            json.dumps(metadata),
            request.created_by,
        )
        command_result = await _record_command_result(
            conn,
            command="target.invariant_contract.record",
            status="completed",
            risk_tier="active",
            scope_receipt_id=(approval or {}).get("scope_receipt_id"),
            approval_receipt_id=request.approval_receipt_id,
            operator_message="Recorded typed target invariant as a non-authoritative draft",
            result_json={
                "target_id": target_id,
                "contract_id": str(row["id"]),
                "planning_authority": False,
                "promotion_authority": False,
            },
            created_by=request.created_by,
        )
    return {
        "contract": _public_target_invariant_contract_row(row),
        "operation_id": command_result["id"],
        "approval_required": True,
        "planning_authority": False,
        "promotion_authority": False,
        "findings_created": 0,
    }


@router.post("/targets/{target_id}/invariants/{contract_id}/approve")
async def approve_target_invariant_contract(
    target_id: str,
    contract_id: str,
    request: TargetInvariantContractApproval,
):
    """Approve one typed policy oracle for planning; approval still grants no finding authority."""
    if not request.confirm_authoritative:
        raise HTTPException(status_code=400, detail="confirm_authoritative must be true")
    target_uuid = _uuid_or_400(target_id, "target id")
    contract_uuid = _uuid_or_400(contract_id, "invariant contract id")
    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT url FROM targets WHERE id=$1", target_uuid)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        row = await conn.fetchrow(
            "SELECT * FROM target_invariant_contracts WHERE id=$1 AND target_id=$2",
            contract_uuid,
            target_uuid,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Invariant contract not found")
        contract = _public_target_invariant_contract_row(row)
        errors = invariant_contracts.approval_errors(contract)
        if errors:
            raise HTTPException(
                status_code=422,
                detail={"error": "invariant_contract_not_approvable", "violations": errors},
            )
        approval = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=str(target["url"] or ""),
            target_id=target_uuid,
            action_name="target.invariant_contract.approve",
            command="target.invariant_contract.approve",
            risk_tier="active",
            created_by=request.approved_by,
            always_require_receipt=True,
        )
        updated = await conn.fetchrow(
            """
            UPDATE target_invariant_contracts
            SET status='approved', approved_at=NOW(), approved_by=$3,
                retired_at=NULL, updated_at=NOW()
            WHERE id=$1 AND target_id=$2 AND status <> 'retired'
            RETURNING *
            """,
            contract_uuid,
            target_uuid,
            request.approved_by,
        )
        if not updated:
            raise HTTPException(status_code=409, detail="Retired invariant contracts cannot be approved")
        command_result = await _record_command_result(
            conn,
            command="target.invariant_contract.approve",
            status="completed",
            risk_tier="active",
            scope_receipt_id=(approval or {}).get("scope_receipt_id"),
            approval_receipt_id=request.approval_receipt_id,
            operator_message="Approved typed target invariant for autonomous planning",
            result_json={
                "target_id": target_id,
                "contract_id": contract_id,
                "planning_authority": True,
                "promotion_authority": False,
            },
            created_by=request.approved_by,
        )
    return {
        "contract": _public_target_invariant_contract_row(updated),
        "operation_id": command_result["id"],
        "planning_authority": True,
        "promotion_authority": False,
        "verification_required": True,
        "findings_created": 0,
    }


@router.post("/targets/{target_id}/invariants/{contract_id}/retire")
async def retire_target_invariant_contract(
    target_id: str,
    contract_id: str,
    request: TargetInvariantContractRetire,
):
    """Retire an approved or draft invariant so it can no longer guide new plans."""
    target_uuid = _uuid_or_400(target_id, "target id")
    contract_uuid = _uuid_or_400(contract_id, "invariant contract id")
    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT url FROM targets WHERE id=$1", target_uuid)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        approval = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=str(target["url"] or ""),
            target_id=target_uuid,
            action_name="target.invariant_contract.retire",
            command="target.invariant_contract.retire",
            risk_tier="active",
            created_by=request.retired_by,
            always_require_receipt=True,
        )
        updated = await conn.fetchrow(
            """
            UPDATE target_invariant_contracts
            SET status='retired', retired_at=NOW(), updated_at=NOW()
            WHERE id=$1 AND target_id=$2 AND status <> 'retired'
            RETURNING *
            """,
            contract_uuid,
            target_uuid,
        )
        if not updated:
            raise HTTPException(status_code=404, detail="Active invariant contract not found")
        command_result = await _record_command_result(
            conn,
            command="target.invariant_contract.retire",
            status="completed",
            risk_tier="active",
            scope_receipt_id=(approval or {}).get("scope_receipt_id"),
            approval_receipt_id=request.approval_receipt_id,
            operator_message="Retired typed target invariant",
            result_json={"target_id": target_id, "contract_id": contract_id},
            created_by=request.retired_by,
        )
    return {
        "contract": _public_target_invariant_contract_row(updated),
        "operation_id": command_result["id"],
        "planning_authority": False,
        "promotion_authority": False,
        "findings_created": 0,
    }


@router.get("/targets/{target_id}/principal-matrix")
async def list_target_principal_matrix(target_id: str, limit: int = Query(200, ge=1, le=1000)):
    """List endpoint x principal/role expectations for authorization planning."""
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", target_uuid):
            raise HTTPException(status_code=404, detail="Target not found")
        principals = await conn.fetch(
            """
            SELECT p.*, EXISTS (
              SELECT 1 FROM target_credential_profiles cp
              WHERE cp.target_id = p.target_id
                AND lower(cp.name) = lower(p.credential_profile)
                AND cp.is_active = true
                AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
            ) AS credential_configured
            FROM target_principals p
            WHERE p.target_id = $1 AND p.is_active = true
            ORDER BY p.role, p.label
            """,
            target_uuid,
        )
        rows = await conn.fetch(
            """
            SELECT e.*, p.label AS principal_label, p.auth_state AS principal_auth_state
            FROM target_endpoint_expectations e
            LEFT JOIN target_principals p ON p.id = e.principal_id
            WHERE e.target_id = $1
            ORDER BY e.path, e.method, COALESCE(p.role, e.principal_role, ''), COALESCE(p.label, '')
            LIMIT $2
            """,
            target_uuid,
            limit,
        )
    return {
        "target_id": target_id,
        "principals": [_public_target_principal_row(row) for row in principals],
        "expectations": [_public_target_endpoint_expectation_row(row) for row in rows],
        "count": len(rows),
        "execution_enabled": False,
        "findings_created": 0,
    }


@router.post("/targets/{target_id}/principal-matrix")
async def upsert_target_principal_matrix(target_id: str, request: TargetEndpointExpectationRequest):
    """Record an endpoint access expectation; does not queue probes or create findings."""
    target_uuid = _uuid_or_400(target_id, "target id")
    try:
        endpoint_uuid = _optional_uuid(request.endpoint_id)
        principal_uuid = _optional_uuid(request.principal_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="endpoint_id and principal_id must be UUIDs when provided") from exc
    method = _normalize_target_endpoint_method(request.method)
    path = _normalize_target_endpoint_path(request.path)
    param_shape = str(request.param_shape or "").strip()[:1000]
    param_location = str(request.param_location or "query").strip().lower()[:40] or "query"
    principal_role = _normalize_target_principal_role(request.principal_role) if request.principal_role else None
    metadata = _redact_agent_payload(request.metadata_json or {})
    async with _pool().acquire() as conn:
        target_row = await conn.fetchrow("SELECT url FROM targets WHERE id = $1", target_uuid)
        if not target_row:
            raise HTTPException(status_code=404, detail="Target not found")
        approval_context = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=str(target_row["url"] or ""),
            target_id=target_uuid,
            action_name="target.principal_matrix.record",
            command="target.principal_matrix.record",
            risk_tier="active",
            always_require_receipt=True,
        )
        if endpoint_uuid:
            endpoint = await conn.fetchrow(
                "SELECT method, path, param_shape, param_location FROM target_endpoints WHERE id = $1 AND target_id = $2",
                endpoint_uuid,
                target_uuid,
            )
            if not endpoint:
                raise HTTPException(status_code=404, detail="Endpoint not found for target")
            method = str(endpoint["method"] or method)
            path = str(endpoint["path"] or path)
            param_shape = str(endpoint["param_shape"] or param_shape)
            param_location = str(endpoint["param_location"] or param_location)
        if principal_uuid:
            principal = await conn.fetchrow(
                "SELECT role, tenant_id FROM target_principals WHERE id = $1 AND target_id = $2",
                principal_uuid,
                target_uuid,
            )
            if not principal:
                raise HTTPException(status_code=404, detail="Principal not found for target")
            principal_role = principal_role or str(principal["role"] or "user")
            tenant_id = request.tenant_id if request.tenant_id is not None else principal["tenant_id"]
        else:
            tenant_id = request.tenant_id
        row = await conn.fetchrow(
            """
            INSERT INTO target_endpoint_expectations (
                target_id, endpoint_id, method, path, param_shape, param_location,
                principal_id, principal_role, tenant_id, expected_access,
                expected_http_status, expectation_source, metadata_json
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)
            ON CONFLICT (
                target_id, method, path, param_shape, param_location,
                COALESCE(principal_id, '00000000-0000-0000-0000-000000000000'::uuid),
                COALESCE(principal_role, ''), COALESCE(tenant_id, '')
            )
            DO UPDATE SET
                expected_access = EXCLUDED.expected_access,
                expected_http_status = EXCLUDED.expected_http_status,
                expectation_source = EXCLUDED.expectation_source,
                endpoint_id = COALESCE(EXCLUDED.endpoint_id, target_endpoint_expectations.endpoint_id),
                metadata_json = target_endpoint_expectations.metadata_json || EXCLUDED.metadata_json,
                updated_at = NOW()
            RETURNING *
            """,
            target_uuid,
            endpoint_uuid,
            method,
            path,
            param_shape,
            param_location,
            principal_uuid,
            principal_role,
            tenant_id,
            request.expected_access,
            request.expected_http_status,
            str(request.expectation_source or "manual").strip()[:80] or "manual",
            json.dumps(metadata),
        )
        command_result = await _record_command_result(
            conn,
            command="target.principal_matrix.record",
            status="completed",
            risk_tier="active",
            scope_receipt_id=(approval_context or {}).get("scope_receipt_id"),
            approval_receipt_id=(approval_context or {}).get("approval_receipt_id"),
            operator_message=f"Recorded {method} {path} principal expectation",
            result_json={"target_id": target_id, "expectation_id": str(row["id"]), "expected_access": request.expected_access},
            created_by="principal_matrix_api",
        )
    return {
        "expectation": _public_target_endpoint_expectation_row(row),
        "execution_enabled": False,
        "findings_created": 0,
        "operation_id": command_result["id"],
        "approval_receipt_id": (approval_context or {}).get("approval_receipt_id"),
    }


@router.delete("/targets/{target_id}/principal-matrix/{expectation_id}")
async def delete_target_principal_expectation(
    target_id: str,
    expectation_id: str,
    approval_receipt_id: str = Query(...),
):
    """Delete one record-only endpoint access expectation for a target."""
    target_uuid = _uuid_or_400(target_id, "target id")
    expectation_uuid = _uuid_or_400(expectation_id, "expectation id")
    async with _pool().acquire() as conn:
        target_row = await conn.fetchrow("SELECT url FROM targets WHERE id = $1", target_uuid)
        if not target_row:
            raise HTTPException(status_code=404, detail="Target not found")
        approval_context = await _validate_approval_receipt_for_action(
            conn,
            approval_receipt_id,
            target_url=str(target_row["url"] or ""),
            target_id=target_uuid,
            action_name="target.principal_matrix.delete",
            command="target.principal_matrix.record",
            risk_tier="active",
            always_require_receipt=True,
        )
        deleted = await conn.fetchval(
            "DELETE FROM target_endpoint_expectations WHERE id = $1 AND target_id = $2 RETURNING id",
            expectation_uuid,
            target_uuid,
        )
    if not deleted:
        raise HTTPException(status_code=404, detail="Target principal expectation not found")
    async with _pool().acquire() as conn:
        command_result = await _record_command_result(
            conn,
            command="target.principal_matrix.delete",
            status="completed",
            risk_tier="active",
            scope_receipt_id=(approval_context or {}).get("scope_receipt_id"),
            approval_receipt_id=(approval_context or {}).get("approval_receipt_id"),
            operator_message="Deleted principal expectation",
            result_json={"target_id": target_id, "expectation_id": expectation_id},
            created_by="principal_matrix_api",
        )
    return {
        "status": "deleted",
        "target_id": target_id,
        "expectation_id": expectation_id,
        "execution_enabled": False,
        "findings_created": 0,
        "operation_id": command_result["id"],
        "approval_receipt_id": (approval_context or {}).get("approval_receipt_id"),
    }


@router.delete("/targets/{target_id}")
async def delete_target(target_id: str):
    """Delete a target (soft delete - sets inactive)."""
    async with _pool().acquire() as conn:
        result = await conn.execute("""
            UPDATE targets SET is_active = false, updated_at = NOW()
            WHERE id = $1
        """, uuid.UUID(target_id))

        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Target not found")

    return {'id': target_id, 'status': 'deleted'}


@router.post("/targets/{target_id}/scan")
async def scan_target(
    target_id: str,
    request: Optional[TargetScanRequest] = None,
):
    """Start a scan for a specific target."""
    request = request or TargetScanRequest()
    async with _pool().acquire() as conn:
        target = await conn.fetchrow(
            "SELECT url, scan_options FROM targets WHERE id = $1", uuid.UUID(target_id)
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

    # Historical target defaults remain readable, but old mode fields are never
    # allowed to authorize a new execution.
    stored_options = target['scan_options']
    if isinstance(stored_options, str):
        merged_options = json.loads(stored_options) if stored_options else {}
    else:
        merged_options = stored_options or {}
    for key in LEGACY_SCAN_WRITE_FIELDS:
        merged_options.pop(key, None)
    merged_options.update(request.options.model_dump(exclude_unset=True))

    scan_request = ScanInternalCompatibilityRequest(
        target=target['url'],
        budget_profile=request.budget_profile,
        policy=dict(request.policy or {}),
        advanced=request.advanced,
        approval_receipt_id=request.approval_receipt_id,
        options=ScanOptions(**merged_options),
    )
    return await _submit_scan(scan_request)


@router.get("/targets/{target_id}/graph")
async def get_application_graph(target_id: str, node_type: Optional[str] = None, edge_type: Optional[str] = None):
    """The first-class application graph for a target: routes, objects,
    producer/consumer links, and auth boundaries persisted from scans."""
    tgt = uuid.UUID(target_id)
    async with _pool().acquire() as conn:
        node_clause = " AND node_type = $2" if node_type else ""
        nparams = [tgt] + ([node_type] if node_type else [])
        nodes = await conn.fetch(
            f"SELECT * FROM application_graph_nodes WHERE target_id = $1{node_clause} ORDER BY node_type, node_key",
            *nparams)
        edge_clause = " AND edge_type = $2" if edge_type else ""
        eparams = [tgt] + ([edge_type] if edge_type else [])
        edges = await conn.fetch(
            f"SELECT * FROM application_graph_edges WHERE target_id = $1{edge_clause} ORDER BY edge_type, src_key",
            *eparams)
    node_rows = [row_to_dict(r) for r in nodes]
    edge_rows = [row_to_dict(r) for r in edges]
    by_node: dict[str, int] = {}
    for r in node_rows:
        by_node[str(r.get("node_type"))] = by_node.get(str(r.get("node_type")), 0) + 1
    by_edge: dict[str, int] = {}
    for r in edge_rows:
        by_edge[str(r.get("edge_type"))] = by_edge.get(str(r.get("edge_type")), 0) + 1
    return {
        "target_id": target_id,
        "nodes": node_rows,
        "edges": edge_rows,
        "summary": {"node_count": len(node_rows), "edge_count": len(edge_rows),
                    "by_node_type": by_node, "by_edge_type": by_edge},
    }


@router.post("/targets/{target_id}/graph/hypotheses")
async def generate_application_graph_hypotheses(
    target_id: str,
    created_by: Optional[str] = Query("app_graph", description="Audit label for generated endorsements."),
):
    """Record app-graph authz leads as hypotheses.

    This is a lead-board producer only: it does not queue ASM, run proof tests,
    create findings, or mark anything verified.
    """
    try:
        tgt = uuid.UUID(target_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="target_id must be a UUID")
    async with _pool().acquire() as conn:
        exists = await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", tgt)
        if not exists:
            raise HTTPException(status_code=404, detail="Target not found")
        nodes = await conn.fetch(
            "SELECT * FROM application_graph_nodes WHERE target_id = $1 ORDER BY node_type, node_key",
            tgt,
        )
        edges = await conn.fetch(
            "SELECT * FROM application_graph_edges WHERE target_id = $1 ORDER BY edge_type, src_key",
            tgt,
        )
        principal_rows = await conn.fetch(
            """
            SELECT p.id, p.label, p.role, p.tenant_id, p.auth_state,
                   p.credential_profile, p.is_active, p.metadata_json,
                   EXISTS (
                     SELECT 1 FROM target_credential_profiles cp
                     WHERE cp.target_id = p.target_id
                       AND lower(cp.name) = lower(p.credential_profile)
                       AND cp.is_active = true
                       AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
                   ) AS credential_configured
            FROM target_principals p
            WHERE p.target_id = $1 AND p.is_active = true
            ORDER BY p.role, p.label
            LIMIT 20
            """,
            tgt,
        )
        expectation_rows = await conn.fetch(
            """
            SELECT e.id, e.method, e.path, e.param_shape, e.param_location,
                   e.principal_role, e.tenant_id, e.expected_access, e.expected_http_status,
                   e.expectation_source, p.label AS principal_label, p.auth_state AS principal_auth_state
            FROM target_endpoint_expectations e
            LEFT JOIN target_principals p ON p.id = e.principal_id
            WHERE e.target_id = $1
            ORDER BY e.updated_at DESC
            LIMIT 50
            """,
            tgt,
        )
        requests = _application_graph_hypothesis_requests(
            target_id,
            list(nodes),
            list(edges),
            principal_rows=list(principal_rows),
            expectation_rows=list(expectation_rows),
            created_by=created_by,
        )
        records = [await _upsert_hypothesis(conn, req) for req in requests]
        # A3: auto-draft invariant candidates from the same black-box facts (review-only; never
        # authoritative until an operator approves through the existing invariant approval flow).
        draft_summary = await _auto_persist_invariant_drafts(
            conn,
            tgt,
            expectation_rows=list(expectation_rows),
            graph_edges=[_graph_row_payload(row) for row in edges],
            created_by=created_by,
        )
    return {
        "target_id": target_id,
        "candidate_count": len(requests),
        "created": sum(1 for item in records if item.get("created")),
        "endorsed": sum(1 for item in records if not item.get("created")),
        "hypotheses": [item["hypothesis"] for item in records],
        "invariant_draft_candidates": draft_summary.get("candidates", 0),
        "invariant_drafts_created": draft_summary.get("created", 0),
        "execution_enabled": False,
        "findings_created": 0,
    }


@router.post("/targets/{target_id}/inventory/hypotheses")
async def generate_endpoint_inventory_hypotheses(
    target_id: str,
    created_by: Optional[str] = Query("asm_inventory", description="Audit label for generated leads."),
) -> dict[str, Any]:
    """Record residue-backed BOLA / mass-assignment leads from the persisted endpoint inventory."""
    try:
        tgt = uuid.UUID(target_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="target_id must be a UUID")
    async with _pool().acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id=$1", tgt):
            raise HTTPException(status_code=404, detail="Target not found")
        rows = await conn.fetch(
            """
            SELECT method, path, param_shape, replay_spec, param_location, auth_state,
                   test_status, last_verdict, last_tested_at
            FROM target_endpoints
            -- DAST/ASM "tested" means a generic check ran, not that authorization or workflow
            -- semantics were exhausted. Reuse that map for deeper autonomous experiments.
            WHERE target_id=$1 AND COALESCE(test_status,'') <> 'gone'
            ORDER BY
                CASE COALESCE(test_status,'') WHEN 'untested' THEN 0 WHEN 'stale' THEN 1 ELSE 2 END,
                priority_score DESC NULLS LAST, last_seen_at DESC
            LIMIT 300
            """,
            tgt,
        )
        # A large inventory can sample create collections out of the top-300 (they rank low once
        # generically "tested"), yet a listable create collection (POST + GET on the same route) is the
        # highest-value create-based mass_assignment surface. Always include them + their GET sibling so
        # the create-based lead can form; the family proof backstops any speculative lead.
        create_rows = await conn.fetch(
            """
            SELECT * FROM (
                SELECT DISTINCT ON (upper(method), rtrim(path, '/'))
                       method, path, param_shape, replay_spec, param_location, auth_state,
                       test_status, last_verdict, last_tested_at
                FROM target_endpoints e
                WHERE e.target_id=$1 AND COALESCE(e.test_status,'') <> 'gone'
                  AND upper(e.method) IN ('POST', 'GET')
                  AND rtrim(e.path, '/') IN (
                    SELECT rtrim(p.path, '/') FROM target_endpoints p
                    WHERE p.target_id=$1 AND upper(p.method)='POST' AND COALESCE(p.test_status,'') <> 'gone'
                    INTERSECT
                    SELECT rtrim(g.path, '/') FROM target_endpoints g
                    WHERE g.target_id=$1 AND upper(g.method)='GET' AND COALESCE(g.test_status,'') <> 'gone'
                  )
                ORDER BY upper(method), rtrim(path, '/'),
                         (COALESCE(param_location, '') ~* '(body|json|form)') DESC,
                         (COALESCE(param_shape, '') ~* '(email|password|passwd)') DESC
            ) dedup
            -- Dedupe to one row per (method, route) so a huge inventory (thousands of collections, many
            -- rows each) does not exhaust the budget on one path, then float user/account create surfaces
            -- (where create-based mass_assignment matters most) and bodies that already look like account
            -- registration. Universal name heuristic, not an app-specific fact.
            ORDER BY (path ~* '(user|account|register|signup|member|customer|profile)') DESC,
                     (COALESCE(param_shape,'') ~* '(email|password|passwd)') DESC
            LIMIT 600
            """,
            tgt,
        )
        # Create collections go FIRST: the producer caps how many candidates it emits, so a large
        # inventory would otherwise exhaust the budget on the top-300 generic rows before reaching the
        # (lower-ranked) create surfaces where create-based mass_assignment lives.
        merged: dict[tuple[str, str], Any] = {
            (str(r["method"]).upper(), str(r["path"])): r for r in create_rows
        }
        for r in rows:
            merged.setdefault((str(r["method"]).upper(), str(r["path"])), r)
        requests = _endpoint_inventory_hypothesis_requests(
            target_id, [row_to_dict(r) for r in merged.values()], created_by=created_by,
        )
        # Deterministic create-collection pass: the main producer round-robin-caps candidates, so on a
        # huge inventory the create surfaces get buried. Re-run the producer over EACH user/account create
        # collection ALONE (its POST + GET rows only -- 2-3 endpoints, no cap) and merge any create-based
        # mass_assignment lead the capped pass missed, so create-MA always reaches the board.
        existing_keys = {req.dedupe_key for req in requests}
        account_rows: dict[str, list[Any]] = {}
        for row in create_rows:
            base = str(row["path"]).rstrip("/")
            if re.search(r"(?i)(user|account|register|signup|member|customer|profile|credential)", base):
                account_rows.setdefault(base, []).append(row)
        for rows_for_collection in list(account_rows.values())[:40]:
            for req in _endpoint_inventory_hypothesis_requests(
                target_id, [row_to_dict(r) for r in rows_for_collection], created_by=created_by,
            ):
                if (
                    req.dedupe_key not in existing_keys
                    and req.family == "mass_assignment"
                    and (req.metadata_json or {}).get("create_based")
                ):
                    requests.append(req)
                    existing_keys.add(req.dedupe_key)
        records = [await _upsert_hypothesis(conn, req) for req in requests]
    return {
        "target_id": target_id,
        "candidate_count": len(requests),
        "created": sum(1 for item in records if item.get("created")),
        "hypotheses": [item["hypothesis"] for item in records],
        "execution_enabled": False,
        "findings_created": 0,
    }


@router.get("/targets/{target_id}/asm/endpoints")
async def asm_list_endpoints(
    target_id: str,
    status: Optional[str] = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List the persistent attack-surface inventory for a target + coverage."""
    async with _pool().acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", uuid.UUID(target_id)):
            raise HTTPException(status_code=404, detail="Target not found")
        params: list[Any] = [uuid.UUID(target_id)]
        q = """SELECT id, method, path, param_shape, param_location, replay_spec, content_type,
                      source, auth_state, priority_score, test_status, last_attempt_status,
                      last_verdict, first_seen_at, last_seen_at, last_tested_at
               FROM target_endpoints WHERE target_id = $1"""
        if status:
            params.append(status)
            q += f" AND test_status = ${len(params)}"
        q += " ORDER BY priority_score DESC, last_seen_at DESC"
        params.append(limit)
        q += f" LIMIT ${len(params)}"
        params.append(offset)
        q += f" OFFSET ${len(params)}"
        rows = await conn.fetch(q, *params)
        coverage = await asm_inventory.coverage_summary(conn, target_id)
    return {"endpoints": [row_to_dict(r) for r in rows], "coverage": coverage}


@router.get("/targets/{target_id}/asm/coverage")
async def asm_coverage(target_id: str):
    """Per-target ASM coverage counts (tested / total over time)."""
    async with _pool().acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", uuid.UUID(target_id)):
            raise HTTPException(status_code=404, detail="Target not found")
        return await asm_inventory.coverage_summary(conn, target_id)


@router.post("/targets/{target_id}/asm/test")
async def asm_test(target_id: str, request: AsmTestRequest = None):
    """Queue an async exploitation batch over untested/stale inventory endpoints."""
    request = request or AsmTestRequest()
    r = get_redis()
    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT url, scan_options FROM targets WHERE id = $1", uuid.UUID(target_id))
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        _active_ids = await _asm_active_scan_ids(conn, target_id)
        if _active_ids:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Target already has an active scan ({_active_ids[0]}); wait for it to "
                    "finish before queueing another ASM action. It may be a hidden "
                    "Continuous-ASM batch/recon scan — open it via the 'view scan' link on "
                    "the coverage advisor, the 'ASM activity' panel on this page, or enable "
                    "'Show ASM/internal scans' on the Scans page."
                ),
            )
        coverage = await asm_inventory.coverage_summary(conn, target_id)
        if coverage["total"] == 0:
            raise HTTPException(status_code=400, detail="No endpoints in inventory yet; run a scan or coverage recon first")
        base_opts = _decode_target_scan_options(target["scan_options"])
        approval_context = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=target["url"],
            target_id=target_id,
            action_name="asm.test",
        )
        if approval_context:
            base_opts.update(approval_context)
        enq = await _enqueue_asm_exploit_batch(
            conn, r, target_id, target["url"], base_opts,
            batch_size=request.batch_size, stale_days=request.stale_days,
            exploit_depth=request.exploit_depth, check_family=request.check_family,
            endpoint_filter=request.endpoint_filter,
            triggered_by="api",
        )
        command_result = await _record_command_result(
            conn,
            command="asm.test",
            status="queued",
            risk_tier="credential" if _normalize_asm_check_family(request.check_family) in {"auth", "bola"} else "active",
            campaign_id=enq.get("campaign_id"),
            scan_id=enq.get("scan_id"),
            scope_receipt_id=base_opts.get("scope_receipt_id"),
            approval_receipt_id=base_opts.get("approval_receipt_id"),
            operator_message=f"Queued ASM test batch for {target['url']}",
            result_json={
                "target_id": target_id,
                "batch_size": request.batch_size,
                "stale_days": request.stale_days,
                "check_family": _normalize_asm_check_family(request.check_family) or "all",
                "endpoint_filter": _validate_asm_endpoint_filter_value(request.endpoint_filter),
            },
            next_action=f"/scans/{enq['scan_id']}",
        )
    return {
        "scan_id": enq["scan_id"], "job_id": enq["job_id"], "campaign_id": enq["campaign_id"], "status": "queued",
        "batch_size": request.batch_size,
        "check_family": _normalize_asm_check_family(request.check_family) or "all",
        "endpoint_filter": _validate_asm_endpoint_filter_value(request.endpoint_filter),
        "inventory_total": coverage["total"], "untested": coverage["untested"],
        "approval_receipt_id": base_opts.get("approval_receipt_id"),
        "scope_receipt_id": base_opts.get("scope_receipt_id"),
        "operation_id": command_result["id"],
    }


@router.post("/targets/{target_id}/asm/recon")
async def asm_recon(target_id: str, request: AsmReconRequest = None):
    """Queue an explicit ASM recon refresh for a target."""
    request = request or AsmReconRequest()
    r = get_redis()
    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT url, scan_options FROM targets WHERE id = $1", uuid.UUID(target_id))
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        _active_ids = await _asm_active_scan_ids(conn, target_id)
        if _active_ids:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Target already has an active scan ({_active_ids[0]}); wait for it to "
                    "finish before queueing another ASM action. It may be a hidden "
                    "Continuous-ASM batch/recon scan — open it via the 'view scan' link on "
                    "the coverage advisor, the 'ASM activity' panel on this page, or enable "
                    "'Show ASM/internal scans' on the Scans page."
                ),
            )
        base_opts = _decode_target_scan_options(target["scan_options"])
        approval_context = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=target["url"],
            target_id=target_id,
            action_name="asm.recon",
        )
        if approval_context:
            base_opts.update(approval_context)
        if request.budget_profile:
            base_opts["budget_profile"] = request.budget_profile
        enq = await _enqueue_asm_recon(conn, r, target_id, target["url"], base_opts, triggered_by="api")
        await conn.execute("UPDATE targets SET asm_last_recon_at = NOW() WHERE id = $1", uuid.UUID(target_id))
        command_result = await _record_command_result(
            conn,
            command="asm.recon",
            status="queued",
            risk_tier="passive",
            campaign_id=enq.get("campaign_id"),
            scan_id=enq.get("scan_id"),
            scope_receipt_id=base_opts.get("scope_receipt_id"),
            approval_receipt_id=base_opts.get("approval_receipt_id"),
            operator_message=f"Queued ASM recon refresh for {target['url']}",
            result_json={
                "target_id": target_id,
                "budget_profile": request.budget_profile,
            },
            next_action=f"/scans/{enq['scan_id']}",
        )
    return {
        "action": "recon",
        "scan_id": enq["scan_id"],
        "job_id": enq["job_id"],
        "campaign_id": enq["campaign_id"],
        "status": "queued",
        "reason": "Queued discovery refresh for the persistent ASM inventory",
        "approval_receipt_id": base_opts.get("approval_receipt_id"),
        "scope_receipt_id": base_opts.get("scope_receipt_id"),
        "operation_id": command_result["id"],
    }


@router.post("/targets/{target_id}/asm/prune")
async def asm_prune(target_id: str, request: AsmPruneRequest = None):
    """Re-probe existing inventory rows, persist reachability, and retire phantom
    (404/soft-404) endpoints to ``gone`` so they stop consuming test budget and
    inflating coverage. Read-only GET probes + status bookkeeping; safe anytime.
    Retirement is reversible (re-discovery resurrects ``gone`` -> ``untested``).
    Probes least-recently-swept paths first, so repeated calls rotate the whole
    inventory; bounded by ``max_probe`` to stay responsive."""
    request = request or AsmPruneRequest()
    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT url, scan_options FROM targets WHERE id = $1", uuid.UUID(target_id))
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        before = await asm_inventory.coverage_summary(conn, target_id)
        base_opts = _decode_target_scan_options(target["scan_options"])
        result = await asm_inventory.sweep_endpoint_reachability(
            conn, target["url"], target_id, base_opts,
            max_probe=request.max_probe, retire_threshold=request.retire_threshold,
        )
        after = await asm_inventory.coverage_summary(conn, target_id)
    return {
        "action": "prune",
        "target_id": target_id,
        "sweep": result,
        "inventory_total_before": before.get("total"),
        "inventory_testable_after": (after.get("total") or 0) - (after.get("gone") or 0),
        "gone_after": after.get("gone"),
        "reason": (
            f"Probed {result.get('probed', 0)} path(s); retired {result.get('retired', 0)} "
            f"unreachable endpoint(s) to 'gone' (reversible on re-discovery)."
        ),
    }


@router.post("/targets/{target_id}/asm/improve")
async def asm_improve(target_id: str, request: AsmImproveRequest = None):
    """Choose and queue the next best ASM action: recon if inventory is empty,
    otherwise a test batch when endpoints are claimable."""
    request = request or AsmImproveRequest()
    r = get_redis()
    async with _pool().acquire() as conn:
        target = await conn.fetchrow(
            "SELECT url, scan_options, asm_config FROM targets WHERE id = $1",
            uuid.UUID(target_id),
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        active_scan_ids = await _asm_active_scan_ids(conn, target_id)
        active = len(active_scan_ids)
        coverage = await asm_inventory.coverage_summary(conn, target_id)
        cfg = asm_inventory.merge_asm_config(_decode_asm_config(target["asm_config"]))
        stale_days = request.stale_days if request.stale_days is not None else cfg["stale_days"]
        endpoint_filter = _validate_asm_endpoint_filter_value(request.endpoint_filter)
        scheduler_state = await _asm_scheduler_state(
            conn,
            r,
            target_id,
            endpoint_filter=endpoint_filter,
            stale_days=stale_days,
        )
        claimable = int(scheduler_state.get("claimable") or 0)
        attempts = await conn.fetch(
            """
            SELECT COALESCE(last_attempt_status, 'none') AS status, COUNT(*) AS count
            FROM target_endpoints WHERE target_id = $1
            GROUP BY COALESCE(last_attempt_status, 'none')
            """,
            uuid.UUID(target_id),
        )
        attempt_counts = {str(rw["status"]): int(rw["count"] or 0) for rw in attempts}
        rec = _asm_recommendation(coverage, claimable=claimable, active_scans=active, active_scan_ids=active_scan_ids, last_attempt_counts=attempt_counts)
        if rec["next_action"] == "wait":
            return {
                "action": "wait",
                "status": "busy",
                "endpoint_filter": endpoint_filter,
                "scheduler_state": scheduler_state,
                **rec,
            }

        if endpoint_filter and rec["next_action"] == "test" and claimable <= 0:
            filtered_rec = {
                "next_action": "wait",
                "label": "No matching endpoints",
                "reason": f"No {endpoint_filter}-like endpoints are currently untested or stale.",
                "blockers": rec.get("blockers") or [],
            }
            return {
                "action": "wait",
                "status": "no_claimable_endpoints",
                "endpoint_filter": endpoint_filter,
                "reason": filtered_rec["reason"],
                "recommendation": filtered_rec,
                "scheduler_state": scheduler_state,
            }

        base_opts = _decode_target_scan_options(target["scan_options"])
        approval_context = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=target["url"],
            target_id=target_id,
            action_name="asm.improve",
        )
        if approval_context:
            base_opts.update(approval_context)
        if rec["next_action"] == "recon":
            enq = await _enqueue_asm_recon(conn, r, target_id, target["url"], base_opts, triggered_by="improve")
            await conn.execute("UPDATE targets SET asm_last_recon_at = NOW() WHERE id = $1", uuid.UUID(target_id))
            command_result = await _record_command_result(
                conn,
                command="asm.improve",
                status="queued",
                risk_tier="passive",
                campaign_id=enq.get("campaign_id"),
                scan_id=enq.get("scan_id"),
                scope_receipt_id=base_opts.get("scope_receipt_id"),
                approval_receipt_id=base_opts.get("approval_receipt_id"),
                operator_message=f"Queued ASM improve recon for {target['url']}",
                result_json={
                    "target_id": target_id,
                    "selected_action": "recon",
                    "recommendation": rec,
                },
                next_action=f"/scans/{enq['scan_id']}",
            )
            return {
                "action": "recon",
                "scan_id": enq["scan_id"],
                "job_id": enq["job_id"],
                "campaign_id": enq["campaign_id"],
                "status": "queued",
                "reason": rec["reason"],
                "recommendation": rec,
                "scheduler_state": scheduler_state,
                "approval_receipt_id": base_opts.get("approval_receipt_id"),
                "scope_receipt_id": base_opts.get("scope_receipt_id"),
                "operation_id": command_result["id"],
            }

        batch_size = request.batch_size if request.batch_size is not None else cfg["batch_size"]
        if claimable > 0:
            batch_size = min(batch_size, claimable)
        exploit_depth = request.exploit_depth if request.exploit_depth is not None else bool(cfg["exploit_depth"])
        enq = await _enqueue_asm_exploit_batch(
            conn, r, target_id, target["url"], base_opts,
            batch_size=batch_size, stale_days=stale_days,
            exploit_depth=exploit_depth, check_family=request.check_family,
            endpoint_filter=endpoint_filter,
            triggered_by="improve",
        )
        await conn.execute("UPDATE targets SET asm_last_test_at = NOW() WHERE id = $1", uuid.UUID(target_id))
        command_result = await _record_command_result(
            conn,
            command="asm.improve",
            status="queued",
            risk_tier="credential" if _normalize_asm_check_family(request.check_family) in {"auth", "bola"} else "active",
            campaign_id=enq.get("campaign_id"),
            scan_id=enq.get("scan_id"),
            scope_receipt_id=base_opts.get("scope_receipt_id"),
            approval_receipt_id=base_opts.get("approval_receipt_id"),
            operator_message=f"Queued ASM improve test batch for {target['url']}",
            result_json={
                "target_id": target_id,
                "selected_action": "test",
                "batch_size": batch_size,
                "stale_days": stale_days,
                "check_family": _normalize_asm_check_family(request.check_family) or "all",
                "endpoint_filter": endpoint_filter,
                "recommendation": rec,
            },
            next_action=f"/scans/{enq['scan_id']}",
        )
    return {
        "action": "test",
        "scan_id": enq["scan_id"],
        "job_id": enq["job_id"],
        "campaign_id": enq["campaign_id"],
        "status": "queued",
        "batch_size": batch_size,
        "check_family": _normalize_asm_check_family(request.check_family) or "all",
        "endpoint_filter": endpoint_filter,
        "reason": rec["reason"],
        "recommendation": rec,
        "scheduler_state": scheduler_state,
        "approval_receipt_id": base_opts.get("approval_receipt_id"),
        "scope_receipt_id": base_opts.get("scope_receipt_id"),
        "operation_id": command_result["id"],
    }


@router.get("/targets/{target_id}/asm/policy")
async def asm_get_policy(target_id: str):
    """Return the effective Continuous ASM policy for a target."""
    r = get_redis()
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            "SELECT asm_enabled, asm_config, asm_last_test_at, asm_last_recon_at FROM targets WHERE id = $1",
            uuid.UUID(target_id),
        )
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")
        scheduler_state = await _asm_scheduler_state(conn, r, target_id)
    return {
        "enabled": bool(row["asm_enabled"]),
        "config": asm_inventory.merge_asm_config(_decode_asm_config(row["asm_config"])),
        "last_test_at": row["asm_last_test_at"].isoformat() if row["asm_last_test_at"] else None,
        "last_recon_at": row["asm_last_recon_at"].isoformat() if row["asm_last_recon_at"] else None,
        "scheduler_state": scheduler_state,
    }


@router.put("/targets/{target_id}/asm/policy")
async def asm_set_policy(target_id: str, body: AsmPolicyUpdate):
    """Enable/disable continuous ASM and update the per-target policy (validated
    + clamped to safe bounds)."""
    r = get_redis()
    async with _pool().acquire() as conn:
        row = await conn.fetchrow("SELECT asm_config FROM targets WHERE id = $1", uuid.UUID(target_id))
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")
        current = _decode_asm_config(row["asm_config"])
        new_config = asm_inventory.merge_asm_config(
            {**current, **body.config} if isinstance(body.config, dict) else current
        )
        await conn.execute(
            """UPDATE targets
               SET asm_enabled = COALESCE($1, asm_enabled), asm_config = $2, updated_at = NOW()
               WHERE id = $3""",
            body.enabled, json.dumps(new_config), uuid.UUID(target_id),
        )
        out = await conn.fetchrow(
            "SELECT asm_enabled, asm_last_test_at, asm_last_recon_at FROM targets WHERE id = $1",
            uuid.UUID(target_id),
        )
        scheduler_state = await _asm_scheduler_state(conn, r, target_id)
    return {
        "enabled": bool(out["asm_enabled"]),
        "config": new_config,
        "last_test_at": out["asm_last_test_at"].isoformat() if out["asm_last_test_at"] else None,
        "last_recon_at": out["asm_last_recon_at"].isoformat() if out["asm_last_recon_at"] else None,
        "scheduler_state": scheduler_state,
    }


@router.get("/targets/{target_id}/asm/diff")
async def asm_diff(
    target_id: str,
    days: int = Query(7, ge=1, le=365),
    limit: int = Query(100, ge=1, le=500),
):
    """New attack surface for a target: endpoints first seen within N days."""
    async with _pool().acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", uuid.UUID(target_id)):
            raise HTTPException(status_code=404, detail="Target not found")
        return await asm_inventory.new_surface(conn, target_id, days=days, limit=limit)


@router.get("/targets/{target_id}/asm/gaps")
async def asm_gaps(target_id: str):
    """Explain remaining ASM coverage gaps for UI and AI agents."""
    r = get_redis()
    async with _pool().acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", uuid.UUID(target_id)):
            raise HTTPException(status_code=404, detail="Target not found")
        coverage = await asm_inventory.coverage_summary(conn, target_id)
        cfg_row = await conn.fetchrow("SELECT asm_config FROM targets WHERE id = $1", uuid.UUID(target_id))
        cfg = asm_inventory.merge_asm_config(_decode_asm_config(cfg_row["asm_config"] if cfg_row else {}))
        claimable = await asm_inventory.claimable_count(conn, target_id, stale_days=cfg["stale_days"])
        scheduler_state = await _asm_scheduler_state(conn, r, target_id, stale_days=cfg["stale_days"])
        active_scan_ids = await _asm_active_scan_ids(conn, target_id)
        active = len(active_scan_ids)
        by_auth_rows = await conn.fetch(
            """
            SELECT auth_state, test_status, COUNT(*) AS count
            FROM target_endpoints WHERE target_id = $1
            GROUP BY auth_state, test_status
            ORDER BY auth_state, test_status
            """,
            uuid.UUID(target_id),
        )
        by_location_rows = await conn.fetch(
            """
            SELECT COALESCE(param_location, 'none') AS param_location, COUNT(*) AS count
            FROM target_endpoints WHERE target_id = $1
            GROUP BY COALESCE(param_location, 'none')
            ORDER BY count DESC
            """,
            uuid.UUID(target_id),
        )
        attempt_rows = await conn.fetch(
            """
            SELECT COALESCE(last_attempt_status, 'none') AS status, COUNT(*) AS count
            FROM target_endpoints WHERE target_id = $1
            GROUP BY COALESCE(last_attempt_status, 'none')
            ORDER BY count DESC
            """,
            uuid.UUID(target_id),
        )
        samples = await conn.fetch(
            """
            SELECT id, method, path, param_shape, param_location, auth_state, priority_score,
                   test_status, last_attempt_status, last_verdict, lease_owner,
                   lease_expires_at, attempt_count, last_seen_at, last_tested_at
            FROM target_endpoints
            WHERE target_id = $1
              AND (test_status IN ('untested', 'stale', 'in_progress')
                   OR last_attempt_status IN ('auth_missing', 'partial', 'partial_timeout', 'partial_findings'))
            ORDER BY priority_score DESC, last_seen_at DESC
            LIMIT 25
            """,
            uuid.UUID(target_id),
        )
        ledger_rows = await conn.fetch(
            """
            SELECT status, COUNT(*) AS count
            FROM asm_endpoint_attempts
            WHERE endpoint_id IN (
                SELECT id FROM target_endpoints WHERE target_id = $1
            )
            GROUP BY status
            ORDER BY count DESC
            """,
            uuid.UUID(target_id),
        )
        # §7: family-level coverage — which vuln families have PROOF-quality attempts
        # (completed) vs only touched. "endpoint attempted" != "family proved".
        family_rows = await conn.fetch(
            """
            SELECT COALESCE(check_family, 'all') AS family,
                   COUNT(*) FILTER (
                       WHERE status = 'completed'
                         AND scanner_telemetry_json #>> '{endpoint_attempt,schema_version}' = 'active_endpoint_attempt_v1'
                   ) AS completed,
                   COUNT(*) FILTER (
                       WHERE scanner_telemetry_json #>> '{endpoint_attempt,proof_observed}' = 'true'
                   ) AS proved,
                   COUNT(*) FILTER (WHERE status IN ('auth_missing', 'auth_failed')) AS blocked,
                   COUNT(*) FILTER (
                       WHERE (
                           status IN ('partial', 'timeout')
                           AND COALESCE(scanner_telemetry_json #>> '{endpoint_attempt,cancelled}', 'false') <> 'true'
                           AND COALESCE(error_summary, '') <> 'cancelled'
                       ) OR (
                           status = 'completed'
                           AND scanner_telemetry_json #>> '{endpoint_attempt,schema_version}' IS DISTINCT FROM 'active_endpoint_attempt_v1'
                       )
                   ) AS partial,
                   COUNT(*) FILTER (
                       WHERE scanner_telemetry_json #>> '{endpoint_attempt,cancelled}' = 'true'
                          OR error_summary = 'cancelled'
                   ) AS cancelled,
                   COUNT(*) FILTER (WHERE status = 'error') AS failed,
                   COUNT(*) AS attempts
            FROM asm_endpoint_attempts
            WHERE endpoint_id IN (SELECT id FROM target_endpoints WHERE target_id = $1)
            GROUP BY COALESCE(check_family, 'all')
            """,
            uuid.UUID(target_id),
        )
        # §10.5: proof-quality distribution of active findings, so ASM gaps surface
        # how trustworthy findings are (not just coverage). Bucketed by the
        # deterministic verification verdict — 'exploited' = proven, no verdict =
        # still suspected — which is the queryable proof signal on the findings table.
        conf_rows = await conn.fetch(
            """
            SELECT
                CASE
                    WHEN last_verification_verdict = 'exploited' THEN 'verified'
                    WHEN last_verification_verdict IN ('blocked_by_security', 'out_of_scope_internal') THEN 'mitigated'
                    WHEN last_verification_verdict IN ('likely_fixed', 'false_positive') THEN 'likely_fixed'
                    WHEN last_verification_verdict IN ('inconclusive', 'error') THEN 'inconclusive'
                    ELSE 'suspected'
                END AS tier,
                count(*) AS n,
                count(*) FILTER (WHERE severity IN ('critical', 'high')) AS high_critical
            FROM findings
            WHERE target_id = $1 AND status = 'active'
            GROUP BY 1
            """,
            uuid.UUID(target_id),
        )
        # Verification Depth plan (B): High/Critical findings that are stuck unproven —
        # either a retest wedged in queued/running for over an hour (measured by the
        # finding_verifications ROW timestamp, not findings.updated_at which a later
        # finding edit can reset and hide the wedged retest), or one that hit the
        # auto-retest attempt ceiling and is still not 'exploited'. Surfacing this keeps
        # findings from sitting needs_verification forever, invisibly.
        stuck_verification = await conn.fetchval(
            """
            SELECT count(DISTINCT f.id) FROM findings f
            WHERE f.target_id = $1 AND f.status = 'active'
              AND f.severity IN ('critical', 'high')
              AND f.last_verification_verdict IS DISTINCT FROM 'exploited'
              AND (
                  EXISTS (
                      SELECT 1 FROM finding_verifications v
                      WHERE v.finding_id = f.id
                        AND v.status IN ('queued', 'running')
                        AND COALESCE(v.updated_at, v.created_at) < NOW() - INTERVAL '1 hour'
                  )
                  OR f.verification_count >= $2
              )
            """,
            uuid.UUID(target_id),
            int(os.environ.get("AUTO_RETEST_MAX_ATTEMPTS", "3")),
        )

    attempt_counts = {str(r["status"]): int(r["count"] or 0) for r in attempt_rows}
    family_coverage = {
        str(r["family"]): {
            "attempted": int(r["attempts"] or 0),
            "completed": int(r["completed"] or 0),
            "proved": int(r["proved"] or 0),
            "blocked": int(r["blocked"] or 0),
            "cancelled": int(r["cancelled"] or 0),
            "partial": int(r["partial"] or 0),
            "failed": int(r["failed"] or 0),
            # Backward-compatible alias for existing API/UI consumers.
            "attempts": int(r["attempts"] or 0),
        }
        for r in family_rows
    }
    recommendation = _asm_recommendation(
        coverage,
        claimable=claimable,
        active_scans=active,
        active_scan_ids=active_scan_ids,
        last_attempt_counts=attempt_counts,
    )
    recommended_campaigns = _asm_recommended_campaigns(
        coverage=coverage,
        family_coverage=family_coverage,
        by_auth=None,
        last_attempt_counts=attempt_counts,
        active_scans=active,
    )
    by_auth: dict[str, dict[str, int]] = {}
    for row in by_auth_rows:
        state = str(row["auth_state"] or "anonymous")
        by_auth.setdefault(state, {})[str(row["test_status"])] = int(row["count"] or 0)

    confidence_distribution = {
        str(r["tier"]): {"total": int(r["n"] or 0), "high_critical": int(r["high_critical"] or 0)}
        for r in conf_rows
    }

    return {
        "coverage": coverage,
        "claimable": claimable,
        "active_scans": active,
        "recommendation": recommendation,
        "scheduler_state": scheduler_state,
        "recommended_campaigns": recommended_campaigns,
        "by_auth_state": by_auth,
        "by_param_location": {str(r["param_location"]): int(r["count"] or 0) for r in by_location_rows},
        "family_coverage": family_coverage,
        "confidence_distribution": confidence_distribution,
        "stuck_verification": int(stuck_verification or 0),
        "last_attempt_status": attempt_counts,
        "attempt_ledger_status": {str(r["status"]): int(r["count"] or 0) for r in ledger_rows},
        "sample_gaps": [row_to_dict(r) for r in samples],
    }


@router.get("/targets/{target_id}/asm/activity")
async def asm_activity(
    target_id: str,
    limit: int = Query(25, ge=1, le=100),
):
    """Recent ASM recon/test jobs for a target, grouped away from normal scan rows."""
    try:
        target_uuid = uuid.UUID(target_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="target_id must be a UUID")
    r = get_redis()
    async with _pool().acquire() as conn:
        target_row = await conn.fetchrow("SELECT id, url FROM targets WHERE id = $1", target_uuid)
        if not target_row:
            raise HTTPException(status_code=404, detail="Target not found")
        scheduler_state = await _asm_scheduler_state(conn, r, target_id)
        next_schedule = await conn.fetchrow(
            """
            SELECT id, schedule_kind, frequency, day_of_week, time_of_day, timezone,
                   next_run_at, last_run_at
            FROM schedules
            WHERE target_id = $1
              AND is_active = true
              AND (
                COALESCE(schedule_kind, 'normal_scan') = 'asm_improve'
                OR COALESCE(scan_options->>'kind', '') = 'asm_improve'
              )
            ORDER BY next_run_at NULLS LAST, created_at DESC
            LIMIT 1
            """,
            target_uuid,
        )
        active_rows = await conn.fetch(
            """
            SELECT id, scan_role, status, current_phase, created_at, started_at, campaign_id
            FROM scans
            WHERE target_id = $1
              AND status IN ('pending', 'queued', 'running')
            ORDER BY created_at DESC
            LIMIT 5
            """,
            target_uuid,
        )
        rows = await conn.fetch(
            """
            SELECT s.id, s.job_id, s.scan_role, s.scan_type, s.status, s.current_phase, s.progress,
                   s.findings_count, s.score, s.grade, s.error_message,
                   s.created_at, s.started_at, s.completed_at, s.duration_seconds,
                   s.campaign_id, c.mode AS campaign_mode, c.requested_by AS campaign_requested_by,
                   c.status AS campaign_status, c.check_families AS campaign_check_families
            FROM scans s
            LEFT JOIN scan_campaigns c ON c.id = s.campaign_id
            WHERE s.target_id = $1 AND s.scan_role IN ($2, $3)
            ORDER BY s.created_at DESC
            LIMIT $4
            """,
            target_uuid, asm_inventory.ASM_BATCH_ROLE, asm_inventory.ASM_RECON_ROLE, limit,
        )
        campaign_ids = [r["campaign_id"] for r in rows if r["campaign_id"]]
        attempt_counts: dict[str, dict[str, int]] = {}
        if campaign_ids:
            attempts = await conn.fetch(
                """
                SELECT campaign_id, status, COUNT(*) AS count
                FROM asm_endpoint_attempts
                WHERE campaign_id = ANY($1::uuid[])
                GROUP BY campaign_id, status
                """,
                campaign_ids,
            )
            for attempt in attempts:
                cid = str(attempt["campaign_id"])
                attempt_counts.setdefault(cid, {})[str(attempt["status"])] = int(attempt["count"] or 0)
        hypothesis_situation = await _load_hypothesis_situation_report(
            conn,
            target_uuid=target_uuid,
            limit=5,
            include_graph=True,
        )
    activity = []
    for row in rows:
        item = row_to_dict(row)
        cid = str(row["campaign_id"]) if row["campaign_id"] else None
        item["attempt_status_counts"] = attempt_counts.get(cid, {}) if cid else {}
        activity.append(item)
    timeline = _build_asm_campaign_timeline(
        scheduler_state=scheduler_state,
        activity=activity,
        next_schedule=row_to_dict(next_schedule) if next_schedule else None,
        active_scans=[row_to_dict(row) for row in active_rows],
        target_id=str(target_uuid),
        target_url=str(target_row.get("url") or ""),
        limit=limit,
    )
    return {
        "activity": activity,
        "scheduler_state": scheduler_state,
        "next_schedule": row_to_dict(next_schedule) if next_schedule else None,
        "active_scans": [row_to_dict(row) for row in active_rows],
        "timeline": timeline,
        "hypothesis_situation": hypothesis_situation,
    }
def _public_target_row(row: Any) -> dict[str, Any]:
    """Serialize a target without exposing credentials stored in scan options."""
    target = row_to_dict(row)
    for key, limit in (("url", 2049), ("name", 512), ("root_domain", 253)):
        value = target.get(key)
        if isinstance(value, str) and len(value) > limit:
            target[key] = value[:limit]
    if "scan_options" in target:
        target["scan_options"] = _sanitize_scan_options(target.get("scan_options"))
    metadata = _decode_json_value(target.get("metadata_json")) or {}
    if not isinstance(metadata, dict):
        metadata = {}
    target["metadata_json"] = metadata
    target["cohort"] = target_cohort(
        url=target.get("url"),
        name=target.get("name"),
        discovery_source=target.get("discovery_source"),
        metadata=metadata,
    )
    if str(target.get("discovery_source") or "").lower() != "model-intake":
        values = _decode_json_value(target.get("origins")) or []
        if not isinstance(values, list):
            values = []
        origins: list[str] = []
        for value in [*values, target.get("url")]:
            try:
                origin, _note = normalize_target_url(str(value or ""))
            except TargetNormalizationError:
                continue
            if origin and origin not in origins:
                origins.append(origin)
        target["origins"] = origins
    return target


def _normalize_asm_check_family(value: Any) -> str | None:
    return check_registry.validate_asm_focus_family(value)


def _validate_asm_endpoint_filter_value(value: Any) -> str | None:
    return asm_inventory.normalize_endpoint_filter(value)


class TargetScanRequest(BaseModel):
    """Canonical controls for starting a Scan from an existing target."""

    model_config = ConfigDict(extra="forbid")

    budget_profile: Optional[Literal["fast", "balanced", "thorough"]] = None
    policy: Optional[dict[str, Any]] = None
    advanced: Optional[ScanAdvancedLimits] = None
    approval_receipt_id: Optional[str] = None
    options: ScanPublicCompatibilityOptions = Field(
        default_factory=ScanPublicCompatibilityOptions,
    )


class TargetCreate(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    name: Optional[str] = Field(default=None, max_length=512)
    scan_options: Optional[dict] = None
    cohort: Optional[Literal["production", "staging", "lab", "demo", "calibration", "internal"]] = None


class TargetUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=512)
    is_active: Optional[bool] = None
    scan_options: Optional[dict] = None
    # Merged into the existing metadata (JSONB ||), so partial ownership
    # updates don't clobber unrelated keys. Set a key to "" to clear it.
    metadata_json: Optional[dict] = None
    cohort: Optional[Literal["production", "staging", "lab", "demo", "calibration", "internal"]] = None

    @field_validator("metadata_json")
    @classmethod
    def metadata_cannot_bypass_cohort_validation(cls, value: Optional[dict]) -> Optional[dict]:
        if value and "cohort" in value:
            raise ValueError("set cohort through the validated cohort field")
        return value


class TargetPrincipalAutoProvisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_receipt_id: str
    created_by: Optional[str] = Field(default="target_principal_auto_provision", max_length=120)


class TargetCredentialProfileCreate(BaseModel):
    name: str
    auth_kind: str = Field(pattern="^(authorization_header|cookie)$")
    secret: str
    expires_at: Optional[datetime] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class TargetCredentialProfileUpdate(BaseModel):
    name: Optional[str] = None
    auth_kind: Optional[str] = Field(default=None, pattern="^(authorization_header|cookie)$")
    secret: Optional[str] = None
    expires_at: Optional[datetime] = None
    clear_expiry: bool = False
    is_active: Optional[bool] = None
    metadata_json: Optional[dict[str, Any]] = None


class TargetCredentialProfileRotate(BaseModel):
    secret: str
    expires_at: Optional[datetime] = None
    clear_expiry: bool = False


class TargetPrincipalCreate(BaseModel):
    label: str
    role: str = "user"
    tenant_id: Optional[str] = None
    auth_state: str = "user1"
    credential_profile: Optional[str] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True


class TargetPrincipalUpdate(BaseModel):
    label: Optional[str] = None
    role: Optional[str] = None
    tenant_id: Optional[str] = None
    auth_state: Optional[str] = None
    credential_profile: Optional[str] = None
    metadata_json: Optional[dict[str, Any]] = None
    is_active: Optional[bool] = None


class TargetEndpointExpectationRequest(BaseModel):
    endpoint_id: Optional[str] = None
    method: str = "GET"
    path: str
    param_shape: str = ""
    param_location: str = "query"
    principal_id: Optional[str] = None
    principal_role: Optional[str] = None
    tenant_id: Optional[str] = None
    expected_access: str = Field(default="unknown", pattern="^(allow|deny|requires_role|unknown)$")
    expected_http_status: Optional[int] = Field(default=None, ge=100, le=599)
    expectation_source: str = "manual"
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    approval_receipt_id: Optional[str] = None


class TargetInvariantContractCreate(BaseModel):
    """Draft a typed rule; free text is retained as context but never becomes proof authority."""

    model_config = ConfigDict(extra="forbid")

    contract_kind: str = Field(pattern="^(access_control|field_constraint|workflow_transition|ownership)$")
    title: str = Field(min_length=1, max_length=300)
    source_text: Optional[str] = Field(default=None, max_length=4000)
    subject_role: Optional[str] = Field(default=None, max_length=80)
    action: Optional[str] = Field(default=None, max_length=120)
    resource: Optional[str] = Field(default=None, max_length=160)
    method: Optional[str] = Field(default=None, max_length=12)
    path: Optional[str] = Field(default=None, max_length=1000)
    field_name: Optional[str] = Field(default=None, max_length=160)
    operator: Optional[str] = Field(default=None, pattern="^(eq|ne|lt|lte|gt|gte|in|not_in)$")
    expected_value: Any = None
    expected_access: Optional[str] = Field(default=None, pattern="^(allow|deny|requires_role)$")
    conditions: dict[str, Any] = Field(default_factory=dict)
    source: str = Field(default="manual", pattern="^(manual|compiled|imported)$")
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = Field(default="target_invariant_api", max_length=120)
    approval_receipt_id: str


class TargetInvariantCompileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_text: str = Field(min_length=3, max_length=4000)
    method: Optional[str] = Field(default=None, max_length=12)
    path: Optional[str] = Field(default=None, max_length=1000)
    persist_drafts: bool = False
    approval_receipt_id: Optional[str] = None
    created_by: Optional[str] = Field(default="target_invariant_compiler", max_length=120)


class TargetInvariantHypothesisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    created_by: Optional[str] = Field(default="target_invariant_hypotheses", max_length=120)


class TargetInvariantContractApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_receipt_id: str
    approved_by: str = Field(min_length=1, max_length=120)
    confirm_authoritative: bool


class TargetInvariantContractRetire(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_receipt_id: str
    retired_by: str = Field(min_length=1, max_length=120)


def _dedupe_canonical_target_rows(rows: list) -> list:
    """Collapse target rows that share a canonical host key (scheme/port variants
    of the same web asset) so grouped targets don't expose duplicate targets.
    Keeps one survivor per key — active first, then most active findings, then most
    scans, then an https URL — preserving first-occurrence order. Display-layer
    safeguard; a deliberate data merge is the durable fix."""
    def rank(row) -> tuple:
        url = str(row['url'] or "")
        return (
            1 if row['is_active'] else 0,
            int(row['active_findings_count'] or 0),
            int(row['total_scans'] or 0),
            1 if url.lower().startswith("https://") else 0,
        )

    survivors: dict[str, Any] = {}
    order: list[str] = []
    for row in rows:
        key = _canonical_target_key(row['url'], row.get('discovery_source'))
        if key not in survivors:
            survivors[key] = row
            order.append(key)
        elif rank(row) > rank(survivors[key]):
            survivors[key] = row
    return [survivors[k] for k in order]


class DedupeTargetsRequest(BaseModel):
    dry_run: bool = True


def _normalize_target_principal_label(value: Any) -> str:
    label = re.sub(r"\s+", " ", str(value or "").strip())
    if not label:
        raise HTTPException(status_code=400, detail="principal label is required")
    if len(label) > 120:
        raise HTTPException(status_code=400, detail="principal label must be 120 characters or fewer")
    return label


def _normalize_target_credential_secret(value: Any) -> str:
    secret = str(value or "").strip()
    if not secret:
        raise HTTPException(status_code=400, detail="credential profile secret is required")
    if "\r" in secret or "\n" in secret:
        raise HTTPException(status_code=400, detail="credential profile secret must not contain CR or LF")
    if len(secret) > 16384:
        raise HTTPException(status_code=400, detail="credential profile secret is too large")
    return secret


def _public_target_credential_profile_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    status, refresh_required = _target_credential_profile_status(payload)
    stored_secret = str(payload.pop("secret_value", "") or "")
    payload["metadata_json"] = _redact_agent_payload(_decode_json_value(payload.get("metadata_json")) or {})
    payload["secret_configured"] = bool(stored_secret)
    payload["storage_encrypted"] = stored_secret.startswith("enc:fernet:")
    payload["encryption_available"] = encryption_enabled()
    payload["status"] = status
    payload["refresh_required"] = refresh_required
    payload["execution_compatible"] = status == "active" and bool(stored_secret)
    return payload


def _target_credential_profile_values(
    *,
    name: Any,
    auth_kind: Any,
    secret: Any,
    expires_at: datetime | None,
    metadata_json: Any,
) -> dict[str, Any]:
    normalized_secret = _normalize_target_credential_secret(secret)
    kind = str(auth_kind or "").strip().lower()
    if kind not in {"authorization_header", "cookie"}:
        raise HTTPException(status_code=400, detail="auth_kind must be authorization_header or cookie")
    return {
        "name": _normalize_target_credential_profile_name(name),
        "auth_kind": kind,
        "secret_value": encrypt_secret(normalized_secret),
        "secret_preview": _mask_ai_target_secret(normalized_secret),
        "expires_at": expires_at,
        "metadata_json": _redact_agent_payload(metadata_json if isinstance(metadata_json, dict) else {}),
    }


def _normalize_target_principal_role(value: Any) -> str:
    role = re.sub(r"[^a-z0-9_.-]+", "_", str(value or "user").strip().lower()).strip("_")
    return (role or "user")[:80]


def _normalize_target_auth_state(value: Any) -> str:
    state = str(value or "user1").strip().lower()
    if state not in {"user1", "user2"}:
        raise HTTPException(
            status_code=400,
            detail="principal auth_state must be user1 or user2; use role for application roles",
        )
    return state


def _principal_slot_conflict() -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "error": "principal_auth_state_conflict",
            "message": "This target already has an active principal assigned to that auth_state",
            "blocked_by": ["principal_auth_state_already_assigned"],
        },
    )


def _normalize_target_endpoint_method(value: Any) -> str:
    method = str(value or "GET").strip().upper()
    if not re.fullmatch(r"[A-Z]{2,12}", method):
        raise HTTPException(status_code=400, detail="endpoint method is invalid")
    return method


def _normalize_target_endpoint_path(value: Any) -> str:
    path = str(value or "").strip()
    if not path:
        raise HTTPException(status_code=400, detail="endpoint path is required")
    if "://" in path:
        parsed = urllib.parse.urlparse(path)
        path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path[:1000]


def _public_target_principal_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    payload["metadata_json"] = _redact_agent_payload(_decode_json_value(payload.get("metadata_json")) or {})
    payload["credential_configured"] = bool(payload.get("credential_configured"))
    payload["execution_enabled"] = False
    return payload


def _public_target_endpoint_expectation_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    payload["metadata_json"] = _redact_agent_payload(_decode_json_value(payload.get("metadata_json")) or {})
    payload["execution_enabled"] = False
    payload["finding_created"] = False
    return payload


def _public_target_invariant_contract_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    payload["expected_value"] = _decode_jsonb_scalar(payload.get("expected_value"))
    payload["conditions"] = _decode_json_value(payload.get("conditions")) or {}
    payload["metadata_json"] = _redact_agent_payload(_decode_json_value(payload.get("metadata_json")) or {})
    projection = invariant_contracts.planner_projection(payload)
    return {
        **payload,
        **projection,
        "execution_enabled": False,
        "finding_created": False,
    }


_AUTO_PROVISION_SEMAPHORE = asyncio.Semaphore(2)


def _auto_provisioning_config(target_row: Any) -> dict[str, Any]:
    row = target_row if isinstance(target_row, dict) else {}
    meta = _decode_json_value(row.get("metadata_json")) or {}
    config = meta.get("auto_provisioning") if isinstance(meta, dict) else None
    return config if isinstance(config, dict) else {}


async def _auto_provision_principals(conn, target_uuid, target_url: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    import httpx  # container-local; api.py has no top-level httpx dependency

    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="auto_provisioning is not enabled for this target")
    if not encryption_enabled():
        raise HTTPException(
            status_code=409,
            detail="auto_provisioning requires AI_CREDENTIAL_ENC_KEY so managed credentials are encrypted at rest",
        )
    signup = config.get("signup") if isinstance(config.get("signup"), dict) else None
    login = config.get("login") if isinstance(config.get("login"), dict) else None
    if not signup or not login:
        raise HTTPException(status_code=400, detail="auto_provisioning requires both a signup and a login recipe")
    specs = config.get("principals")
    if not isinstance(specs, list) or not specs:
        specs = [{"label": "user1", "auth_state": "user1"}, {"label": "user2", "auth_state": "user2"}]
    specs = [s for s in specs if isinstance(s, dict)][:_MAX_AUTO_PROVISION_PRINCIPALS]
    if not specs:
        raise HTTPException(status_code=400, detail="auto_provisioning has no valid principal specs")
    normalized_specs: list[dict[str, str]] = []
    seen_labels: set[str] = set()
    seen_states: set[str] = set()
    for spec in specs:
        label = _normalize_target_principal_label(spec.get("label") or "user1")
        auth_state = _normalize_target_auth_state(spec.get("auth_state") or "user1")
        if label.lower() in seen_labels or auth_state in seen_states:
            raise HTTPException(status_code=400, detail="auto_provisioning principal labels and auth_state values must be unique")
        seen_labels.add(label.lower())
        seen_states.add(auth_state)
        normalized_specs.append({"label": label, "auth_state": auth_state})
    token_path = str(login.get("token_path") or "$.token")
    auth_kind = str(login.get("auth_kind") or "authorization_header").strip().lower()
    header_format = str(login.get("header_format") or "Bearer {{token}}")
    provisioned: list[dict[str, Any]] = []
    for recipe_name, recipe in (("signup", signup), ("login", login)):
        method = str(recipe.get("method") or "POST").strip().upper()
        if method != "POST":
            raise HTTPException(status_code=400, detail=f"auto_provisioning {recipe_name} method must be POST")

    async def bounded_request(
        client, url: str, body: Any, *, method: str = "POST", headers: dict[str, str] | None = None,
    ) -> tuple[int, Any]:
        request = client.build_request(
            method, url, json=body or None,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        response = await client.send(request, stream=True)
        chunks: list[bytes] = []
        received = 0
        try:
            async for chunk in response.aiter_bytes():
                received += len(chunk)
                if received > _MAX_AUTO_PROVISION_RESPONSE_BYTES:
                    raise HTTPException(status_code=502, detail="auto_provisioning upstream response exceeded 64 KiB")
                chunks.append(chunk)
        finally:
            await response.aclose()
        payload: Any = None
        if chunks:
            try:
                payload = json.loads(b"".join(chunks).decode(response.encoding or "utf-8", errors="replace"))
            except (ValueError, TypeError):
                payload = None
        return response.status_code, payload

    async with httpx.AsyncClient(timeout=httpx.Timeout(15), follow_redirects=False, trust_env=False) as client:
        for spec in normalized_specs:
            label = spec["label"]
            auth_state = spec["auth_state"]
            existing = await conn.fetchrow(
                """
                SELECT p.label, p.auth_state, p.credential_profile
                FROM target_principals p
                JOIN target_credential_profiles cp
                  ON cp.target_id=p.target_id AND lower(cp.name)=lower(p.credential_profile)
                WHERE p.target_id=$1 AND p.auth_state=$2 AND p.is_active=true
                  AND cp.is_active=true AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
                ORDER BY p.updated_at DESC LIMIT 1
                """,
                target_uuid, auth_state,
            )
            if existing:
                provisioned.append({
                    "label": str(existing["label"]), "auth_state": str(existing["auth_state"]),
                    "credential_profile": str(existing["credential_profile"]), "reused": True,
                })
                continue
            # Persist random account material BEFORE the first external request.  A retry after a
            # successful signup but failed login/DB write must reuse the same identity and password.
            seed = secrets.token_hex(32)
            generated_variables = {
                "email": f"sk{seed[:10]}@shaker.test",
                "password": f"ShakerHunt!{seed[10:26]}Aa1",
                "number": str(int(seed[26:42], 16) % 10_000_000_000).zfill(10),
                "name": f"Shaker {label}",
                "label": label,
            }
            encrypted_variables = encrypt_secret(json.dumps(generated_variables, sort_keys=True))
            if not str(encrypted_variables or "").startswith("enc:fernet:"):
                raise HTTPException(status_code=409, detail="auto_provisioning could not encrypt retry material")
            await conn.execute(
                """
                INSERT INTO target_principal_provisioning_attempts (
                    target_id, principal_label, auth_state, encrypted_variables, status, attempt_count
                ) VALUES ($1,$2,$3,$4,'pending',1)
                ON CONFLICT (target_id, auth_state) DO UPDATE SET
                    attempt_count=target_principal_provisioning_attempts.attempt_count+1,
                    updated_at=NOW()
                """,
                target_uuid, label, auth_state, encrypted_variables,
            )
            attempt = await conn.fetchrow(
                """
                SELECT encrypted_variables FROM target_principal_provisioning_attempts
                WHERE target_id=$1 AND auth_state=$2
                """,
                target_uuid, auth_state,
            )
            try:
                variables = json.loads(str(decrypt_secret(attempt["encrypted_variables"])))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise HTTPException(status_code=500, detail="stored provisioning retry material is unavailable") from exc
            # 1) Register through the app's own signup flow (real account, same origin only).
            signup_url = _provision_same_origin_url(target_url, signup.get("path"))
            signup_body = _render_provision_template(signup.get("json") or {}, variables)
            signup_status, _signup_payload = await bounded_request(client, signup_url, signup_body)
            if not (200 <= signup_status < 300 or signup_status == 409):
                raise HTTPException(status_code=502, detail=f"signup failed for {label}: {signup_status}")
            # 2) Log in to capture the managed token.
            login_url = _provision_same_origin_url(target_url, login.get("path"))
            login_body = _render_provision_template(login.get("json") or {}, variables)
            login_status, login_payload = await bounded_request(client, login_url, login_body)
            token = _provision_json_path(login_payload, token_path) if 200 <= login_status < 300 else None
            if not token:
                raise HTTPException(status_code=502, detail=f"login returned no token for {label} (status {login_status})")
            secret = _render_provision_template(header_format, {"token": str(token)})
            # Capture stable object refs from the login response (e.g. a basket id) so a read-existing
            # BOLA can target an object the owner already holds when there is no list endpoint.
            captured: dict[str, str] = {}
            capture_config = login.get("capture") if isinstance(login.get("capture"), dict) else {}
            for cap_name, cap_path in capture_config.items():
                if is_sensitive_key(str(cap_name)):
                    logger.warning("ignored sensitive captured ref name %s for %s", cap_name, label)
                    continue
                cap_value = _provision_json_path(login_payload, str(cap_path))
                if cap_value is not None:
                    captured[str(cap_name)[:60]] = str(cap_value)[:120]
            profile_name = f"auto-{label}"
            values = _target_credential_profile_values(
                name=profile_name, auth_kind=auth_kind, secret=secret, expires_at=None,
                metadata_json={
                    "auto_provisioned": True, "source": "self_registration",
                    "principal_identity": variables["email"],
                },
            )
            await conn.execute(
                """
                INSERT INTO target_credential_profiles (
                    target_id, name, auth_kind, secret_value, secret_preview, expires_at, metadata_json, rotated_at
                ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,NOW())
                ON CONFLICT (target_id, lower(name)) DO UPDATE SET
                    auth_kind=EXCLUDED.auth_kind, secret_value=EXCLUDED.secret_value,
                    secret_preview=EXCLUDED.secret_preview, is_active=true,
                    metadata_json=target_credential_profiles.metadata_json || EXCLUDED.metadata_json,
                    rotated_at=NOW(), updated_at=NOW()
                """,
                target_uuid, values["name"], values["auth_kind"], values["secret_value"],
                values["secret_preview"], values["expires_at"], json.dumps(values["metadata_json"]),
            )
            await conn.execute(
                """
                INSERT INTO target_principals (
                    target_id, label, role, tenant_id, auth_state, credential_profile, is_active, metadata_json
                ) VALUES ($1,$2,'user',NULL,$3,$4,true,$5::jsonb)
                ON CONFLICT (target_id, lower(label), COALESCE(tenant_id, ''), COALESCE(auth_state, ''))
                DO UPDATE SET credential_profile=EXCLUDED.credential_profile, is_active=true,
                    metadata_json=target_principals.metadata_json || EXCLUDED.metadata_json, updated_at=NOW()
                """,
                target_uuid, label, auth_state, profile_name,
                json.dumps({"auto_provisioned": True, "principal_identity": variables["email"], "captured_refs": captured}),
            )
            try:
                await sync_legacy_web_credential_by_name(
                    conn, target_id=target_uuid, profile_name=profile_name,
                )
            except (LegacyCredentialMigrationError, CredentialStoreError) as exc:
                raise _legacy_credential_migration_http_error(exc) from exc
            await conn.execute(
                """
                UPDATE target_principal_provisioning_attempts
                SET status='completed', last_error=NULL, updated_at=NOW()
                WHERE target_id=$1 AND auth_state=$2
                """,
                target_uuid, auth_state,
            )
            # Optional object creation is POST-only, same-origin and response-capped.  It runs after
            # the principal is durable, so retries cannot duplicate seeds after a partial failure.
            seed_header = {"Authorization": secret} if auth_kind == "authorization_header" else {"Cookie": secret}
            for seed_request in (config.get("seed_requests") or [])[:4]:
                if not isinstance(seed_request, dict):
                    continue
                method = str(seed_request.get("method") or "POST").upper()
                if method != "POST":
                    logger.warning("ignored non-POST seed request for %s on target %s", label, target_uuid)
                    continue
                try:
                    seed_url = _provision_same_origin_url(target_url, seed_request.get("path"))
                    seed_body = _render_provision_template(seed_request.get("json") or {}, variables)
                    seed_status, _ = await bounded_request(
                        client, seed_url, seed_body, method="POST", headers=seed_header,
                    )
                    if not 200 <= seed_status < 300:
                        logger.warning("seed request returned %s for %s on target %s", seed_status, label, target_uuid)
                except Exception:  # noqa: BLE001 - seeding is optional and must not revoke valid auth
                    logger.warning("seed request failed for %s on target %s", label, target_uuid, exc_info=True)
            provisioned.append({"label": label, "auth_state": auth_state, "credential_profile": profile_name, "reused": False})
    return provisioned


def _invariant_hypothesis_request(
    target_id: str,
    contract: dict[str, Any],
    *,
    created_by: str | None,
) -> HypothesisRequest:
    plan = invariant_contracts.verification_plan(contract)
    contract_id = str(contract.get("id") or "")
    kind = str(contract.get("contract_kind") or "invariant")
    family = str(plan.get("proof_family") or f"invariant_{kind}")
    route = contract.get("path")
    method = contract.get("method") or "GET"
    supported = bool(plan.get("deterministic_family_supported")) and contract.get("status") == "approved"
    return HypothesisRequest(
        target_id=target_id,
        source="invariant",
        family=family,
        cwe={
            "bola": "CWE-639",
            "access_control": "CWE-285",
            "field_constraint": "CWE-840",
            "workflow": "CWE-841",
        }.get(family),
        # Use a synthetic, typed label -- never the operator's free-text title -- so untyped
        # prose cannot re-enter the planner via the hypothesis summary. planner_projection
        # deliberately strips the contract title for the same reason.
        title=f"Invariant lead: {kind} on {route or contract.get('resource') or 'target'}",
        description=(
            "An operator-approved typed invariant identifies a security property to test. "
            "It is planning evidence only; a supported deterministic live verifier and independent "
            "replay are required before finding promotion."
        ),
        severity_guess="high" if family == "bola" else "medium",
        confidence=0.7,
        dedupe_key=f"target_invariant|{contract_id}|{contract.get('version') or contract.get('contract_version')}",
        dedupe_dimensions={
            "invariant_contract_id": contract_id,
            "contract_kind": kind,
            "method": method,
            "route": route,
            "proof_surface": "approved_target_invariant",
        },
        next_test_action={
            # A typed invariant cannot safely manufacture concrete workflow steps, object ids,
            # or restoration assertions. Point the backlog at the executable read-only planning
            # command; the planner can then bind the returned verifier requirements to live routes
            # and principals before proposing experiment.workflow.
            "command": "target.invariant.verification_plan",
            "parameters": {"target_id": target_id, "contract_id": contract_id},
            "requires": plan.get("missing_inputs") or plan.get("required_inputs") or [],
            "execution_ready": False,
            "recommended_verifier": plan.get("verifier") if supported else None,
            "recommended_proof_family": family if supported else None,
        },
        endorsement={"source": "approved_target_invariant", "contract_id": contract_id},
        metadata_json={
            "invariant_contract_id": contract_id,
            "contract_kind": kind,
            "verification_plan": plan,
            "invariant_contract": invariant_contracts.planner_projection(contract),
            "unexplained_residue": True,
            "residue_source": "approved_target_invariant",
            "requires_auth": kind in {"ownership", "access_control"},
            "route": route,
            "operator_policy_only": True,
            "promotion_authority": False,
        },
        created_by=created_by,
    )


def _graph_row_payload(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    payload["attributes"] = _decode_json_value(payload.get("attributes")) or {}
    return payload


def _application_graph_hypothesis_requests(
    target_id: str,
    nodes: list[Any],
    edges: list[Any],
    *,
    principal_rows: list[Any] | None = None,
    expectation_rows: list[Any] | None = None,
    created_by: str | None = None,
) -> list[HypothesisRequest]:
    """Build app-graph authz hypotheses from persisted graph facts.

    The graph is a signal source only. These requests become hypotheses/leads,
    never findings, and their next_test_action is an operator/agent suggestion
    through existing Command Arsenal commands.
    """
    node_by_key: dict[str, dict[str, Any]] = {}
    for row in nodes:
        payload = _graph_row_payload(row)
        if payload.get("node_key"):
            node_by_key[str(payload.get("node_key"))] = payload
    edge_rows = [_graph_row_payload(row) for row in edges]
    produced_by_route: dict[str, list[str]] = {}
    consumed_by_route: dict[str, list[str]] = {}
    for edge in edge_rows:
        edge_type = str(edge.get("edge_type") or "")
        if edge_type == "produces":
            produced_by_route.setdefault(str(edge.get("src_key")), []).append(str(edge.get("dst_key")))
        elif edge_type == "consumed_by":
            consumed_by_route.setdefault(str(edge.get("dst_key")), []).append(str(edge.get("src_key")))

    candidates: list[HypothesisRequest] = []
    seen: set[str] = set()
    for edge in edge_rows:
        if str(edge.get("edge_type") or "") != "auth_boundary":
            continue
        producer_key = str(edge.get("src_key") or "")
        consumer_key = str(edge.get("dst_key") or "")
        if not producer_key or not consumer_key:
            continue
        attrs = edge.get("attributes") if isinstance(edge.get("attributes"), dict) else {}
        object_id_key = str(attrs.get("object_id_key") or "").strip()
        object_key = f"object:{object_id_key}" if object_id_key else ""
        if not object_key or object_key not in node_by_key:
            shared = [
                key for key in produced_by_route.get(producer_key, [])
                if key in set(consumed_by_route.get(consumer_key, []))
            ]
            object_key = shared[0] if shared else object_key
        object_node = node_by_key.get(object_key)
        producer_node = node_by_key.get(producer_key)
        consumer_node = node_by_key.get(consumer_key)
        producer_label = _graph_route_label(producer_node, producer_key)
        consumer_label = _graph_route_label(consumer_node, consumer_key)
        object_label = _graph_object_label(object_node, object_key or object_id_key or "object_id")
        sensitive = attrs.get("sensitive_fields")
        if not isinstance(sensitive, list):
            sensitive = []
        source_principal = attrs.get("source_principal")
        excluded_principal = attrs.get("excluded_principal") or attrs.get("excluded_from_principal")
        family = "bola" if object_key or object_id_key else "bfla"
        principal_part = f"{source_principal or 'source'}->{excluded_principal or 'other'}"
        dedupe_key = "|".join([
            "app_graph_authz",
            family,
            producer_key,
            object_key or object_id_key or "object",
            consumer_key,
            principal_part,
        ])
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        confidence = 0.72
        if source_principal and excluded_principal:
            confidence += 0.08
        if sensitive:
            confidence += 0.08
        confidence = min(confidence, 0.9)
        severity = "high" if sensitive or excluded_principal else "medium"
        consumer_parts = consumer_label.split(" ", 1)
        method = consumer_parts[0] if len(consumer_parts) == 2 else None
        route = consumer_parts[1] if len(consumer_parts) == 2 else consumer_label
        principal_context = _principal_matrix_context_for_graph_hypothesis(
            method=method,
            route=route,
            source_principal=source_principal,
            excluded_principal=excluded_principal,
            principal_rows=principal_rows,
            expectation_rows=expectation_rows,
        )
        candidates.append(HypothesisRequest(
            target_id=target_id,
            source="app_graph",
            family=family,
            cwe="CWE-639" if family == "bola" else "CWE-862",
            title=f"Graph authz lead: {consumer_label} consumes {object_label}",
            description=(
                f"{producer_label} appears to produce {object_label}; {consumer_label} appears to consume it. "
                "Record a two-principal authorization hypothesis before running proof-backed tests."
            ),
            severity_guess=severity,
            confidence=confidence,
            dedupe_key=dedupe_key,
            dedupe_dimensions={
                "method": method,
                "route": route,
                "object_key": object_key or object_id_key or object_label,
                "principal_actor": source_principal,
                "principal_other": excluded_principal,
                "proof_surface": "runtime_authz_replay",
            },
            next_test_action={
                "command": "asm.improve",
                "parameters": {
                    "target_id": target_id,
                    "check_family": "bola" if family == "bola" else "auth",
                    "exploit_depth": family == "bola",
                },
                "requires": ["primary_auth", "second_user_auth"] if family == "bola" else ["primary_auth"],
                "principal_matrix": principal_context,
            },
            endorsement={
                "source": "app_graph",
                "producer_route": producer_label,
                "consumer_route": consumer_label,
                "object": object_label,
                "source_principal": source_principal,
                "excluded_principal": excluded_principal,
                "sensitive_fields": sensitive[:25],
                "principal_matrix": principal_context,
            },
            metadata_json={
                "producer_key": producer_key,
                "consumer_key": consumer_key,
                "object_key": object_key or None,
                "edge_id": str(edge.get("id")) if edge.get("id") else None,
                "edge_type": "auth_boundary",
                "dedupe_dimensions": {
                    "method": method,
                    "route": route,
                    "object_key": object_key or object_id_key or object_label,
                    "principal_actor": source_principal,
                    "principal_other": excluded_principal,
                    "proof_surface": "runtime_authz_replay",
                },
                "source_principal": source_principal,
                "excluded_principal": excluded_principal,
                "sensitive_fields": sensitive[:25],
                "principal_matrix": principal_context,
            },
            created_by=created_by or "app_graph",
        ))
        # Sensitive field names on a cross-principal boundary are a lead producer, never proof.
        # The live data-exposure workflow still has to observe a high-precision sensitive VALUE on
        # a server-trusted protected/denied route before family promotion can occur.
        if sensitive and (excluded_principal or principal_context.get("matching_expectations")):
            exposure_key = "|".join([
                "app_graph_data_exposure",
                consumer_key,
                principal_part,
                ",".join(sorted(str(field).lower() for field in sensitive[:25])),
            ])
            if exposure_key not in seen:
                seen.add(exposure_key)
                candidates.append(HypothesisRequest(
                    target_id=target_id,
                    source="app_graph",
                    family="data_exposure",
                    cwe="CWE-200",
                    title=f"Sensitive-value exposure lead: {consumer_label}",
                    description=(
                        f"The application graph associated sensitive fields with {consumer_label} "
                        "across an authorization boundary. Re-read it as the excluded principal and "
                        "require a live server-classified sensitive value before promotion."
                    ),
                    severity_guess="high",
                    confidence=min(confidence, 0.82),
                    dedupe_key=exposure_key,
                    dedupe_dimensions={
                        "method": method,
                        "route": route,
                        "principal_actor": source_principal,
                        "principal_other": excluded_principal,
                        "proof_surface": "sensitive_value_boundary",
                    },
                    next_test_action={
                        "command": "experiment.workflow",
                        "parameters": {"proof_family": "data_exposure"},
                        "requires": ["primary_auth"] if source_principal else [],
                        "principal_matrix": principal_context,
                    },
                    endorsement={
                        "source": "app_graph",
                        "consumer_route": consumer_label,
                        "sensitive_fields": sensitive[:25],
                        "source_principal": source_principal,
                        "excluded_principal": excluded_principal,
                    },
                    metadata_json={
                        "unexplained_residue": True,
                        "residue_source": "app_graph_sensitive_boundary",
                        "consumer_key": consumer_key,
                        "edge_id": str(edge.get("id")) if edge.get("id") else None,
                        "route": route,
                        "method": method,
                        "sensitive_fields": sensitive[:25],
                        "source_principal": source_principal,
                        "excluded_principal": excluded_principal,
                        "principal_matrix": principal_context,
                    },
                    created_by=created_by or "app_graph",
                ))
    return candidates


class AsmTestRequest(BaseModel):
    batch_size: int = Field(default=100, ge=1, le=1000)
    stale_days: int = Field(default=30, ge=0)
    exploit_depth: bool = False
    check_family: Optional[str] = None
    endpoint_filter: Optional[str] = None
    approval_receipt_id: Optional[str] = None

    @field_validator("check_family")
    @classmethod
    def validate_check_family(cls, value):
        return _validate_asm_check_family_value(value)

    @field_validator("endpoint_filter")
    @classmethod
    def validate_endpoint_filter(cls, value):
        return _validate_asm_endpoint_filter_value(value)


class AsmReconRequest(BaseModel):
    budget_profile: Optional[str] = None
    approval_receipt_id: Optional[str] = None


class AsmImproveRequest(BaseModel):
    batch_size: Optional[int] = Field(default=None, ge=1, le=1000)
    stale_days: Optional[int] = Field(default=None, ge=0)
    exploit_depth: Optional[bool] = None
    check_family: Optional[str] = None
    endpoint_filter: Optional[str] = None
    approval_receipt_id: Optional[str] = None

    @field_validator("check_family")
    @classmethod
    def validate_check_family(cls, value):
        return _validate_asm_check_family_value(value)

    @field_validator("endpoint_filter")
    @classmethod
    def validate_endpoint_filter(cls, value):
        return _validate_asm_endpoint_filter_value(value)


class AsmPolicyUpdate(BaseModel):
    """Per-target Continuous ASM policy (docs §16 Phase 3/4)."""
    enabled: Optional[bool] = None
    config: Optional[dict] = None


def _decode_target_scan_options(raw) -> dict:
    decoded = _decode_json_value(raw) or {}
    return decoded if isinstance(decoded, dict) else {}


async def _asm_active_scan_ids(conn, target_id: str) -> list[str]:
    """IDs of the active scans blocking ASM actions on this target.

    The blocking scan is usually a Continuous-ASM batch/recon row, which is hidden
    from the /scans list by default — so callers surface the id here, letting the
    UI link the otherwise-invisible "a scan is already active" scan.
    """
    rows = await conn.fetch(
        """
        SELECT id FROM scans
        WHERE target_id = $1 AND status IN ('pending', 'queued', 'running')
        ORDER BY started_at DESC NULLS LAST
        """,
        uuid.UUID(target_id),
    )
    return [str(r["id"]) for r in rows]


async def _asm_scheduler_state(
    conn,
    r,
    target_id: str,
    *,
    endpoint_filter: str | None = None,
    stale_days: int | None = None,
) -> dict[str, Any]:
    target = await conn.fetchrow(
        """
        SELECT id, url, root_domain, asm_config, asm_last_test_at, asm_last_recon_at,
               metadata_json
        FROM targets
        WHERE id = $1
        """,
        uuid.UUID(target_id),
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    cfg = asm_inventory.merge_asm_config(_decode_asm_config(target["asm_config"]))
    effective_stale_days = stale_days if stale_days is not None else cfg["stale_days"]
    active_scan_ids = await _asm_active_scan_ids(conn, target_id)
    claimable = await asm_inventory.claimable_count(
        conn,
        target_id,
        stale_days=effective_stale_days,
        endpoint_filter=endpoint_filter,
    )
    tested_today = await asm_inventory.tested_recently_count(conn, target_id, hours=24)
    root_domain = target["root_domain"]
    domain_rate_cap = int(cfg["max_requests_per_hour_per_domain"] or 0)
    domain_rate_used = 0
    domain_rate_reserved = 0
    domain_rate_remaining: int | None = None
    if domain_rate_cap > 0 and root_domain:
        domain_rate_used = await asm_inventory.domain_tested_recently_count(conn, root_domain, hours=1)
        domain_rate_reserved = _asm_reserved_count(r, root_domain)
        domain_rate_remaining = max(0, domain_rate_cap - domain_rate_used - domain_rate_reserved)
    decision = asm_inventory.decide_asm_action(
        now=utc_now(),
        last_test_at=target["asm_last_test_at"],
        last_recon_at=target["asm_last_recon_at"],
        has_active_scan=bool(active_scan_ids),
        claimable=claimable,
        tested_today=tested_today,
        domain_rate_exceeded=domain_rate_remaining == 0 if domain_rate_remaining is not None else False,
        domain_rate_remaining=domain_rate_remaining,
        config=cfg,
    )
    public_decision = _public_asm_decision(decision) or {}
    if active_scan_ids:
        public_decision["active_scan_id"] = active_scan_ids[0]
        public_decision["active_scan_ids"] = active_scan_ids
    metadata = _decode_json_value(target["metadata_json"]) or {}
    persisted = metadata.get("asm_last_decision") if isinstance(metadata, dict) else None
    return {
        "decision": public_decision,
        "last_decision": persisted if isinstance(persisted, dict) else None,
        "active_scan_ids": active_scan_ids,
        "claimable": claimable,
        "tested_today": tested_today,
        "daily_cap_remaining": public_decision.get("daily_cap_remaining"),
        "rate_cap_remaining": public_decision.get("rate_cap_remaining"),
        "domain_rate_cap": domain_rate_cap,
        "domain_rate_used": domain_rate_used,
        "domain_rate_reserved": domain_rate_reserved,
    }


def _asm_recommended_campaigns(
    *,
    coverage: dict[str, Any],
    family_coverage: dict[str, Any] | None = None,
    by_auth: dict[str, Any] | None = None,
    last_attempt_counts: dict[str, int] | None = None,
    active_scans: int = 0,
) -> list[dict[str, Any]]:
    """§7: prioritized next-campaign suggestions for UI/AI.

    Maps current coverage/family/blocker state to concrete campaign types:
    recon, add_credentials, sqli_wave, xss_wave, bola_wave, retest_stale, test.
    Family waves are suggested when no PROOF-quality (completed) attempt exists for
    that family — endpoint-attempted is not family-proved.
    """
    attempts = last_attempt_counts or {}
    fams = family_coverage or {}
    total = int(coverage.get("total") or 0)
    untested = int(coverage.get("untested") or 0)
    stale = int(coverage.get("stale") or 0)
    auth_missing = int(attempts.get("auth_missing") or 0) + int(attempts.get("auth_failed") or 0)

    if active_scans > 0:
        return [{"campaign": "wait", "label": "Wait for current work",
                 "reason": "A scan is already active for this target.", "priority": "low"}]
    if total == 0:
        return [{"campaign": "recon", "label": "Discover endpoints",
                 "reason": "No persistent endpoint inventory exists yet.", "priority": "high"}]

    recs: list[dict[str, Any]] = []
    if auth_missing > 0:
        recs.append({"campaign": "add_credentials", "label": "Add credentials",
                     "reason": f"{auth_missing} endpoints need auth to replay.", "priority": "high"})

    def _completed(fam: str) -> int:
        return int((fams.get(fam) or {}).get("completed") or 0)

    # Recommend a family wave whenever THAT family has no proof-quality (completed)
    # attempt — generic 'all' endpoint coverage is NOT family proof, so it must not
    # suppress focused waves (a 'all' pass touching an endpoint doesn't prove SQLi/
    # XSS/BOLA on it).
    for fam, label, prio in (("sqli", "Run SQLi wave", "high"),
                             ("xss", "Run XSS wave", "medium"),
                             ("bola", "Run BOLA wave (needs 2 users + Lab/deep)", "medium")):
        if _completed(fam) == 0:
            recs.append({"campaign": f"{fam}_wave", "label": label,
                         "reason": f"No proof-quality {fam.upper()} attempt recorded yet "
                                   f"(generic endpoint coverage is not {fam.upper()} proof).",
                         "priority": prio})
    if stale > 0:
        recs.append({"campaign": "retest_stale", "label": "Retest stale endpoints",
                     "reason": f"{stale} endpoints are stale and may have changed.", "priority": "medium"})
    if untested > 0 and not any(r["campaign"].endswith("_wave") for r in recs):
        recs.append({"campaign": "test", "label": "Test untested endpoints",
                     "reason": f"{untested} endpoints have never been tested.", "priority": "medium"})
    if not recs:
        recs.append({"campaign": "recon", "label": "Refresh discovery",
                     "reason": "Inventory looks covered; refresh to catch new surface.", "priority": "low"})
    return recs


def _asm_recommendation(
    coverage: dict[str, Any],
    *,
    claimable: int = 0,
    active_scans: int = 0,
    active_scan_ids: list[str] | None = None,
    last_attempt_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Small, stable decision model for UI/API/AI callers.

    This intentionally exposes one recommended next action instead of every
    allocator knob. It is conservative: active scan first, then empty inventory
    recon, then claimable endpoint testing, then recon refresh.
    """
    attempts = last_attempt_counts or {}
    total = int(coverage.get("total") or 0)
    untested = int(coverage.get("untested") or 0)
    stale = int(coverage.get("stale") or 0)
    in_progress = int(coverage.get("in_progress") or 0)
    auth_missing = int(attempts.get("auth_missing") or attempts.get("auth_failed") or 0)
    partial = sum(v for k, v in attempts.items() if str(k or "").startswith("partial"))

    blockers: list[dict[str, Any]] = []
    if active_scans > 0:
        # Surface the active scan id(s) so the UI can link the otherwise-hidden
        # ASM batch/recon scan instead of leaving the user with "active (1)" and
        # nothing to click.
        active_blocker: dict[str, Any] = {
            "kind": "active_scan",
            "count": active_scans,
            "message": "A scan is already active for this target.",
        }
        if active_scan_ids:
            active_blocker["scan_id"] = active_scan_ids[0]
            active_blocker["scan_ids"] = active_scan_ids
        blockers.append(active_blocker)
    if auth_missing > 0:
        blockers.append({"kind": "auth_missing", "count": auth_missing, "message": "Some authenticated endpoints need credentials before they can be replayed."})
    if partial > 0:
        blockers.append({"kind": "partial", "count": partial, "message": "Some endpoints have partial attempts and need another pass."})

    if active_scans > 0:
        return {
            "next_action": "wait",
            "label": "Wait for current work",
            "reason": "A scan is already queued or running for this target.",
            "blockers": blockers,
        }
    if total == 0:
        return {
            "next_action": "recon",
            "label": "Discover endpoints",
            "reason": "No persistent endpoint inventory exists yet.",
            "blockers": blockers,
        }
    if claimable > 0 or untested > 0 or stale > 0:
        return {
            "next_action": "test",
            "label": "Test next endpoint batch",
            "reason": f"{max(claimable, untested + stale)} endpoint(s) are untested or stale.",
            "blockers": blockers,
        }
    if in_progress > 0:
        return {
            "next_action": "wait",
            "label": "Wait for current batch",
            "reason": f"{in_progress} endpoint(s) are currently being tested.",
            "blockers": blockers,
        }
    return {
        "next_action": "recon",
        "label": "Refresh discovery",
        "reason": "Current inventory has no claimable endpoints; refresh discovery to find new surface.",
        "blockers": blockers,
    }


def _build_asm_campaign_timeline(
    *,
    scheduler_state: dict[str, Any] | None,
    activity: list[dict[str, Any]],
    next_schedule: dict[str, Any] | None = None,
    active_scans: list[dict[str, Any]] | None = None,
    target_id: str | None = None,
    target_url: str | None = None,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Derived operator timeline for one target's Continuous ASM state.

    This intentionally merges scheduler, recurring schedule, active scan, and
    recent implementation-scan facts without creating another persistence
    model. The order answers "what is happening now, what runs next, why did it
    wait, and what just happened?"
    """
    events: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def remediation(
        *,
        status: Any = None,
        scan_id: str | None = None,
        blocked_by: Any = None,
    ) -> dict[str, Any] | None:
        normalized_status = str(status or "").strip().lower()
        blocker = str(blocked_by or "").strip().lower()
        if scan_id:
            return {
                "kind": "open_scan",
                "label": "Review failed scan" if normalized_status == "failed" else "View scan",
                "href": f"/scans/{scan_id}",
            }
        if any(token in blocker for token in ("auth_missing", "auth_failed", "second_user", "principal")):
            params = []
            if target_url:
                params.append(f"target={urllib.parse.quote(str(target_url), safe='')}")
            if target_id:
                params.append(f"target_id={urllib.parse.quote(str(target_id), safe='')}")
            suffix = f"?{'&'.join(params)}" if params else ""
            return {
                "kind": "configure_auth",
                "label": "Configure target credentials",
                "href": f"/credentials{suffix}",
            }
        if "worker_stale" in blocker or "stale_worker" in blocker:
            return {"kind": "workers", "label": "Review workers", "href": "/#workers"}
        policy_or_rate_blocker = (
            ("daily" in blocker and "cap" in blocker)
            or ("rate" in blocker and "cap" in blocker)
            or "schedule" in blocker
            or "policy_window" in blocker
        )
        if policy_or_rate_blocker:
            suffix = f"?create=true&target_id={target_id}" if target_id else ""
            return {"kind": "schedule", "label": "Adjust schedule", "href": f"/schedules{suffix}"}
        if blocker:
            return {"kind": "review_coverage", "label": "Review coverage", "href": f"/asm?target_id={target_id}" if target_id else "/asm"}
        return {"kind": "improve", "label": "Improve coverage"}

    def add(event: dict[str, Any]) -> None:
        key = (str(event.get("kind") or ""), str(event.get("id") or event.get("scan_id") or event.get("timestamp") or event.get("title") or ""))
        if key in seen:
            return
        seen.add(key)
        events.append({k: v for k, v in event.items() if v is not None})

    for row in active_scans or []:
        scan_id = str(row.get("id") or "")
        if not scan_id:
            continue
        label = _scan_role_label(row.get("scan_role"))
        add({
            "id": f"active-{scan_id}",
            "kind": "active_scan",
            "title": f"Active {label.lower()}",
            "status": row.get("status"),
            "detail": row.get("current_phase") or "This target already has queued/running work.",
            "timestamp": _event_time(row.get("started_at") or row.get("created_at")),
            "scan_id": scan_id,
            "campaign_id": str(row.get("campaign_id")) if row.get("campaign_id") else None,
            "href": f"/scans/{scan_id}",
            "remediation": remediation(status=row.get("status"), scan_id=scan_id),
        })

    decision = (scheduler_state or {}).get("decision") if isinstance(scheduler_state, dict) else None
    if isinstance(decision, dict):
        action = str(decision.get("action") or "none")
        blocked_by = decision.get("blocked_by")
        add({
            "id": "scheduler-live",
            "kind": "scheduler_decision",
            "title": f"Scheduler decision: {action}",
            "status": str(blocked_by or action),
            "detail": decision.get("reason") or "No scheduler reason was returned.",
            "timestamp": _event_time(decision.get("recorded_at")),
            "remediation": remediation(
                blocked_by=blocked_by,
                scan_id=str(decision.get("active_scan_id")) if decision.get("active_scan_id") else None,
            ),
        })
        if decision.get("next_eligible_at"):
            add({
                "id": "next-eligible",
                "kind": "next_eligible",
                "title": "Next eligible time",
                "status": "waiting",
                "detail": "Continuous ASM can try again after this policy window or rate limit clears.",
                "timestamp": _event_time(decision.get("next_eligible_at")),
            })

    if next_schedule:
        schedule_id = str(next_schedule.get("id") or "")
        frequency = next_schedule.get("frequency") or "scheduled"
        time_of_day = next_schedule.get("time_of_day") or ""
        add({
            "id": f"schedule-{schedule_id}" if schedule_id else "schedule-next",
            "kind": "scheduled_wave",
            "title": "Next recurring ASM coverage wave",
            "status": "scheduled",
            "detail": f"{frequency} at {time_of_day} UTC".strip(),
            "timestamp": _event_time(next_schedule.get("next_run_at")),
            "schedule_id": schedule_id or None,
            "href": "/schedules",
            "remediation": {"kind": "schedule", "label": "Manage schedule", "href": "/schedules"},
        })

    last_decision = (scheduler_state or {}).get("last_decision") if isinstance(scheduler_state, dict) else None
    if isinstance(last_decision, dict):
        add({
            "id": "scheduler-last",
            "kind": "last_scheduler_decision",
            "title": "Last recorded scheduler decision",
            "status": str(last_decision.get("blocked_by") or last_decision.get("action") or "recorded"),
            "detail": last_decision.get("reason") or "Recorded by dispatcher/schedule.",
            "timestamp": _event_time(last_decision.get("recorded_at")),
            "scan_id": str(last_decision.get("active_scan_id")) if last_decision.get("active_scan_id") else None,
            "href": f"/scans/{last_decision.get('active_scan_id')}" if last_decision.get("active_scan_id") else None,
            "remediation": remediation(
                blocked_by=last_decision.get("blocked_by"),
                scan_id=str(last_decision.get("active_scan_id")) if last_decision.get("active_scan_id") else None,
            ),
        })

    for row in activity:
        scan_id = str(row.get("id") or "")
        label = _scan_role_label(row.get("scan_role"))
        attempts = row.get("attempt_status_counts") if isinstance(row.get("attempt_status_counts"), dict) else {}
        completed = attempts.get("completed") if attempts else None
        detail_bits = []
        if row.get("campaign_requested_by"):
            detail_bits.append(f"triggered by {row['campaign_requested_by']}")
        if completed is not None:
            detail_bits.append(f"{completed} completed attempt(s)")
        if row.get("error_message"):
            detail_bits.append(str(row["error_message"]))
        add({
            "id": f"activity-{scan_id}",
            "kind": "activity",
            "title": label,
            "status": row.get("status"),
            "detail": "; ".join(detail_bits) or row.get("current_phase") or "Recent ASM implementation scan.",
            "timestamp": _event_time(row.get("completed_at") or row.get("started_at") or row.get("created_at")),
            "scan_id": scan_id,
            "campaign_id": str(row.get("campaign_id")) if row.get("campaign_id") else None,
            "href": f"/scans/{scan_id}" if scan_id else None,
            "remediation": remediation(status=row.get("status"), scan_id=scan_id or None),
        })

    return events[: max(1, int(limit or 12))]


async def _enqueue_asm_exploit_batch(
    conn, r, target_id: str, target_url: str, base_opts: dict,
    *, batch_size: int, stale_days: int, exploit_depth: bool,
    check_family: str | None = None,
    endpoint_filter: str | None = None,
    triggered_by: str = "api",
    domain_rate_reserved: int = 0,
) -> dict:
    """Create an asm_batch scan row and enqueue the exploit_batch job. Shared by
    POST /asm/test and the continuous dispatcher."""
    scan_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    family = _normalize_asm_check_family(check_family)
    opts = _apply_asm_check_family(base_opts or {}, family)
    opts, scan_contract = await _canonical_asm_scan_options(
        target_id=target_id,
        target_url=target_url,
        base_options=opts,
        check_family=family,
    )
    opts["run_kind"] = "asm_batch"
    endpoint_filter = _validate_asm_endpoint_filter_value(endpoint_filter)
    _enforce_asm_family_preconditions(family, opts, exploit_depth=exploit_depth)
    if endpoint_filter:
        opts["asm_endpoint_filter"] = endpoint_filter
    research_correlation = _current_research_dispatch_correlation()
    campaign_id = await asm_inventory.create_campaign(
        conn,
        target_id,
        mode=asm_inventory.CAMPAIGN_FOCUSED_FAMILY if family else asm_inventory.CAMPAIGN_CONTINUOUS_ASM,
        requested_by=triggered_by,
        budget_profile=opts.get("budget_profile"),
        wide_budget={"batch_size": batch_size, "stale_days": stale_days, "endpoint_filter": endpoint_filter},
        deep_budget={"exploit_depth": exploit_depth},
        check_families=[family] if family else ["all"],
        auth_states=[],
        metadata_json={
            "scan_role": asm_inventory.ASM_BATCH_ROLE,
            "endpoint_filter": endpoint_filter,
            **(
                {_RESEARCH_DISPATCH_CORRELATION_KEY: research_correlation}
                if research_correlation else {}
            ),
        },
    )
    claimed = await asm_inventory.claim_test_batch(
        conn,
        target_id,
        limit=batch_size,
        stale_days=stale_days,
        lease_owner=job_id,
        campaign_id=campaign_id,
        campaign_only=False,
        check_family=family,
        endpoint_filter=endpoint_filter,
        auth_state=opts.get("auth_state"),
    )
    claimed_ids = [str(item["id"]) for item in claimed]
    opts.update({
        "custom_endpoints": [
            asm_inventory.to_custom_endpoint(
                item["method"], item["path"], item["param_shape"],
                param_location=item.get("param_location") or "query",
                replay_spec=item.get("replay_spec"),
            )
            for item in claimed
        ],
        "focused_endpoints_only": True,
        "zero_rediscovery": True,
    })
    if claimed:
        opts["auth_state"] = asm_inventory.normalize_auth_state(
            claimed[0].get("auth_state")
        )
    try:
        authority = _compile_asm_scan_authority(
            scan_id=scan_id,
            job_id=job_id,
            target_url=target_url,
            options=opts,
            scan_contract=scan_contract,
        )
        persisted_opts = {**opts, _QUEUE_HANDOFF_CONFIRMATION_KEY: False}
        if research_correlation:
            # This is committed with the scan row before Redis handoff. It lets crash
            # recovery and operator cancellation find work even if the API process
            # dies before the later command_result receipt is written.
            persisted_opts[_RESEARCH_DISPATCH_CORRELATION_KEY] = research_correlation
        canonical_job = authority["job"]
        async with conn.transaction():
            await conn.execute(
                """INSERT INTO scans (
                       id, target_id, target_url, job_id, status, options, scan_type,
                       scan_role, campaign_id, scan_generation, policy_json, budget_json,
                       coverage_status, coverage_json, scan_job_payload, scan_job_digest
                   ) VALUES (
                       $1, $2, $3, $4, 'pending', $5, $6, $7, $8,
                       'v2', $9, $10, 'pending', $11, $12, $13
                   )""",
                uuid.UUID(scan_id), uuid.UUID(target_id), target_url, job_id,
                json.dumps(persisted_opts), "scan",
                asm_inventory.ASM_BATCH_ROLE, uuid.UUID(campaign_id),
                json.dumps(scan_contract.execution_plan.canonical_dict()["policy"]),
                json.dumps(scan_contract.execution_plan.canonical_dict()["budget"]),
                json.dumps({"status": "pending", "reasons": []}),
                json.dumps(canonical_job.payload()), canonical_job.payload_digest,
            )
            await _persist_asm_scan_authority(conn, authority=authority)
    except Exception:
        await asm_inventory.release_leased_test_batch(
            conn,
            claimed_ids,
            lease_owner=job_id,
            reason="admission_failed",
        )
        await asm_inventory.finish_campaign(conn, campaign_id, status="failed")
        raise
    job_payload = {
        "type": asm_inventory.EXPLOIT_BATCH_JOB_TYPE,
        "job_id": job_id, "scan_id": scan_id,
        "target_id": target_id, "target": target_url,
        "batch_size": batch_size, "stale_days": stale_days, "exploit_depth": exploit_depth,
        "campaign_id": campaign_id,
        "check_family": family,
        "endpoint_filter": endpoint_filter,
        "domain_rate_reserved": max(0, int(domain_rate_reserved or 0)),
        "claimed_endpoint_ids": claimed_ids,
        "scan_job": canonical_job.queue_payload(),
        "triggered_by": triggered_by,
        **(
            {_RESEARCH_DISPATCH_CORRELATION_KEY: research_correlation}
            if research_correlation else {}
        ),
        "submitted_at": utc_now_iso(),
    }
    try:
        enqueue_job(r, QUEUE_NAME, job_payload)
    except Exception as enqueue_error:
        await asm_inventory.release_leased_test_batch(
            conn,
            claimed_ids,
            lease_owner=job_id,
            reason="queue_failed",
        )
        await _fail_asm_queue_handoff(conn, scan_id, campaign_id, enqueue_error)
        raise
    try:
        await _confirm_asm_queue_handoff(
            conn,
            scan_id=scan_id,
            job_id=job_id,
            campaign_id=campaign_id,
        )
    except Exception:
        await asm_inventory.release_leased_test_batch(
            conn,
            claimed_ids,
            lease_owner=job_id,
            reason="handoff_failed",
        )
        raise
    try:
        r.hset(f"job:{job_id}", mapping={"status": "queued", "target": target_url})
    except Exception:
        # The durable queue entry is authoritative. A metadata-cache failure must
        # not make the caller believe an already-enqueued job was rejected.
        logger.warning("Failed to cache queued ASM job metadata for %s", job_id, exc_info=True)
    return {
        "scan_id": scan_id,
        "job_id": job_id,
        "campaign_id": campaign_id,
        "claimed_count": len(claimed_ids),
    }


async def _enqueue_asm_recon(
    conn, r, target_id: str, target_url: str, base_opts: dict,
    *, triggered_by: str = "dispatcher",
) -> dict:
    """Create an asm_recon scan row and enqueue a lean standalone discovery scan
    that refreshes/grows the inventory (worklist persisted on completion)."""
    opts = dict(base_opts or {})
    opts.pop("parallel", None)  # recon is one lightweight standalone scan
    custom_budget = dict(opts.get("custom_budget") or {})
    custom_budget.update(parallel_scan.RECON_DISCOVERY_BUDGET)
    opts["custom_budget"] = custom_budget
    opts, scan_contract = await _canonical_asm_scan_options(
        target_id=target_id,
        target_url=target_url,
        base_options=opts,
        check_family="recon",
        active_testing=False,
    )
    opts["run_kind"] = "asm_recon"
    research_correlation = _current_research_dispatch_correlation()
    scan_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    authority = _compile_asm_scan_authority(
        scan_id=scan_id,
        job_id=job_id,
        target_url=target_url,
        options=opts,
        scan_contract=scan_contract,
    )
    persisted_opts = {**opts, _QUEUE_HANDOFF_CONFIRMATION_KEY: False}
    if research_correlation:
        persisted_opts[_RESEARCH_DISPATCH_CORRELATION_KEY] = research_correlation
    campaign_id = await asm_inventory.create_campaign(
        conn,
        target_id,
        mode=asm_inventory.CAMPAIGN_SURFACE_RECON,
        requested_by=triggered_by,
        budget_profile=opts.get("budget_profile"),
        wide_budget=scan_contract.execution_plan.canonical_dict()["budget"],
        check_families=["recon"],
        metadata_json={
            "scan_role": asm_inventory.ASM_RECON_ROLE,
            **(
                {_RESEARCH_DISPATCH_CORRELATION_KEY: research_correlation}
                if research_correlation else {}
            ),
        },
    )
    canonical_job = authority["job"]
    async with conn.transaction():
        await conn.execute(
            """INSERT INTO scans (
                   id, target_id, target_url, job_id, status, options, scan_type,
                   scan_role, campaign_id, scan_generation, policy_json, budget_json,
                   coverage_status, coverage_json, scan_job_payload, scan_job_digest
               ) VALUES (
                   $1, $2, $3, $4, 'pending', $5, $6, $7, $8,
                   'v2', $9, $10, 'pending', $11, $12, $13
               )""",
            uuid.UUID(scan_id), uuid.UUID(target_id), target_url, job_id,
            json.dumps(persisted_opts), "scan", asm_inventory.ASM_RECON_ROLE,
            uuid.UUID(campaign_id),
            json.dumps(scan_contract.execution_plan.canonical_dict()["policy"]),
            json.dumps(scan_contract.execution_plan.canonical_dict()["budget"]),
            json.dumps({"status": "pending", "reasons": []}),
            json.dumps(canonical_job.payload()), canonical_job.payload_digest,
        )
        await _persist_asm_scan_authority(conn, authority=authority)
    job_payload = canonical_job.queue_payload()
    try:
        enqueue_job(r, QUEUE_NAME, job_payload)
    except Exception as enqueue_error:
        await _fail_asm_queue_handoff(conn, scan_id, campaign_id, enqueue_error)
        raise
    await _confirm_asm_queue_handoff(
        conn,
        scan_id=scan_id,
        job_id=job_id,
        campaign_id=campaign_id,
    )
    try:
        r.hset(f"job:{job_id}", mapping={"status": "queued", "target": target_url})
    except Exception:
        # The durable queue entry is authoritative. A metadata-cache failure must
        # not make the caller believe an already-enqueued job was rejected.
        logger.warning("Failed to cache queued ASM job metadata for %s", job_id, exc_info=True)
    return {"scan_id": scan_id, "job_id": job_id, "campaign_id": campaign_id}


async def _auto_persist_invariant_drafts(
    conn: Any,
    target_uuid: uuid.UUID,
    *,
    expectation_rows: list[Any] | None = None,
    graph_edges: list[Any] | None = None,
    created_by: str | None = None,
) -> dict[str, int]:
    """Auto-draft typed invariant candidates from black-box facts already loaded for board seeding
    (A3): endpoint expectations -> access_control, app-graph auth_boundary edges -> ownership,
    Deep Hunt investigation candidates -> field_constraint / workflow_transition.

    A draft is a REVIEW CANDIDATE only: status='draft', source='auto_black_box', promotion_authority
    False — it can never route through the binder (the dispatch fetches status='approved' only) and
    never enters the authoritative pack section. Idempotent: a (kind, method, canonical path,
    field/role) already contracted for the target (any status) is skipped. Capped per kind per call
    so a huge inventory cannot flood the review queue. Best-effort: a failure never breaks seeding.
    """
    summary = {"candidates": 0, "created": 0, "skipped_existing": 0}
    try:
        drafts: list[dict[str, Any]] = []
        drafts.extend(invariant_proposals.propose_access_control_drafts(expectation_rows or []))
        drafts.extend(invariant_proposals.propose_ownership_drafts(graph_edges or []))
        suspected_rows = await conn.fetch(
            """
            SELECT id,
                   COALESCE(canonical_locus->>'route', verification_context->>'target_url') AS url,
                   jsonb_strip_nulls(jsonb_build_object(
                       'family', family,
                       'route', COALESCE(canonical_locus->>'route', verification_context->>'route'),
                       'method', COALESCE(canonical_locus->>'method', verification_context->>'method'),
                       'proof', verification_context->'proof'
                   )) AS evidence
            FROM investigation_candidates
            WHERE target_id=$1 AND plane='web'
              AND status IN ('new','verification_queued','verifying','inconclusive','blocked')
            ORDER BY last_seen_at DESC LIMIT 100
            """,
            target_uuid,
        )
        drafts.extend(invariant_proposals.propose_drafts_from_suspected_findings(
            [row_to_dict(row) for row in suspected_rows]))
        summary["candidates"] = len(drafts)
        if not drafts:
            return summary
        existing_rows = await conn.fetch(
            "SELECT contract_kind, method, path, field_name, subject_role FROM target_invariant_contracts "
            "WHERE target_id=$1 LIMIT 500",
            target_uuid,
        )
        existing: set[tuple[Any, ...]] = set()
        for row in existing_rows:
            kind = str(row["contract_kind"] or "")
            method = str(row["method"] or "").upper()
            path = _canonical_vulnerability_route(row["path"]) or str(row["path"] or "")
            who = str(row["field_name"] or row["subject_role"] or "")
            existing.add((kind, method, path, who))
        created_per_kind: dict[str, int] = {}
        for draft in drafts:
            kind = str(draft.get("contract_kind") or "")
            if created_per_kind.get(kind, 0) >= 25:
                continue
            method = str(draft.get("method") or "").upper()
            path = _canonical_vulnerability_route(draft.get("path")) or str(draft.get("path") or "")
            who = str(draft.get("field_name") or draft.get("subject_role") or "")
            if (kind, method, path, who) in existing:
                summary["skipped_existing"] += 1
                continue
            await conn.execute(
                """
                INSERT INTO target_invariant_contracts (
                    target_id, contract_version, contract_kind, title, source_text,
                    subject_role, action, resource, method, path, field_name, operator,
                    expected_value, expected_access, conditions, status, source,
                    metadata_json, created_by
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15::jsonb,
                    'draft','auto_black_box',$16::jsonb,$17
                )
                """,
                target_uuid,
                str(draft.get("version") or ""),
                kind,
                str(draft.get("title") or "")[:300],
                None,
                draft.get("subject_role"),
                draft.get("action"),
                draft.get("resource"),
                draft.get("method"),
                draft.get("path"),
                draft.get("field_name"),
                draft.get("operator"),
                json.dumps(draft.get("expected_value")),
                draft.get("expected_access"),
                json.dumps(draft.get("conditions") or {}),
                json.dumps({
                    "auto_proposed": True,
                    "approvable": bool(draft.get("approvable")),
                    "approval_errors": list(draft.get("approval_errors") or []),
                }),
                created_by or "invariant_auto_proposals",
            )
            existing.add((kind, method, path, who))
            created_per_kind[kind] = created_per_kind.get(kind, 0) + 1
            summary["created"] += 1
    except Exception:
        logger.exception("auto invariant draft persistence failed for target %s (best-effort)", target_uuid)
    return summary


def _endpoint_inventory_hypothesis_requests(
    target_id: str, endpoints: list[dict[str, Any]], *, created_by: str | None = None,
) -> list[HypothesisRequest]:
    """Turn discovered-but-unproven surface into residue-backed hunt leads.

    The application graph is often empty (its auth_boundary edges need a two-user resource-map
    scan), which starves a residue-only hunt board. The endpoint inventory always has surface: an
    object-id path parameter is a BOLA/IDOR lead; a write endpoint with a body is a mass-assignment
    lead. These are leads only -- never findings -- and carry unexplained_residue so the scheduler
    ranks them alongside graph leads.
    """
    requests: list[HypothesisRequest] = []
    seen: set[str] = set()
    methods_by_route: dict[str, set[str]] = {}
    for endpoint in endpoints:
        endpoint_path = str(endpoint.get("path") or "").strip()
        endpoint_route = _canonical_vulnerability_route(endpoint_path) or endpoint_path
        if endpoint_route:
            methods_by_route.setdefault(endpoint_route, set()).add(
                str(endpoint.get("method") or "GET").strip().upper()
            )
    for endpoint in endpoints:
        method = str(endpoint.get("method") or "GET").strip().upper()
        path = str(endpoint.get("path") or "").strip()
        if not path:
            continue
        route = _canonical_vulnerability_route(path) or path
        auth_state = str(endpoint.get("auth_state") or "")
        param_location = str(endpoint.get("param_location") or "").lower()
        # The endpoint's request schema so the planner can author a WORKING create/mutation body
        # instead of an empty one the app rejects (the cause of inconclusive BOLA/mass-assignment).
        request_fields = str(endpoint.get("param_shape") or "").strip() or None
        request_example = str(endpoint.get("replay_spec") or "").strip()[:300] or None
        if _ID_PATH_SEGMENT.search(path):
            key = f"asm_residue|bola|{method}|{route}"
            if key not in seen:
                seen.add(key)
                requests.append(HypothesisRequest(
                    target_id=target_id, source="app_graph", family="bola", cwe="CWE-639",
                    title=f"Object-reference lead: {method} {route}",
                    description=(
                        "An object-id path parameter the scanner discovered but did not prove for "
                        "cross-principal access. Test with two principals before treating it as a finding."
                    ),
                    severity_guess="high", confidence=0.6, dedupe_key=key,
                    dedupe_dimensions={"method": method, "route": route, "proof_surface": "runtime_authz_replay"},
                    next_test_action={
                        "command": "asm.improve",
                        "parameters": {"target_id": target_id, "check_family": "bola", "exploit_depth": True},
                        "requires": ["primary_auth", "second_user_auth"],
                    },
                    metadata_json={"unexplained_residue": True, "residue_source": "endpoint_inventory",
                                   "route": route, "request_fields": request_fields, "request_example": request_example},
                    endorsement={"source": "endpoint_inventory", "method": method, "route": route, "auth_state": auth_state},
                    created_by=created_by,
                ))
        # Auth-session endpoints (login/token/reset/...) are not object-mutation targets; excluding
        # them keeps the board from drowning in mass-assignment noise that stalls the planner.
        auth_session_noise = _research_auth_session_route(path)
        if (
            method in {"POST", "PUT", "PATCH"}
            and any(hint in param_location for hint in ("body", "json", "form"))
            and not auth_session_noise
        ):
            key = f"asm_residue|mass_assignment|{method}|{route}"
            if key not in seen:
                seen.add(key)
                # Read-back pairing. An UPDATE (PUT/PATCH /obj/{id}) reads back on its own route. A CREATE
                # (POST /collection) has no same-route object read -- the created object lives at the child
                # route /collection/{id}; pair its GET (read-back) and DELETE (cleanup) so the create-based
                # mass-assignment proof (create -> read the created object -> restore) is constructible.
                same_route_methods = methods_by_route.get(route, set())
                is_create = method == "POST" and not _ID_PATH_SEGMENT.search(route)
                object_route = route.rstrip("/") + "/{id}"
                object_route_methods = methods_by_route.get(object_route, set()) if is_create else set()
                if is_create:
                    # A listable collection (GET on the same route) that also accepts POST is a create
                    # collection; its object-instance route is the natural read-back even when the crawler
                    # never captured a concrete /collection/{id} (it won't create objects during passive
                    # discovery). Infer it so the create-based lead can form -- the experiment probes it and
                    # the family proof falsifies a non-readable create, so an inferred read-back cannot mint
                    # a false finding. A discovered read-back stays a stronger signal (see provability).
                    discovered_readback = object_route if "GET" in object_route_methods else None
                    collection_is_listable = "GET" in same_route_methods
                    # An account/user resource create (register, signup, users, accounts, ...) is the
                    # canonical create-based mass_assignment surface even when the GET sibling isn't
                    # co-discovered (trailing-slash/auth-state variants split the inventory). Universal
                    # name heuristic; the dispatch probe confirms the endpoint and the proof backstops it.
                    account_create = bool(re.search(
                        r"(?i)(user|account|register|signup|member|customer|profile|credential)", route))
                    readback_route = discovered_readback or (
                        object_route if (collection_is_listable or account_create) else None)
                    cleanup_route = object_route if "DELETE" in object_route_methods else None
                    create_based = bool(readback_route)
                else:
                    readback_route = route if "GET" in same_route_methods else None
                    cleanup_route = None
                    create_based = False
                mass_blockers: list[str] = []
                if not readback_route:
                    mass_blockers.append("readback_route_missing")
                # cleanup_route is NOT required: create-based mass_assignment restoration is best-effort
                # (the create template always attempts a DELETE on the created object, and the two-run
                # proof accepts an unrestorable create). A missing DELETE only means the labeled test
                # object persists -- a bounded artifact, not a soundness gap -- so it neither blocks the
                # lead nor penalizes it; a real cleanup route is a small provability bonus.
                mass_provability = (
                    2 + (3 if readback_route else 0)
                    + (1 if method in {"POST", "PUT", "PATCH"} else 0)
                    + (2 if request_fields or request_example else 0)
                    + (1 if cleanup_route else 0)
                )
                requests.append(HypothesisRequest(
                    target_id=target_id, source="app_graph", family="mass_assignment", cwe="CWE-915",
                    title=f"Mass-assignment lead: {method} {route}",
                    description=(
                        "A write endpoint with a request body the scanner discovered but did not probe for "
                        "forbidden-field acceptance. Test a mutation + a rejected control before treating it as a finding."
                    ),
                    # A create-based mass_assignment (overposting role/isAdmin on a registration-style
                    # create) is a privilege escalation -> genuinely high, and this floats the net-new
                    # create surface onto the ranked board instead of being buried under generic writes.
                    severity_guess="high" if create_based else "medium",
                    confidence=0.55 if create_based else 0.5, dedupe_key=key,
                    dedupe_dimensions={"method": method, "route": route, "proof_surface": "mutation_differential"},
                    next_test_action={
                        # No ASM mass-assignment actuator + gated hunts reject check_family='all';
                        # the loop proves this with a bounded mutation workflow instead.
                        "command": "experiment.workflow",
                        "parameters": {"proof_family": "mass_assignment"},
                        "requires": ["primary_auth"],
                    },
                    metadata_json={
                        "unexplained_residue": True,
                        "residue_source": "endpoint_inventory",
                        "route": route,
                        "request_fields": request_fields,
                        "request_example": request_example,
                        "available_methods": sorted(same_route_methods),
                        "object_route": object_route if is_create else None,
                        "object_route_methods": sorted(object_route_methods) if is_create else [],
                        "readable_route": readback_route,
                        "readback_route": readback_route,
                        "cleanup_route": cleanup_route,
                        "create_based": create_based,
                        "provability_score": mass_provability,
                        "provability_blockers": mass_blockers,
                    },
                    endorsement={"source": "endpoint_inventory", "method": method, "route": route},
                    created_by=created_by,
                ))
        # Sensitive-value read: a GET route whose path/fields name sensitive data is a data-exposure
        # lead. The app graph only emits these off a two-user resource map (usually empty), so the
        # inventory is the fallback that keeps data_exposure on the board. Lead only -- the workflow
        # proof still requires a live server-classified sensitive value on a protected/denied read.
        if (
            method == "GET"
            and not auth_session_noise
            and _SENSITIVE_FIELD_TOKENS.search(f"{path} {request_fields or ''}")
        ):
            key = f"asm_residue|data_exposure|{method}|{route}"
            if key not in seen:
                seen.add(key)
                requests.append(HypothesisRequest(
                    target_id=target_id, source="app_graph", family="data_exposure", cwe="CWE-200",
                    title=f"Sensitive-read lead: {method} {route}",
                    description=(
                        "A read endpoint whose path or fields name sensitive data the scanner discovered "
                        "but did not prove for over-exposure. Re-read it as a lower-privilege/anonymous "
                        "principal and require a live server-classified sensitive value before promotion."
                    ),
                    severity_guess="medium", confidence=0.5, dedupe_key=key,
                    dedupe_dimensions={"method": method, "route": route, "proof_surface": "sensitive_value_boundary"},
                    next_test_action={
                        "command": "experiment.workflow",
                        "parameters": {"proof_family": "data_exposure"},
                        "requires": ["primary_auth"],
                    },
                    metadata_json={"unexplained_residue": True, "residue_source": "endpoint_inventory",
                                   "route": route, "request_fields": request_fields, "request_example": request_example},
                    endorsement={"source": "endpoint_inventory", "method": method, "route": route, "auth_state": auth_state},
                    created_by=created_by,
                ))
        # Privileged function: a path that names an admin/management function is a function-level-authz
        # (BFLA/auth_bypass) lead. Also inventory-sourced so it survives an empty app graph. Lead only --
        # the workflow proof still has to show the function executes for an unauthorized principal.
        if not auth_session_noise and _PRIVILEGED_FUNCTION_TOKENS.search(path):
            key = f"asm_residue|auth_bypass|{method}|{route}"
            if key not in seen:
                seen.add(key)
                requests.append(HypothesisRequest(
                    target_id=target_id, source="app_graph", family="auth_bypass", cwe="CWE-862",
                    title=f"Privileged-function lead: {method} {route}",
                    description=(
                        "A path that names an administrative/management function the scanner discovered "
                        "but did not prove for authorization. Invoke it as an unauthorized/anonymous "
                        "principal and require a server-confirmed access differential before promotion."
                    ),
                    severity_guess="high", confidence=0.55, dedupe_key=key,
                    dedupe_dimensions={"method": method, "route": route, "proof_surface": "function_authz_control"},
                    next_test_action={
                        "command": "experiment.workflow",
                        "parameters": {"proof_family": "auth_bypass"},
                        "requires": ["primary_auth"],
                    },
                    metadata_json={"unexplained_residue": True, "residue_source": "endpoint_inventory",
                                   "route": route, "request_fields": request_fields, "request_example": request_example},
                    endorsement={"source": "endpoint_inventory", "method": method, "route": route, "auth_state": auth_state},
                    created_by=created_by,
                ))
    # Apply the cap after family-aware round-robin selection. Otherwise a long
    # object-reference prefix can consume all 100 slots before later
    # data-exposure, auth-bypass, or mutation leads are persisted.
    by_family: dict[str, list[HypothesisRequest]] = {}
    family_order: list[str] = []
    for request in requests:
        if request.family not in by_family:
            family_order.append(request.family)
            by_family[request.family] = []
        by_family[request.family].append(request)
    # Within each family, float the highest-value leads to the front so the round-robin cap keeps them:
    # create-based mass_assignment (the net-new surface a huge inventory would otherwise bury) and then
    # higher provability. Stable sort preserves discovery order among equals.
    for bucket in by_family.values():
        bucket.sort(
            key=lambda request: (
                bool((request.metadata_json or {}).get("create_based")),
                int((request.metadata_json or {}).get("provability_score") or 0),
            ),
            reverse=True,
        )
    balanced: list[HypothesisRequest] = []
    while len(balanced) < 100 and any(by_family.values()):
        for family in family_order:
            bucket = by_family[family]
            if bucket:
                balanced.append(bucket.pop(0))
                if len(balanced) >= 100:
                    break
    return balanced


class AsmPruneRequest(BaseModel):
    """On-demand reachability sweep / GC of the persistent endpoint inventory."""
    max_probe: int = Field(default=2000, ge=1, le=20000)
    retire_threshold: Optional[int] = Field(default=None, ge=1, le=10)


def _decode_asm_config(raw) -> dict:
    decoded = _decode_json_value(raw) or {}
    return decoded if isinstance(decoded, dict) else {}


class TargetNormalizationError(ValueError):
    """Raised when target URL is malformed or invalid."""
    pass


def _attach_target_note(options: dict, original_target: str, note: str | None, scheme_inferred: bool = False) -> dict:
    """Attach original target info to scan options for transparency."""
    updated = dict(options) if options else {}
    if note:
        updated.setdefault("_original_target", original_target)
        updated.setdefault("_target_warning", note)
    if scheme_inferred:
        updated.setdefault("target_scheme_inferred", True)
    return updated
def _asm_reserved_count(r, root_domain: str) -> int:
    if not root_domain:
        return 0
    return asm_inventory.reserved_domain_rate_count(r, root_domain)


def _default_asm_enabled_for_new_web_target(discovery_source: str = "manual") -> bool:
    """Default Continuous ASM only for web targets the product should track.

    The targets table also stores model artifacts and other non-web subjects, so
    callers should opt those out explicitly instead of relying on a table-wide
    default.
    """
    if str(discovery_source or "").strip().lower() in {"model-intake", "model_intake"}:
        return False
    return bool(_load_effective_automation_settings().get("default_asm_enabled"))


def _default_asm_config_for_new_web_target(discovery_source: str = "manual") -> dict[str, Any]:
    if str(discovery_source or "").strip().lower() in {"model-intake", "model_intake"}:
        return {}
    return _safe_default_asm_config(_load_effective_automation_settings().get("default_asm_config"))


def _apply_asm_check_family(options: dict[str, Any], check_family: Any) -> dict[str, Any]:
    """Apply a supported focused ASM family to scan options.

    This uses the first-class check registry, while preserving the scanner's
    current legacy focused flags for SQLi/XSS and explicit check-family routing
    for gated families such as BOLA.
    """
    opts, _family = check_registry.apply_asm_focus(options or {}, check_family)
    return opts


def _validate_asm_check_family_value(value: Any) -> str | None:
    return check_registry.validate_asm_focus_family(value)


def _enforce_asm_family_preconditions(
    family: str | None,
    options: dict[str, Any],
    *,
    exploit_depth: bool,
) -> None:
    """Fail closed for focused families whose registry metadata needs more context."""
    error = check_registry.family_precondition_error(
        family,
        options or {},
        exploit_depth=exploit_depth,
    )
    if error:
        raise HTTPException(
            status_code=400,
            detail=error,
        )


class ScanInternalCompatibilityRequest(_ScanRequestBase):
    """Server-authored Scan request for historical rows and bounded adapters.

    This model is never attached to a public route or OpenAPI operation.
    """

    options: ScanOptions = Field(default_factory=ScanOptions)


def _mask_ai_target_secret(secret: str | None) -> str | None:
    if not secret:
        return None
    trimmed = secret.strip()
    if not trimmed:
        return None
    if len(trimmed) <= 8:
        return f"{trimmed[:2]}****"
    return f"{trimmed[:4]}...{trimmed[-2:]}"


def _normalize_target_credential_profile_name(value: Any) -> str:
    name = re.sub(r"\s+", " ", str(value or "").strip())
    if not name:
        raise HTTPException(status_code=400, detail="credential profile name is required")
    if len(name) > 120:
        raise HTTPException(status_code=400, detail="credential profile name must be 120 characters or fewer")
    return name


_MAX_AUTO_PROVISION_PRINCIPALS = 4


_MAX_AUTO_PROVISION_RESPONSE_BYTES = 64 * 1024


def _render_provision_template(node: Any, variables: dict[str, str]) -> Any:
    if isinstance(node, str):
        rendered = node
        for key, value in variables.items():
            rendered = rendered.replace("{{" + key + "}}", value)
        return rendered
    if isinstance(node, dict):
        return {key: _render_provision_template(value, variables) for key, value in node.items()}
    if isinstance(node, list):
        return [_render_provision_template(item, variables) for item in node]
    return node


def _provision_json_path(payload: Any, path: str) -> Any:
    node = payload
    for part in str(path or "").replace("$", "").strip(".").split("."):
        if not part:
            continue
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return None
    return node


def _graph_route_label(node: dict[str, Any] | None, node_key: str) -> str:
    if node and node.get("label"):
        return str(node.get("label"))
    if str(node_key).startswith("route:"):
        return str(node_key)[len("route:"):]
    return str(node_key)


def _graph_object_label(node: dict[str, Any] | None, node_key: str) -> str:
    if node and node.get("label"):
        return str(node.get("label"))
    if str(node_key).startswith("object:"):
        return str(node_key)[len("object:"):]
    return str(node_key)


def _principal_matrix_context_for_graph_hypothesis(
    *,
    method: str | None,
    route: str | None,
    source_principal: Any,
    excluded_principal: Any,
    principal_rows: list[Any] | None = None,
    expectation_rows: list[Any] | None = None,
) -> dict[str, Any]:
    """Return bounded principal-matrix facts for graph authz planning.

    This context is a scheduler/planner hint only. It never contains raw
    credentials and does not promote graph facts into proof.
    """
    principals: list[dict[str, Any]] = []
    for row in principal_rows or []:
        payload = _public_target_principal_row(row)
        principals.append({
            "label": payload.get("label"),
            "role": payload.get("role"),
            "tenant_id": payload.get("tenant_id"),
            "auth_state": payload.get("auth_state"),
            "credential_configured": bool(payload.get("credential_configured")),
            "is_active": bool(payload.get("is_active", True)),
        })

    expectations: list[dict[str, Any]] = []
    route_value = str(route or "").strip()
    method_value = str(method or "").strip().upper()
    for row in expectation_rows or []:
        payload = _public_target_endpoint_expectation_row(row)
        expected_path = str(payload.get("path") or "").strip()
        expected_method = str(payload.get("method") or "").strip().upper()
        matches_route = bool(
            route_value
            and (
                expected_path == route_value
                or _authz_template_replay_path(expected_path) == _authz_template_replay_path(route_value)
            )
        )
        matches_method = not method_value or not expected_method or expected_method == method_value
        expectations.append({
            "method": payload.get("method"),
            "path": payload.get("path"),
            "principal_label": payload.get("principal_label"),
            "principal_role": payload.get("principal_role"),
            "tenant_id": payload.get("tenant_id"),
            "expected_access": payload.get("expected_access"),
            "expected_http_status": payload.get("expected_http_status"),
            "expectation_source": payload.get("expectation_source"),
            "principal_auth_state": payload.get("principal_auth_state"),
            "matching_route": matches_route and matches_method,
        })

    role_counts = Counter(str(item.get("role") or "unknown") for item in principals)
    tenant_counts = Counter(str(item.get("tenant_id") or "none") for item in principals)

    def _principal_match(value: Any) -> dict[str, Any] | None:
        needle = str(value or "").strip().lower()
        if not needle:
            return None
        for item in principals:
            candidates = (
                item.get("label"),
                item.get("auth_state"),
                item.get("role"),
            )
            if any(str(candidate or "").strip().lower() == needle for candidate in candidates):
                return item
        return None

    primary = _principal_match(source_principal)
    alternate = _principal_match(excluded_principal)
    matching_expectations = [item for item in expectations if item.get("matching_route")]
    credential_profiles = {
        "primary": bool(primary and primary.get("credential_configured")),
        "alternate": bool(alternate and alternate.get("credential_configured")),
    }
    return {
        "available": bool(principals or expectations),
        "principals": principals[:10],
        "expectations": expectations[:15],
        "matching_expectations": matching_expectations[:10],
        "role_counts": dict(role_counts),
        "tenant_counts": dict(tenant_counts),
        "matched_principals": {
            "primary": primary,
            "alternate": alternate,
        },
        "credential_profiles": credential_profiles,
        "precondition_signals": {
            "primary_credentials": "configured" if credential_profiles["primary"] else "unknown",
            "second_user_credentials": "configured" if credential_profiles["alternate"] else "unknown",
        },
        "proof_state": "unproven_planning_context",
    }


async def _load_hypothesis_situation_report(
    conn,
    *,
    limit: int = 5,
    target_uuid: uuid.UUID | None = None,
    requester: str | None = None,
    include_graph: bool = True,
) -> dict[str, Any]:
    """Load a bounded hypothesis situation report for one consumer surface."""
    bounded_limit = max(1, min(int(limit or 5), 25))
    query_limit = min(max(bounded_limit * 20, 50), 250)
    rows = await conn.fetch(
        """
        SELECT *
        FROM hypotheses
        WHERE ($2::uuid IS NULL OR target_id = $2)
        ORDER BY updated_at DESC
        LIMIT $1
        """,
        query_limit,
        target_uuid,
    )
    graph_context = (
        await _load_application_graph_context_for_hypotheses(conn, rows, limit_targets=bounded_limit)
        if include_graph
        else _empty_application_graph_context()
    )
    return _hypothesis_situation_report(
        rows,
        requester=requester,
        limit=bounded_limit,
        graph_context=graph_context,
    )


def _public_asm_decision(decision: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(decision, dict):
        return None
    return {
        "action": decision.get("action"),
        "reason": decision.get("reason"),
        "blocked_by": decision.get("blocked_by"),
        "next_eligible_at": decision.get("next_eligible_at"),
        "daily_cap_remaining": decision.get("daily_cap_remaining"),
        "rate_cap_remaining": decision.get("rate_cap_remaining"),
        "claimable": decision.get("claimable"),
        "tested_today": decision.get("tested_today"),
    }


def _scan_role_label(scan_role: Any) -> str:
    role = str(scan_role or "")
    if role == asm_inventory.ASM_RECON_ROLE:
        return "Discovery"
    if role == asm_inventory.ASM_BATCH_ROLE:
        return "Test batch"
    return "Scan"


def _event_time(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value else None


_RESEARCH_DISPATCH_CORRELATION_KEY = "research_dispatch_correlation"


def _current_research_dispatch_correlation() -> str | None:
    """Return the server-created research decision correlation, never caller text."""
    value = str(_ARSENAL_CREATED_BY_CONTEXT.get() or "").strip()
    if re.fullmatch(
        r"research_episode:[0-9a-fA-F-]{36}:decision:[0-9a-fA-F-]{36}",
        value,
    ):
        return value
    return None


async def _fail_asm_queue_handoff(
    conn,
    scan_id: str,
    campaign_id: str,
    enqueue_error: Exception,
) -> None:
    """Fail closed when the Redis/DB queue handoff cannot be durably confirmed."""
    error_message = (
        "ASM queue handoff could not be durably confirmed "
        f"({type(enqueue_error).__name__})."
    )
    try:
        scan_result = await conn.execute(
            """
            UPDATE scans
            SET status='failed', progress=100, current_phase='queue_failed',
                error_message=$2, completed_at=NOW()
            WHERE id=$1 AND status='pending'
            """,
            uuid.UUID(str(scan_id)),
            error_message,
        )
        if not str(scan_result).endswith("0"):
            await conn.execute(
                """
                UPDATE scan_campaigns campaign
                SET status='failed', completed_at=COALESCE(completed_at, NOW()), updated_at=NOW()
                WHERE campaign.id=$1 AND campaign.status='active'
                  AND EXISTS (
                      SELECT 1 FROM scans owner
                      WHERE owner.id=$2 AND owner.campaign_id=campaign.id
                        AND owner.status='failed'
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM scans other
                      WHERE other.campaign_id=campaign.id AND other.id<>$2
                  )
                """,
                uuid.UUID(str(campaign_id)),
                uuid.UUID(str(scan_id)),
            )
    except Exception:
        # Preserve the Redis exception as the caller-visible failure while making
        # the secondary database failure explicit in service logs.
        logger.exception("Failed to mark ASM scan %s after queue handoff failure", scan_id)


async def _confirm_asm_queue_handoff(
    conn,
    *,
    scan_id: str,
    job_id: str,
    campaign_id: str,
) -> None:
    try:
        confirmation = await conn.execute(
            """
            UPDATE scans
            SET status='queued',
                options=jsonb_set(COALESCE(options, '{}'::jsonb),
                                  '{queue_handoff_confirmed}', 'true'::jsonb, true)
            WHERE id=$1 AND status='pending'
              AND options->>'queue_handoff_confirmed'='false'
            """,
            uuid.UUID(scan_id),
        )
        if str(confirmation).endswith("0"):
            raise RuntimeError("ASM queue handoff confirmation was not persisted")
    except Exception as confirmation_error:
        if await _asm_queue_handoff_readback_confirmed(scan_id, job_id, campaign_id):
            return
        await _fail_asm_queue_handoff(conn, scan_id, campaign_id, confirmation_error)
        raise


async def _canonical_asm_scan_options(
    *,
    target_id: str,
    target_url: str,
    base_options: Mapping[str, Any] | None,
    check_family: str | None,
    active_testing: bool = True,
) -> tuple[dict[str, Any], Any]:
    """Resolve one internal ASM test batch to canonical Scan V2 authority.

    Continuous ASM chooses a bounded endpoint subset, but that selection does not
    create another scanner identity.  The resulting target traffic is still one
    deterministic Scan action and therefore needs the same immutable policy,
    budget, target binding, and durable reservation contract as an interactive
    Scan submission.
    """
    options = dict(base_options or {})
    existing_policy = (
        dict(options.get("scan_policy") or {})
        if isinstance(options.get("scan_policy"), Mapping)
        else {}
    )
    family = (
        _normalize_asm_check_family(check_family)
        if active_testing else None
    )
    include_families = list(existing_policy.get("include_families") or ())
    if family and family != "all":
        include_families = [family]
    elif not active_testing:
        include_families = ["recon"]
    approval_receipt_id = str(
        options.get("approval_receipt_id")
        or existing_policy.get("approval_receipt_id")
        or ""
    ).strip() or None
    contract = resolve_scan_contract(
        budget_profile=options.get("budget_profile"),
        policy={
            "preset": (
                "custom" if include_families
                else "standard_active" if active_testing
                else "passive"
            ),
            "active_testing": active_testing,
            # ASM has no first-class state-changing permission in its request
            # contract, so an old target option or stale receipt can never grant it.
            "allow_state_changing_http": False,
            "network_discovery": False,
            "subdomain_discovery": False,
            "include_families": include_families,
            "exclude_families": list(existing_policy.get("exclude_families") or ()),
        },
        approval_receipt_id=approval_receipt_id,
    )
    contract = bind_scan_scope_receipt(
        contract,
        str(
            options.get("scope_receipt_id")
            or existing_policy.get("scope_receipt_id")
            or ""
        ).strip() or None,
    )
    for key in ("scan_type", "quick", "thorough"):
        options.pop(key, None)
    options.update(contract.option_metadata())
    options.update({
        "active": active_testing,
        "network_discovery": False,
        "subfinder": False,
        "budget_profile": contract.budget_profile,
    })
    target_guard = await _freeze_scan_target_binding(
        target_id=target_id,
        target_kind="web",
        target_url=target_url,
        scope_receipt_id=contract.policy.scope_receipt_id,
        scheme_inferred=False,
        existing_guard=(
            options.get("runtime_scope_guard")
            if isinstance(options.get("runtime_scope_guard"), Mapping)
            else None
        ),
        subject="ASM Scan target",
    )
    options["runtime_scope_guard"] = target_guard
    options["_canonical_target_binding"] = TargetBinding(
        target_id=str(target_id),
        target_kind="web",
        canonical_host=target_guard.get("canonical_host"),
        allowed_origins=tuple(target_guard.get("allowed_origins") or ()),
        allowed_addresses=tuple(target_guard.get("allowed_addresses") or ()),
        allowed_root_domains=tuple(target_guard.get("allowed_root_domains") or ()),
        environment=str(target_guard.get("environment") or "unknown"),
        scope_receipt_id=contract.policy.scope_receipt_id,
    ).canonical_dict()
    return options, contract


def _compile_asm_scan_authority(
    *,
    scan_id: str,
    job_id: str,
    target_url: str,
    options: dict[str, Any],
    scan_contract: ResolvedScanContract,
) -> dict[str, Any]:
    """Compile one exact ASM operation into the canonical Scan V2 stores."""
    guard = options.get("runtime_scope_guard")
    if not isinstance(guard, Mapping):
        raise ScanActionPlanError("ASM Scan has no frozen runtime target binding")
    target_binding = TargetBinding(
        target_id=str(guard.get("target_id") or ""),
        target_kind=str(guard.get("target_kind") or "web"),
        canonical_host=guard.get("canonical_host"),
        allowed_origins=tuple(guard.get("allowed_origins") or ()),
        allowed_addresses=tuple(guard.get("allowed_addresses") or ()),
        allowed_root_domains=tuple(guard.get("allowed_root_domains") or ()),
        environment=str(guard.get("environment") or "unknown"),
        scope_receipt_id=scan_contract.policy.scope_receipt_id,
    )
    endpoint_manifest, candidate_manifest = (
        _compile_scan_admission_surface_work_manifests(
            scan_id=scan_id,
            target_url=target_url,
            scan_contract=scan_contract,
            target_binding=target_binding,
            options=options,
        )
    )
    endpoint_ref = endpoint_manifest.reference().canonical_dict()
    candidate_ref = candidate_manifest.reference().canonical_dict()
    template_manifest = _compile_scan_template_work_manifest(
        scan_id=scan_id,
        scan_contract=scan_contract,
        target_binding=target_binding,
    )
    options.update({
        "endpoint_manifest_id": str(endpoint_manifest.manifest_id),
        "endpoint_manifest_ref": endpoint_ref,
        "candidate_manifest_ref": candidate_ref,
    })
    if template_manifest is not None:
        options["template_manifest_ref"] = (
            template_manifest.reference().canonical_dict()
        )
    credential_refs = [
        dict(item)
        for item in options.get("credential_profile_refs") or ()
        if isinstance(item, Mapping)
    ]
    action_plan, continuation = _compile_scan_admission_action_authority(
        scan_id=scan_id,
        scan_contract=scan_contract,
        target_binding=target_binding,
        credential_refs=credential_refs,
        endpoint_manifest_ref=endpoint_ref,
        candidate_manifest_ref=(candidate_ref if candidate_manifest.entries else None),
        template_manifest_ref=(
            template_manifest.reference().canonical_dict()
            if template_manifest is not None else None
        ),
    )
    if continuation is not None:
        options["scan_continuation_allocation_digest"] = (
            continuation.allocation_digest
        )
    canonical_job = CanonicalScanJob.create(
        job_id=job_id,
        scan_id=scan_id,
        target=target_binding,
        execution_plan=scan_contract.execution_plan,
        credential_profile_ids=admitted_credential_profile_ids(credential_refs),
        endpoint_manifest_id=str(endpoint_manifest.manifest_id),
    )
    return {
        "job": canonical_job,
        "action_plan": action_plan,
        "continuation": continuation,
        "manifests": tuple(
            item
            for item in (endpoint_manifest, candidate_manifest, template_manifest)
            if item is not None
        ),
    }


async def _persist_asm_scan_authority(
    conn,
    *,
    authority: Mapping[str, Any],
) -> None:
    action_plan = authority["action_plan"]
    action_store = PostgresScanActionStore()
    await action_store.persist_plan(conn, plan=action_plan)
    continuation = authority.get("continuation")
    if continuation is not None:
        await action_store.persist_continuation_allocation(
            conn,
            allocation=continuation,
            parent_plan=action_plan,
        )
    manifest_store = PostgresScanManifestStore()
    for manifest in authority.get("manifests") or ():
        await manifest_store.persist(conn, manifest=manifest)


_ID_PATH_SEGMENT = re.compile(
    r"/(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,36}|\{[^/{}]+\}|:[A-Za-z_][A-Za-z0-9_]*)(?=/|$)"
)


_SENSITIVE_FIELD_TOKENS = re.compile(
    r"(?:user|account|profile|email|ssn|social|passport|credit|card|cvv|iban|secret|"
    r"password|apikey|api_key|order|invoice|payment|billing|balance|salary|address|phone|"
    r"birth|dob|license|medical|patient|tax|private)",
    re.IGNORECASE,
)


_PRIVILEGED_FUNCTION_TOKENS = re.compile(
    r"(?:admin|internal|manage|management|config|dashboard|approve|approval|grant|revoke|"
    r"privilege|superuser|backend|console|moderat|impersonat)",
    re.IGNORECASE,
)


def _research_auth_session_route(value: Any) -> bool:
    path = str(value or "").lower().split("?", 1)[0]
    return bool({segment for segment in path.split("/") if segment} & _AUTH_SESSION_ROUTE_TOKENS)


def is_root_domain(url: str) -> bool:
    """Check if URL is a root domain (not a subdomain)."""
    from urllib.parse import urlparse
    import ipaddress
    try:
        parsed = urlparse(url if '://' in url else f'https://{url}')
        host = parsed.hostname or parsed.netloc or parsed.path.split('/')[0]
        host = host.lower()  # parsed.hostname already strips port
        # IPs are treated as root targets
        try:
            ipaddress.ip_address(host.strip("[]"))
            return True
        except ValueError:
            pass
        root = extract_root_domain(url).lower()
        # It's a root if host equals root_domain or www.root_domain
        return host == root or host == f'www.{root}'
    except Exception:
        return False
def _empty_application_graph_context() -> dict[str, Any]:
    return {
        "summary": {
            "hypothesis_target_count": 0,
            "target_count": 0,
            "node_count": 0,
            "edge_count": 0,
            "auth_boundary_edge_count": 0,
            "producer_consumer_edge_count": 0,
            "missing_graph_target_count": 0,
        },
        "targets": [],
        "missing_graph_target_ids": [],
        "truncated": False,
    }


async def _load_application_graph_context_for_hypotheses(
    conn,
    hypothesis_rows: Sequence[Any],
    *,
    limit_targets: int = 5,
) -> dict[str, Any]:
    target_ids: list[uuid.UUID] = []
    seen: set[str] = set()
    for row in hypothesis_rows:
        payload = row_to_dict(row)
        raw_target_id = payload.get("target_id")
        if not raw_target_id:
            continue
        try:
            target_uuid = uuid.UUID(str(raw_target_id))
        except ValueError:
            continue
        target_key = str(target_uuid)
        if target_key in seen:
            continue
        seen.add(target_key)
        target_ids.append(target_uuid)
        if len(target_ids) >= max(1, min(int(limit_targets or 5), 25)):
            break
    if not target_ids:
        return _empty_application_graph_context()
    nodes = await conn.fetch(
        """
        SELECT *
        FROM application_graph_nodes
        WHERE target_id = ANY($1::uuid[])
        ORDER BY target_id, node_type, node_key
        """,
        target_ids,
    )
    edges = await conn.fetch(
        """
        SELECT *
        FROM application_graph_edges
        WHERE target_id = ANY($1::uuid[])
        ORDER BY target_id, edge_type, src_key
        """,
        target_ids,
    )
    return _application_graph_context_for_hypotheses(
        hypothesis_rows,
        list(nodes),
        list(edges),
        limit_targets=limit_targets,
    )


def _authz_template_replay_path(path: Any) -> str:
    raw = str(path or "").strip()
    if not raw:
        return ""
    parsed = urllib.parse.urlparse(raw)
    route = parsed.path if parsed.scheme or parsed.netloc else raw.split("?", 1)[0]
    parts: list[str] = []
    for segment in route.split("/"):
        if not segment:
            continue
        lowered = segment.lower()
        if re.fullmatch(r"\d+", segment):
            parts.append("{id}")
        elif re.fullmatch(r"[0-9a-f]{24}", lowered) or re.fullmatch(r"[0-9a-f]{32,}", lowered):
            parts.append("{hash}")
        elif re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", lowered):
            parts.append("{uuid}")
        else:
            parts.append(segment)
    templated = "/" + "/".join(parts)
    return templated or "/"


async def _asm_queue_handoff_readback_confirmed(
    scan_id: str,
    job_id: str,
    campaign_id: str,
) -> bool:
    """Resolve an ambiguous DB acknowledgement from an independent connection."""
    try:
        async with _pool().acquire() as read_conn:
            row = await read_conn.fetchrow(
                """
                SELECT status, job_id, campaign_id, options
                FROM scans
                WHERE id=$1
                """,
                uuid.UUID(str(scan_id)),
            )
    except Exception:
        return False
    if not row:
        return False
    options = _decode_json_value(row.get("options")) or {}
    return bool(
        str(row.get("job_id") or "") == str(job_id)
        and str(row.get("campaign_id") or "") == str(campaign_id)
        and isinstance(options, dict)
        and options.get(_QUEUE_HANDOFF_CONFIRMATION_KEY) is True
    )


_AUTH_SESSION_ROUTE_TOKENS = frozenset({
    "login", "logout", "signin", "signout", "token", "refresh", "reset",
    "forgot", "verify", "otp", "oauth", "callback", "session",
})


def normalize_target_url(target: str) -> tuple[str, str | None]:
    """
    Normalize target URL to canonical origin (strip path/query/fragment).

    Returns:
        tuple: (normalized_url, warning_note)

    Raises:
        TargetNormalizationError: If URL is malformed (e.g., invalid IPv6)
    """
    from urllib.parse import urlparse
    raw = (target or "").strip()
    if not raw:
        return "", None

    # Parse URL, handling missing scheme
    has_scheme = "://" in raw
    url_to_parse = raw if has_scheme else f"https://{raw}"

    try:
        parsed = urlparse(url_to_parse)
        # Access port early to catch ValueError for malformed ports/IPv6
        port = parsed.port
        host = parsed.hostname
    except ValueError as e:
        # Malformed URL (e.g., IPv6 without brackets, invalid port)
        hint = " (hint: wrap IPv6 addresses in brackets, e.g. [2001:db8::1])"
        raise TargetNormalizationError(f"Invalid target URL: {e}{hint}")

    # Extract host from path if hostname is empty (e.g., bare domain)
    if not host:
        host = (parsed.path.split("/")[0] if parsed.path else "")
    if not host:
        return "", None

    # Lowercase host for consistent canonicalization
    host = host.lower()
    # DNS names are bounded to 253 visible characters. Apart from producing an
    # unusable target, accepting an unbounded host lets one historical row turn
    # lightweight domain-filter responses into multi-megabyte UI payloads.
    if len(host.rstrip('.')) > 253:
        raise TargetNormalizationError("Invalid target URL: hostname exceeds 253 characters")

    # Validate scheme (only http/https allowed when explicitly provided)
    scheme = parsed.scheme.lower() if has_scheme else "https"
    if scheme not in ("http", "https"):
        raise TargetNormalizationError(f"Invalid scheme '{scheme}': only http/https allowed")

    # Format host (bracket IPv6 addresses)
    host_display = f"[{host}]" if ":" in host and not host.startswith("[") else host

    # Strip default ports for cleaner canonicalization when scheme is known
    port_suffix = ""
    if port:
        if scheme:
            is_default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
            if not is_default_port:
                port_suffix = f":{port}"
        else:
            port_suffix = f":{port}"

    normalized = f"{scheme}://{host_display}{port_suffix}"

    # Track if path/query/fragment was stripped
    had_path = bool(parsed.path and parsed.path not in ("", "/"))
    had_query = bool(parsed.query)
    had_fragment = bool(parsed.fragment)
    note = None
    if had_path or had_query or had_fragment:
        note = "Target URL contained a path/query/fragment; scanning root origin instead."

    return normalized, note
def _application_graph_context_for_hypotheses(
    hypothesis_rows: Sequence[Any],
    node_rows: Sequence[Any],
    edge_rows: Sequence[Any],
    *,
    limit_targets: int = 5,
    sample_limit: int = 5,
) -> dict[str, Any]:
    bounded_targets = max(1, min(int(limit_targets or 5), 25))
    bounded_samples = max(1, min(int(sample_limit or 5), 10))
    hypotheses = [_public_hypothesis_row(row) for row in hypothesis_rows]
    targets_by_id: dict[str, dict[str, Any]] = {}
    target_order: list[str] = []
    for hypothesis in hypotheses:
        target_id = str(hypothesis.get("target_id") or "")
        if not target_id:
            continue
        if target_id not in targets_by_id:
            targets_by_id[target_id] = {
                "target_id": target_id,
                "hypothesis_count": 0,
                "sample_hypothesis_ids": [],
                "families": Counter(),
                "by_node_type": Counter(),
                "by_edge_type": Counter(),
                "sample_route_keys": [],
                "sample_object_keys": [],
                "sample_principal_keys": [],
            }
            target_order.append(target_id)
        target_bucket = targets_by_id[target_id]
        target_bucket["hypothesis_count"] += 1
        family = str(hypothesis.get("family") or "unknown")
        target_bucket["families"][family] += 1
        if len(target_bucket["sample_hypothesis_ids"]) < bounded_samples:
            target_bucket["sample_hypothesis_ids"].append(str(hypothesis.get("id") or ""))

    if not targets_by_id:
        return _empty_application_graph_context()

    included_ids = target_order[:bounded_targets]
    included = {target_id: targets_by_id[target_id] for target_id in included_ids}
    node_count = 0
    edge_count = 0
    auth_boundary_edge_count = 0
    producer_consumer_edge_count = 0
    producer_consumer_types = {
        "produces",
        "consumed_by",
        "consumes",
        "producer",
        "consumer",
        "producer_consumer",
    }

    for row in node_rows:
        payload = row_to_dict(row)
        target_id = str(payload.get("target_id") or "")
        bucket = included.get(target_id)
        if not bucket:
            continue
        node_type = str(payload.get("node_type") or "unknown")
        node_key = str(payload.get("node_key") or payload.get("label") or "")
        bucket["by_node_type"][node_type] += 1
        node_count += 1
        sample_key = f"sample_{node_type}_keys"
        if sample_key in bucket and node_key and len(bucket[sample_key]) < bounded_samples:
            bucket[sample_key].append(node_key)

    for row in edge_rows:
        payload = row_to_dict(row)
        target_id = str(payload.get("target_id") or "")
        bucket = included.get(target_id)
        if not bucket:
            continue
        edge_type = str(payload.get("edge_type") or "unknown")
        bucket["by_edge_type"][edge_type] += 1
        edge_count += 1
        if edge_type == "auth_boundary":
            auth_boundary_edge_count += 1
        if edge_type in producer_consumer_types:
            producer_consumer_edge_count += 1

    target_summaries: list[dict[str, Any]] = []
    missing_graph_target_ids: list[str] = []
    for target_id in included_ids:
        bucket = included[target_id]
        by_node_type = dict(bucket["by_node_type"])
        by_edge_type = dict(bucket["by_edge_type"])
        target_node_count = sum(by_node_type.values())
        target_edge_count = sum(by_edge_type.values())
        if target_node_count == 0 and target_edge_count == 0:
            missing_graph_target_ids.append(target_id)
        target_summaries.append({
            "target_id": target_id,
            "hypothesis_count": bucket["hypothesis_count"],
            "sample_hypothesis_ids": bucket["sample_hypothesis_ids"],
            "families": dict(bucket["families"]),
            "node_count": target_node_count,
            "edge_count": target_edge_count,
            "route_nodes": by_node_type.get("route", 0),
            "object_nodes": by_node_type.get("object", 0),
            "principal_nodes": by_node_type.get("principal", 0),
            "auth_boundary_edges": by_edge_type.get("auth_boundary", 0),
            "producer_consumer_edges": sum(by_edge_type.get(kind, 0) for kind in producer_consumer_types),
            "by_node_type": by_node_type,
            "by_edge_type": by_edge_type,
            "sample_route_keys": bucket["sample_route_keys"],
            "sample_object_keys": bucket["sample_object_keys"],
            "sample_principal_keys": bucket["sample_principal_keys"],
        })

    return {
        "summary": {
            "hypothesis_target_count": len(targets_by_id),
            "target_count": len(included_ids),
            "node_count": node_count,
            "edge_count": edge_count,
            "auth_boundary_edge_count": auth_boundary_edge_count,
            "producer_consumer_edge_count": producer_consumer_edge_count,
            "missing_graph_target_count": len(missing_graph_target_ids),
        },
        "targets": target_summaries,
        "missing_graph_target_ids": missing_graph_target_ids,
        "truncated": len(target_order) > bounded_targets,
    }
@router.get("/asm/check-families")
async def asm_check_families():
    """Return the registered check-family contract for API/UI/AI clients."""
    return {
        "families": check_registry.describe_check_families(),
        "asm_focus_allowed": list(check_registry.asm_focus_family_names()),
        "default": "all",
    }
