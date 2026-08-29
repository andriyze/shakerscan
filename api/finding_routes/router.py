"""Finding list, detail, triage, retest, and cleanup routes.

Extracted verbatim from the api.py monolith. Owns the finding surface: the
filtered list (including agent candidates merged in as pseudo-findings), the
detail and evidence views, status triage, deletion, bulk update, bulk cleanup,
manual creation, and the deterministic/AI retest queue.

Collaborators that are still hubs inside api.py — the approval gate and policy
check, the command-result ledger, effective AI settings, the Redis client, and
the Continuous-ASM defaults for a newly registered target — are injected by the
composition root and resolved lazily, so the dependency direction stays
app -> router and existing test patches of those names keep working.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
from typing import Any, Callable, Optional
import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

try:
    from api_utils import (
        SEVERITY_ORDER, _clean_string_list, _int_or_none, _iso_or_none,
        _optional_uuid, _row_value, _uuid_or_400, utc_now, utc_now_iso,
    )
    import asm_inventory
    import family_proof
    from scan_verification_state import scan_time_verification_fields as _scan_time_verification_fields
    from evidence_storage import hydrate_evidence_content
    from evidence_triage import redact_finding_evidence as _redact_finding_evidence
    from retest_contract import (
        AI_ONLY_RETEST_TYPES, SUPPORTED_RETEST_TYPES, build_replay_commands,
        build_retest_job_payload, extract_auth_context, infer_type_from_title_tool,
        normalize_retest_type, parse_json_field, validate_retest_job_payload,
    )
    from serialization import _decode_json_value, _json_object, _str_list, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..api_utils import (
        SEVERITY_ORDER, _clean_string_list, _int_or_none, _iso_or_none,
        _optional_uuid, _row_value, _uuid_or_400, utc_now, utc_now_iso,
    )
    from .. import asm_inventory, family_proof
    from ..scan_verification_state import scan_time_verification_fields as _scan_time_verification_fields
    from ..evidence_storage import hydrate_evidence_content
    from ..evidence_triage import redact_finding_evidence as _redact_finding_evidence
    from ..retest_contract import (
        AI_ONLY_RETEST_TYPES, SUPPORTED_RETEST_TYPES, build_replay_commands,
        build_retest_job_payload, extract_auth_context, infer_type_from_title_tool,
        normalize_retest_type, parse_json_field, validate_retest_job_payload,
    )
    from ..serialization import _decode_json_value, _json_object, _str_list, row_to_dict


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


def configure_findings_router(
    pool_provider: Callable[[], Any], **collaborators: Callable[..., Any]
) -> None:
    """Bind the pool and the collaborators this domain needs.

    Collaborators are supplied as lazily-resolved callables rather than imported:
    several are hubs that still live in api.py, and late resolution also keeps
    existing test monkeypatches of those names effective.
    """
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


def get_redis():
    return _dep("get_redis")()


def _load_effective_ai_settings(*a: Any, **k: Any) -> Any:
    return _dep("load_effective_ai_settings")(*a, **k)


def _default_asm_enabled_for_new_web_target(*a: Any, **k: Any) -> Any:
    return _dep("asm_enabled_default")(*a, **k)


def _default_asm_config_for_new_web_target(*a: Any, **k: Any) -> Any:
    return _dep("asm_config_default")(*a, **k)


async def _validate_approval_receipt_for_action(*a: Any, **k: Any) -> Any:
    return await _dep("validate_approval_receipt")(*a, **k)


async def _require_approval_receipt_if_policy_enabled(*a: Any, **k: Any) -> Any:
    return await _dep("require_approval_receipt")(*a, **k)


async def _record_command_result(*a: Any, **k: Any) -> Any:
    return await _dep("record_command_result")(*a, **k)


async def _record_blocked_command_result(*a: Any, **k: Any) -> Any:
    return await _dep("record_blocked_command_result")(*a, **k)


def enqueue_job(*a: Any, **k: Any) -> Any:
    return _dep("enqueue_job")(*a, **k)


def _results_dir() -> Any:
    return _dep("results_dir")()


def _public_evidence_object_row(row: Any) -> dict[str, Any]:
    return hydrate_evidence_content(row_to_dict(row), results_dir=_results_dir())


RETEST_QUEUE_NAME = os.environ.get("RETEST_QUEUE_NAME", "retest_jobs")

_FINDING_DETAIL_ONLY_FIELDS = {
    "description", "evidence", "request", "response", "ai_rationale",
    "ai_recommendations", "notes", "analyst_verdict_notes",
}


def _source_type_filter_sql(source_type: Optional[str]) -> str:
    """SQL fragment for the findings `source_type` filter (first-class taxonomy).

    Values: dast / device / ai / ai_gate / ai_session / deep_hunt / autonomous /
    model_intake / asm / manual.
    model_intake, ASM, manual, and the AI sources filter separately from DAST;
    the UI exposes this same product taxonomy.
    """
    if source_type == "ai":
        return " AND (f.source IN ('ai_gate', 'ai_session', 'autonomous') OR f.ai_target_id IS NOT NULL)"
    if source_type == "ai_gate":
        return " AND f.source = 'ai_gate'"
    if source_type == "ai_session":
        return " AND f.source = 'ai_session'"
    if source_type == "deep_hunt":
        return (
            " AND ("
            "f.source = 'autonomous'"
            " OR f.tool = 'autonomous_workflow'"
            " OR f.evidence->'research'->>'driven_by' = 'autonomous_research'"
            ")"
        )
    if source_type == "autonomous":
        return " AND (f.source = 'autonomous' OR f.tool = 'autonomous_workflow')"
    if source_type == "model_intake":
        return " AND (f.source = 'model_intake' OR f.tool = 'model_intake')"
    if source_type == "asm":
        return " AND f.source = 'asm'"
    if source_type == "manual":
        return " AND f.source = 'manual'"
    if source_type == "device":
        return " AND f.source = 'device'"
    if source_type == "dast":
        return (
            " AND COALESCE(f.source, 'scan') NOT IN "
            "('ai_gate', 'ai_session', 'autonomous', 'model_intake', 'asm', 'manual', 'device')"
            " AND f.ai_target_id IS NULL"
            " AND COALESCE(f.tool, '') NOT IN ('model_intake', 'autonomous_workflow')"
            " AND COALESCE(f.evidence->'research'->>'driven_by', '') <> 'autonomous_research'"
        )
    return ""


def _strip_pagination_for_count(query: str, params: list) -> tuple[str, list]:
    """Convert a SELECT…ORDER BY…LIMIT $N OFFSET $N+1 into a COUNT(*) query.

    Used by list endpoints that optimize the common case with COUNT(*) OVER()
    but still need a fallback `COUNT(*)` when the page is past the end of the
    result set (the window function returns no rows in that case).
    """
    # Remove ORDER BY ... LIMIT ... OFFSET ... — everything from ORDER BY on.
    order_by_idx = query.rfind("ORDER BY")
    body = query[:order_by_idx] if order_by_idx != -1 else query
    # Replace the SELECT … FROM with SELECT COUNT(*) FROM.
    from_idx = body.find("FROM")
    count_sql = "SELECT COUNT(*) " + body[from_idx:]
    # Drop the trailing LIMIT and OFFSET placeholders (always the last two args).
    return count_sql, params[:-2]


class FindingUpdate(BaseModel):
    status: str  # active, resolved, false_positive, accepted_risk
    notes: Optional[str] = None
    analyst_verdict: Optional[str] = Field(
        default=None,
        pattern="^(needs_review|true_positive|false_positive|duplicate|accepted_risk|retest_needed)$",
    )


class FindingRetestRequest(BaseModel):
    finding_type: Optional[str] = None  # xss, sqli, ssrf, path_traversal, open_redirect, cors
    target: Optional[str] = None
    original_url: Optional[str] = None
    param: Optional[str] = None
    payload: Optional[str] = None
    method: Optional[str] = None
    request_body: Optional[str] = None
    requested_by: Optional[str] = "api"
    approval_receipt_id: Optional[str] = Field(
        default=None,
        description="Optional durable approval receipt to validate and stamp on the queued retest job.",
    )


class FindingsBulkRetestRequest(BaseModel):
    finding_ids: Optional[list[str]] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    target_id: Optional[str] = None
    scan_id: Optional[str] = None
    root_domain: Optional[str] = None
    search: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=200)
    finding_type: Optional[str] = None
    requested_by: Optional[str] = "api"
    mode: Optional[str] = None  # "ai" or "deterministic"; None = tiered
    approval_receipt_id: Optional[str] = Field(
        default=None,
        description="Optional durable approval receipt to validate and stamp on each queued retest job.",
    )


class ManualFindingCreate(BaseModel):
    """Create a finding from manual testing or AI session."""
    target: str  # Target URL (required for manual, optional for session)
    title: str
    severity: str  # critical, high, medium, low, info
    description: Optional[str] = None
    category: Optional[str] = None  # BOLA, XSS, SQLi, etc.
    cwe: Optional[str] = None  # CWE ID (e.g., "CWE-639")
    cvss_score: Optional[float] = None
    url: Optional[str] = None  # Specific vulnerable URL/endpoint
    evidence: Optional[str] = None  # Proof of vulnerability
    request: Optional[str] = None  # HTTP request that triggered it
    response: Optional[str] = None  # HTTP response showing vuln
    remediation: Optional[str] = None  # How to fix
    notes: Optional[str] = None


_CANDIDATE_OPEN_STATUSES = ("new", "verification_queued", "verifying")


def _candidate_to_pseudo_finding(row: dict[str, Any]) -> dict[str, Any]:
    """Finding-shaped view of an open web-plane investigation candidate.

    Candidates are non-authoritative hunt claims (SUSPECTED tier). Verified
    candidates never reach this path: promotion materializes a real findings row,
    so including them here would double-count.
    """
    locus = row.get("canonical_locus") or {}
    if isinstance(locus, str):
        locus = _decode_json_value(locus) or {}
    severity = str(row.get("claimed_severity") or "info")
    return {
        "id": str(row["id"]),
        "is_candidate": True,
        "source": "deep_hunt",
        "tool": "investigation_candidate",
        "status": "active",
        "severity": severity,
        "title": row.get("title"),
        "family": row.get("family"),
        "url": locus.get("route") or locus.get("url"),
        "target_id": str(row["target_id"]) if row.get("target_id") else None,
        "target_url": row.get("target_url"),
        "target_name": row.get("target_name"),
        "root_domain": row.get("root_domain"),
        "evidence_refs": row.get("evidence_refs") or [],
        "cvss_score": None,
        "first_seen_at": row.get("first_seen_at"),
        "last_seen_at": row.get("last_seen_at"),
        "verification_status": row.get("status"),
        "is_verified": False,
        "is_suspected": severity in ("high", "critical"),
        "proof_state": "suspected",
        "trust_tier": "suspected",
    }


def _merge_findings_and_candidates(
    findings_out: list[dict[str, Any]],
    candidate_items: list[dict[str, Any]],
    *,
    sort_by: Optional[str],
    sort_order: str,
    limit: int,
    offset: int,
) -> list[dict[str, Any]]:
    """Interleave candidate pseudo-findings with DB findings under the list's sort contract.

    Both inputs are already bounded to the offset+limit prefix window, so the merge
    stays cheap and the returned page honors the same pagination semantics as the
    findings-only listing.
    """
    def _sort_value(item: dict[str, Any]) -> Any:
        if sort_by == "cvss":
            try:
                return None if item.get("cvss_score") is None else float(item["cvss_score"])
            except (TypeError, ValueError):
                return None
        field = "first_seen_at" if sort_by == "first_seen" else "last_seen_at"
        return item.get(field)

    merged = list(findings_out) + list(candidate_items)
    reverse = sort_order == "desc"
    if sort_by in ("first_seen", "last_seen", "cvss"):
        # NULLS LAST in both directions: partition first, then order the valued rows.
        valued = [item for item in merged if _sort_value(item) is not None]
        nulls = [item for item in merged if _sort_value(item) is None]
        valued.sort(key=_sort_value, reverse=reverse)
        merged = valued + nulls
    else:
        # Default severity ordering mirrors the SQL clause: sort_order desc puts
        # critical first; the secondary last_seen tiebreak always runs newest-first.
        merged.sort(key=lambda item: str(item.get("last_seen_at") or ""), reverse=True)
        merged.sort(
            key=lambda item: _FINDING_SEVERITY_ORDER.get(str(item.get("severity") or "").lower(), 6),
            reverse=not reverse,
        )
    return merged[offset:offset + limit]


@router.get("/findings")
async def list_findings(
    request: Request,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_type: Optional[str] = Query(None, pattern="^(dast|device|ai|ai_gate|ai_session|deep_hunt|autonomous|model_intake|asm|manual)$"),
    target_id: Optional[str] = None,
    ai_target_id: Optional[str] = None,
    device_target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    root_domain: Optional[str] = None,
    verification_verdict: Optional[str] = Query(None, pattern="^(exploited|likely_vulnerable|blocked_by_security|out_of_scope_internal|false_positive|likely_fixed|inconclusive|error)$"),
    verification_mode: Optional[str] = Query(None, pattern="^(deterministic|ai_driven)$"),
    verified_only: bool = False,
    driven_by: Optional[str] = Query(None, pattern="^(autonomous_research)$"),
    research_campaign_id: Optional[str] = None,
    search: Optional[str] = None,
    seen_within_days: Optional[int] = Query(None, ge=1),
    first_seen_within_days: Optional[int] = Query(None, ge=1),
    resolved_within_days: Optional[int] = Query(None, ge=1),
    sort_by: Optional[str] = Query(None, pattern="^(severity|first_seen|last_seen|cvss)$"),
    sort_order: Optional[str] = Query("desc", pattern="^(asc|desc)$"),
    include_candidates: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    include_details: bool = False,
):
    """List findings with filtering and sorting.

    The COUNT(*) OVER() window emits the unbounded row total alongside each
    paginated row, so we only execute the (expensive, ILIKE-heavy) query
    once instead of twice.
    """
    # Reject unknown query parameters instead of silently ignoring them. A typo'd
    # filter (e.g. ?domain= instead of ?root_domain=) would otherwise return the
    # full, unfiltered result set with no indication the filter did nothing.
    allowed_params = {
        "severity", "status", "source_type", "target_id", "ai_target_id", "device_target_id",
        "scan_id", "root_domain", "verification_verdict", "verification_mode",
        "verified_only", "driven_by", "research_campaign_id", "search",
        "seen_within_days", "first_seen_within_days",
        "resolved_within_days", "sort_by", "sort_order",
        "include_candidates", "include_details", "limit", "offset",
    }
    unknown_params = sorted({k for k in request.query_params if k not in allowed_params})
    if unknown_params:
        hint = ""
        if any(p in ("domain", "last_seen") for p in unknown_params):
            hint = " (did you mean 'root_domain' / 'seen_within_days'?)"
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown query parameter(s): {', '.join(unknown_params)}{hint}. "
                f"Allowed: {', '.join(sorted(allowed_params))}"
            ),
        )

    async with _pool().acquire() as conn:
        query = """
            SELECT f.*,
                   COALESCE(t.url, ait.endpoint_url, dt.primary_locator) as target_url,
                   COALESCE(t.name, ait.name, dt.name) as target_name,
                   t.root_domain,
                   ait.endpoint_url as ai_target_url,
                   ait.name as ai_target_name,
                   latest_retest.status AS latest_retest_status,
                   latest_retest.result_status AS latest_retest_result_status,
                   latest_retest.verdict AS latest_retest_verdict,
                   latest_retest.confidence AS latest_retest_confidence,
                   latest_retest.completed_at AS latest_retest_completed_at,
                   latest_retest.verification_mode AS latest_retest_mode,
                   COUNT(*) OVER() AS total_count
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            LEFT JOIN device_targets dt ON f.device_target_id = dt.id
            LEFT JOIN LATERAL (
                SELECT status, result_status, verdict, confidence, completed_at, verification_mode
                FROM finding_verifications
                WHERE finding_id=f.id
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            ) latest_retest ON TRUE
            WHERE 1=1
        """
        params: list = []
        param_idx = 1

        if severity:
            query += f" AND f.severity = ${param_idx}"
            params.append(severity)
            param_idx += 1

        if status:
            query += f" AND f.status = ${param_idx}"
            params.append(status)
            param_idx += 1

        query += _source_type_filter_sql(source_type)

        if target_id:
            query += f" AND f.target_id = ${param_idx}"
            params.append(uuid.UUID(target_id))
            param_idx += 1

        if ai_target_id:
            query += f" AND f.ai_target_id = ${param_idx}"
            params.append(uuid.UUID(ai_target_id))
            param_idx += 1

        if device_target_id:
            query += f" AND f.device_target_id = ${param_idx}"
            params.append(uuid.UUID(device_target_id))
            param_idx += 1

        if scan_id:
            query += f" AND f.scan_id = ${param_idx}"
            params.append(uuid.UUID(scan_id))
            param_idx += 1

        if root_domain:
            query += f""" AND (
                t.root_domain = ${param_idx}
                OR LOWER(ait.endpoint_url) LIKE '%' || LOWER(${param_idx}) || '%'
                OR LOWER(dt.primary_locator) LIKE '%' || LOWER(${param_idx}) || '%'
            )"""
            params.append(root_domain)
            param_idx += 1

        if verification_verdict:
            query += f" AND f.last_verification_verdict = ${param_idx}"
            params.append(verification_verdict)
            param_idx += 1

        if verified_only:
            query += " AND f.last_verification_verdict = 'exploited'"

        if driven_by == "autonomous_research":
            # Findings produced by research-driven work (a deep-hunt decision queued the scan
            # that found them) — stamped by backfill_campaign_scan_finding_links. Distinct from
            # source_type='autonomous' (agent-native claims) and organic DAST (no marker).
            query += " AND f.evidence->'research'->>'driven_by' = 'autonomous_research'"

        if research_campaign_id:
            try:
                campaign_uuid = uuid.UUID(str(research_campaign_id))
            except ValueError:
                raise HTTPException(status_code=400, detail="research_campaign_id must be a UUID")
            query += f" AND f.evidence->'research'->>'campaign_id' = ${param_idx}"
            params.append(str(campaign_uuid))
            param_idx += 1

        if verification_mode:
            query += f""" AND EXISTS (
                SELECT 1 FROM finding_verifications fv2
                WHERE fv2.finding_id = f.id AND fv2.verification_mode = ${param_idx}
            )"""
            params.append(verification_mode)
            param_idx += 1

        if search:
            search_pattern = f"%{search}%"
            query += f""" AND (
                f.title ILIKE ${param_idx}
                OR f.url ILIKE ${param_idx}
                OR t.url ILIKE ${param_idx}
                OR ait.endpoint_url ILIKE ${param_idx}
                OR ait.name ILIKE ${param_idx}
            )"""
            params.append(search_pattern)
            param_idx += 1

        if seen_within_days:
            query += f" AND f.last_seen_at >= NOW() - INTERVAL '1 day' * ${param_idx}"
            params.append(seen_within_days)
            param_idx += 1

        if first_seen_within_days:
            query += f" AND f.first_seen_at >= NOW() - INTERVAL '1 day' * ${param_idx}"
            params.append(first_seen_within_days)
            param_idx += 1

        if resolved_within_days:
            query += f" AND f.resolved_at >= NOW() - INTERVAL '1 day' * ${param_idx}"
            params.append(resolved_within_days)
            param_idx += 1

        # Build ORDER BY clause based on sort_by parameter
        order_dir = "DESC" if sort_order == "desc" else "ASC"
        if sort_by == "first_seen":
            order_clause = f"f.first_seen_at {order_dir} NULLS LAST"
        elif sort_by == "last_seen":
            order_clause = f"f.last_seen_at {order_dir} NULLS LAST"
        elif sort_by == "cvss":
            order_clause = f"f.cvss_score {order_dir} NULLS LAST"
        else:
            severity_dir = "ASC" if sort_order == "desc" else "DESC"
            order_clause = """
                CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END""" + f" {severity_dir}, f.last_seen_at DESC NULLS LAST"

        # Open web-plane hunt candidates are an explicit compatibility opt-in. The default
        # findings contract remains authoritative findings only; candidates have their own
        # endpoint and UI. When requested, ordinary filters can still exclude them.
        candidates_included = (
            include_candidates
            and source_type in (None, "deep_hunt")
            and status in (None, "active")
            and not (
                scan_id or ai_target_id or device_target_id or verification_verdict
                or verification_mode or verified_only or driven_by
                or research_campaign_id or resolved_within_days
            )
        )

        if candidates_included:
            # The Python merge below applies offset/limit over the combined list, so the
            # findings side only needs the same bounded prefix window, not its own OFFSET.
            query += f"""
                ORDER BY {order_clause}
                LIMIT ${param_idx}
            """
            params.append(limit + offset)
        else:
            query += f"""
                ORDER BY {order_clause}
                LIMIT ${param_idx} OFFSET ${param_idx + 1}
            """
            params.extend([limit, offset])

        rows = await conn.fetch(query, *params)

        # `total_count` is identical on every row of the window. The empty
        # result set is ambiguous (truly no matches vs offset past end), so
        # only trust the window count when we got rows back. With offset > 0
        # and no rows we fall back to a dedicated COUNT(*) query so the UI
        # paginator can render correctly.
        if rows:
            total = rows[0]["total_count"]
        elif offset > 0:
            # Strip the window column from the SELECT, drop the LIMIT/OFFSET
            # parameters, and wrap as COUNT(*). The candidates path emits LIMIT only.
            count_sql, count_args = _strip_pagination_for_count(query, params)
            if candidates_included:
                count_args = params[:-1]
            total = await conn.fetchval(count_sql, *count_args) or 0
        else:
            total = 0

        candidates_total = 0
        candidate_items: list[dict[str, Any]] = []
        if candidates_included:
            candidate_query = f"""
                SELECT c.id, c.target_id, c.family, c.canonical_locus, c.title,
                       c.claimed_severity, c.evidence_refs, c.status,
                       c.first_seen_at, c.last_seen_at,
                       t.url AS target_url, t.name AS target_name, t.root_domain,
                       COUNT(*) OVER() AS total_count
                FROM investigation_candidates c
                LEFT JOIN targets t ON c.target_id = t.id
                WHERE c.plane = 'web'
                  AND c.status = ANY($1::text[])
                  AND (c.verification_context->>'finding_id') IS NULL
            """
            candidate_params: list = [list(_CANDIDATE_OPEN_STATUSES)]
            cand_idx = 2
            # Mirror the findings filters that candidates can satisfy.
            if severity:
                candidate_query += f" AND c.claimed_severity = ${cand_idx}"
                candidate_params.append(severity)
                cand_idx += 1
            if target_id:
                candidate_query += f" AND c.target_id = ${cand_idx}"
                candidate_params.append(uuid.UUID(target_id))
                cand_idx += 1
            if root_domain:
                candidate_query += f""" AND (
                    t.root_domain = ${cand_idx}
                    OR LOWER(t.url) LIKE '%' || LOWER(${cand_idx}) || '%'
                )"""
                candidate_params.append(root_domain)
                cand_idx += 1
            if search:
                candidate_query += f""" AND (
                    c.title ILIKE ${cand_idx}
                    OR c.claim ILIKE ${cand_idx}
                    OR t.url ILIKE ${cand_idx}
                )"""
                candidate_params.append(f"%{search}%")
                cand_idx += 1
            if seen_within_days:
                candidate_query += f" AND c.last_seen_at >= NOW() - INTERVAL '1 day' * ${cand_idx}"
                candidate_params.append(seen_within_days)
                cand_idx += 1
            if first_seen_within_days:
                candidate_query += f" AND c.first_seen_at >= NOW() - INTERVAL '1 day' * ${cand_idx}"
                candidate_params.append(first_seen_within_days)
                cand_idx += 1
            if sort_by == "first_seen":
                cand_order = f"c.first_seen_at {order_dir} NULLS LAST"
            elif sort_by == "last_seen":
                cand_order = f"c.last_seen_at {order_dir} NULLS LAST"
            else:
                # Candidates carry no CVSS; the merge re-sorts anyway, so fall back
                # to the default severity ordering for a deterministic page fetch.
                cand_severity_dir = "ASC" if sort_order == "desc" else "DESC"
                cand_order = f"""
                    CASE c.claimed_severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END {cand_severity_dir}, c.last_seen_at DESC NULLS LAST"""
            candidate_query += f"""
                ORDER BY {cand_order}
                LIMIT ${cand_idx}
            """
            candidate_params.append(limit + offset)
            candidate_rows = await conn.fetch(candidate_query, *candidate_params)
            if candidate_rows:
                candidates_total = candidate_rows[0]["total_count"]
            for cand_row in candidate_rows:
                cand_dict = dict(cand_row)
                cand_dict.pop("total_count", None)
                candidate_items.append(_candidate_to_pseudo_finding(cand_dict))

    findings_out = []
    for row in rows:
        row_dict = dict(row)
        row_dict.pop("total_count", None)
        # Single proof-state so the list distinguishes proven vs suspected at a
        # glance and agrees with the detail page (docs §7).
        row_dict.update(finding_proof_fields(row_dict))
        if not include_details:
            for key in _FINDING_DETAIL_ONLY_FIELDS:
                row_dict.pop(key, None)
        findings_out.append(row_dict)

    included_candidates = 0
    if candidates_included:
        page_items = _merge_findings_and_candidates(
            findings_out, candidate_items,
            sort_by=sort_by, sort_order=sort_order or "desc",
            limit=limit, offset=offset,
        )
        included_candidates = sum(1 for item in page_items if item.get("is_candidate"))
        total = total + candidates_total
    else:
        page_items = findings_out

    return {
        'findings': page_items,
        'total': total,
        'limit': limit,
        'offset': offset,
        'candidates_total': candidates_total,
        'included_candidates': included_candidates,
    }


@router.get("/findings/{finding_id}/evidence")
async def list_finding_evidence(finding_id: str):
    """Durable evidence objects (hash, redaction profile, retention class, storage
    URI) for a finding. Accepts a UUID OR a fingerprint, like the finding detail
    route, and returns 404 for an unknown id rather than 500 on a non-UUID."""
    async with _pool().acquire() as conn:
        finding = await get_finding_record(conn, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        rows = await conn.fetch(
            "SELECT * FROM evidence_objects WHERE finding_id = $1 ORDER BY created_at, object_type",
            finding["id"],
        )
    return {
        "finding_id": str(finding["id"]),
        "original_finding_scan_id": str(finding.get("first_seen_scan_id") or finding.get("scan_id") or "") or None,
        "latest_observation_scan_id": str(finding.get("last_seen_scan_id") or finding.get("scan_id") or "") or None,
        "evidence_objects": [_public_evidence_object_row(r) for r in rows],
    }


@router.get("/findings/{finding_id:path}")
async def get_finding(finding_id: str):
    """Get finding details by ID or fingerprint."""
    async with _pool().acquire() as conn:
        finding = await get_finding_record(conn, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

    result = dict(finding)
    # Same single proof-state the list uses, so list and detail never disagree (§7).
    result.update(finding_proof_fields(result))

    # Retest capability hints so the UI can gate the retest button instead of
    # surfacing a 400 after the click.
    if result.get("source") == "device" or result.get("device_target_id"):
        result["retest_supported"] = False
        result["retest_type"] = None
        result["retest_modes"] = []
        result["retest_unsupported_reason"] = "device_findings_are_retested_by_a_bounded_device_scan"
    elif result.get("source") == "ai_gate" or result.get("ai_target_id"):
        result["retest_supported"] = True
        result["retest_type"] = None
        result["retest_modes"] = ["same_probe", "same_family", "strict_replay"]
    else:
        evidence = parse_json_field(result.get("evidence"))
        retest_type = infer_retest_type(result, evidence)
        tool = str(result.get("tool") or "").lower()
        if retest_type:
            result["retest_supported"] = True
            result["retest_type"] = retest_type
            result["retest_modes"] = (
                ["tiered", "ai"] if retest_type in AI_ONLY_RETEST_TYPES
                else ["tiered", "deterministic", "ai"]
            )
        elif tool == "model_intake":
            result["retest_supported"] = False
            result["retest_type"] = None
            result["retest_modes"] = []
            result["retest_unsupported_reason"] = "model_intake"
        else:
            ai_settings = _load_effective_ai_settings()
            ai_ready = bool(
                ai_settings.get("ai_verify_enabled")
                and (ai_settings.get("ai_verify_url") or ai_settings.get("ai_url"))
                and (ai_settings.get("ai_verify_api_key") or ai_settings.get("ai_api_key"))
            )
            if ai_ready:
                result["retest_supported"] = True
                result["retest_type"] = "generic_http"
                result["retest_modes"] = ["ai"]
            else:
                result["retest_supported"] = False
                result["retest_type"] = None
                result["retest_modes"] = []
                result["retest_unsupported_reason"] = "no_deterministic_prover_and_ai_verification_disabled"

    return result


@router.post("/findings/{finding_id:path}/retest")
async def retest_finding(
    finding_id: str,
    request: FindingRetestRequest | None = None,
    mode: Optional[str] = Query(None, pattern="^(ai|deterministic)$"),
):
    """Queue a retest for a finding and persist verification history.

    Pass mode=ai to skip deterministic provers and go straight to AI verification.
    """
    request = request or FindingRetestRequest()
    r = get_redis()
    try:
        r.ping()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Retest queue unavailable: {e}")

    async with _pool().acquire() as conn:
        finding = await get_finding_record(conn, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        finding_data = dict(finding)
        if finding_data.get("source") == "device" or finding_data.get("device_target_id"):
            raise HTTPException(
                status_code=400,
                detail="Connected-device findings must be retested by an authorized bounded device scan.",
            )
        if finding_data.get("source") == "ai_gate" or finding_data.get("ai_target_id"):
            raise HTTPException(
                status_code=400,
                detail="AI Gate findings are not supported by the web retest endpoint; re-run the AI Gate target instead.",
            )
        retest_inputs = extract_retest_inputs(
            finding_data,
            override_type=request.finding_type,
            override_target=request.target,
            override_original_url=request.original_url,
            override_param=request.param,
            override_payload=request.payload,
            override_method=request.method,
            override_request_body=request.request_body,
        )

        if not retest_inputs.get("finding_type"):
            tool = str(finding_data.get("tool") or "").lower()
            if tool == "model_intake":
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "unsupported_finding_type",
                        "message": "Model Intake findings cannot be retested via HTTP replay; re-run the Model Intake scan for this artifact instead.",
                    },
                )

            # No deterministic prover for this finding. Fall back to the AI
            # verification tier (generic_http) when an AI verifier is configured.
            ai_settings = _load_effective_ai_settings()
            ai_ready = bool(
                ai_settings.get("ai_verify_enabled")
                and (ai_settings.get("ai_verify_url") or ai_settings.get("ai_url"))
                and (ai_settings.get("ai_verify_api_key") or ai_settings.get("ai_api_key"))
            )
            if not ai_ready:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "unsupported_finding_type",
                        "message": (
                            "Could not infer a deterministic retest type from this finding, "
                            "and AI verification is not configured. Enable AI verification in "
                            "AI settings to retest this finding type."
                        ),
                        "supported_types": list(SUPPORTED_RETEST_TYPES),
                    },
                )
            if mode == "deterministic":
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "no_deterministic_prover",
                        "message": "This finding has no deterministic prover; retest it in tiered or AI mode.",
                    },
                )
            retest_inputs["finding_type"] = "generic_http"
            # Force the AI tier so an explicit user retest is not silently
            # skipped by the severity-based AI escalation gate.
            mode = "ai"

        if not retest_inputs.get("target_url"):
            raise HTTPException(
                status_code=400,
                detail="Finding is missing target URL context required for retest"
            )

        approval_context = await _validate_approval_receipt_for_action(
            conn,
            request.approval_receipt_id,
            target_url=retest_inputs.get("target_url"),
            target_id=finding_data.get("target_id"),
            action_name="finding.retest",
        )

        retest_id, job_id = await enqueue_finding_retest(
            conn,
            finding_data,
            retest_inputs,
            requested_by=request.requested_by or "api",
        )

    job_data = build_retest_job_payload(
        job_id=job_id,
        verification_id=str(retest_id),
        finding_id=str(finding_data["id"]),
        submitted_at=utc_now_iso(),
        trigger=request.requested_by or "api",
    )
    # Pass mode through to the worker
    if mode:
        job_data["mode"] = mode
    if approval_context:
        job_data.update(approval_context)
    valid, reason = validate_retest_job_payload(job_data)
    if not valid:
        async with _pool().acquire() as conn:
            await mark_retest_enqueue_failed(
                conn,
                verification_id=retest_id,
                finding_id=finding_data["id"],
                error_message=f"Retest job payload failed contract validation: {reason}",
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error": "invalid_retest_job_payload",
                "message": "Retest job payload failed contract validation",
                "reason": reason,
            },
        )
    async with _pool().acquire() as conn:
        command_result = await _record_command_result(
            conn,
            command="finding.retest",
            status="retest_scheduled",
            risk_tier="active",
            finding_ids=[str(finding_data["id"])],
            scope_receipt_id=approval_context.get("scope_receipt_id") if approval_context else None,
            approval_receipt_id=approval_context.get("approval_receipt_id") if approval_context else None,
            operator_message=f"Queued retest for finding {finding_data.get('title') or finding_data['id']}",
            result_json={
                "finding_id": str(finding_data["id"]),
                "retest_id": str(retest_id),
                "job_id": job_id,
                "mode": mode or "tiered",
                "finding_type": retest_inputs.get("finding_type"),
                "target_url": retest_inputs.get("target_url"),
            },
            next_action=f"/findings/{finding_data['id']}",
            created_by=request.requested_by or "api",
        )
    try:
        enqueue_job(r, RETEST_QUEUE_NAME, job_data)
    except Exception as e:
        async with _pool().acquire() as conn:
            await mark_retest_enqueue_failed(
                conn,
                verification_id=retest_id,
                finding_id=finding_data["id"],
                error_message=f"Retest queue enqueue failed: {type(e).__name__}: {e}",
            )
        raise HTTPException(status_code=503, detail=f"Retest queue unavailable: {e}")
    try:
        r.hset(
            f"retest_job:{job_id}",
            mapping={
                "status": "queued",
                "verification_id": str(retest_id),
                "finding_id": str(finding_data["id"]),
                "queue_schema_version": str(job_data.get("queue_schema_version", "")),
            },
        )
        r.expire(f"retest_job:{job_id}", 86400)
    except Exception:
        # Non-critical metadata cache write; queue already has the job.
        pass

    return {
        "retest_id": str(retest_id),
        "job_id": job_id,
        "status": "queued",
        "mode": mode or "tiered",
        "finding_id": str(finding_data["id"]),
        "finding_type": retest_inputs["finding_type"],
        "target_url": retest_inputs["target_url"],
        "replay_commands": build_replay_commands(retest_inputs),
        "approval_receipt_id": approval_context.get("approval_receipt_id") if approval_context else None,
        "scope_receipt_id": approval_context.get("scope_receipt_id") if approval_context else None,
        "operation_id": command_result["id"],
    }


@router.post("/findings/retest")
async def bulk_retest_findings(request: FindingsBulkRetestRequest):
    """Queue retests for multiple findings by IDs or filters."""
    if request.mode and request.mode not in {"ai", "deterministic"}:
        raise HTTPException(status_code=400, detail="mode must be 'ai' or 'deterministic'")

    r = get_redis()
    try:
        r.ping()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Retest queue unavailable: {e}")

    queued: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    async with _pool().acquire() as conn:
        # Early missing-receipt guard before any retest is queued.
        await _require_approval_receipt_if_policy_enabled(
            conn,
            request.approval_receipt_id,
            action_name="finding.bulk_retest",
        )
        findings: list[Any] = []

        if request.finding_ids:
            for fid in request.finding_ids:
                finding = await get_finding_record(conn, fid)
                if finding:
                    findings.append(finding)
                else:
                    skipped.append({"finding_id": fid, "reason": "not_found"})
        else:
            scoped = any([
                request.severity,
                request.status,
                request.target_id,
                request.scan_id,
                request.root_domain,
                request.search,
            ])
            if not scoped:
                raise HTTPException(
                    status_code=400,
                    detail="Provide finding_ids or at least one filter to scope bulk retest request"
                )

            query = """
                SELECT f.*,
                       COALESCE(t.url, ait.endpoint_url) as target_url,
                       COALESCE(t.name, ait.name) as target_name,
                       t.root_domain,
                       ait.endpoint_url as ai_target_url,
                       ait.name as ai_target_name
                FROM findings f
                LEFT JOIN targets t ON f.target_id = t.id
                LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
                WHERE 1=1
            """
            params: list[Any] = []
            idx = 1

            if request.severity:
                query += f" AND f.severity = ${idx}"
                params.append(request.severity)
                idx += 1
            if request.status:
                query += f" AND f.status = ${idx}"
                params.append(request.status)
                idx += 1
            else:
                query += " AND f.status = 'active'"
            if request.target_id:
                try:
                    target_uuid = uuid.UUID(request.target_id)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid target_id")
                query += f" AND f.target_id = ${idx}"
                params.append(target_uuid)
                idx += 1
            if request.scan_id:
                try:
                    scan_uuid = uuid.UUID(request.scan_id)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid scan_id")
                query += f" AND f.scan_id = ${idx}"
                params.append(scan_uuid)
                idx += 1
            if request.root_domain:
                query += f" AND t.root_domain = ${idx}"
                params.append(request.root_domain)
                idx += 1
            if request.search:
                query += f""" AND (
                    f.title ILIKE ${idx}
                    OR f.url ILIKE ${idx}
                    OR t.url ILIKE ${idx}
                    OR ait.endpoint_url ILIKE ${idx}
                    OR ait.name ILIKE ${idx}
                )"""
                params.append(f"%{request.search}%")
                idx += 1

            query += f"""
                ORDER BY
                    CASE f.severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    f.last_seen_at DESC
                LIMIT ${idx}
            """
            params.append(request.limit)
            findings = await conn.fetch(query, *params)

        queue_failed_at: int | None = None
        queue_error: str | None = None
        for idx, row in enumerate(findings):
            finding_data = dict(row)
            if finding_data.get("source") == "device" or finding_data.get("device_target_id"):
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": "device_findings_require_device_rescan",
                })
                continue
            if finding_data.get("source") == "ai_gate" or finding_data.get("ai_target_id"):
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": "ai_gate_findings_require_ai_gate_rescan",
                })
                continue
            retest_inputs = extract_retest_inputs(
                finding_data,
                override_type=request.finding_type,
            )

            if not retest_inputs.get("finding_type"):
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": "unsupported_type",
                })
                continue
            if not retest_inputs.get("target_url"):
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": "missing_target_url",
                })
                continue
            try:
                approval_context = await _validate_approval_receipt_for_action(
                    conn,
                    request.approval_receipt_id,
                    target_url=retest_inputs.get("target_url"),
                    target_id=finding_data.get("target_id"),
                    action_name="finding.bulk_retest",
                    # One aggregate audit row covers the batch; skip per-finding
                    # blocked rows to avoid flooding the timeline.
                    record_blocked=False,
                )
            except HTTPException as exc:
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": f"approval_receipt_invalid:{exc.detail}",
                })
                continue

            try:
                retest_id, job_id = await enqueue_finding_retest(
                    conn,
                    finding_data,
                    retest_inputs,
                    requested_by=request.requested_by or "api",
                )
            except HTTPException as exc:
                detail = exc.detail if isinstance(exc.detail, dict) else {}
                if exc.status_code != 409 or detail.get("error") != "finding_retest_already_active":
                    raise
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": "retest_already_active",
                    "retest_id": detail.get("retest_id"),
                })
                continue

            job_data = build_retest_job_payload(
                job_id=job_id,
                verification_id=str(retest_id),
                finding_id=str(finding_data["id"]),
                submitted_at=utc_now_iso(),
                trigger=request.requested_by or "api",
            )
            if request.mode:
                job_data["mode"] = request.mode
            if approval_context:
                job_data.update(approval_context)
            valid, reason = validate_retest_job_payload(job_data)
            if not valid:
                await mark_retest_enqueue_failed(
                    conn,
                    verification_id=retest_id,
                    finding_id=finding_data["id"],
                    error_message=f"Retest job payload failed contract validation: {reason}",
                )
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": f"invalid_job_payload:{reason}",
                })
                continue
            try:
                enqueue_job(r, RETEST_QUEUE_NAME, job_data)
            except Exception as e:
                await mark_retest_enqueue_failed(
                    conn,
                    verification_id=retest_id,
                    finding_id=finding_data["id"],
                    error_message=f"Retest queue enqueue failed: {type(e).__name__}: {e}",
                )
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": "queue_unavailable",
                })
                queue_failed_at = idx
                queue_error = f"{type(e).__name__}: {e}"
                break
            try:
                r.hset(
                    f"retest_job:{job_id}",
                    mapping={
                        "status": "queued",
                        "verification_id": str(retest_id),
                        "finding_id": str(finding_data["id"]),
                        "queue_schema_version": str(job_data.get("queue_schema_version", "")),
                    },
                )
                r.expire(f"retest_job:{job_id}", 86400)
            except Exception:
                # Non-critical metadata cache write; queue already has the job.
                pass

            queued.append({
                "finding_id": str(finding_data["id"]),
                "retest_id": str(retest_id),
                "job_id": job_id,
                "finding_type": retest_inputs["finding_type"],
                "replay_commands": build_replay_commands(retest_inputs),
                "approval_receipt_id": approval_context.get("approval_receipt_id") if approval_context else None,
                "scope_receipt_id": approval_context.get("scope_receipt_id") if approval_context else None,
            })

        if queue_failed_at is not None:
            for remaining in findings[queue_failed_at + 1:]:
                skipped.append({
                    "finding_id": str(remaining["id"]),
                    "reason": "queue_unavailable",
                })
            if not queued:
                raise HTTPException(status_code=503, detail=f"Retest queue unavailable: {queue_error or 'unknown error'}")

        command_result = None
        if queued:
            first_receipt = next(
                (
                    item
                    for item in queued
                    if item.get("approval_receipt_id") or item.get("scope_receipt_id")
                ),
                {},
            )
            command_result = await _record_command_result(
                conn,
                command="finding.bulk_retest",
                status="partial" if skipped else "retest_scheduled",
                risk_tier="active",
                finding_ids=[item["finding_id"] for item in queued],
                scope_receipt_id=first_receipt.get("scope_receipt_id"),
                approval_receipt_id=first_receipt.get("approval_receipt_id"),
                blocked_by=sorted({item["reason"] for item in skipped if item.get("reason")}),
                operator_message=f"Queued {len(queued)} finding retest(s); skipped {len(skipped)}",
                result_json={
                    "mode": request.mode or "tiered",
                    "queued_count": len(queued),
                    "skipped_count": len(skipped),
                    "filters": {
                        "severity": request.severity,
                        "status": request.status,
                        "target_id": request.target_id,
                        "scan_id": request.scan_id,
                        "root_domain": request.root_domain,
                        "search": request.search,
                        "limit": request.limit,
                    },
                    "queued_retests": [
                        {
                            "finding_id": item["finding_id"],
                            "retest_id": item["retest_id"],
                            "job_id": item["job_id"],
                            "finding_type": item["finding_type"],
                        }
                        for item in queued
                    ],
                    "skipped": skipped,
                },
                next_action="/findings",
                created_by=request.requested_by or "api",
            )
        elif skipped:
            # Nothing was queued: record a durable "blocked" audit row so the
            # entirely-skipped batch is not invisible in the timeline.
            command_result = await _record_blocked_command_result(
                conn,
                action_name="finding.bulk_retest",
                blocked_by=sorted({item["reason"] for item in skipped if item.get("reason")}),
                operator_message=f"Blocked finding.bulk_retest: 0 queued, {len(skipped)} skipped",
                risk_tier="active",
            )

    response = {
        "status": "queued" if queued else "blocked",
        "mode": request.mode or "tiered",
        "queued_count": len(queued),
        "skipped_count": len(skipped),
        "queued": queued,
        "skipped": skipped,
    }
    if command_result:
        response["operation_id"] = command_result["id"]
    return response


async def _refresh_web_active_finding_counts(conn: Any, target_ids: Sequence[Any]) -> None:
    normalized = sorted({item for item in target_ids if item is not None}, key=str)
    if not normalized:
        return
    await conn.execute(
        """UPDATE targets t
           SET active_findings_count=(
               SELECT COUNT(*) FROM findings f
               WHERE f.target_id=t.id AND f.status='active'
           ), updated_at=NOW()
           WHERE t.id=ANY($1::uuid[])""",
        normalized,
    )


async def _refresh_finding_owner_counts(conn: Any, rows: Sequence[Any]) -> None:
    await _refresh_web_active_finding_counts(
        conn, [row["target_id"] for row in rows]
    )
    await _refresh_device_active_finding_counts(
        conn, [row["device_target_id"] for row in rows]
    )


@router.patch("/findings/{finding_id:path}")
async def update_finding(
    finding_id: str,
    request: FindingUpdate,
    scan_id: Optional[str] = Query(None, description="Scope update to specific scan")
):
    """Update a finding status by ID or fingerprint.

    Lookup order:
    1. UUID (exact match)
    2. Full scanner ID as fingerprint (new format: "tool:hash")
    3. Suffix-only fingerprint (backward compat)
    4. Legacy computed fingerprint (pre-change findings)

    Pass scan_id to scope updates to a specific scan and prevent cross-target collisions.
    """
    async with _pool().acquire() as conn:
        updated_id = None
        scan_uuid = None
        if scan_id:
            try:
                scan_uuid = uuid.UUID(scan_id)
            except ValueError:
                pass

        # Try UUID first
        try:
            finding_uuid = uuid.UUID(finding_id)
            result = await conn.fetchrow("""
                UPDATE findings
                SET status = $1,
                    resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                       WHEN $1 = 'active' THEN NULL
                                       ELSE resolved_at END,
                    notes = COALESCE($2, notes),
                    analyst_verdict = COALESCE($3, analyst_verdict),
                    analyst_verdict_at = CASE WHEN $3 IS NULL THEN analyst_verdict_at ELSE NOW() END,
                    analyst_verdict_notes = CASE WHEN $3 IS NULL THEN analyst_verdict_notes ELSE COALESCE($2, analyst_verdict_notes) END,
                    updated_at = NOW()
                WHERE id = $4
                RETURNING id, target_id, device_target_id
            """, request.status, request.notes, request.analyst_verdict, finding_uuid)
            if result:
                updated_id = result['id']
        except ValueError:
            pass

        # Try full scanner ID as fingerprint (new format: "tool:hash")
        if not updated_id:
            if scan_uuid:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1,
                        resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                           WHEN $1 = 'active' THEN NULL
                                           ELSE resolved_at END,
                        notes = COALESCE($2, notes),
                        analyst_verdict = COALESCE($3, analyst_verdict),
                        analyst_verdict_at = CASE WHEN $3 IS NULL THEN analyst_verdict_at ELSE NOW() END,
                        analyst_verdict_notes = CASE WHEN $3 IS NULL THEN analyst_verdict_notes ELSE COALESCE($2, analyst_verdict_notes) END,
                        updated_at = NOW()
                    WHERE fingerprint = $4 AND scan_id = $5
                    RETURNING id, target_id, device_target_id
                """, request.status, request.notes, request.analyst_verdict, finding_id, scan_uuid)
            else:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1,
                        resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                           WHEN $1 = 'active' THEN NULL
                                           ELSE resolved_at END,
                        notes = COALESCE($2, notes),
                        analyst_verdict = COALESCE($3, analyst_verdict),
                        analyst_verdict_at = CASE WHEN $3 IS NULL THEN analyst_verdict_at ELSE NOW() END,
                        analyst_verdict_notes = CASE WHEN $3 IS NULL THEN analyst_verdict_notes ELSE COALESCE($2, analyst_verdict_notes) END,
                        updated_at = NOW()
                    WHERE id = (
                        SELECT id FROM findings WHERE fingerprint = $4
                        ORDER BY last_seen_at DESC LIMIT 1
                    )
                    RETURNING id, target_id, device_target_id
                """, request.status, request.notes, request.analyst_verdict, finding_id)
            if result:
                updated_id = result['id']

        # Backward compat: try suffix-only for old findings
        if not updated_id and ':' in finding_id:
            suffix = finding_id.split(':')[-1]
            if scan_uuid:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1,
                        resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                           WHEN $1 = 'active' THEN NULL
                                           ELSE resolved_at END,
                        notes = COALESCE($2, notes),
                        analyst_verdict = COALESCE($3, analyst_verdict),
                        analyst_verdict_at = CASE WHEN $3 IS NULL THEN analyst_verdict_at ELSE NOW() END,
                        analyst_verdict_notes = CASE WHEN $3 IS NULL THEN analyst_verdict_notes ELSE COALESCE($2, analyst_verdict_notes) END,
                        updated_at = NOW()
                    WHERE fingerprint = $4 AND scan_id = $5
                    RETURNING id, target_id, device_target_id
                """, request.status, request.notes, request.analyst_verdict, suffix, scan_uuid)
            else:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1,
                        resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                           WHEN $1 = 'active' THEN NULL
                                           ELSE resolved_at END,
                        notes = COALESCE($2, notes),
                        analyst_verdict = COALESCE($3, analyst_verdict),
                        analyst_verdict_at = CASE WHEN $3 IS NULL THEN analyst_verdict_at ELSE NOW() END,
                        analyst_verdict_notes = CASE WHEN $3 IS NULL THEN analyst_verdict_notes ELSE COALESCE($2, analyst_verdict_notes) END,
                        updated_at = NOW()
                    WHERE id = (
                        SELECT id FROM findings WHERE fingerprint = $4
                        ORDER BY last_seen_at DESC LIMIT 1
                    )
                    RETURNING id, target_id, device_target_id
                """, request.status, request.notes, request.analyst_verdict, suffix)
            if result:
                updated_id = result['id']

        if not updated_id:
            raise HTTPException(status_code=404, detail="Finding not found")
        await _refresh_finding_owner_counts(conn, [result])

    return {'id': str(updated_id), 'status': request.status, 'analyst_verdict': request.analyst_verdict}


@router.delete("/findings/{finding_id:path}")
async def delete_finding(finding_id: str):
    """Delete a finding by ID or fingerprint."""
    async with _pool().acquire() as conn:
        deleted_id = None

        # Try UUID first
        try:
            finding_uuid = uuid.UUID(finding_id)
            result = await conn.fetchrow(
                "DELETE FROM findings WHERE id = $1 RETURNING id, target_id, device_target_id", finding_uuid
            )
            if result:
                deleted_id = result['id']
        except ValueError:
            pass

        # Try fingerprint
        if not deleted_id:
            result = await conn.fetchrow("""
                DELETE FROM findings
                WHERE id = (
                    SELECT id FROM findings WHERE fingerprint = $1
                    ORDER BY last_seen_at DESC LIMIT 1
                )
                RETURNING id, target_id, device_target_id
            """, finding_id)
            if result:
                deleted_id = result['id']

        # Backward compat: suffix-only
        if not deleted_id and ':' in finding_id:
            suffix = finding_id.split(':')[-1]
            result = await conn.fetchrow("""
                DELETE FROM findings
                WHERE id = (
                    SELECT id FROM findings WHERE fingerprint = $1
                    ORDER BY last_seen_at DESC LIMIT 1
                )
                RETURNING id, target_id, device_target_id
            """, suffix)
            if result:
                deleted_id = result['id']

        if not deleted_id:
            raise HTTPException(status_code=404, detail="Finding not found")
        await _refresh_finding_owner_counts(conn, [result])

    return {'id': str(deleted_id), 'status': 'deleted'}


class FindingsCleanup(BaseModel):
    older_than_days: int = Field(..., ge=1)
    status: Optional[str] = None
    root_domain: Optional[str] = None
    dry_run: bool = True


@router.post("/findings/cleanup")
async def cleanup_findings(request: FindingsCleanup):
    """Delete old findings by age, optionally filtered by status and domain."""
    async with _pool().acquire() as conn:
        where = "f.last_seen_at < NOW() - INTERVAL '1 day' * $1"
        params: list = [request.older_than_days]
        idx = 2

        if request.status:
            where += f" AND f.status = ${idx}"
            params.append(request.status)
            idx += 1

        if request.root_domain:
            where += f" AND t.root_domain = ${idx}"
            params.append(request.root_domain)
            idx += 1

        if request.dry_run:
            count = await conn.fetchval(f"""
                SELECT COUNT(*)
                FROM findings f
                LEFT JOIN targets t ON f.target_id = t.id
                WHERE {where}
            """, *params)
            return {'would_delete': count, 'dry_run': True}
        else:
            # Use subquery to select IDs, then delete by ID
            ids = await conn.fetch(f"""
                SELECT f.id, f.target_id, f.device_target_id
                FROM findings f
                LEFT JOIN targets t ON f.target_id = t.id
                WHERE {where}
            """, *params)
            if ids:
                id_list = [r['id'] for r in ids]
                await conn.execute(
                    "DELETE FROM findings WHERE id = ANY($1)", id_list
                )
                await _refresh_finding_owner_counts(conn, ids)
            return {'deleted': len(ids), 'dry_run': False}


class BulkFindingUpdateRequest(BaseModel):
    """Body for POST /findings/bulk.

    Audit P2-2: the handler previously took bare `finding_ids: list[str], status: str` params, which
    FastAPI binds to the QUERY string — so the JSON body documented in AGENTS.md returned 422. A model
    makes the documented `{"finding_ids":[...],"status":"...","notes":"..."}` body work as written.
    """
    finding_ids: list[str] = Field(min_length=1, max_length=500)
    status: str
    notes: Optional[str] = None


@router.post("/findings/bulk")
async def bulk_update_findings(request: BulkFindingUpdateRequest):
    """Bulk update finding statuses."""
    valid_statuses = {"active", "resolved", "false_positive", "accepted_risk"}
    if request.status not in valid_statuses:
        raise HTTPException(status_code=400,
                            detail=f"Invalid status. Must be one of: {', '.join(sorted(valid_statuses))}")
    try:
        ids = list(dict.fromkeys(uuid.UUID(fid) for fid in request.finding_ids))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=400, detail="finding_ids must all be valid UUIDs")
    async with _pool().acquire() as conn:
        updated_rows = await conn.fetch("""
            UPDATE findings
            SET status = $1,
                resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                   WHEN $1 = 'active' THEN NULL
                                   ELSE resolved_at END,
                notes = COALESCE($2, notes),
                updated_at = NOW()
            WHERE id = ANY($3)
            RETURNING id, target_id, device_target_id
        """, request.status, request.notes, ids)
        await _refresh_finding_owner_counts(conn, updated_rows)

    return {
        'updated': len(updated_rows),
        'requested': len(request.finding_ids),
        'unique_requested': len(ids),
        'not_found': max(0, len(ids) - len(updated_rows)),
        'status': request.status,
    }


@router.post("/findings/manual")
async def create_manual_finding(request: ManualFindingCreate):
    """
    Create a finding from manual testing.

    Use this endpoint to record vulnerabilities discovered during manual
    penetration testing, bug bounty hunting, or AI-assisted security sessions.

    The finding will be linked to the target (created if it doesn't exist).
    """
    # Validate severity
    valid_severities = ['critical', 'high', 'medium', 'low', 'info']
    if request.severity.lower() not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )

    # Normalize target URL
    from urllib.parse import urlparse
    target_url = request.target.strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = f"https://{target_url}"

    parsed = urlparse(target_url)
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid target URL")

    # Normalize to origin (scheme + host)
    normalized_target = f"{parsed.scheme}://{parsed.netloc}"

    # Generate fingerprint for deduplication
    fingerprint_source = f"{normalized_target}:{request.title}:{request.severity}"
    if request.url:
        fingerprint_source += f":{request.url}"
    fingerprint = hashlib.sha256(fingerprint_source.encode()).hexdigest()[:32]

    async with _pool().acquire() as conn:
        # Get or create target
        target = await conn.fetchrow(
            "SELECT id FROM targets WHERE url = $1",
            normalized_target
        )

        if target:
            target_id = target['id']
        else:
            # Create new target
            target_id = await conn.fetchval("""
                INSERT INTO targets (url, name, root_domain, discovery_source, asm_enabled, asm_config)
                VALUES ($1, $2, $3, 'manual', $4, $5)
                ON CONFLICT (canonical_key) DO UPDATE SET url = targets.url
                RETURNING id
            """, normalized_target, parsed.hostname, parsed.hostname,
                 _default_asm_enabled_for_new_web_target("manual"),
                 json.dumps(_default_asm_config_for_new_web_target("manual")))

        # Check for existing finding with same fingerprint
        existing = await conn.fetchrow(
            "SELECT id, status FROM findings WHERE fingerprint = $1 AND target_id = $2",
            fingerprint, target_id
        )

        if existing:
            # Update last_seen and potentially resurface
            if existing['status'] == 'resolved':
                await conn.execute("""
                    UPDATE findings
                    SET status = 'active', last_seen_at = NOW(),
                        resurfaced_count = resurfaced_count + 1, updated_at = NOW()
                    WHERE id = $1
                """, existing['id'])
                await _refresh_web_active_finding_counts(conn, [target_id])
                return {
                    'id': str(existing['id']),
                    'fingerprint': fingerprint,
                    'status': 'resurfaced',
                    'message': 'Existing finding resurfaced'
                }
            else:
                await conn.execute(
                    "UPDATE findings SET last_seen_at = NOW() WHERE id = $1",
                    existing['id']
                )
                return {
                    'id': str(existing['id']),
                    'fingerprint': fingerprint,
                    'status': 'duplicate',
                    'message': 'Finding already exists'
                }

        # Build evidence JSON if provided. Redact live auth material (bearer
        # tokens, JWTs, auth headers/cookies) the same way scanner findings are
        # sanitised in save_findings_from_partial — manual/session evidence
        # captured during interactive testing routinely carries live credentials
        # we must never persist (they leak via the API/UI and outlive the
        # engagement).
        evidence_json = None
        if request.evidence or request.remediation:
            evidence_json = {}
            if request.evidence:
                evidence_json['proof'] = request.evidence
            if request.remediation:
                evidence_json['remediation'] = request.remediation
            evidence_json = _redact_finding_evidence(evidence_json)
        redacted_request = _redact_finding_evidence(request.request)
        redacted_response = _redact_finding_evidence(request.response)

        # Create new finding
        finding_id = await conn.fetchval("""
            INSERT INTO findings (
                target_id, fingerprint, title, description, severity,
                cvss_score, tool, cwe, url, evidence, request, response,
                notes, source, status
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'manual', 'active'
            )
            RETURNING id
        """,
            target_id,
            fingerprint,
            request.title,
            request.description,
            request.severity.lower(),
            request.cvss_score,
            request.category or 'manual',
            request.cwe,
            request.url or normalized_target,
            json.dumps(evidence_json) if evidence_json else None,
            redacted_request,
            redacted_response,
            request.notes
        )

        # Update target finding count
        await conn.execute("""
            UPDATE targets SET
                active_findings_count = (
                    SELECT COUNT(*) FROM findings
                    WHERE target_id = $1 AND status = 'active'
                ),
                updated_at = NOW()
            WHERE id = $1
        """, target_id)

    return {
        'id': str(finding_id),
        'fingerprint': fingerprint,
        'target_id': str(target_id),
        'target': normalized_target,
        'status': 'created',
        'message': 'Finding created successfully'
    }
_FINDING_SEVERITY_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}


async def _refresh_device_active_finding_counts(conn: Any, device_ids: Sequence[Any]) -> None:
    normalized = sorted({item for item in device_ids if item is not None}, key=str)
    if not normalized:
        return
    await conn.execute(
        """UPDATE device_targets d
           SET active_findings_count=(
               SELECT COUNT(*) FROM findings f
               WHERE f.device_target_id=d.id AND f.status='active'
           ), updated_at=NOW()
           WHERE d.id=ANY($1::uuid[])""",
        normalized,
    )
async def enqueue_finding_retest(
    conn,
    finding: dict[str, Any],
    inputs: dict[str, Any],
    requested_by: str = "api",
    auth_context: dict[str, str] | None = None,
):
    """Create at most one active retest per finding across API replicas."""
    lock_key = f"finding-retest:{finding['id']}"
    await conn.fetchval("SELECT pg_advisory_lock(hashtextextended($1, 0))", lock_key)
    try:
        active = await conn.fetchrow(
            """
            SELECT id, status FROM finding_verifications
            WHERE finding_id=$1 AND status IN ('queued','running')
            ORDER BY created_at DESC LIMIT 1
            """,
            finding["id"],
        )
        if active:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "finding_retest_already_active",
                    "retest_id": str(active["id"]),
                    "status": str(active["status"]),
                },
            )
        return await _enqueue_finding_retest_unlocked(
            conn,
            finding,
            inputs,
            requested_by=requested_by,
            auth_context=auth_context,
        )
    finally:
        try:
            await conn.fetchval("SELECT pg_advisory_unlock(hashtextextended($1, 0))", lock_key)
        except Exception:
            # PostgreSQL releases session locks when a broken connection closes. Never mask the
            # original queue/validation failure with an unlock error.
            pass


async def _enqueue_finding_retest_unlocked(
    conn,
    finding: dict[str, Any],
    inputs: dict[str, Any],
    requested_by: str = "api",
    auth_context: dict[str, str] | None = None,
):
    """Insert a queued retest while the per-finding advisory lock is held."""
    retest_id = uuid.uuid4()
    job_id = str(uuid.uuid4())
    replay_commands = build_replay_commands(inputs)

    # If no auth_context provided, try to pull from the finding's scan
    if auth_context is None and finding.get("scan_id"):
        scan_row = await conn.fetchrow(
            "SELECT options FROM scans WHERE id = $1", finding["scan_id"]
        )
        if scan_row:
            auth_context = extract_auth_context(parse_json_field(scan_row["options"]))

    auth_ctx_json = json.dumps(auth_context) if auth_context else None
    campaign_id = None
    if finding.get("target_id"):
        try:
            campaign_id = await asm_inventory.create_campaign(
                conn,
                str(finding["target_id"]),
                mode=asm_inventory.CAMPAIGN_FINDING_RETEST,
                requested_by=requested_by or "api",
                priority=90,
                check_families=[str(inputs.get("finding_type") or "generic_http")],
                metadata_json={
                    "finding_id": str(finding["id"]),
                    "source_scan_id": str(finding.get("scan_id") or ""),
                    "target_url": str(inputs.get("target_url") or ""),
                    "original_url": str(inputs.get("original_url") or ""),
                    "method": str(inputs.get("method") or ""),
                    "param": str(inputs.get("param") or ""),
                },
            )
        except Exception:
            campaign_id = None

    await conn.execute("""
        INSERT INTO finding_verifications (
            id, finding_id, scan_id, target_id, job_id, requested_by, status,
            finding_type, target_url, original_url, param, payload, method, request_body,
            replay_commands, auth_context, campaign_id
        ) VALUES (
            $1, $2, $3, $4, $5, $6, 'queued',
            $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
        )
    """,
        retest_id,
        finding["id"],
        finding.get("scan_id"),
        finding.get("target_id"),
        job_id,
        requested_by or "api",
        inputs["finding_type"],
        inputs["target_url"],
        inputs.get("original_url"),
        inputs.get("param"),
        inputs.get("payload"),
        inputs.get("method"),
        inputs.get("request_body"),
        json.dumps(replay_commands) if replay_commands else None,
        auth_ctx_json,
        uuid.UUID(str(campaign_id)) if campaign_id else None,
    )

    await conn.execute("""
        UPDATE findings
        SET last_verification_status = 'queued',
            last_verification_verdict = NULL,
            updated_at = NOW()
        WHERE id = $1
    """, finding["id"])

    return retest_id, job_id


async def mark_retest_enqueue_failed(
    conn,
    *,
    verification_id: uuid.UUID,
    finding_id: uuid.UUID,
    error_message: str,
):
    """Mark a queued retest as failed when it cannot be enqueued to Redis."""
    reason = (error_message or "Queue enqueue failed").strip()
    await conn.execute(
        """
        UPDATE finding_verifications
        SET status = 'failed',
            result_status = 'error',
            verdict = 'error',
            verdict_reason = $2,
            attempts_exhausted = TRUE,
            retry_class = 'transient',
            retryable = FALSE,
            error_message = $2,
            completed_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        """,
        verification_id,
        reason,
    )
    await conn.execute(
        """
        UPDATE findings
        SET last_verification_status = 'error',
            last_verification_verdict = 'error',
            last_verification_confidence = NULL,
            last_verified_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        """,
        finding_id,
    )
def finding_proof_fields(finding: dict[str, Any]) -> dict[str, Any]:
    """Derive a single proof state for a finding so the list and detail agree.

    A High/Critical lead shown at full severity is the trust problem (docs §7):
    `is_verified` is the ONE boolean (deterministic proof == verdict 'exploited');
    `is_suspected` marks explicit candidate evidence at every severity, plus any
    unproven High/Critical that must render as "suspected" with a visible badge
    in the findings LIST, not only the detail page. Neither case counts as
    deterministic proof in the headline grade.
    """
    fields = _scan_time_verification_fields(finding) or {}
    scan_time_verdict = str(fields.get("last_verification_verdict") or "").lower()
    persisted_verdict = str(finding.get("last_verification_verdict") or "").lower()
    latest_retest_mode = str(finding.get("latest_retest_mode") or "").lower()
    # DB rows use the persisted verdict; report-sourced rows must carry typed
    # deterministic proof. A generic legacy `verified: true` flag is not enough.
    is_verified = (
        scan_time_verdict == "exploited"
        or (
            persisted_verdict == "exploited"
            and latest_retest_mode == "deterministic"
        )
    )
    severity = str(finding.get("severity") or "").lower()
    is_high_crit = severity in ("high", "critical")
    evidence = _json_object(finding.get("evidence"))
    triage = _json_object(evidence.get("triage"))
    evidence_proof_state = str(
        finding.get("proof_state")
        or evidence.get("proof_state")
        or triage.get("proof_state")
        or ""
    ).strip().lower()
    explicit_candidate = (
        finding.get("suspected") is True
        or finding.get("needs_verification") is True
        or triage.get("suspected") is True
        or triage.get("needs_verification") is True
        or evidence_proof_state in {
            "candidate", "suspected", "likely_vulnerable", "needs_review",
        }
    )
    is_suspected = not is_verified and (is_high_crit or explicit_candidate)
    return {
        "is_verified": is_verified,
        "is_suspected": is_suspected,
        "proof_state": "verified" if is_verified else ("suspected" if is_suspected else "unverified"),
    }


def extract_retest_inputs(
    finding: dict[str, Any],
    override_type: str | None = None,
    override_target: str | None = None,
    override_original_url: str | None = None,
    override_param: str | None = None,
    override_payload: str | None = None,
    override_method: str | None = None,
    override_request_body: str | None = None,
) -> dict[str, Any]:
    evidence = parse_json_field(finding.get("evidence"))
    finding_type = infer_retest_type(finding, evidence, override_type=override_type)
    autonomous = evidence.get("autonomous_workflow") if isinstance(evidence.get("autonomous_workflow"), dict) else {}
    dimensions = (
        evidence.get("canonical_vulnerability_dimensions")
        if isinstance(evidence.get("canonical_vulnerability_dimensions"), dict)
        else {}
    )
    dedupe_dimensions = evidence.get("dedupe_dimensions") if isinstance(evidence.get("dedupe_dimensions"), dict) else {}
    autonomous_url = autonomous.get("url") if autonomous else None
    target_url = (
        override_target or autonomous_url or finding.get("target_url")
        or finding.get("url") or evidence.get("target") or ""
    )
    original_url = override_original_url or finding.get("url") or autonomous.get("url") or evidence.get("url") or target_url
    dimension_params = dimensions.get("parameters") or dimensions.get("object_parameters") or dimensions.get("fields") or []
    if not isinstance(dimension_params, list):
        dimension_params = [dimension_params]
    param = (
        override_param or finding.get("param") or evidence.get("param") or evidence.get("parameter")
        or dedupe_dimensions.get("parameter") or dedupe_dimensions.get("object_key")
        or (dimension_params[0] if dimension_params else "")
    )
    payload = override_payload or finding.get("payload") or evidence.get("payload") or ""
    if not payload and isinstance(evidence.get("detail"), dict):
        payload = evidence.get("detail", {}).get("payload") or ""
    method = (
        override_method or finding.get("method") or evidence.get("method")
        or autonomous.get("method") or dedupe_dimensions.get("method") or "GET"
    ).upper()
    request_body = (
        override_request_body or finding.get("body") or evidence.get("body")
        or autonomous.get("request_body") or ""
    )

    return {
        "finding_type": finding_type,
        "target_url": str(target_url).strip(),
        "original_url": str(original_url).strip() if original_url else None,
        "param": str(param).strip() if param else None,
        "payload": str(payload) if payload else None,
        "method": method,
        "request_body": str(request_body) if request_body else None,
    }


async def get_finding_record(conn, finding_id: str):
    """Fetch finding by UUID or fingerprint (with backward-compatible suffix lookup)."""
    finding = None

    try:
        finding_uuid = uuid.UUID(finding_id)
        finding = await conn.fetchrow("""
            SELECT f.*,
                   COALESCE(t.url, ait.endpoint_url, dt.primary_locator) as target_url,
                   COALESCE(t.name, ait.name, dt.name) as target_name,
                   t.root_domain,
                   ait.endpoint_url as ai_target_url,
                   ait.name as ai_target_name,
                   latest_retest.status AS latest_retest_status,
                   latest_retest.result_status AS latest_retest_result_status,
                   latest_retest.verdict AS latest_retest_verdict,
                   latest_retest.confidence AS latest_retest_confidence,
                   latest_retest.completed_at AS latest_retest_completed_at,
                   latest_retest.verification_mode AS latest_retest_mode
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            LEFT JOIN device_targets dt ON f.device_target_id = dt.id
            LEFT JOIN LATERAL (
                SELECT status, result_status, verdict, confidence, completed_at, verification_mode
                FROM finding_verifications
                WHERE finding_id=f.id
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            ) latest_retest ON TRUE
            WHERE f.id = $1
        """, finding_uuid)
    except ValueError:
        pass

    if not finding:
        finding = await conn.fetchrow("""
            SELECT f.*,
                   COALESCE(t.url, ait.endpoint_url, dt.primary_locator) as target_url,
                   COALESCE(t.name, ait.name, dt.name) as target_name,
                   t.root_domain,
                   ait.endpoint_url as ai_target_url,
                   ait.name as ai_target_name,
                   latest_retest.status AS latest_retest_status,
                   latest_retest.result_status AS latest_retest_result_status,
                   latest_retest.verdict AS latest_retest_verdict,
                   latest_retest.confidence AS latest_retest_confidence,
                   latest_retest.completed_at AS latest_retest_completed_at,
                   latest_retest.verification_mode AS latest_retest_mode
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            LEFT JOIN device_targets dt ON f.device_target_id = dt.id
            LEFT JOIN LATERAL (
                SELECT status, result_status, verdict, confidence, completed_at, verification_mode
                FROM finding_verifications
                WHERE finding_id=f.id
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            ) latest_retest ON TRUE
            WHERE f.fingerprint = $1
            ORDER BY f.last_seen_at DESC
            LIMIT 1
        """, finding_id)

    if not finding and ':' in finding_id:
        suffix = finding_id.split(':')[-1]
        finding = await conn.fetchrow("""
            SELECT f.*,
                   COALESCE(t.url, ait.endpoint_url, dt.primary_locator) as target_url,
                   COALESCE(t.name, ait.name, dt.name) as target_name,
                   t.root_domain,
                   ait.endpoint_url as ai_target_url,
                   ait.name as ai_target_name,
                   latest_retest.status AS latest_retest_status,
                   latest_retest.result_status AS latest_retest_result_status,
                   latest_retest.verdict AS latest_retest_verdict,
                   latest_retest.confidence AS latest_retest_confidence,
                   latest_retest.completed_at AS latest_retest_completed_at,
                   latest_retest.verification_mode AS latest_retest_mode
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            LEFT JOIN device_targets dt ON f.device_target_id = dt.id
            LEFT JOIN LATERAL (
                SELECT status, result_status, verdict, confidence, completed_at, verification_mode
                FROM finding_verifications
                WHERE finding_id=f.id
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            ) latest_retest ON TRUE
            WHERE f.fingerprint = $1
            ORDER BY f.last_seen_at DESC
            LIMIT 1
        """, suffix)

    return finding
def infer_retest_type(finding: dict[str, Any], evidence: dict[str, Any], override_type: str | None = None) -> str | None:
    normalized = normalize_retest_type(override_type)
    if normalized:
        return normalized

    autonomous = evidence.get("autonomous_workflow") if isinstance(evidence.get("autonomous_workflow"), dict) else {}
    family_proof_evidence = evidence.get("family_proof") if isinstance(evidence.get("family_proof"), dict) else {}
    for candidate in (
        evidence.get("type"), evidence.get("retest_type"),
        autonomous.get("retest_type"), family_proof_evidence.get("family"),
    ):
        evidence_type = normalize_retest_type(candidate)
        if evidence_type:
            return evidence_type
    autonomous_family = family_proof.canonical_family(
        autonomous.get("family") or family_proof_evidence.get("family")
    )
    if autonomous_family == "bola":
        return "bola"
    if autonomous_family:
        return "generic_http"

    # Shared title/tool inference from retest_contract so API, worker, and
    # auto-retest policy always agree on whether a finding is retestable.
    return infer_type_from_title_tool(finding.get("title"), finding.get("tool"))
