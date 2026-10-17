"""The 2.11-milestone-1 GET /exposure/assets, kept verbatim as the oracle for equality tests.

It ranked every asset in Python (cohort, exposure class, action reasons, priority). The route now
ranks in SQL (api/exposure/asset_rank.py); tests/test_exposure_assets_rank_postgres.py runs this
against the same fixture and asserts the same response. Nothing in the product calls it.
"""
# ruff: noqa: E501
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ai_assurance import build_agent_blast_radius
from asset_cohorts import target_cohort, target_exposure_class
from api_utils import extract_root_domain, _parse_graph_json, _scan_completion_flags, _short_url_label
from serialization import row_to_dict
from finding_routes.list_query import without_jit
from exposure.proof_rollup import asset_finding_counts_sql, undetermined_adjustments, undetermined_rows_sql

_EXPOSURE_PRIORITY_WEIGHT = {"P1": 300, "P2": 200, "P3": 100}


def _exposure_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _exposure_is_new(created: Any, *, days: int = 7) -> bool:
    when = _exposure_datetime(created)
    if not when:
        return False
    return (datetime.now(timezone.utc) - when) < timedelta(days=days)


def _exposure_risk_score(critical: int, high: int, total: int) -> int:
    return critical * 1000 + high * 50 + total


def _exposure_class(value: str | None, *, kind: str = "web") -> str:
    if kind == "model":
        return "supply_chain"
    return target_exposure_class(value)


def _exposure_days_since(value: Any) -> int | None:
    when = _exposure_datetime(value)
    if not when:
        return None
    return max(0, (datetime.now(timezone.utc) - when).days)


def _exposure_action_priority(
    reasons: list[str],
    *,
    exposure_class: str,
    active_critical: int,
    active_high: int,
) -> tuple[str | None, int]:
    """Return ``(priority, score)`` for ranking. ``None`` when no action needed.

    P1 = exploitable risk on an exposed/production surface, P2 = high-severity or
    high-blast exposure, P3 = scan-hygiene only (stale / incomplete / unscanned).
    """
    rs = set(reasons)
    if not rs:
        return None, 0
    if active_critical > 0 or "production_ai_risk" in rs:
        priority = "P1"
    elif "public_high_risk" in rs or "high_blast_radius" in rs or active_high > 0:
        priority = "P2"
    else:
        priority = "P3"
    score = _EXPOSURE_PRIORITY_WEIGHT[priority] + active_critical * 10 + active_high
    if exposure_class == "public":
        score += 25
    return priority, score


def _exposure_action_reasons(
    *,
    kind: str,
    exposure_class: str,
    active_critical: int,
    active_high: int,
    total_scans: int,
    last_scanned_at: Any,
    scan_limited: bool,
    production_mode: bool = False,
    blast_radius_tier: str | None = None,
    deployment_approved: bool | None = None,
    latest_scan_status: str | None = None,
) -> list[str]:
    reasons: list[str] = []
    days = _exposure_days_since(last_scanned_at)
    if total_scans <= 0 or not last_scanned_at:
        reasons.append("never_scanned")
    elif days is not None and days >= 30:
        reasons.append("stale_scan")
    if latest_scan_status == "failed":
        reasons.append("failed_scan")
    if scan_limited:
        reasons.append("incomplete_scan")
    if active_critical > 0:
        reasons.append("critical_findings")
    elif active_high > 0:
        reasons.append("high_findings")
    if exposure_class == "public" and (active_critical > 0 or active_high > 0):
        reasons.append("public_high_risk")
    if kind == "ai" and production_mode and (active_critical > 0 or active_high > 0):
        reasons.append("production_ai_risk")
    if kind == "ai" and blast_radius_tier in {"high", "critical"}:
        reasons.append("high_blast_radius")
    if kind == "model" and deployment_approved is False:
        reasons.append("model_not_approved")
    return reasons


def _exposure_coverage_posture(*, total_scans: int, last_scanned_at: Any, scan_limited: bool, latest_scan_status: str | None) -> str:
    days = _exposure_days_since(last_scanned_at)
    if total_scans <= 0 or not last_scanned_at:
        return "unscanned"
    if latest_scan_status == "failed":
        return "failed"
    if scan_limited:
        return "limited"
    if days is not None and days >= 30:
        return "stale"
    return "fresh"


def _exposure_recommended_actions(*, kind: str, reasons: list[str], active_verified: int, active_needs_verification: int) -> list[dict[str, str]]:
    """Prioritized, contextual next steps as ``{label, kind}``.

    ``kind`` tells the UI which action the recommendation maps to so it can be
    rendered as a real CTA: ``scan`` (run/refresh coverage), ``findings``
    (triage/verify), ``latest_scan`` (open the latest run), or ``none`` (advisory).
    """
    actions: list[dict[str, str]] = []
    rs = set(reasons)
    if "never_scanned" in rs:
        actions.append({"label": "Run first scan", "kind": "scan"})
    if "failed_scan" in rs:
        actions.append({"label": "Open latest failed scan", "kind": "latest_scan"})
    if "incomplete_scan" in rs:
        actions.append({"label": "Review skipped scan coverage", "kind": "latest_scan"})
    if "stale_scan" in rs:
        actions.append({"label": "Refresh scan", "kind": "scan"})
    if "critical_findings" in rs:
        actions.append({"label": "Triage critical findings", "kind": "findings"})
    elif "high_findings" in rs:
        actions.append({"label": "Triage high findings", "kind": "findings"})
    if "public_high_risk" in rs:
        actions.append({"label": "Prioritize public exposure", "kind": "none"})
    if kind == "ai" and "high_blast_radius" in rs:
        actions.append({"label": "Review AI runtime controls", "kind": "none"})
    if kind == "ai" and "production_ai_risk" in rs:
        actions.append({"label": "Retest production AI surface", "kind": "scan"})
    if kind == "model" and "model_not_approved" in rs:
        actions.append({"label": "Complete model approval", "kind": "none"})
    if active_verified > 0:
        actions.append({"label": "Fix verified findings", "kind": "findings"})
    if active_needs_verification > 0:
        actions.append({"label": "Review Hunt candidates", "kind": "deep_hunt"})
    # Stable de-dupe by label, preserving priority order.
    seen: set[str] = set()
    unique = [a for a in actions if not (a["label"] in seen or seen.add(a["label"]))]
    return unique[:5]


# Metadata keys the asset row reads (cohort, ownership, AI blast radius): the rest of the JSON
# stays in the database.
_TARGET_METADATA_KEYS = ("cohort", "environment", "owner", "asset_owner", "risk_tier", "data_classification")
_AI_METADATA_KEYS = (
    "cohort", "environment", "owner", "asset_owner", "risk_tier", "data_classification",
    "tool_inventory", "tools", "mcp_tools", "per_tool_scopes", "tool_scopes", "mcp_scopes",
    "oauth_scopes", "delegated_identity", "service_accounts", "agent_identities", "memory_stores",
    "memory", "state_stores", "write_action_approval", "dry_run_mode", "transaction_limits",
    "sandboxing", "audit_logs", "kill_switch",
)


def _metadata_subset_sql(column: str, keys: tuple[str, ...]) -> str:
    """Only ``keys`` of a JSON object (absent keys stay absent); a non-object passes unchanged."""
    names = ", ".join("'" + key + "'" for key in keys)
    return (
        f"(CASE WHEN jsonb_typeof({column}) = 'object' THEN COALESCE((SELECT jsonb_object_agg(e.key, e.value)"
        f" FROM jsonb_each({column}) e WHERE e.key IN ({names})), '{{}}'::jsonb) ELSE {column} END)"
    )


def _proof_numbers(row: Any, adjust: dict[str, int] | None) -> dict[str, int]:
    adjust = adjust or {}
    return {
        "verified": int(row["proof_verified"] or 0) + adjust.get("verified", 0),
        "needs_verification": int(row["proof_needs_verification"] or 0) + adjust.get("needs_verification", 0),
        "investigator_verified": int(row.get("proof_investigator_verified") or 0)
        + adjust.get("investigator_verified", 0),
    }


async def reference_exposure_assets(
    pool: Any,
    root_domain: Optional[str] = None,
    kind: Optional[str] = None,
    cohort: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0,
):
    """Unified, risk-ranked asset inventory for the triage view.

    Merges web targets, AI surfaces, and model artifacts with their active
    critical/high/total finding counts (uncapped SQL aggregation), grade, and
    first-seen timestamp. Each asset carries the graph ``node_id`` so the UI can
    jump straight into the Map lens focused on it.
    """
    include_web = kind in (None, "web", "model")
    include_ai = kind in (None, "ai")
    target_rows: list[Any] = []
    ai_rows: list[Any] = []
    async with pool.acquire() as conn, without_jit(conn):
        if include_web:
            target_rows = await conn.fetch(
                f"""
                SELECT t.id, t.url, t.name, t.root_domain, t.discovery_source,
                       {_metadata_subset_sql("t.metadata_json", _TARGET_METADATA_KEYS)} AS metadata_json,
                       t.last_grade, t.last_score, t.last_scanned_at, t.created_at, t.total_scans,
                       ls.id AS latest_scan_id, ls.status AS latest_scan_status,
                       ls.scan_type AS latest_scan_type, ls.completion_status, ls.top_coverage_status,
                       ls.completed_at AS latest_scan_completed_at,
                       COALESCE(fc.active_total, 0) AS active_total,
                       COALESCE(fc.active_critical, 0) AS active_critical,
                       COALESCE(fc.active_high, 0) AS active_high,
                       COALESCE(fc.proof_verified, 0) AS proof_verified,
                       COALESCE(fc.proof_needs_verification, 0) AS proof_needs_verification,
                       COALESCE(fc.proof_investigator_verified, 0) AS proof_investigator_verified,
                       COALESCE(ic.investigator_suspected_count, 0) AS investigator_suspected_count
                FROM targets t
                LEFT JOIN LATERAL (
                    SELECT id, status, scan_type, completed_at,
                           result -> 'scan_completion_status' AS completion_status,
                           result ->> 'coverage_status' AS top_coverage_status
                    FROM scans s
                    WHERE s.target_id = t.id
                      AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
                    ORDER BY s.created_at DESC
                    LIMIT 1
                ) ls ON true
                LEFT JOIN ({asset_finding_counts_sql("target_id", proof_scope="TRUE")}) fc
                    ON fc.asset_id = t.id
                LEFT JOIN (
                    SELECT target_id, COUNT(*) AS investigator_suspected_count
                    FROM investigation_candidates
                    WHERE plane='web'
                      AND status IN ('new','verification_queued','verifying','inconclusive','blocked')
                    GROUP BY target_id
                ) ic ON ic.target_id = t.id
                WHERE t.is_active = true
                  AND ($1::text IS NULL OR t.root_domain = $1::text)
                  AND ($2::text IS NULL
                       OR ($2::text = 'model') = (t.discovery_source IS NOT DISTINCT FROM 'model-intake'))
                """,
                root_domain, kind if kind in ("web", "model") else None,
            )
        if include_ai:
            ai_rows = await conn.fetch(
                f"""
                SELECT a.id, a.name, a.endpoint_url, a.target_type, a.production_mode,
                       a.last_scanned_at, a.created_at,
                       {_metadata_subset_sql("a.metadata_json", _AI_METADATA_KEYS)} AS metadata_json,
                       ls.id AS latest_scan_id, ls.status AS latest_scan_status,
                       ls.scan_type AS latest_scan_type, ls.completion_status, ls.top_coverage_status,
                       ls.completed_at AS latest_scan_completed_at,
                       COALESCE(sc.scan_count, 0) AS scan_count,
                       COALESCE(fc.active_total, 0) AS active_total,
                       COALESCE(fc.active_critical, 0) AS active_critical,
                       COALESCE(fc.active_high, 0) AS active_high,
                       COALESCE(fc.proof_verified, 0) AS proof_verified,
                       COALESCE(fc.proof_needs_verification, 0) AS proof_needs_verification
                FROM ai_targets a
                LEFT JOIN LATERAL (
                    SELECT id, status, scan_type, completed_at,
                           result -> 'scan_completion_status' AS completion_status,
                           result ->> 'coverage_status' AS top_coverage_status
                    FROM scans s
                    WHERE s.ai_target_id = a.id
                    ORDER BY s.created_at DESC
                    LIMIT 1
                ) ls ON true
                LEFT JOIN LATERAL (
                    SELECT COUNT(*) AS scan_count FROM scans s WHERE s.ai_target_id = a.id
                ) sc ON true
                LEFT JOIN ({asset_finding_counts_sql("ai_target_id", proof_scope="f.target_id IS NULL")}) fc
                    ON fc.asset_id = a.id
                WHERE a.is_active = true
                  AND ($1::text IS NULL OR LOWER(a.endpoint_url) LIKE '%' || LOWER($1::text) || '%')
                """,
                root_domain,
            )
        # The SQL counts decide proof for every row but the rare one whose triage only Python's
        # JSON reader accepts; those few are projected here (an index probe finds them).
        adjustments = undetermined_adjustments(await conn.fetch(
            undetermined_rows_sql(), [row["id"] for row in target_rows], [row["id"] for row in ai_rows],
        ))

    proof_counts = {
        **{("target", str(row["id"])): _proof_numbers(row, adjustments.get(("target", str(row["id"]))))
           for row in target_rows},
        **{("ai", str(row["id"])): _proof_numbers(row, adjustments.get(("ai", str(row["id"]))))
           for row in ai_rows},
    }
    assets: list[dict[str, Any]] = []

    for row in target_rows:
        row = row_to_dict(row)
        is_model = row.get("discovery_source") == "model-intake"
        asset_kind = "model" if is_model else "web"
        if kind and kind != asset_kind:
            continue
        crit = int(row["active_critical"] or 0)
        high = int(row["active_high"] or 0)
        total = int(row["active_total"] or 0)
        proof = proof_counts.get(("target", str(row["id"])), {})
        verified = proof.get("verified", 0)
        needs_verification = proof.get("needs_verification", 0) + int(row.get("investigator_suspected_count") or 0)
        investigator_verified = proof.get("investigator_verified", 0)
        investigator_suspected = int(row.get("investigator_suspected_count") or 0)
        completion = _scan_completion_flags(row.get("completion_status"), row.get("top_coverage_status"))
        exposure_class = _exposure_class(row.get("url"), kind=asset_kind)
        total_scans = int(row.get("total_scans") or 0)
        last_scanned_at = row.get("latest_scan_completed_at") or row.get("last_scanned_at")
        latest_scan_status = row.get("latest_scan_status")
        action_reasons = _exposure_action_reasons(
            kind=asset_kind,
            exposure_class=exposure_class,
            active_critical=crit,
            active_high=high,
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            deployment_approved=None,
            latest_scan_status=latest_scan_status,
        )
        action_priority, action_score = _exposure_action_priority(
            action_reasons, exposure_class=exposure_class, active_critical=crit, active_high=high
        )
        coverage_posture = _exposure_coverage_posture(
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            latest_scan_status=latest_scan_status,
        )
        meta = _parse_graph_json(row.get("metadata_json"))
        assets.append({
            "id": str(row["id"]),
            "node_id": f"target:{row['id']}",
            "kind": asset_kind,
            "label": _short_url_label(row.get("url")) or row.get("name") or "",
            "url": row.get("url"),
            "root_domain": None if is_model else row.get("root_domain"),
            "origin": row.get("root_domain") if is_model else None,
            "exposure_class": exposure_class,
            "cohort": target_cohort(
                url=row.get("url"), name=row.get("name"),
                discovery_source=row.get("discovery_source"), metadata=meta,
                exposure_class=exposure_class,
            ),
            "owner": str(meta.get("owner") or meta.get("asset_owner") or "").strip() or None,
            "environment": str(meta.get("environment") or "").strip().lower() or None,
            "risk_tier": str(meta.get("risk_tier") or "").strip() or None,
            "data_classification": str(meta.get("data_classification") or "").strip() or None,
            "grade": row.get("last_grade"),
            "score": row.get("last_score"),
            "active_total": total,
            "active_critical": crit,
            "active_high": high,
            "active_verified": verified,
            "active_needs_verification": needs_verification,
            "investigator_verified_count": investigator_verified,
            "investigator_suspected_count": investigator_suspected,
            "total_scans": total_scans,
            "last_scanned_at": last_scanned_at,
            "latest_scan_id": str(row["latest_scan_id"]) if row.get("latest_scan_id") else None,
            "latest_scan_status": latest_scan_status,
            "latest_scan_type": row.get("latest_scan_type"),
            "latest_scan_href": f"/scans/{row['latest_scan_id']}" if row.get("latest_scan_id") else None,
            "scan_complete": completion["scan_complete"],
            "scan_limited": completion["scan_limited"],
            "coverage_status": completion["coverage_status"],
            "coverage_posture": coverage_posture,
            "skipped_modules_count": completion["skipped_modules_count"],
            "capped_lists_count": completion["capped_lists_count"],
            "scan_age_days": _exposure_days_since(last_scanned_at),
            "action_reasons": action_reasons,
            "needs_action": bool(action_reasons),
            "action_priority": action_priority,
            "action_score": action_score,
            "recommended_actions": _exposure_recommended_actions(
                kind=asset_kind,
                reasons=action_reasons,
                active_verified=verified,
                active_needs_verification=needs_verification,
            ),
            "first_seen_at": row.get("created_at"),
            "is_new": _exposure_is_new(row.get("created_at")),
            "risk_score": _exposure_risk_score(crit, high, total),
            "findings_href": f"/findings?target_id={row['id']}&status=active&freshness=all",
        })

    for row in ai_rows:
        row = row_to_dict(row)
        if kind and kind != "ai":
            continue
        crit = int(row["active_critical"] or 0)
        high = int(row["active_high"] or 0)
        total = int(row["active_total"] or 0)
        proof = proof_counts.get(("ai", str(row["id"])), {})
        verified = proof.get("verified", 0)
        needs_verification = proof.get("needs_verification", 0)
        completion = _scan_completion_flags(row.get("completion_status"), row.get("top_coverage_status"))
        exposure_class = _exposure_class(row.get("endpoint_url"), kind="ai")
        total_scans = int(row.get("scan_count") or 0)
        last_scanned_at = row.get("latest_scan_completed_at") or row.get("last_scanned_at")
        latest_scan_status = row.get("latest_scan_status")
        blast_radius = build_agent_blast_radius(row, [{"status": "active"} for _ in range(total)])
        blast_radius_tier = str(blast_radius.get("tier") or "")
        ai_meta = _parse_graph_json(row.get("metadata_json"))
        ai_owner = str(ai_meta.get("asset_owner") or ai_meta.get("owner") or "").strip() or None
        # Normalized once at emission (trimmed, lowercased) so every consumer —
        # UI prod filter/confirmation, API metrics, action reasons — compares
        # the same canonical value regardless of how metadata was written.
        ai_environment = (
            str(ai_meta.get("environment") or "").strip().lower()
            or ("production" if row.get("production_mode") else "")
        ) or None
        # Production semantics shared with the UI's isProductionAIAsset(): the
        # explicit flag OR declared environment metadata. Keeps action reasons,
        # P1 promotion, and metrics consistent with the UI's scan confirmation.
        ai_is_production = bool(row.get("production_mode")) or (
            str(ai_meta.get("environment") or "").strip().lower() == "production"
        )
        action_reasons = _exposure_action_reasons(
            kind="ai",
            exposure_class=exposure_class,
            active_critical=crit,
            active_high=high,
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            production_mode=ai_is_production,
            blast_radius_tier=blast_radius_tier,
            latest_scan_status=latest_scan_status,
        )
        action_priority, action_score = _exposure_action_priority(
            action_reasons, exposure_class=exposure_class, active_critical=crit, active_high=high
        )
        coverage_posture = _exposure_coverage_posture(
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            latest_scan_status=latest_scan_status,
        )
        assets.append({
            "id": str(row["id"]),
            "node_id": f"ai_target:{row['id']}",
            "kind": "ai",
            "label": row.get("name") or _short_url_label(row.get("endpoint_url")) or "",
            "url": row.get("endpoint_url"),
            "root_domain": extract_root_domain(row.get("endpoint_url") or ""),
            "target_type": row.get("target_type"),
            "production_mode": bool(row.get("production_mode")),
            "exposure_class": exposure_class,
            "cohort": target_cohort(
                url=row.get("endpoint_url"), name=row.get("name"),
                discovery_source="ai_gate", metadata=ai_meta,
                exposure_class=exposure_class,
            ),
            "owner": ai_owner,
            "environment": ai_environment,
            "blast_radius_score": blast_radius.get("score"),
            "blast_radius_tier": blast_radius.get("tier"),
            "blast_radius_factors": blast_radius.get("factors") or [],
            "data_classification": blast_radius.get("data_classification"),
            "risk_tier": blast_radius.get("risk_tier"),
            "missing_runtime_controls": blast_radius.get("missing_runtime_controls") or [],
            "grade": None,
            "score": None,
            "active_total": total,
            "active_critical": crit,
            "active_high": high,
            "active_verified": verified,
            "active_needs_verification": needs_verification,
            "total_scans": total_scans,
            "last_scanned_at": last_scanned_at,
            "latest_scan_id": str(row["latest_scan_id"]) if row.get("latest_scan_id") else None,
            "latest_scan_status": latest_scan_status,
            "latest_scan_type": row.get("latest_scan_type"),
            "latest_scan_href": f"/scans/{row['latest_scan_id']}" if row.get("latest_scan_id") else None,
            "scan_complete": completion["scan_complete"],
            "scan_limited": completion["scan_limited"],
            "coverage_status": completion["coverage_status"],
            "coverage_posture": coverage_posture,
            "skipped_modules_count": completion["skipped_modules_count"],
            "capped_lists_count": completion["capped_lists_count"],
            "scan_age_days": _exposure_days_since(last_scanned_at),
            "action_reasons": action_reasons,
            "needs_action": bool(action_reasons),
            "action_priority": action_priority,
            "action_score": action_score,
            "recommended_actions": _exposure_recommended_actions(
                kind="ai",
                reasons=action_reasons,
                active_verified=verified,
                active_needs_verification=needs_verification,
            ),
            "first_seen_at": row.get("created_at"),
            "is_new": _exposure_is_new(row.get("created_at")),
            "risk_score": _exposure_risk_score(crit, high, total),
            "findings_href": f"/findings?ai_target_id={row['id']}&status=active&freshness=all",
        })

    cohort_counts = dict(Counter(
        str(asset.get("cohort") or "unclassified") for asset in assets
    ))
    selected_cohort = str(cohort if isinstance(cohort, str) else "all")
    if selected_cohort != "all":
        if selected_cohort == "operational":
            allowed_cohorts = {"production", "staging", "unclassified"}
        elif selected_cohort == "non_operational":
            allowed_cohorts = {"lab", "demo", "calibration", "internal"}
        else:
            allowed_cohorts = {selected_cohort}
        assets = [
            asset for asset in assets
            if str(asset.get("cohort") or "unclassified") in allowed_cohorts
        ]

    # Headline metrics from the full selected (uncapped) set so the stat row stays
    # accurate and independent of the heavier graph fetch. Compute before the
    # display limit is applied.
    metrics = {
        "asset_count": len(assets),
        "active_critical": sum(a["active_critical"] for a in assets),
        "active_high": sum(a["active_high"] for a in assets),
        "active_verified": sum(a.get("active_verified", 0) for a in assets),
        "active_needs_verification": sum(a.get("active_needs_verification", 0) for a in assets),
        "ai_surfaces": sum(1 for a in assets if a["kind"] == "ai"),
        "web_targets": sum(1 for a in assets if a["kind"] == "web"),
        "model_artifacts": sum(1 for a in assets if a["kind"] == "model"),
        "public_assets": sum(1 for a in assets if a.get("exposure_class") == "public"),
        "internal_assets": sum(1 for a in assets if a.get("exposure_class") == "internal"),
        "unscanned_assets": sum(1 for a in assets if "never_scanned" in a.get("action_reasons", [])),
        "stale_assets": sum(1 for a in assets if "stale_scan" in a.get("action_reasons", [])),
        "incomplete_scans": sum(1 for a in assets if "incomplete_scan" in a.get("action_reasons", [])),
        "failed_scans": sum(1 for a in assets if "failed_scan" in a.get("action_reasons", [])),
        "fresh_scans": sum(1 for a in assets if a.get("coverage_posture") == "fresh"),
        "verified_assets": sum(1 for a in assets if (a.get("active_verified") or 0) > 0),
        "investigator_verified_assets": sum(1 for a in assets if (a.get("investigator_verified_count") or 0) > 0),
        "investigator_suspected_assets": sum(1 for a in assets if (a.get("investigator_suspected_count") or 0) > 0),
        "unverified_high_assets": sum(
            1 for a in assets
            if (a.get("active_needs_verification") or 0) > 0
            and (a.get("active_critical", 0) + a.get("active_high", 0)) > 0
        ),
        "unowned_assets": sum(1 for a in assets if not a.get("owner")),
        "needs_action": sum(1 for a in assets if a.get("needs_action")),
        "p1_count": sum(1 for a in assets if a.get("action_priority") == "P1"),
        "p2_count": sum(1 for a in assets if a.get("action_priority") == "P2"),
        "p3_count": sum(1 for a in assets if a.get("action_priority") == "P3"),
        "prod_ai_surfaces": sum(
            1 for a in assets
            if a["kind"] == "ai" and (a.get("production_mode") or a.get("environment") == "production")
        ),
        "high_blast_ai_surfaces": sum(1 for a in assets if a["kind"] == "ai" and a.get("blast_radius_tier") in {"high", "critical"}),
    }
    new_count = sum(1 for a in assets if a["is_new"])

    # Rank by action priority first, then raw risk — so the urgent few surface
    # above the long tail. Stable id tiebreak keeps ordering deterministic.
    assets.sort(key=lambda a: (a.get("action_score") or 0, a["risk_score"], a["is_new"], a["id"]), reverse=True)
    total = len(assets)
    assets = assets[offset:offset + limit]
    return {
        "assets": assets,
        "count": len(assets),
        "total": total,
        "offset": offset,
        "new_count": new_count,
        "metrics": metrics,
        "cohort": selected_cohort,
        "cohort_counts": cohort_counts,
        "truncated": offset + len(assets) < total,
    }
