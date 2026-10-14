"""Exposure proof counts from the finding view's canonical proof projection."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping

try:
    from finding_routes.router import finding_proof_fields
except ModuleNotFoundError:  # package import in host-side tests
    from ..finding_routes.router import finding_proof_fields


def active_finding_proof_counts(rows: Iterable[Mapping[str, Any]]) -> dict[tuple[str, str], dict[str, int]]:
    counts: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"verified": 0, "needs_verification": 0, "investigator_verified": 0}
    )
    for source in rows:
        finding = dict(source)
        if finding.get("status") != "active":
            continue
        kind = "target" if finding.get("target_id") else "ai"
        asset_id = finding.get("target_id") or finding.get("ai_target_id")
        if not asset_id:
            continue
        item = counts[(kind, str(asset_id))]
        if finding_proof_fields(finding)["is_verified"]:
            item["verified"] += 1
            if finding.get("tool") in {"autonomous_workflow", "bola"}:
                item["investigator_verified"] += 1
        elif (
            finding.get("last_verification_verdict") in {None, "inconclusive", "error", "likely_vulnerable", "exploited"}
            or finding.get("analyst_verdict") in {"needs_review", "retest_needed"}
        ):
            item["needs_verification"] += 1
    return dict(counts)


# --- The same counts in SQL, per asset, without reading a findings row into Python ------------

try:
    from finding_routes.list_query import (
        INDEXED_UNDETERMINED_SQL, UNDETERMINED_SQL, VERIFIED_CANDIDATE_SQL,
    )
    from finding_routes.proof_sql import latest_retest_mode_sql, verified_sql
except ModuleNotFoundError:  # package import in host-side tests
    from ..finding_routes.list_query import (
        INDEXED_UNDETERMINED_SQL, UNDETERMINED_SQL, VERIFIED_CANDIDATE_SQL,
    )
    from ..finding_routes.proof_sql import latest_retest_mode_sql, verified_sql

INVESTIGATOR_TOOLS = ("autonomous_workflow", "bola")
_NEEDS_VERDICTS = ("inconclusive", "error", "likely_vulnerable", "exploited")
_NEEDS_ANALYST = ("needs_review", "retest_needed")

#: ``active_finding_proof_counts``' "needs verification" test before the proof (a verified row is
#: not counted; the SQL subtracts those).
NEEDS_VERIFICATION_SQL = (
    "(f.last_verification_verdict IS NULL"
    f" OR f.last_verification_verdict IN {tuple(_NEEDS_VERDICTS)!r}"
    f" OR f.analyst_verdict IN {tuple(_NEEDS_ANALYST)!r})"
)
_VERIFIED_SQL = verified_sql(
    evidence="f.evidence", verdict="f.last_verification_verdict",
    retest_mode=latest_retest_mode_sql(finding_id="f.id", verdict="f.last_verification_verdict"),
)


def asset_finding_counts_sql(asset_column: str, *, proof_scope: str) -> str:
    """Per-asset active finding counts and proof counts, one row per ``asset_column`` value.

    Severity and needs-verification counts come from the active-findings index; the proof is
    projected only for rows that could be proven (idx_findings_proof_candidates), never for every
    finding. ``proof_scope`` restricts which rows count toward the proof numbers (the Python
    rollup files a finding with both a target and an AI target under the target). Undetermined
    rows are left out of the proof numbers here; ``undetermined_rows_sql`` returns them for the
    Python projection.
    """
    return f"""
        SELECT c.asset_id,
               c.active_total, c.active_critical, c.active_high,
               c.needs_all - COALESCE(p.verified_needs, 0) AS proof_needs_verification,
               COALESCE(p.verified, 0) AS proof_verified,
               COALESCE(p.investigator_verified, 0) AS proof_investigator_verified
        FROM (
            SELECT f.{asset_column} AS asset_id,
                   count(*) AS active_total,
                   count(*) FILTER (WHERE f.severity = 'critical') AS active_critical,
                   count(*) FILTER (WHERE f.severity = 'high') AS active_high,
                   count(*) FILTER (WHERE {proof_scope} AND {NEEDS_VERIFICATION_SQL}) AS needs_all
            FROM findings f
            WHERE f.status = 'active' AND f.{asset_column} IS NOT NULL
            GROUP BY f.{asset_column}
        ) c
        LEFT JOIN (
            SELECT asset_id,
                   count(*) FILTER (WHERE verified) AS verified,
                   count(*) FILTER (WHERE verified AND tool IN {INVESTIGATOR_TOOLS!r}) AS investigator_verified,
                   count(*) FILTER (WHERE verified AND needs) AS verified_needs
            FROM (
                SELECT f.{asset_column} AS asset_id, f.tool, {_VERIFIED_SQL} AS verified,
                       {NEEDS_VERIFICATION_SQL} AS needs
                FROM findings f
                WHERE f.status = 'active' AND f.{asset_column} IS NOT NULL AND {proof_scope}
                  AND {VERIFIED_CANDIDATE_SQL} AND NOT {UNDETERMINED_SQL}
            ) x
            GROUP BY asset_id
        ) p ON p.asset_id = c.asset_id"""


def undetermined_rows_sql() -> str:
    """Active rows whose proof only Python decides, for ``target_id = ANY($1)``/``ai_target_id = ANY($2)``."""
    return f"""
        SELECT f.target_id, f.ai_target_id, f.status, f.severity, f.tool, f.evidence,
               f.last_verification_verdict, f.analyst_verdict,
               {latest_retest_mode_sql(finding_id="f.id", verdict="f.last_verification_verdict")}
                   AS latest_retest_mode
        FROM findings f
        WHERE f.status = 'active' AND {INDEXED_UNDETERMINED_SQL}
          AND (f.target_id = ANY($1::uuid[]) OR f.ai_target_id = ANY($2::uuid[]))"""


def undetermined_adjustments(rows: Iterable[Mapping[str, Any]]) -> dict[tuple[str, str], dict[str, int]]:
    """What the undetermined rows add to the SQL counts: their verified rows, moved out of
    "needs verification" (the SQL counted every undetermined row there as unproven)."""
    adjust: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"verified": 0, "needs_verification": 0, "investigator_verified": 0}
    )
    for source in rows:
        finding = dict(source)
        kind = "target" if finding.get("target_id") else "ai"
        asset_id = finding.get("target_id") or finding.get("ai_target_id")
        if not asset_id or not finding_proof_fields(finding)["is_verified"]:
            continue
        item = adjust[(kind, str(asset_id))]
        item["verified"] += 1
        if finding.get("tool") in INVESTIGATOR_TOOLS:
            item["investigator_verified"] += 1
        if (finding.get("last_verification_verdict") in {None, *_NEEDS_VERDICTS}
                or finding.get("analyst_verdict") in set(_NEEDS_ANALYST)):
            item["needs_verification"] -= 1
    return dict(adjust)
