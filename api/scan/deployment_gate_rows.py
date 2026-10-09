"""The rows a scan's deployment gate lists, and the ids and provenance each one carries.

The gate's count and list are release evidence. They hold every finding at or above the block
threshold (a former 20-row cap dropped the last highs of a 22-finding scan), each with the id
of its persisted row, and say who found a row the scan did not: an earlier scan or a Hunt.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .carried_over import HISTORY_ROW_CAP, SEVERITY_ORDER, attach_persisted_ids
from .finding_identity import canonical_finding_fingerprint

_RANK = {level: len(SEVERITY_ORDER) - index for index, level in enumerate(SEVERITY_ORDER)}

# Every active blocking row, highest severity first, bounded like the carried-over history.
# A row cut here would leave this scan's report copy of it without an id.
TARGET_BLOCKING_SQL = """
    SELECT id, fingerprint, title, severity, tool, url, scan_id, hunt_run_id
    FROM findings
    WHERE target_id = ANY($1::uuid[]) AND status = 'active'
      AND severity IN ('critical', 'high')
    ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, created_at, id
    LIMIT $2
"""
TARGET_BLOCKING_COUNT_SQL = """
    SELECT count(*) FROM findings
    WHERE target_id = ANY($1::uuid[]) AND status = 'active'
      AND severity IN ('critical', 'high')
"""
# The rows a scan wrote or saw, in any status: the persisted identity of each report row.
SCAN_FINDING_IDS_SQL = """
    SELECT id, fingerprint FROM findings
    WHERE scan_id = $1 OR first_seen_scan_id = $1 OR last_seen_scan_id = $1
"""


async def load_target_blocking_rows(conn: Any, target_ids: Sequence[Any], *, cap: int = HISTORY_ROW_CAP) -> dict[str, Any]:
    """The target's active blocking rows, and whether every one of them was loaded."""
    ids = list(target_ids or [])
    if not ids:
        return {"rows": [], "total": 0, "complete": True}
    total = int(await conn.fetchval(TARGET_BLOCKING_COUNT_SQL, ids) or 0)
    rows = list(await conn.fetch(TARGET_BLOCKING_SQL, ids, int(cap)))
    return {"rows": rows, "total": total, "complete": total <= len(rows)}


# Rows an agent-facing surface (the Arsenal deployment.decision command) returns. The full
# list stays on the REST decision; an agent gets the count, the first rows and a note.
AGENT_BLOCKER_LIMIT = 50


def gate_completeness(
    decision: str, rationale: str, missing: list[dict[str, Any]], target_active: Mapping[str, Any] | None,
) -> tuple[str, str]:
    """Fail closed when the target's blocking rows were not all loaded: an all-clear or an
    exception-covered verdict computed over a truncated set is not a verdict. A block stays
    a block; it is already the conservative answer."""
    if not target_active or target_active.get("complete", True):
        return decision, rationale
    total, loaded = int(target_active.get("total") or 0), len(target_active.get("rows") or [])
    missing.append({
        "id": "target_active_findings_complete",
        "label": "Complete set of the target's unresolved blocking findings",
        "status": "truncated", "loaded": loaded, "total": total,
    })
    if decision == "block":
        return decision, rationale
    return "needs_review", (
        f"Only {loaded} of the target's {total} unresolved high/critical findings could be "
        "evaluated; the decision is withheld until all of them can be."
    )


def summarize_for_agent(decision: dict[str, Any], limit: int = AGENT_BLOCKER_LIMIT) -> dict[str, Any]:
    """The decision with its blocker list bounded, stating how many rows were left out."""
    blockers = decision.get("blocking_findings") or []
    if len(blockers) <= limit:
        return decision
    return {**decision, "blocking_findings": blockers[:limit], "blocking_findings_truncated": True,
            "blocking_findings_omitted": len(blockers) - limit}


async def load_scan_finding_ids(conn: Any, scan_id: Any) -> dict[str, str]:
    rows = await conn.fetch(SCAN_FINDING_IDS_SQL, scan_id)
    return {str(row["fingerprint"]): str(row["id"]) for row in rows if row["fingerprint"]}


def deployment_gate_findings(findings: Any, *, minimum: str = "high") -> list[dict[str, Any]]:
    """Every finding at or above the block threshold, highest severity first, untruncated."""
    if not isinstance(findings, list):
        return []
    threshold = _RANK.get(minimum, _RANK["high"])
    selected: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "info").lower()
        if _RANK.get(severity, 0) < threshold:
            continue
        item = {
            "id": finding.get("id") or finding.get("source_finding_id"),
            "fingerprint": finding.get("fingerprint"),
            "title": finding.get("title"),
            "severity": severity,
            "tool": finding.get("tool"),
            "url": finding.get("url"),
        }
        for provenance in ("source", "scan_id", "hunt_run_id"):
            if finding.get(provenance):
                item[provenance] = finding.get(provenance)
        selected.append(item)
    selected.sort(key=lambda item: _RANK.get(str(item.get("severity")), 0), reverse=True)
    return selected


def with_report_identity(findings: list[Any]) -> list[Any]:
    """Report rows with the canonical fingerprint persistence keyed them by. Report rows carry
    no persisted identity of their own, and findings.scan_id moves to whichever scan last saw
    a row.

    Only the canonical fingerprint matches a report row to a stored row. The pre-check and
    pre-service aliases are deliberately not authority (persistence does not re-key rows by
    them, see reconcile_legacy_finding_row): a stored row under an alias can be a different
    finding, and lending its id to a report row would let that row's policy exception waive
    a new blocker."""
    return [
        {**item, "fingerprint": item.get("fingerprint") or canonical_finding_fingerprint(item)}
        if isinstance(item, dict) else item
        for item in findings
    ]


def finish_blockers(blocking: list[dict[str, Any]], persisted_ids: Mapping[str, Any] | None) -> None:
    """Attach persisted ids and label each blocker's origin; a row
    merged from the target's active set already says whether a Hunt or earlier scan found it."""
    if persisted_ids:
        attach_persisted_ids(blocking, persisted_ids)
    for finding in blocking:
        finding.setdefault("origin", "this_scan")


__all__ = [
    "AGENT_BLOCKER_LIMIT",
    "deployment_gate_findings",
    "gate_completeness",
    "summarize_for_agent",
    "finish_blockers",
    "load_scan_finding_ids",
    "load_target_blocking_rows",
    "with_report_identity",
]
