"""The target's unresolved findings a scan did not observe: the carried-over summary.

The scan page used to compute this from a paged client fetch, while the deployment gate
computed its own view of the same rows. Two definitions of one fact drift; this module is
the one the gate response carries and the page renders.

A row counts as observed by a run only through persisted linkage (the run wrote it or last
saw it) or through a fingerprint the run reported. Display strings are never proof of
re-observation. When the history could not be loaded completely the summary says so and a
reader must not claim an all-clear from it.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
MATERIAL_SEVERITIES = frozenset({"critical", "high", "medium"})
# Active rows loaded for one summary. Past this the summary is reported incomplete rather
# than computed over a silently truncated set.
HISTORY_ROW_CAP = 5000

TARGET_HISTORY_COUNT_SQL = """
    SELECT COUNT(*) FROM findings
    WHERE target_id = ANY($1::uuid[]) AND status = 'active'
"""
TARGET_HISTORY_SQL = """
    SELECT id, fingerprint, severity, scan_id, last_seen_scan_id
    FROM findings
    WHERE target_id = ANY($1::uuid[]) AND status = 'active'
    ORDER BY created_at DESC, id
    LIMIT $2
"""


def gate_findings_from_rows(rows: Any) -> list[dict[str, Any]]:
    """The target's active blocking rows in the shape the deployment gate merges."""
    findings: list[dict[str, Any]] = []
    for row in rows or []:
        findings.append({
            "id": str(row["id"]),
            "fingerprint": row["fingerprint"],
            "title": row["title"],
            "severity": row["severity"],
            "tool": row["tool"],
            "url": row["url"],
            "source": "target_active",
        })
    return findings


async def load_target_history(conn: Any, target_ids: Sequence[Any], *, cap: int = HISTORY_ROW_CAP) -> dict[str, Any]:
    """Load the target's active findings once, and say whether all of them were loaded."""
    ids = list(target_ids or [])
    if not ids:
        return {"rows": [], "total": 0, "complete": True}
    total = int(await conn.fetchval(TARGET_HISTORY_COUNT_SQL, ids) or 0)
    rows = [dict(row) for row in await conn.fetch(TARGET_HISTORY_SQL, ids, int(cap))]
    return {"rows": rows, "total": total, "complete": total <= len(rows)}


def summarize_carried_over(
    scan_id: Any,
    reported_findings: Any,
    history: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Count the active rows this scan neither wrote, last saw, nor reported by fingerprint."""
    scan_key = str(scan_id or "")
    reported = reported_findings if isinstance(reported_findings, list) else []
    reported_fingerprints = {
        str(item.get("fingerprint") or "").strip()
        for item in reported if isinstance(item, Mapping) and item.get("fingerprint")
    }
    source = history if isinstance(history, Mapping) else {}
    rows = source.get("rows") if isinstance(source.get("rows"), list) else []
    carried: list[Mapping[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        if str(row.get("status") or "active") != "active":
            continue
        if scan_key and (str(row.get("scan_id") or "") == scan_key or str(row.get("last_seen_scan_id") or "") == scan_key):
            continue
        fingerprint = str(row.get("fingerprint") or "").strip()
        if fingerprint and fingerprint in reported_fingerprints:
            continue
        carried.append(row)
    severities = [str(row.get("severity") or "info").lower() for row in carried]
    highest = next((level for level in SEVERITY_ORDER if level in severities), None)
    complete = bool(source.get("complete", True))
    return {
        "count": len(carried),
        "material": sum(1 for level in severities if level in MATERIAL_SEVERITIES),
        "highest": highest,
        "complete": complete,
        "total_active": int(source.get("total") or len(rows)),
        # Rows counted but not loaded: the count above is a lower bound when this is > 0.
        "unloaded_active": max(0, int(source.get("total") or 0) - len(rows)),
    }


__all__ = [
    "HISTORY_ROW_CAP",
    "gate_findings_from_rows",
    "load_target_history",
    "summarize_carried_over",
]
