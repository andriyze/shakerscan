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
    SELECT id, fingerprint, severity, scan_id, last_seen_scan_id, hunt_run_id
    FROM findings
    WHERE target_id = ANY($1::uuid[]) AND status = 'active'
    ORDER BY created_at DESC, id
    LIMIT $2
"""


def is_hunt_finding(row: Mapping[str, Any]) -> bool:
    """A row a Hunt created. A Hunt that later re-proves a scan's row also stamps its
    hunt_run_id there, so a row some scan wrote stays a scan finding."""
    return bool(row.get("hunt_run_id")) and not row.get("scan_id")


def finding_origin(row: Mapping[str, Any]) -> str:
    """Who recorded a row this run did not observe: a Hunt, an earlier scan, or something
    else (a manual entry, an AI session, a device import) that has neither a scan nor a Hunt
    behind it and must not be called an earlier scan."""
    if is_hunt_finding(row):
        return "hunt"
    return "earlier_scan" if row.get("scan_id") else "other"


def gate_findings_from_rows(rows: Any) -> list[dict[str, Any]]:
    """The target's active blocking rows in the shape the deployment gate merges."""
    findings: list[dict[str, Any]] = []
    for row in rows or []:
        item = dict(row) if not isinstance(row, dict) else row
        finding = {
            "id": str(item["id"]),
            "fingerprint": item["fingerprint"],
            "title": item["title"],
            "severity": item["severity"],
            "tool": item["tool"],
            "url": item["url"],
            "source": "target_active",
        }
        if item.get("scan_id"):
            finding["scan_id"] = str(item["scan_id"])
        if item.get("hunt_run_id"):
            finding["hunt_run_id"] = str(item["hunt_run_id"])
        findings.append(finding)
    return findings


def attach_persisted_ids(blocking: list[dict[str, Any]], ids_by_fingerprint: Mapping[str, Any]) -> None:
    """Give a report row the id of its persisted row when the active set did not supply it
    (the row is no longer active, or past the active-set bound). A report row's own ``id`` is
    the scanner's identifier, not a row id, so it is replaced. A blocker the page cannot link
    to is not evidence a reader can act on."""
    persisted_ids = {str(value) for value in ids_by_fingerprint.values()}
    for finding in blocking:
        if finding.get("from_target_active") or str(finding.get("id") or "") in persisted_ids:
            continue
        persisted = ids_by_fingerprint.get(str(finding.get("fingerprint") or ""))
        if persisted:
            finding["id"] = str(persisted)


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
        # Of those, the rows a Hunt created rather than an earlier scan.
        "from_hunts": sum(1 for row in carried if finding_origin(row) == "hunt"),
        # Rows with neither a scan nor a Hunt behind them (manual, AI session, device).
        "from_other": sum(1 for row in carried if finding_origin(row) == "other"),
        "material": sum(1 for level in severities if level in MATERIAL_SEVERITIES),
        "highest": highest,
        "complete": complete,
        "total_active": int(source.get("total") or len(rows)),
        # Rows counted but not loaded: the count above is a lower bound when this is > 0.
        "unloaded_active": max(0, int(source.get("total") or 0) - len(rows)),
    }


def merge_target_active_blockers(
    blocking: list[dict[str, Any]],
    active: list[dict[str, Any]],
    history: Mapping[str, Any] | None,
    scan_id: Any,
) -> list[dict[str, Any]]:
    """Merge durable blockers without double-counting a finding this scan reported.

    Report rows are matched to persisted rows by id or by the fingerprint persistence keyed
    them by (the caller derives it for report rows that omit it). ``findings.scan_id`` is not
    usable for this: a later scan that re-observes a row takes it over. A matched report row
    takes the persisted row's id, so a policy exception recorded against the persisted finding
    also covers this scan's copy of it.
    """
    observed_ids = {
        str(row.get("id")) for row in (history or {}).get("rows", [])
        if isinstance(row, Mapping) and row.get("id")
        and (str(row.get("scan_id") or "") == str(scan_id or "")
             or str(row.get("last_seen_scan_id") or "") == str(scan_id or ""))
    }
    report_count = len(blocking)
    index_by_key: dict[str, int] = {}
    for index, finding in enumerate(blocking):
        for value in (finding.get("id"), finding.get("fingerprint")):
            if value:
                index_by_key.setdefault(str(value), index)
    for extra in active:
        fid = str(extra.get("id") or "")
        fingerprint = str(extra.get("fingerprint") or "")
        match = index_by_key.get(fid) if fid else None
        if match is None and fingerprint:
            match = index_by_key.get(fingerprint)
        if match is not None:
            if match < report_count and fid:
                blocking[match]["id"] = fid
                index_by_key.setdefault(fid, match)
            continue
        merged = dict(extra)
        if fid not in observed_ids:
            merged["from_target_active"] = True
            # Who found it: an earlier scan, or a Hunt. A Hunt's row is not "from an
            # earlier scan", and the page must not say so.
            merged["origin"] = finding_origin(extra)
        else:
            merged["origin"] = "this_scan"
        blocking.append(merged)
        for value in (fid, fingerprint):
            if value:
                index_by_key.setdefault(value, len(blocking) - 1)
    return blocking


__all__ = [
    "HISTORY_ROW_CAP",
    "attach_persisted_ids",
    "finding_origin",
    "is_hunt_finding",
    "gate_findings_from_rows",
    "load_target_history",
    "merge_target_active_blockers",
    "summarize_carried_over",
]
