"""Roll canonical action outcomes into the scan's top-level coverage.

The action receipts are the primary signal (``GET /scans/{id}/actions``); the scan's
``coverage_status`` is a consequence of them. Until now the rollup fell back to ``complete``
whenever the run produced no error, so a crawler killed after emitting output (recorded as a
partial action since the crawler fix) still left the scan saying its coverage was complete.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

DEGRADED_STATUSES = frozenset({"partial", "timed_out", "failed", "blocked", "cancelled"})
COMPLETE_STATUSES = frozenset({"complete", "completed"})


def action_coverage_reasons(rows: Iterable[Mapping[str, Any]]) -> list[str]:
    """``<capability>_<status>[:<reason_code>]`` for every required action that fell short."""
    reasons: list[str] = []
    for row in rows or ():
        if not isinstance(row, Mapping) or not row.get("required"):
            continue
        status = str(row.get("status") or "").strip().lower()
        if status not in DEGRADED_STATUSES:
            continue
        capability = str(row.get("capability_name") or "unknown").strip().replace(".", "_")
        reason_code = str(row.get("reason_code") or "").strip()
        reason = f"{capability}_{status}"
        if reason_code:
            reason += f":{reason_code[:80]}"
        if reason not in reasons:
            reasons.append(reason)
    return reasons


def apply_action_coverage(
    coverage: Mapping[str, Any] | None, rows: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """Downgrade a coverage that claims completeness when a required action did not complete."""
    result = dict(coverage or {})
    reasons = action_coverage_reasons(rows)
    if not reasons:
        return result
    existing = [str(item) for item in (result.get("reasons") or []) if str(item).strip()]
    result["reasons"] = existing + [item for item in reasons if item not in existing]
    status = str(result.get("status") or "").strip().lower()
    if status in COMPLETE_STATUSES or not status:
        result["status"] = "partial"
    return result
