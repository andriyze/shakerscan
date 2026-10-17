"""A finding retired by a release is not a fix: how readers tell the two apart.

``scan.retired_findings`` resolves stored rows of kinds a release stopped reporting (a template
duplicate another finding now carries; an absent opt-in header that was never a finding). Such a
row is ``resolved`` with ``evidence.retired`` naming the kind, the reason and the release. Nobody
remediated anything, so it is never counted as resolved in digests, "what changed" summaries or
the "resolved within" filter, and the list and detail label it "Retired by release <version>".
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

RETIRED_BY_RELEASE = "retired_by_release"
_RELEASE_IN_REASON = re.compile(r"\s*\((\d+\.\d+(?:\.\d+)?)\)\s*$")


def retired_sql(alias: str = "f") -> str:
    """True for a row a release retired (``evidence.retired`` present)."""
    prefix = f"{alias}." if alias else ""
    return f"(COALESCE({prefix}evidence, '{{}}'::jsonb) ? 'retired')"


def not_retired_sql(alias: str = "f") -> str:
    """True for every row a release did not retire: the rows a resolved count may include."""
    return f"NOT {retired_sql(alias)}"


def resolution_reason_sql(alias: str = "f") -> str:
    """``retired_by_release`` or ``resolved`` for a resolved row; NULL for any other status."""
    prefix = f"{alias}." if alias else ""
    return (
        f"CASE WHEN {prefix}status = 'resolved' AND {retired_sql(alias)} THEN '{RETIRED_BY_RELEASE}' "
        f"WHEN {prefix}status = 'resolved' THEN 'resolved' END"
    )


def retirement_sql(alias: str = "f") -> str:
    """The retirement record of a resolved, retired row (NULL otherwise)."""
    prefix = f"{alias}." if alias else ""
    return f"CASE WHEN {prefix}status = 'resolved' THEN {prefix}evidence->'retired' END"


def retirement_record(raw: Any) -> dict[str, Any] | None:
    """``{kind, reason, release, scan_id, label}`` from a stored ``evidence.retired``, else None."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return None
    if not isinstance(raw, Mapping):
        return None
    reason = str(raw.get("reason") or "").strip().rstrip(".")
    release = str(raw.get("release") or "").strip()
    match = _RELEASE_IN_REASON.search(reason)
    if match:
        # Rows retired before the record named its release carry it in the reason: "... (2.11)".
        release = release or match.group(1)
        reason = reason[:match.start()].rstrip()
    reason = reason.rstrip(".")
    label = f"Retired by release {release}" if release else "Retired by a release"
    return {
        "kind": str(raw.get("kind") or "") or None,
        "reason": reason or None,
        "release": release or None,
        "scan_id": str(raw.get("scan_id") or "") or None,
        "label": f"{label}: {reason}" if reason else label,
    }


def retirement_fields(finding: Mapping[str, Any]) -> dict[str, Any]:
    """``resolution_reason`` and ``retirement`` for one finding row (detail or list)."""
    if str(finding.get("status") or "") != "resolved":
        return {"resolution_reason": None, "retirement": None}
    evidence = finding.get("evidence")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except ValueError:
            evidence = None
    raw = finding.get("retirement")
    if raw is None and isinstance(evidence, Mapping):
        raw = evidence.get("retired")
    record = retirement_record(raw)
    return {
        "resolution_reason": RETIRED_BY_RELEASE if record else "resolved",
        "retirement": record,
    }


__all__ = [
    "RETIRED_BY_RELEASE", "not_retired_sql", "resolution_reason_sql", "retired_sql", "retirement_fields",
    "retirement_record", "retirement_sql",
]
