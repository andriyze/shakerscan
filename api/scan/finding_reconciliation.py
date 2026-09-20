"""Carry a finding's row across the 2.3.8 identity change instead of duplicating it."""

from __future__ import annotations

import hashlib
from typing import Any


def legacy_finding_fingerprint(legacy_identity: str | None, fingerprint: str) -> str | None:
    """The fingerprint a pre-2.3.8 installation stored for this identity, if it differs."""
    if not legacy_identity:
        return None
    candidate = "t:" + hashlib.sha256(legacy_identity.encode()).hexdigest()[:16]
    return candidate if candidate != fingerprint else None


def _legacy_identity(finding: dict) -> str | None:
    try:
        from findings import legacy_templated_finding_identity
    except ImportError:  # package layout
        from scanner.findings import legacy_templated_finding_identity
    try:
        return legacy_templated_finding_identity(finding)
    except Exception:  # noqa: BLE001 - an unreadable finding simply has no legacy row
        return None


async def reconcile_legacy_finding_row(
    conn: Any,
    *,
    target_uuid: Any,
    fingerprint: str,
    finding: dict,
) -> Any | None:
    """Move the row an older installation holds for this finding to its new key.

    Before 2.3.8 every CWE-less match on a route shared one row, so that row is
    one of several checks and carries the title of whichever was written last.
    It is the same finding only when the title agrees; then its triage and
    history move to the new fingerprint and the caller updates it as existing.
    Any other legacy row is left alone: it belongs to a different check, goes
    stale on its own, and never has one disposition copied onto every split.
    """
    legacy_fingerprint = legacy_finding_fingerprint(_legacy_identity(finding), fingerprint)
    if not legacy_fingerprint:
        return None
    legacy_row = await conn.fetchrow(
        """
        SELECT id, status, resurfaced_count, title, tool, cwe, evidence
        FROM findings
        WHERE target_id = $1 AND fingerprint = $2
        FOR UPDATE
        """,
        target_uuid, legacy_fingerprint,
    )
    if not legacy_row or str(legacy_row.get("title") or "") != str(finding.get("title") or ""):
        return None
    await conn.execute(
        "UPDATE findings SET fingerprint = $1 WHERE id = $2",
        fingerprint, legacy_row["id"],
    )
    return legacy_row
