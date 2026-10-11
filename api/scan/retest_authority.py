"""What a finding retest is authorized by, recorded when it is admitted.

A retest replays a finding's proof against its web target. It is watched while it runs by the
same machinery as a device or AI run (``running_scan_authority.running_retest_authority``), and
this module supplies what that watch binds to:

* when a retest is admitted, ``admitted_authority`` records the web target, the target's
  current authorization (standing, inherited or bounded) and the approval receipt the request
  named, in ``finding_verifications.admitted_authority``. A retest admitted with neither
  receipt has nothing revocable and is not watched;
* a retest queued by an earlier engine has no record (``admitted_authority`` is NULL). When it
  starts, ``legacy_admitted_authority`` binds the target's current authorization and the
  approval receipt its queue message named (earlier engines put it there after validating it),
  and that binding is kept on the row. A target that had an authorization when the retest was
  queued and has none now (revoked, expired, or no longer covering it) refuses the retest before
  any traffic.

Only receipt ids and the target id are recorded; no receipt contents and no credentials.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Mapping
import uuid

from .capability_result import CapabilityResultReason


RETEST_AUTHORITY_SCHEMA = "retest-authority/v1"
# Additive: installed on every start by ``targets.asset_migration.run_unified_startup`` and,
# with the same definition, by db/init.sql. Earlier engines never read it.
FINDING_VERIFICATION_AUTHORITY_SQL = (
    "ALTER TABLE finding_verifications ADD COLUMN IF NOT EXISTS admitted_authority JSONB"
)


def _uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value)) if value else None
    except (TypeError, ValueError, AttributeError):
        return None


async def _current_authorization(conn: Any, target_id: uuid.UUID) -> dict[str, Any] | None:
    try:
        from ..target_authorization import current_target_authorization
    except (ImportError, ModuleNotFoundError):
        from target_authorization import current_target_authorization
    return await current_target_authorization(conn, target_id)


def _standing_action() -> str:
    try:
        from ..runtime.approval_policy import STANDING_ACTION_NAME
    except (ImportError, ModuleNotFoundError):
        from runtime.approval_policy import STANDING_ACTION_NAME
    return STANDING_ACTION_NAME


async def admitted_authority(
    conn: Any, *, target_id: Any, approval_receipt_id: Any = None,
) -> dict[str, Any]:
    """The record a retest is admitted with: the target and the receipts it is bound to."""
    target = _uuid(target_id)
    current = await _current_authorization(conn, target) if target is not None else None
    standing = _uuid((current or {}).get("approval_receipt_id"))
    approval = _uuid(approval_receipt_id)
    return {
        "schema": RETEST_AUTHORITY_SCHEMA,
        "target_id": str(target) if target else None,
        "standing_receipt_id": str(standing) if standing else None,
        "approval_receipt_id": str(approval) if approval else None,
        "admitted_at": datetime.now(timezone.utc).isoformat(),
    }


def admitted_authority_json(record: Mapping[str, Any]) -> str:
    return json.dumps(dict(record), sort_keys=True)


def parse_admitted_authority(value: Any) -> dict[str, Any] | None:
    """The stored record, or ``None`` for a retest an earlier engine queued."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return None
    return dict(value) if isinstance(value, Mapping) else None


async def legacy_admitted_authority(
    conn: Any, *, target_id: Any, queued_at: Any, approval_receipt_id: Any = None,
) -> tuple[dict[str, Any], str | None]:
    """``(record, refusal)`` for a retest queued without a record (an earlier engine).

    ``refusal`` is a ``CapabilityResultReason`` value when the target had an authorization when
    the retest was queued and has none now: revoked, expired, or no longer covering the target
    (its URL or scope changed).
    """
    record = await admitted_authority(conn, target_id=target_id, approval_receipt_id=approval_receipt_id)
    record["legacy"] = True
    target = _uuid(target_id)
    if record["standing_receipt_id"] or target is None or not isinstance(queued_at, datetime):
        return record, None
    if queued_at.tzinfo is None:
        queued_at = queued_at.replace(tzinfo=timezone.utc)
    # The receipts the target's authorization resolves through (its own, or the asset owner's it
    # inherits), as they stood when the retest was queued.
    rows = await conn.fetch(
        """SELECT a.status, a.revoked_at, a.expires_at
             FROM approval_receipts a JOIN scope_receipts s ON s.id = a.scope_receipt_id
            WHERE s.target_id = COALESCE(target_effective_authorization_target($1), $1)
              AND a.action_name = $2 AND a.approved_by IS NOT NULL AND a.created_at <= $3
              AND (a.revoked_at IS NULL OR a.revoked_at >= $3)
              AND (a.expires_at IS NULL OR a.expires_at > $3)""",
        target, _standing_action(), queued_at,
    )
    if not rows:
        return record, None
    if any(row["revoked_at"] is not None for row in rows):
        return record, CapabilityResultReason.AUTHORIZATION_REVOKED.value
    if any(row["expires_at"] is not None and row["expires_at"] <= datetime.now(timezone.utc) for row in rows):
        return record, CapabilityResultReason.AUTHORIZATION_EXPIRED.value
    # Still active but no longer the target's authorization: its URL or scope changed.
    return record, CapabilityResultReason.SCOPE_INVALID.value


AUTHORIZATION_WITHDRAWN = "authorization_withdrawn"
_UNVERIFIED = CapabilityResultReason.AUTHORIZATION_UNVERIFIED.value
RETEST_ACTION = "finding.retest"
_CAUSES = {
    CapabilityResultReason.AUTHORIZATION_REVOKED.value: "the target's authorization was revoked",
    CapabilityResultReason.AUTHORIZATION_EXPIRED.value: "the testing approval expired",
    CapabilityResultReason.SCOPE_INVALID.value: (
        "the target was deactivated or removed, or the approved scope does not cover it or the "
        "replayed URL"),
    _UNVERIFIED: "the target's authorization could not be confirmed (the check did not answer in time)",
}


def retest_authority_stop(reason: str, *, before_start: bool) -> dict[str, Any]:
    """The stop record a retest keeps, in the shape a Scan report's ``authority_stop`` has.

    ``stop_reason`` is ``authorization_unverified`` only for a check that did not answer, never
    a revoke; every refusal is ``authorization_withdrawn`` with its ``reason_code``.
    """
    try:
        reason = CapabilityResultReason(reason).value
    except ValueError:
        reason = _UNVERIFIED
    return {
        "stop_reason": _UNVERIFIED if reason == _UNVERIFIED else AUTHORIZATION_WITHDRAWN,
        "reason_code": reason,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "before_start": bool(before_start),
        "interrupted_actions": [] if before_start else [RETEST_ACTION],
        "not_run_actions": [RETEST_ACTION] if before_start else [],
    }


def retest_authority_stop_message(stop: Mapping[str, Any]) -> str:
    cause = _CAUSES.get(str(stop.get("reason_code") or ""), "the target's authorization was withdrawn")
    when = "before it started" if stop.get("before_start") else "while it ran"
    return (f"Retest stopped {when}: {cause}. No verdict was recorded; a partial retest shows "
            "neither a fix nor that the finding is still vulnerable.")


async def approval_covers_destination(conn: Any, approval_receipt_id: Any, destination: str) -> bool:
    """Whether an approval receipt's scope covers the host a retest replays against.

    The same rule the running check applies (``running_scan_authority._host_in_admitted_scope``),
    so a retest bound to the receipt is not admitted only to be refused when it starts.
    """
    from urllib.parse import urlparse

    from .running_scan_authority import _host_in_admitted_scope

    approval = _uuid(approval_receipt_id)
    if approval is None:
        return False
    scope = await conn.fetchrow(
        """SELECT s.verdict, s.normalized_scope, s.allowed_hosts, s.allowed_root_domains
             FROM approval_receipts a JOIN scope_receipts s ON s.id = a.scope_receipt_id
            WHERE a.id = $1""", approval)
    if scope is None or str(scope["verdict"] or "") == "blocked":
        return False
    parsed = urlparse(destination if "://" in destination else f"https://{destination}")
    return _host_in_admitted_scope(parsed.hostname or "", dict(scope))
