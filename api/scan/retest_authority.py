"""What a finding retest is authorized by, recorded when it is admitted.

A retest replays a finding's proof against its web target. It is watched while it runs by the
same machinery as a device or AI run (``running_scan_authority.running_retest_authority``), and
this module supplies what that watch binds to:

* when a retest is admitted, ``admit_retest`` records the web target (none for a finding
  without one), the target's current authorization (standing, inherited or bounded), the approval
  receipt the request named and the receipt whose scope covers the replayed host, in
  ``finding_verifications.admitted_authority``, and refuses a replay host that scope does not
  cover. A retest admitted with neither receipt has nothing revocable and is not watched;
* a retest queued by an earlier engine has no record (``admitted_authority`` is NULL). When it
  starts, ``legacy_admitted_authority`` binds the target's current authorization and the
  approval receipt its queue message (or its operation record) named, checks the replayed host,
  and keeps that binding on the row. An authorization the target had when the retest was queued
  that has gone since (revoked, expired, or no longer covering it) refuses the retest before any
  traffic, even if the target was authorized again.

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
    """The target and the receipts a retest is bound to (no destination check)."""
    target = _uuid(target_id)
    current = await _current_authorization(conn, target) if target is not None else None
    standing = _uuid((current or {}).get("approval_receipt_id"))
    approval = _uuid(approval_receipt_id)
    return {
        "schema": RETEST_AUTHORITY_SCHEMA,
        "target_id": str(target) if target else None,
        "standing_receipt_id": str(standing) if standing else None,
        "approval_receipt_id": str(approval) if approval else None,
        "destination_receipt_id": None,
        "admitted_at": datetime.now(timezone.utc).isoformat(),
    }


async def _receipt_covers(conn: Any, receipt_id: Any, host: str | None) -> bool:
    """Whether the scope of an approval receipt covers ``host`` (``receipt_scope_covers_host``)."""
    try:
        from ..action_scope import receipt_scope_covers_host
    except (ImportError, ModuleNotFoundError):
        from action_scope import receipt_scope_covers_host
    receipt = _uuid(receipt_id)
    if receipt is None or not host:
        return False
    scope = await conn.fetchrow(
        """SELECT s.verdict, s.normalized_scope, s.allowed_hosts, s.allowed_root_domains
             FROM approval_receipts a JOIN scope_receipts s ON s.id = a.scope_receipt_id
            WHERE a.id = $1""", receipt)
    if scope is None or str(scope["verdict"] or "") == "blocked":
        return False
    return receipt_scope_covers_host(host, dict(scope))


REPLAY_OUT_OF_SCOPE = "replay_url_out_of_scope"


async def admit_retest(
    conn: Any, *, target_id: Any, approval_receipt_id: Any = None, destination: Any = None,
) -> tuple[dict[str, Any], str | None]:
    """``(record, refusal)``: what a retest is bound to, and why it cannot be admitted.

    The replay destination (the URL the retest is sent to) must be covered by the scope that
    admits it: the approval receipt the request named, else the target's authorization. A
    retest with neither receipt has nothing to check it against and is admitted unwatched.
    ``refusal`` is an operator message; no receipt contents are included.
    """
    try:
        from ..action_scope import url_host_for_scope
    except (ImportError, ModuleNotFoundError):
        from action_scope import url_host_for_scope
    record = await admitted_authority(conn, target_id=target_id, approval_receipt_id=approval_receipt_id)
    approval, standing = record["approval_receipt_id"], record["standing_receipt_id"]
    if not approval and not standing:
        return record, None
    host = url_host_for_scope(destination)
    covering = approval or standing
    if await _receipt_covers(conn, covering, host):
        record["destination_receipt_id"] = covering
        return record, None
    which = "approval receipt" if approval else "target's authorization"
    return record, f"The {which} does not cover the host of the URL the retest replays"


async def _approval_from_operation(conn: Any, verification_id: Any) -> str | None:
    """The approval an earlier engine recorded for this retest on its operation record."""
    retest = _uuid(verification_id)
    if retest is None:
        return None
    value = await conn.fetchval(
        """SELECT approval_receipt_id FROM command_results
            WHERE command = 'finding.retest' AND result_json->>'retest_id' = $1
              AND approval_receipt_id IS NOT NULL
            ORDER BY created_at DESC LIMIT 1""", str(retest))
    return str(value) if value else None


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
    destination: Any = None, verification_id: Any = None,
) -> tuple[dict[str, Any], str | None]:
    """``(record, refusal)`` for a retest queued without a record (an earlier engine).

    It is bound to the approval its queue message named (or, when a requeue lost it, the one its
    operation record names) and to the target's authorization, and its replay destination is
    checked as at admission. ``refusal`` is a ``CapabilityResultReason`` value when an
    authorization the target had when the retest was queued has gone since, even if the target
    was authorized again afterwards (revoked, expired, or no longer covering the target), or when
    the destination is not covered.
    """
    approval = approval_receipt_id or await _approval_from_operation(conn, verification_id)
    record, out_of_scope = await admit_retest(
        conn, target_id=target_id, approval_receipt_id=approval, destination=destination)
    record["legacy"] = True
    target = _uuid(target_id)
    if target is not None and isinstance(queued_at, datetime):
        if queued_at.tzinfo is None:
            queued_at = queued_at.replace(tzinfo=timezone.utc)
        # The receipts the target's authorization resolved through (its own, or the asset
        # owner's it inherits) when the retest was queued.
        rows = await conn.fetch(
            """SELECT a.id, a.revoked_at, a.expires_at
                 FROM approval_receipts a JOIN scope_receipts s ON s.id = a.scope_receipt_id
                WHERE s.target_id = COALESCE(target_effective_authorization_target($1), $1)
                  AND a.action_name = $2 AND a.approved_by IS NOT NULL AND a.created_at <= $3
                  AND (a.revoked_at IS NULL OR a.revoked_at >= $3)
                  AND (a.expires_at IS NULL OR a.expires_at > $3)""",
            target, _standing_action(), queued_at,
        )
        if rows and record["standing_receipt_id"] not in {str(row["id"]) for row in rows}:
            if any(row["revoked_at"] is not None for row in rows):
                return record, CapabilityResultReason.AUTHORIZATION_REVOKED.value
            now = datetime.now(timezone.utc)
            if any(row["expires_at"] is not None and row["expires_at"] <= now for row in rows):
                return record, CapabilityResultReason.AUTHORIZATION_EXPIRED.value
            # Still active but no longer the target's authorization: its URL or scope changed.
            return record, CapabilityResultReason.SCOPE_INVALID.value
    if out_of_scope is not None:
        return record, CapabilityResultReason.SCOPE_INVALID.value
    return record, None


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
