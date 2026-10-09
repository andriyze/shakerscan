"""Runtime revalidation of immutable Scan action scope and approval authority."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import ipaddress
import json
from typing import Any, Mapping

try:
    from scope.psl import spans_public_suffix
except ModuleNotFoundError:  # package import
    from ..scope.psl import spans_public_suffix

try:
    from ..runtime.capability_registry import CAPABILITY_REGISTRY
except (ImportError, ModuleNotFoundError):
    from runtime.capability_registry import CAPABILITY_REGISTRY


class ActionAuthorityDecision(str, Enum):
    ALLOWED = "allowed"
    REJECTED_CAPABILITY = "capability_unknown"
    REJECTED_MISSING = "authorization_missing"
    REJECTED_REVOKED = "authorization_revoked"
    REJECTED_EXPIRED = "authorization_expired"
    REJECTED_SCOPE = "scope_invalid"
    REJECTED_MISMATCH = "authorization_mismatch"


def _value(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    try:
        return source[name]
    except (KeyError, IndexError, TypeError, AttributeError):
        pass
    return getattr(source, name, default)


def _timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _sequence(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return (value,)
        if not isinstance(decoded, list):
            return (value,)
        value = decoded
    if not isinstance(value, (list, tuple, set, frozenset)):
        return ()
    return tuple(str(item) for item in value)


def _host_in_scope(host: str, scope_receipt: Any) -> bool:
    normalized = str(host or "").strip().lower().rstrip(".")
    if not normalized:
        return False
    allowed_hosts = {
        item.strip().lower().rstrip(".")
        for item in _sequence(_value(scope_receipt, "allowed_hosts", ()))
        if item.strip()
    }
    roots = {
        item.strip().lower().rstrip(".")
        for item in _sequence(_value(scope_receipt, "allowed_root_domains", ()))
        if item.strip() and not spans_public_suffix(item)
    }
    try:
        address = str(ipaddress.ip_address(normalized))
    except ValueError:
        address = ""
    return bool(
        normalized in allowed_hosts
        or (address and address in allowed_hosts)
        or any(normalized == root or normalized.endswith("." + root) for root in roots)
    )


STANDING_AUTHORIZATION_ACTION = "target.authorization"


def _standing_authorization(approval_receipt: Any) -> bool:
    """A standing target authorization is the one receipt allowed to have no expiry.

    It is created once per target (``target_authorization.authorize_target``), revoked
    explicitly or superseded when the target's scope changes, and never covers the dangerous
    tier, which keeps its bounded per-action approvals.
    """
    action_name = str(_value(approval_receipt, "action_name", "") or "").strip()
    risk_tier = str(_value(approval_receipt, "risk_tier", "") or "").strip().lower()
    return action_name == STANDING_AUTHORIZATION_ACTION and risk_tier in {"active", "intrusive"}


def _requires_approval(action: Any) -> bool | None:
    capability_name = str(_value(action, "capability_name", "") or "").strip()
    try:
        specification = CAPABILITY_REGISTRY.require(capability_name)
        values = _value(action, "capability_input", {})
        method = str(_value(values, "method", "") or "").upper()
        # Writes must not inherit http.request's passive baseline shortcut.
        return specification.requires_active_approval or (
            capability_name == "http.request"
            and (method in {"POST", "PUT", "PATCH", "DELETE"}
                 or bool(_value(values, "capture") or _value(values, "request_bindings")))
        )
    except KeyError:
        return None


def revalidate_action_authority(
    *,
    action: Any,
    target_binding: Any,
    scope_receipt: Any | None = None,
    approval_receipt: Any | None = None,
    scope_receipt_id: str | None = None,
    approval_receipt_id: str | None = None,
    now: datetime | None = None,
    asset_authority_validated: bool = False,
) -> ActionAuthorityDecision:
    """Evaluate fresh durable authority without granting or widening scope."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    approval_status = str(_value(approval_receipt, "status", "") or "").lower()
    scope_status = str(_value(scope_receipt, "status", "") or "").lower()
    target_status = str(_value(target_binding, "status", "active") or "active").lower()
    if (
        approval_status in {"revoked", "denied", "inactive"}
        or scope_status in {"revoked", "denied", "inactive"}
        or _value(approval_receipt, "revoked_at")
        or _value(scope_receipt, "revoked_at")
        or _value(approval_receipt, "denial_reason")
    ):
        return ActionAuthorityDecision.REJECTED_REVOKED
    if target_status not in {"active", "running", "allowed"}:
        return ActionAuthorityDecision.REJECTED_SCOPE

    bound_scope_id = str(
        scope_receipt_id
        or _value(target_binding, "scope_receipt_id", "")
        or ""
    ).strip()
    if bound_scope_id and scope_receipt is None:
        return ActionAuthorityDecision.REJECTED_MISSING
    if scope_receipt is not None:
        actual_scope_id = str(_value(scope_receipt, "id", "") or "").strip()
        if bound_scope_id and actual_scope_id != bound_scope_id:
            return ActionAuthorityDecision.REJECTED_MISMATCH
        verdict = str(_value(scope_receipt, "verdict", "allowed") or "").lower()
        if verdict == "blocked":
            return ActionAuthorityDecision.REJECTED_SCOPE
        target_id = str(_value(target_binding, "target_id", "") or "").strip()
        scope_target_id = str(_value(scope_receipt, "target_id", "") or "").strip()
        if target_id and scope_target_id and target_id != scope_target_id and not asset_authority_validated:
            return ActionAuthorityDecision.REJECTED_SCOPE
        if not _host_in_scope(
            str(_value(target_binding, "canonical_host", "") or ""), scope_receipt,
        ):
            return ActionAuthorityDecision.REJECTED_SCOPE

    requires_approval = _requires_approval(action)
    if requires_approval is None:
        return ActionAuthorityDecision.REJECTED_CAPABILITY
    if not requires_approval:
        return ActionAuthorityDecision.ALLOWED
    if approval_receipt is None or not str(approval_receipt_id or "").strip():
        return ActionAuthorityDecision.REJECTED_MISSING
    actual_approval_id = str(_value(approval_receipt, "id", "") or "").strip()
    if actual_approval_id != str(approval_receipt_id).strip():
        return ActionAuthorityDecision.REJECTED_MISMATCH
    approval_scope_id = str(
        _value(approval_receipt, "scope_receipt_id", "") or ""
    ).strip()
    if not bound_scope_id or approval_scope_id != bound_scope_id:
        return ActionAuthorityDecision.REJECTED_MISMATCH
    expires_at = _timestamp(_value(approval_receipt, "expires_at"))
    if expires_at is None and not _standing_authorization(approval_receipt):
        return ActionAuthorityDecision.REJECTED_MISSING
    if expires_at is not None and expires_at <= current:
        return ActionAuthorityDecision.REJECTED_EXPIRED
    if not _value(approval_receipt, "approved_by"):
        return ActionAuthorityDecision.REJECTED_REVOKED
    confirmations = set(_sequence(_value(approval_receipt, "confirmations", ())))
    if "confirm_authorized" not in confirmations:
        return ActionAuthorityDecision.REJECTED_MISMATCH
    if (
        str(_value(scope_receipt, "verdict", "allowed") or "").lower()
        == "needs_approval"
        and "confirm_scope_reviewed" not in confirmations
    ):
        return ActionAuthorityDecision.REJECTED_MISMATCH
    return ActionAuthorityDecision.ALLOWED


async def revalidate_scan_action_authority(
    conn: Any,
    *,
    action: Any,
    target_binding: Any,
    scope_receipt_id: str | None,
    approval_receipt_id: str | None,
    now: datetime | None = None,
) -> ActionAuthorityDecision:
    """Reload scope and approval rows immediately before one action executes."""
    scope_receipt = None
    approval_receipt = None
    if scope_receipt_id:
        scope_receipt = await conn.fetchrow(
            "SELECT * FROM scope_receipts WHERE id=$1", str(scope_receipt_id),
        )
    if approval_receipt_id:
        try:
            import uuid
            approval_id = uuid.UUID(str(approval_receipt_id))
        except (TypeError, ValueError, AttributeError):
            return ActionAuthorityDecision.REJECTED_MISMATCH
        approval_receipt = await conn.fetchrow(
            "SELECT * FROM approval_receipts WHERE id=$1", approval_id,
        )
    asset_authority_validated = False
    target_id = str(_value(target_binding, "target_id", "") or "")
    scope_target = str(_value(scope_receipt, "target_id", "") or "")
    if _standing_authorization(approval_receipt) and target_id and scope_target and target_id != scope_target:
        try:
            from ..targets.asset_authority import standing_authorization_matches_target
        except (ImportError, ModuleNotFoundError):
            from targets.asset_authority import standing_authorization_matches_target
        asset_authority_validated = await standing_authorization_matches_target(
            conn, target_id=target_id, scope_target_id=scope_target,
            approval_receipt_id=_value(approval_receipt, "id"),
        )
    decision = revalidate_action_authority(
        asset_authority_validated=asset_authority_validated,
        action=action,
        target_binding=target_binding,
        scope_receipt=scope_receipt,
        approval_receipt=approval_receipt,
        scope_receipt_id=scope_receipt_id,
        approval_receipt_id=approval_receipt_id,
        now=now,
    )
    if (
        decision is ActionAuthorityDecision.ALLOWED
        and _standing_authorization(approval_receipt)
        and target_id and (not scope_target or scope_target == target_id)
        and not await _standing_receipt_still_current(conn, target_id, approval_receipt)
    ):
        # The receipt row alone is not the target's authorization: a revoke or a change that
        # did not reach this row (a host change, a blocked scope, a revoked alias source) must
        # stop the work exactly as it stops a new submission. An inherited receipt (target and
        # scope differ) is already resolved afresh by standing_authorization_matches_target.
        return ActionAuthorityDecision.REJECTED_REVOKED
    return decision


async def _standing_receipt_still_current(conn: Any, target_id: str, approval_receipt: Any) -> bool:
    try:
        from ..target_authorization import standing_authorization_is_current
    except (ImportError, ModuleNotFoundError):
        from target_authorization import standing_authorization_is_current
    if not await standing_authorization_is_current(conn, target_id, _value(approval_receipt, "id")):
        return False
    context = _value(approval_receipt, "action_context", {}) or {}
    if isinstance(context, str):
        try:
            context = json.loads(context)
        except json.JSONDecodeError:
            return False
    source = str(context.get("derived_from_approval_receipt_id") or "") if isinstance(context, Mapping) else ""
    if not source:
        return True
    # A www/apex alias receipt lives only as long as the authorization it was derived from.
    import uuid
    try:
        source_id = uuid.UUID(source)
    except ValueError:
        return False
    return await conn.fetchval("SELECT status FROM approval_receipts WHERE id=$1", source_id) == "active"
