"""Runtime revalidation of immutable Scan action scope and approval authority."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import ipaddress
from typing import Any, Mapping

try:
    from ..runtime.capability_registry import CAPABILITY_REGISTRY
except (ImportError, ModuleNotFoundError):
    from runtime.capability_registry import CAPABILITY_REGISTRY


class ActionAuthorityDecision(str, Enum):
    ALLOWED = "allowed"
    REJECTED_MISSING = "authorization_missing"
    REJECTED_REVOKED = "authorization_revoked"
    REJECTED_EXPIRED = "authorization_expired"
    REJECTED_SCOPE = "scope_invalid"
    REJECTED_MISMATCH = "authorization_mismatch"


def _value(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
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
        return (value,)
    if not isinstance(value, (list, tuple, set, frozenset)):
        return ()
    return tuple(str(item) for item in value)


def _host_in_scope(host: str, scope_receipt: Any) -> bool:
    normalized = str(host or "").strip().lower().rstrip(".")
    if not normalized:
        return True
    allowed_hosts = {
        item.strip().lower().rstrip(".")
        for item in _sequence(_value(scope_receipt, "allowed_hosts", ()))
        if item.strip()
    }
    roots = {
        item.strip().lower().rstrip(".")
        for item in _sequence(_value(scope_receipt, "allowed_root_domains", ()))
        if item.strip()
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


def _requires_approval(action: Any) -> bool:
    capability_name = str(_value(action, "capability_name", "") or "").strip()
    try:
        return CAPABILITY_REGISTRY.require(capability_name).requires_active_approval
    except KeyError:
        # Compatibility for historic active capability spellings while callers
        # migrate to the canonical registry.
        return any(token in capability_name for token in (
            ".active", "verify", "templates", "ports", "fingerprint", "auth.session",
        ))


def revalidate_action_authority(
    *,
    action: Any,
    target_binding: Any,
    scope_receipt: Any | None = None,
    approval_receipt: Any | None = None,
    scope_receipt_id: str | None = None,
    approval_receipt_id: str | None = None,
    now: datetime | None = None,
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
        if target_id and scope_target_id and target_id != scope_target_id:
            return ActionAuthorityDecision.REJECTED_SCOPE
        if not _host_in_scope(
            str(_value(target_binding, "canonical_host", "") or ""), scope_receipt,
        ):
            return ActionAuthorityDecision.REJECTED_SCOPE

    if not _requires_approval(action):
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
    if expires_at is None:
        return ActionAuthorityDecision.REJECTED_MISSING
    if expires_at <= current:
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
    return revalidate_action_authority(
        action=action,
        target_binding=target_binding,
        scope_receipt=scope_receipt,
        approval_receipt=approval_receipt,
        scope_receipt_id=scope_receipt_id,
        approval_receipt_id=approval_receipt_id,
        now=now,
    )
