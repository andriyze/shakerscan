"""Standing target authorization: one recorded act per target, reused by every scan and Hunt.

Active testing needs a target-bound approval receipt. Until now every submission created its own
short-lived receipt (the UI defaulted to two hours), which felt like asking for permission on
every scan. A standing authorization is the same receipt, created once for the target's scope
with no expiry, and resolved automatically when a submission for that target carries none.

What still ends it: an explicit revocation (the approval revoke endpoint or the target endpoint),
or a change of the target's scope (a different host produces a different scope receipt, so the
old authorization no longer matches and the target is authorized again). The dangerous tier
(evidence deletion, retention sweeps) is unaffected: it keeps its per-action, bounded approval.
"""
from __future__ import annotations

import json
import urllib.parse
import uuid
from typing import Any, Mapping

try:
    from action_scope import evaluate_scope, receipt_to_dict
except ModuleNotFoundError:  # package-native import layout
    from api.action_scope import evaluate_scope, receipt_to_dict

STANDING_ACTION_NAME = "target.authorization"
STANDING_RISK_TIERS = ("active", "intrusive")


class TargetAuthorizationError(ValueError):
    """The target cannot be authorized as requested (blocked scope, unknown target)."""


def _host(url: str) -> str:
    parsed = urllib.parse.urlparse(str(url or "").strip())
    return (parsed.hostname or "").lower().strip("[]")


def _row(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    try:
        return dict(value)
    except (TypeError, ValueError):
        return {}


def _json(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def public_authorization(approval: Mapping[str, Any], scope: Mapping[str, Any]) -> dict[str, Any]:
    """The projection a target detail, the UI and a gateway read."""
    return {
        "approval_receipt_id": str(approval.get("id") or ""),
        "scope_receipt_id": str(scope.get("id") or scope.get("receipt_id") or ""),
        "approved_by": approval.get("approved_by"),
        "risk_tier": approval.get("risk_tier"),
        "created_at": approval.get("created_at"),
        "expires_at": approval.get("expires_at"),
        "standing": approval.get("expires_at") is None,
    }


async def persist_scope_receipt(conn: Any, receipt: Mapping[str, Any], target_id: uuid.UUID) -> None:
    await conn.execute(
        """
        INSERT INTO scope_receipts
            (id, target_id, input_scope, normalized_scope, verdict, blocked_by, warnings,
             checks, environment, allowed_hosts, allowed_root_domains, redirect_destinations)
        VALUES ($1,$2,$3::jsonb,$4::jsonb,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10::jsonb,$11::jsonb,$12::jsonb)
        ON CONFLICT (id) DO UPDATE SET
            target_id = EXCLUDED.target_id,
            verdict = EXCLUDED.verdict,
            blocked_by = EXCLUDED.blocked_by,
            warnings = EXCLUDED.warnings,
            checks = EXCLUDED.checks,
            environment = EXCLUDED.environment,
            allowed_hosts = EXCLUDED.allowed_hosts,
            allowed_root_domains = EXCLUDED.allowed_root_domains,
            redirect_destinations = EXCLUDED.redirect_destinations,
            created_at = NOW()
        """,
        receipt["receipt_id"],
        target_id,
        json.dumps(receipt["input_scope"]),
        json.dumps(receipt["normalized_scope"]),
        receipt["verdict"],
        json.dumps(receipt["blocked_by"]),
        json.dumps(receipt["warnings"]),
        json.dumps(receipt["checks"]),
        receipt["environment"],
        json.dumps(receipt["allowed_hosts"]),
        json.dumps(receipt["allowed_root_domains"]),
        json.dumps(receipt["redirect_destinations"]),
    )


async def current_target_authorization(conn: Any, target_id: Any) -> dict[str, Any] | None:
    """The target's standing (or still valid bounded) authorization, or None.

    Only receipts whose scope still names the target's current host count: a target whose URL
    changed since the authorization was given must be authorized again.
    """
    try:
        target_uuid = uuid.UUID(str(target_id))
    except (TypeError, ValueError):
        return None
    target = _row(await conn.fetchrow("SELECT id, url FROM targets WHERE id=$1", target_uuid))
    if not target:
        return None
    rows = await conn.fetch(
        """
        SELECT a.*, s.id AS scope_id, s.allowed_hosts AS scope_allowed_hosts,
               s.normalized_scope AS scope_normalized, s.verdict AS scope_verdict
          FROM approval_receipts a
          JOIN scope_receipts s ON s.id = a.scope_receipt_id
         WHERE s.target_id = $1
           AND a.approved_by IS NOT NULL
           AND a.status = 'active'
           AND a.risk_tier = ANY($2::text[])
           AND (a.action_name IS NULL OR a.action_name = $3)
           AND (a.expires_at IS NULL OR a.expires_at > NOW())
         ORDER BY (a.expires_at IS NULL) DESC, a.created_at DESC
         LIMIT 20
        """,
        target_uuid,
        list(STANDING_RISK_TIERS),
        STANDING_ACTION_NAME,
    )
    host = _host(target.get("url", ""))
    for raw in rows:
        row = _row(raw)
        if str(row.get("scope_verdict") or "") == "blocked":
            continue
        allowed = _json(row.get("scope_allowed_hosts")) or []
        normalized = _json(row.get("scope_normalized")) or {}
        scope_host = str((normalized or {}).get("host") or "").lower() if isinstance(normalized, dict) else ""
        hosts = {str(item).lower() for item in allowed if str(item).strip()} | ({scope_host} if scope_host else set())
        if host and host not in hosts:
            continue
        scope = {"id": row.get("scope_id"), "verdict": row.get("scope_verdict")}
        return public_authorization(row, scope)
    return None


async def authorize_target(
    conn: Any,
    target_id: Any,
    *,
    approved_by: str,
    environment: str | None = None,
    risk_tier: str = "active",
) -> dict[str, Any]:
    """Record the standing authorization for a target; idempotent while one already stands."""
    approved_by = str(approved_by or "").strip()
    if not approved_by:
        raise TargetAuthorizationError("approved_by is required")
    if risk_tier not in STANDING_RISK_TIERS:
        raise TargetAuthorizationError("a standing authorization is active or intrusive")
    try:
        target_uuid = uuid.UUID(str(target_id))
    except (TypeError, ValueError) as exc:
        raise TargetAuthorizationError("target id must be a UUID") from exc
    existing = await current_target_authorization(conn, target_uuid)
    if existing and existing.get("standing") and existing.get("risk_tier") == risk_tier:
        return existing
    target = _row(await conn.fetchrow("SELECT id, url, metadata_json FROM targets WHERE id=$1", target_uuid))
    if not target:
        raise TargetAuthorizationError("target not found")
    metadata = _json(target.get("metadata_json")) or {}
    env = str(environment or (metadata.get("environment") if isinstance(metadata, dict) else "") or "production").strip().lower()
    url = str(target.get("url") or "")
    host = _host(url)
    receipt = receipt_to_dict(evaluate_scope(
        url, allowed_hosts=[host] if host else None, environment=env, target_id=str(target_uuid),
    ))
    if receipt["verdict"] == "blocked":
        raise TargetAuthorizationError(
            "the target's scope is blocked: " + ", ".join(receipt["blocked_by"])
        )
    await persist_scope_receipt(conn, receipt, target_uuid)
    confirmations = ["confirm_authorized"]
    if receipt["verdict"] == "needs_approval":
        confirmations.append("confirm_scope_reviewed")
    row = _row(await conn.fetchrow(
        """
        INSERT INTO approval_receipts
            (scope_receipt_id, risk_tier, confirmations, action_name, action_context,
             approved_by, denial_reason, expires_at)
        VALUES ($1,$2,$3::jsonb,$4,$5::jsonb,$6,NULL,NULL)
        RETURNING *
        """,
        receipt["receipt_id"],
        risk_tier,
        json.dumps(confirmations),
        STANDING_ACTION_NAME,
        json.dumps({"target_id": str(target_uuid), "host": host}, sort_keys=True),
        approved_by,
    ))
    return public_authorization(row, {"id": receipt["receipt_id"], "verdict": receipt["verdict"]})


async def revoke_target_authorization(
    conn: Any, target_id: Any, *, revoked_by: str, reason: str
) -> int:
    """Revoke every standing authorization of the target; returns how many were revoked."""
    try:
        target_uuid = uuid.UUID(str(target_id))
    except (TypeError, ValueError) as exc:
        raise TargetAuthorizationError("target id must be a UUID") from exc
    revoked_by = str(revoked_by or "").strip()
    reason = str(reason or "").strip()
    if not revoked_by or not reason:
        raise TargetAuthorizationError("revoked_by and reason are required")
    result = await conn.execute(
        """
        UPDATE approval_receipts a
           SET status='revoked', revoked_at=NOW(), revoked_by=$2, revocation_reason=$3
          FROM scope_receipts s
         WHERE s.id = a.scope_receipt_id AND s.target_id = $1
           AND a.status = 'active' AND a.approved_by IS NOT NULL
           AND a.action_name = $4
        """,
        target_uuid,
        revoked_by,
        reason[:2000],
        STANDING_ACTION_NAME,
    )
    try:
        return int(str(result).split()[-1])
    except (ValueError, IndexError):
        return 0
