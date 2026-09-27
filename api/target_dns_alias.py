"""Keep a registered web target's identity when DNS selects its www twin."""

from __future__ import annotations

import json
import urllib.parse
import uuid
from typing import Any

try:
    import target_authorization
    import target_resolution
    from action_scope import evaluate_scope, receipt_to_dict
except ModuleNotFoundError:  # package-native import layout
    from api import target_authorization, target_resolution
    from api.action_scope import evaluate_scope, receipt_to_dict


def _host(url: str) -> str:
    return str(urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")


def _is_www_pair(requested_url: str, effective_url: str) -> bool:
    requested = urllib.parse.urlsplit(requested_url)
    effective = urllib.parse.urlsplit(effective_url)
    first, second = _host(requested_url), _host(effective_url)
    return bool(
        first and second and first != second
        and (first == f"www.{second}" or second == f"www.{first}")
        and requested.scheme == effective.scheme
        and requested.port == effective.port
    )


async def registered_alias_target_id(pool: Any, requested_url: str, effective_url: str) -> Any | None:
    """Return the preexisting target ID; never create a second row for its DNS twin."""
    if pool is None or not _is_www_pair(requested_url, effective_url):
        return None
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id FROM targets WHERE canonical_key = $1",
            target_resolution.canonical_web_key(requested_url),
        )
    return row["id"] if row else None


async def existing_registration_for_dns_alias(conn: Any, requested_url: str, effective_url: str) -> Any | None:
    """Reuse a historical dead-host target instead of registering a second target row."""
    if not _is_www_pair(requested_url, effective_url):
        return None
    return await conn.fetchrow(
        """SELECT id, url, name, discovery_source, metadata_json, root_domain, is_root,
                  false AS created FROM targets WHERE canonical_key=$1""",
        target_resolution.canonical_web_key(requested_url),
    )


async def prepare_scan_dns_alias(
    pool: Any, requested_url: str, *, active: bool,
    supplied_receipt_id: str | None,
) -> tuple[str, dict[str, Any] | None, Any | None, str | None]:
    """Resolve the execution URL while retaining a registered alias's ID and authority."""
    effective_url, fallback = await target_resolution.scan_target_dns_fallback(requested_url, pool)
    alias_id = await registered_alias_target_id(pool, requested_url, effective_url) if fallback else None
    receipt_id = supplied_receipt_id
    if alias_id and active:
        derived = await standing_receipt_for_dns_alias(
            pool, target_id=alias_id, requested_url=requested_url,
            effective_url=effective_url, supplied_receipt_id=receipt_id,
        )
        if derived:
            receipt_id = derived
    return effective_url, fallback, alias_id, receipt_id


async def standing_authorization_for_target_url(pool: Any, target_url: str) -> str | None:
    """Resolve an exact target's current standing receipt without changing its scope."""
    if pool is None:
        return None
    try:
        async with pool.acquire() as conn:
            target = await conn.fetchrow("SELECT id FROM targets WHERE url = $1", target_url)
            if not target:
                return None
            standing = await target_authorization.current_target_authorization(conn, target["id"])
    except Exception:  # convenience lookup; submission still validates the receipt
        return None
    return str(standing["approval_receipt_id"]) if standing else None


async def standing_receipt_for_dns_alias(
    pool: Any,
    *,
    target_id: Any,
    requested_url: str,
    effective_url: str,
    supplied_receipt_id: str | None = None,
) -> str | None:
    """Derive one auditable www/apex scope from this target's standing authorization.

    The caller has already observed NO_ADDRESS on the requested hostname and an admitted DNS
    answer for its exact twin. A bounded or unrelated receipt is never copied. The target row
    remains the owner of credentials, collections, findings, and revocation history.
    """
    if pool is None or not _is_www_pair(requested_url, effective_url):
        return None
    target_uuid = uuid.UUID(str(target_id))
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Serialize parallel alias submissions on the target. Revocation locks the approval
            # row below, so a revoked authorization cannot be used to derive a fresh one.
            target = await conn.fetchrow(
                "SELECT id, url, metadata_json FROM targets WHERE id=$1 FOR UPDATE", target_uuid,
            )
            if not target or str(target["url"]) != requested_url:
                return None
            standing = await target_authorization.current_target_authorization(conn, target_uuid)
            if not standing:
                return None
            approval_id = uuid.UUID(str(standing["approval_receipt_id"]))
            approval = await conn.fetchrow(
                "SELECT id, status, approved_by, risk_tier, action_name, action_context FROM approval_receipts WHERE id=$1 FOR UPDATE",
                approval_id,
            )
            if not approval or approval["status"] != "active" or not approval["approved_by"]:
                return None
            if supplied_receipt_id and str(approval_id) != supplied_receipt_id:
                context = approval["action_context"] or {}
                if isinstance(context, str):
                    context = json.loads(context)
                if not isinstance(context, dict) or context.get("derived_from_approval_receipt_id") != supplied_receipt_id:
                    return None
                try:
                    source_id = uuid.UUID(supplied_receipt_id)
                except ValueError:
                    return None
                source = await conn.fetchrow(
                    "SELECT id, status, approved_by, risk_tier, action_name, action_context FROM approval_receipts WHERE id=$1 FOR UPDATE",
                    source_id,
                )
                if (not source or source["status"] != "active"
                        or source["action_name"] != target_authorization.STANDING_ACTION_NAME):
                    return None
            scope = await conn.fetchrow(
                "SELECT allowed_hosts FROM scope_receipts WHERE id=$1",
                standing["scope_receipt_id"],
            )
            allowed_hosts = scope["allowed_hosts"] if scope else []
            if isinstance(allowed_hosts, str):
                allowed_hosts = json.loads(allowed_hosts)
            if _host(effective_url) in (allowed_hosts or []):
                return str(approval_id)

            metadata = target["metadata_json"]
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except ValueError:
                    metadata = None
            environment = target_authorization.effective_target_environment(metadata)
            receipt = receipt_to_dict(evaluate_scope(
                effective_url,
                allowed_hosts=[_host(requested_url), _host(effective_url)],
                environment=environment,
                target_id=str(target_uuid),
            ))
            if receipt["verdict"] == "blocked":
                return None
            await target_authorization.persist_scope_receipt(conn, receipt, target_uuid)
            confirmations = ["confirm_authorized"]
            if receipt["verdict"] == "needs_approval":
                confirmations.append("confirm_scope_reviewed")
            derived = await conn.fetchrow(
                """INSERT INTO approval_receipts
                   (scope_receipt_id, risk_tier, confirmations, action_name, action_context,
                    approved_by, denial_reason, expires_at)
                   VALUES ($1,$2,$3::jsonb,$4,$5::jsonb,$6,NULL,NULL) RETURNING id""",
                receipt["receipt_id"], approval["risk_tier"], json.dumps(confirmations),
                target_authorization.STANDING_ACTION_NAME,
                json.dumps({
                    "target_id": str(target_uuid), "host": _host(effective_url),
                    "dns_alias_from": _host(requested_url),
                    "derived_from_approval_receipt_id": str(approval_id),
                }, sort_keys=True),
                approval["approved_by"],
            )
            return str(derived["id"])


async def revoke_dns_alias_lineage(conn: Any, approval: Any, *, revoked_by: str, reason: str) -> None:
    """Revoking either side of a derived standing receipt ends the whole alias authority."""
    if approval.get("action_name") != target_authorization.STANDING_ACTION_NAME:
        return
    context = approval.get("action_context") or {}
    if isinstance(context, str):
        context = json.loads(context)
    if not isinstance(context, dict) or not context.get("target_id"):
        return
    source_id = context.get("derived_from_approval_receipt_id") or approval.get("id")
    await conn.execute(
        """UPDATE approval_receipts a
              SET status='revoked', revoked_at=NOW(), revoked_by=$2, revocation_reason=$3
             FROM scope_receipts s
            WHERE s.id=a.scope_receipt_id AND s.target_id=$1
              AND a.status='active' AND a.action_name=$4
              AND (a.id=$5 OR a.action_context->>'derived_from_approval_receipt_id'=$6)""",
        uuid.UUID(str(context["target_id"])), revoked_by, reason,
        target_authorization.STANDING_ACTION_NAME, uuid.UUID(str(source_id)), str(source_id),
    )
