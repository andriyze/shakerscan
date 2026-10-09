"""Standing target authorization: one recorded act per target, reused by every scan and Hunt.

Active testing needs a target-bound approval receipt. Until now every submission created its own
short-lived receipt (the UI defaulted to two hours), which felt like asking for permission on
every scan. A standing authorization is the same receipt, created once for the target's scope
with no expiry, and resolved automatically when a submission for that target carries none.

It covers the credentials attached to this target: the target's own credential profiles and
principals, and profiles another target shared to it through a credential grant. A Hunt may use
any of them and records each use (``hunt_credential_uses``); an unattached credential is refused.
The authorization never extends to another target, and a credential never authorizes one.

What still ends it: an explicit revocation (the approval revoke endpoint or the target endpoint),
or a change of the target's scope (a different host produces a different scope receipt, so the
old authorization no longer matches and the target is authorized again). The dangerous tier
(evidence deletion, retention sweeps) is unaffected: it keeps its per-action, bounded approval.
"""
from __future__ import annotations

import ipaddress
import json
import urllib.parse
import uuid
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

try:
    from action_scope import evaluate_scope, receipt_to_dict
except ModuleNotFoundError:  # package-native import layout
    from api.action_scope import evaluate_scope, receipt_to_dict

try:
    from runtime.approval_policy import STANDING_ACTION_NAME, STANDING_RISK_TIERS
except ModuleNotFoundError:
    from api.runtime.approval_policy import STANDING_ACTION_NAME, STANDING_RISK_TIERS


class TargetAuthorizationError(ValueError):
    """The target cannot be authorized as requested (blocked scope, unknown target).

    ``code`` names the refusal for callers that map it to a status ("not_found",
    "scope_blocked"); matching on the message text broke as soon as the message explained more.
    """

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


def _host(url: str) -> str:
    parsed = urllib.parse.urlparse(str(url or "").strip())
    return (parsed.hostname or "").lower().strip("[]")


def _host_key(value: Any) -> str:
    """One spelling per host for comparing a target with its scope: lower case, no brackets or
    trailing dot, and an IP literal in its canonical form. `2001:DB8::0001` and `2001:db8::1`
    are one host; the inventory's SQL (target_asset_locator) compares the same way."""
    text = str(value or "").strip().lower().strip("[]").rstrip(".")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


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


def effective_target_environment(
    metadata: Any, *, requested: str | None = None,
) -> str:
    """The one environment a target is judged under.

    Creation stores the operator's choice as `metadata.cohort`, while authorization used to read
    `metadata.environment` and default to production. So a target saved as Lab authorized under a
    Lab evaluation at creation and a Production one when authorized later, and the two paths
    could reach opposite verdicts on the same row.

    `environment` wins where both exist -- it is the older, explicitly-set field -- then the
    stored cohort, then production. A caller may still pass one explicitly; it does not change
    what is stored.
    """
    stored = metadata if isinstance(metadata, Mapping) else {}
    for value in (requested, stored.get("environment"), stored.get("cohort")):
        text = str(value or "").strip().lower()
        if text and text != "unclassified":
            return text
    return "production"


async def current_target_authorization(conn: Any, target_id: Any) -> dict[str, Any] | None:
    try:
        from targets.asset_authority import resolve_target_authorization
    except ModuleNotFoundError:
        from api.targets.asset_authority import resolve_target_authorization
    return await resolve_target_authorization(conn, target_id, _current_exact_target_authorization)


async def standing_authorization_is_current(conn: Any, target_id: Any, approval_receipt_id: Any) -> bool:
    """True while this exact receipt is still one the target's current authorization accepts.

    Running work bound to a standing receipt is re-checked with the same rules as the gate, so a
    receipt the target no longer stands behind (its host changed, its scope is blocked, the
    target is gone) stops the work even though the receipt row itself was never updated.
    """
    try:
        approval_uuid = uuid.UUID(str(approval_receipt_id))
    except (TypeError, ValueError):
        return False
    return await _current_exact_target_authorization(conn, target_id, approval_receipt_id=approval_uuid) is not None


async def _current_exact_target_authorization(
    conn: Any, target_id: Any, *, approval_receipt_id: uuid.UUID | None = None,
) -> dict[str, Any] | None:
    """The target's standing (or still valid bounded) authorization, or None.

    Only receipts whose scope still names the target's current host count: a target whose URL
    changed since the authorization was given must be authorized again. With
    ``approval_receipt_id`` only that receipt is considered.
    """
    try:
        target_uuid = uuid.UUID(str(target_id))
    except (TypeError, ValueError):
        return None
    target = _row(await conn.fetchrow("SELECT id, url FROM targets WHERE id=$1", target_uuid))
    if not target:
        # The same id may name a connected device. Reading only the web table made every
        # standing receipt recorded for a device invisible to the readers that gate scans and
        # Hunts, so the receipt existed and nothing could resolve it.
        device = _row(await conn.fetchrow(
            "SELECT id, primary_locator FROM device_targets WHERE id=$1", target_uuid,
        ))
        if not device:
            return None
        locator = str(device.get("primary_locator") or "").strip()
        target = {"id": device.get("id"), "url": locator if "://" in locator else (
            f"http://[{locator}]" if ":" in locator else f"http://{locator}"
        )}
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
           -- A receipt recorded before the standing-authorization contract has no
           -- action_name. Counting it as standing made the target report itself
           -- authorized while the submission gate, which requires the exact
           -- action_name, refused every active scan of it -- and revoke, which
           -- matches the same name, could never clear it. One definition here,
           -- at the gate, and at revoke, so re-authorizing is the way out.
           AND a.action_name = $3
           AND (a.expires_at IS NULL OR a.expires_at > NOW())
           AND ($4::uuid IS NULL OR a.id = $4::uuid)
         ORDER BY (a.expires_at IS NULL) DESC, a.created_at DESC
         LIMIT 20
        """,
        target_uuid,
        list(STANDING_RISK_TIERS),
        STANDING_ACTION_NAME,
        approval_receipt_id,
    )
    host = _host_key(_host(target.get("url", "")))
    for raw in rows:
        row = _row(raw)
        if str(row.get("scope_verdict") or "") == "blocked":
            continue
        allowed = _json(row.get("scope_allowed_hosts")) or []
        normalized = _json(row.get("scope_normalized")) or {}
        scope_host = str((normalized or {}).get("host") or "").lower() if isinstance(normalized, dict) else ""
        hosts = {_host_key(item) for item in allowed if str(item).strip()} | ({_host_key(scope_host)} if scope_host else set())
        if host and host not in hosts:
            continue
        scope = {"id": row.get("scope_id"), "verdict": row.get("scope_verdict")}
        return public_authorization(row, scope)
    return None


async def evaluate_target_scope(
    conn: Any, target_id: Any, *, environment: str | None = None,
) -> dict[str, Any]:
    """Evaluate the target's destination scope exactly as authorizing it would; writes nothing.

    Returns ``{target_uuid, url, host, environment, receipt}``. Raises
    ``TargetAuthorizationError`` for an id that is not a UUID or names no target.
    """
    try:
        target_uuid = uuid.UUID(str(target_id))
    except (TypeError, ValueError) as exc:
        raise TargetAuthorizationError("target id must be a UUID") from exc
    target = _row(await conn.fetchrow("SELECT id, url, metadata_json FROM targets WHERE id=$1", target_uuid))
    if target:
        metadata = _json(target.get("metadata_json")) or {}
        env = effective_target_environment(metadata, requested=environment)
        url = str(target.get("url") or "")
    else:
        # A connected device is an asset the operator owns exactly as a web target is. Reading
        # only the web table meant `POST /targets/{id}/authorization` answered 404 for a device,
        # so every device scan re-asked for permission inline and no device Hunt could resolve a
        # standing receipt. The device's own environment wins when the caller names none.
        device = _row(await conn.fetchrow(
            "SELECT id, primary_locator, environment FROM device_targets WHERE id=$1",
            target_uuid,
        ))
        if not device:
            raise TargetAuthorizationError("target not found", code="not_found")
        locator = str(device.get("primary_locator") or "").strip()
        env = str(environment or device.get("environment") or "production").strip() or "production"
        url = locator if "://" in locator else (
            f"http://[{locator}]" if ":" in locator else f"http://{locator}"
        )
    if url.startswith("host://"):
        url = "http://" + url[len("host://"):].split("#",1)[0]
    host = _host(url)
    receipt = receipt_to_dict(evaluate_scope(
        url, allowed_hosts=[host] if host else None, environment=env, target_id=str(target_uuid),
    ))
    return {"target_uuid": target_uuid, "url": url, "host": host, "environment": env, "receipt": receipt}


def scope_block_message(receipt: Mapping[str, Any]) -> str:
    """The refusal for a blocked scope: the codes, then each blocked check's own explanation.

    The codes alone (``loopback_or_private_range``) did not say whether the address class is
    never scanned or whether this deployment chose to refuse it, nor which setting changes it;
    the scope evaluation already wrote that into the blocked check.
    """
    message = "the target's scope is blocked: " + ", ".join(
        str(code) for code in receipt.get("blocked_by") or []
    )
    seen: list[str] = []
    for check in receipt.get("checks") or []:
        if not isinstance(check, Mapping) or check.get("status") != "blocked":
            continue
        detail = str(check.get("message") or check.get("detail") or "").strip()
        if detail and detail not in seen:
            seen.append(detail)
    for detail in seen:
        message += ": " + detail
    return message


async def target_scope_refusal(conn: Any, target_id: Any) -> dict[str, Any] | None:
    """The target's blocked-scope refusal, or None when its scope is not blocked.

    Only a "blocked" verdict refuses (a "needs_approval" host is still authorizable). An id that
    is not a UUID or names no target returns None so the caller's existing errors decide it.
    """
    try:
        evaluated = await evaluate_target_scope(conn, target_id)
    except TargetAuthorizationError:
        return None
    receipt = evaluated["receipt"]
    if receipt.get("verdict") != "blocked":
        return None
    return {
        "blocked_by": list(receipt.get("blocked_by") or []),
        "message": scope_block_message(receipt),
        "environment": evaluated["environment"],
    }


def pooled_scope_refusal_resolver(
    pool_provider: Callable[[], Any],
) -> Callable[[Any], Awaitable[dict[str, Any] | None]]:
    """A ``target_scope_refusal`` bound to a connection pool, for the Hunt start boundary.

    It fails open to None (no pool yet, a database error): the receipt gate behind it still
    refuses every privileged start without a receipt, so only the message quality is lost and
    nothing is ever admitted by this resolver.
    """
    async def resolve(target_id: Any) -> dict[str, Any] | None:
        pool = pool_provider()
        if pool is None:
            return None
        try:
            async with pool.acquire() as conn:
                return await target_scope_refusal(conn, target_id)
        except Exception:  # noqa: BLE001 - a better refusal message only, never an admission
            return None

    return resolve


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
    evaluated = await evaluate_target_scope(conn, target_uuid, environment=environment)
    receipt, host = evaluated["receipt"], evaluated["host"]
    if receipt["verdict"] == "blocked":
        raise TargetAuthorizationError(scope_block_message(receipt), code="scope_blocked")
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
    await conn.execute("""UPDATE targets SET authorization_inheritance=false,
        metadata_json=jsonb_set(COALESCE(metadata_json,'{}'::jsonb),'{authorization_inheritance_revoked}',
            jsonb_build_object('revoked_by',$2::text,'reason',$3::text,'at',NOW())),updated_at=NOW()
        WHERE id=$1""", target_uuid, revoked_by, reason[:2000])
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
    # A www/apex alias receipt derived from this authority may be filed under another target
    # (an application service that inherited the host's authorization). Revoking the source
    # must end it too, or the service would stay authorized after its host was revoked.
    derived = await conn.execute(
        """
        -- revoke derived alias lineage
        UPDATE approval_receipts d
           SET status='revoked', revoked_at=NOW(), revoked_by=$2, revocation_reason=$3
         WHERE d.status = 'active' AND d.action_name = $4
           AND d.action_context->>'derived_from_approval_receipt_id' IN (
               SELECT a.id::text FROM approval_receipts a
                 JOIN scope_receipts s ON s.id = a.scope_receipt_id
                WHERE s.target_id = $1 AND a.action_name = $4 AND a.status = 'revoked')
        """,
        target_uuid,
        revoked_by,
        reason[:2000],
        STANDING_ACTION_NAME,
    )
    count = 0
    for value in (result, derived):
        try:
            count += int(str(value).split()[-1])
        except (ValueError, IndexError):
            pass
    return count
