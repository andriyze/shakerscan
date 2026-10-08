"""Server-resolved subjects for Hunt refusals that may become permission requests.

Each function turns one admission refusal into a coded ``HuntRefusal`` whose ``subject`` holds
only values the server resolved: never the agent's words, never response content. A subject that
crosses a hard limit (a private or metadata destination, the deployment's private-network
refusal, an inactive credential, an unregistered capability) produces a refusal without a kind,
which never becomes a request.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
import json
from typing import Any
import urllib.parse
import uuid

from .permission_reasons import HuntRefusal

try:
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.credentials import SSH_CREDENTIAL_KINDS
    from runtime.models import target_kinds_share_asset
except ModuleNotFoundError:
    from ..runtime.capability_registry import CAPABILITY_REGISTRY
    from ..runtime.credentials import SSH_CREDENTIAL_KINDS
    from ..runtime.models import target_kinds_share_asset


def _json(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


# ---------------------------------------------------------------------------------------------
# Capabilities (D31: the refusal names what is missing).

def capability_refusal(run: Mapping[str, Any], name: str) -> HuntRefusal:
    """Why ``name`` is outside this Hunt's allowlist, as a coded refusal."""
    policy = _json(run.get("policy_json"))
    try:
        spec = CAPABILITY_REGISTRY.require(name)
    except KeyError:
        return HuntRefusal("capability_unregistered", f"{name} is not a registered Hunt capability.")
    target_kind = str(run.get("target_kind") or "web")
    if not spec.planner_visible or spec.hunt_executor is None:
        return HuntRefusal("capability_unregistered", f"{name} is not available to a Hunt planner.")
    if target_kind not in spec.target_kinds:
        return HuntRefusal(
            "capability_target_kind_mismatch",
            f"{name} works on {', '.join(sorted(spec.target_kinds))} targets; this Hunt's target is {target_kind}.",
        )
    required = spec.required_approval
    if (spec.risk_tier == "mutation" or required == "state_changing_http"
            or spec.placement_requirements.get("state_changing_http")) and not policy.get("allow_state_changing_http"):
        code, flag, need = "capability_requires_state_changing_http", "state-changing", "state-changing HTTP"
    elif required == "network_discovery" and not policy.get("network_discovery"):
        code, flag, need = "capability_requires_network_discovery", "tcp-discovery", "network discovery"
    elif required == "oob_interactions" and not policy.get("allow_oob_interactions"):
        code, flag, need = "capability_requires_oob", "oob", "out-of-band interactions"
    elif (spec.risk_tier == "credential" or required == "credential_use") and not policy.get("credential_access"):
        return HuntRefusal(
            "capability_requires_credentials",
            f"{name} needs credentials selected when the Hunt starts; this Hunt has none.",
        )
    elif (spec.risk_tier == "active" or required == "active_testing") and not policy.get("active_testing"):
        code, flag, need = "capability_requires_active_testing", "active-testing", "active testing"
    else:
        return HuntRefusal(
            "capability_not_selected",
            f"{name} was not enabled for this Hunt at start (not selected, or its budget dimension is 0).",
            subject={"capability": name, "flag": ""},
        )
    return HuntRefusal(
        code,
        f"{name} needs {need}, which this Hunt was started without. A person can allow it for "
        "this Hunt (a permission request is raised), or start a Hunt with it.",
        subject={"capability": name, "flag": flag},
    )


def http_authority_refusal(values: Mapping[str, Any], policy: Mapping[str, Any], message: str) -> HuntRefusal | None:
    """A coded refusal for a write or workflow ``http.request`` the policy does not allow."""
    method = str(values.get("method") or "GET").upper()
    workflow = bool(values.get("capture") or values.get("request_bindings"))
    if method in {"POST", "PUT", "PATCH", "DELETE"} and not (
        policy.get("active_testing") and policy.get("allow_state_changing_http")
    ):
        return HuntRefusal(
            "state_changing_http_not_allowed",
            f"http.request {method} changes state and needs this Hunt's active_testing and "
            "allow_state_changing_http permissions. A person can allow them for this Hunt (a "
            "permission request is raised).",
            subject={"capability": "http.request", "flag": "state-changing"},
        )
    if workflow and not policy.get("active_testing"):
        return HuntRefusal(
            "capability_requires_active_testing",
            "HTTP workflow bindings need this Hunt's active testing permission.",
            subject={"capability": "http.request", "flag": "active-testing"},
        )
    del message
    return None


def replay_authority_refusal(policy: Mapping[str, Any]) -> HuntRefusal | None:
    if policy.get("active_testing") and policy.get("allow_state_changing_http"):
        return None
    return HuntRefusal(
        "active_replay_not_allowed",
        "collections.replay_active needs this Hunt's state-changing HTTP permission. A person can "
        "allow it for this Hunt (a permission request is raised).",
        subject={"capability": "collections.replay_active", "flag": "active-replay"},
    )


def preflight_reason_code(detail: Any) -> str | None:
    """The code for a verification preflight refusal decided by the stored candidate alone."""
    text = str(detail or "")
    if text == "verification_route_unresolved":
        return "verification_route_unresolved"
    if text.startswith("verification bridge supports"):
        return "verification_family_unsupported"
    if text.startswith("mass_assignment verification requires"):
        return "verification_method_unsupported"
    return None


def approval_required_refusal(
    name: str, *, principal_slot: str, uses_session: bool, writes_http: bool,
    forges_identity: bool, uses_direct_origin: bool, uses_service_origin: bool,
) -> HuntRefusal:
    """D32: which approval a call needs, and why, when the Hunt was started without one."""
    because = (
        f"it uses the {principal_slot} credential" if principal_slot != "anonymous"
        else "it uses an authenticated session (session_ref)" if uses_session
        else "it changes state or binds an HTTP workflow" if writes_http
        else "it forges a client identity header" if forges_identity
        else "it connects to a direct origin address" if uses_direct_origin
        else "it reaches another service on the target" if uses_service_origin
        else f"{name} is an approval-gated capability"
    )
    return HuntRefusal(
        "approval_receipt_required",
        f"{name} needs the target's approval receipt because {because}, and this Hunt was "
        "started without one (a passive Hunt). Omit that input, or start a Hunt with "
        "authorization_confirmed=true on a target that has standing authorization "
        "(POST /targets/{target_id}/authorization).",
    )


# ---------------------------------------------------------------------------------------------
# Destinations.

def destination_refusal(target: Any, origin: Any, policy: Mapping[str, Any], *, principal_slot: str) -> HuntRefusal:
    """Classify an origin ``resolve_hunt_http_origin`` refused."""
    text = str(origin or "").strip()
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port
    except ValueError:
        parsed, port = None, None
    if (parsed is None or parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment or port == 0):
        return HuntRefusal("scope_origin_invalid", "The origin must be scheme://host[:port] with nothing else.")
    host = parsed.hostname.lower().rstrip(".")
    port = port or (443 if parsed.scheme == "https" else 80)
    origin_text = f"{parsed.scheme}://{host}:{port}"
    same_host = host == str(target.canonical_host or "").lower()
    if not same_host and principal_slot != "anonymous":
        return HuntRefusal(
            "scope_credential_other_host",
            f"{host} is not the Hunt's target host. A credential is never sent to another host, "
            "so this request cannot be allowed; omit as_principal to ask for the destination.",
        )
    subject = {
        "target_id": str(target.target_id), "host": host, "port": port, "scheme": parsed.scheme,
        "origin": origin_text, "same_host": same_host,
        "addresses": list(target.allowed_addresses) if same_host else [],
    }
    if same_host:
        return HuntRefusal(
            "scope_other_service_port",
            f"{origin_text} is another service on the Hunt's host, which this Hunt may not reach "
            "without active testing. A person can authorize it for this Hunt (a permission "
            "request is raised).",
            subject=subject,
        )
    return HuntRefusal(
        "scope_other_host",
        f"{host} is not the Hunt's target host. A person can authorize this destination for this "
        "Hunt after its scope check passes (a permission request is raised).",
        subject=subject,
    )


def _public_address(value: str) -> bool:
    """The scope guard's classifier, as at dispatch (NAT64, mapped, 6to4, Teredo, cloud services)."""
    try:
        from action_scope import public_unicast_address
    except ModuleNotFoundError:
        from ..action_scope import public_unicast_address
    return public_unicast_address(value)


async def _default_resolver(url: str, environment: str) -> list[str]:
    try:
        from fleet_routes import router as fleet
    except ModuleNotFoundError:
        from ..fleet_routes import router as fleet
    return await fleet._resolve_runtime_target_addresses(url, subject="Hunt destination", environment=environment)


# Replaceable in tests (labelled doubles): DNS is resolved once, before the request is raised.
resolve_destination_addresses: Callable[[str, str], Awaitable[list[str]]] = _default_resolver


async def complete_destination_subject(run: Mapping[str, Any], refusal: HuntRefusal) -> HuntRefusal:
    """Resolve and scope-check another host; a blocked destination becomes a hard refusal."""
    subject = dict(refusal.subject)
    if refusal.reason_code != "scope_other_host" or not subject or subject.get("same_host"):
        return refusal
    context = _json(run.get("context_pack"))
    environment = str((context.get("target") or {}).get("environment") or "production")
    url = f"{subject['scheme']}://{subject['host']}:{subject['port']}"
    try:
        from action_scope import evaluate_scope, receipt_to_dict
    except ModuleNotFoundError:
        from ..action_scope import evaluate_scope, receipt_to_dict
    receipt = receipt_to_dict(evaluate_scope(url, allowed_hosts=[subject["host"]], environment=environment,
                                             target_id=str(subject["target_id"])))
    blocked = receipt.get("verdict") == "blocked"
    addresses: list[str] = []
    if not blocked:
        try:
            addresses = [str(item) for item in await resolve_destination_addresses(url, environment)]
        except Exception:  # noqa: BLE001 - an unresolvable or refused destination is a hard limit
            addresses = []
    # Loopback, private, link-local, metadata and reserved destinations are hard limits for a
    # permission request whatever the deployment admits for its registered targets.
    if any(not _public_address(item) for item in addresses):
        addresses = []
    if blocked or not addresses:
        return HuntRefusal(
            "scope_destination_blocked",
            f"{subject['host']} cannot be authorized: "
            + (", ".join(str(item) for item in receipt.get("blocked_by") or ()) or "it resolves to no allowed address")
            + ". Private, loopback, link-local, metadata and reserved destinations are never allowed.",
        )
    subject.update(addresses=sorted(set(addresses))[:32], scope_verdict=str(receipt.get("verdict") or ""))
    return HuntRefusal(refusal.reason_code, refusal.message, status_code=refusal.status_code,
                       subject=subject, extra=refusal.extra)


# ---------------------------------------------------------------------------------------------
# Credentials.

async def credential_kind_error(conn: Any, run: Mapping[str, Any], subject: Mapping[str, Any]) -> str | None:
    """The credential-grant kind rules, applied to a Hunt-only use (no binding is created)."""
    row = await conn.fetchrow(
        """SELECT target_kind, auth_kind, current_version, is_active,
                  (expires_at IS NULL OR expires_at > NOW()) AS unexpired
           FROM credential_profiles WHERE id=$1""",
        uuid.UUID(str(subject["profile_id"])),
    )
    if row is None or not row["is_active"] or not row["unexpired"]:
        return "the credential is inactive, expired or gone"
    if int(row["current_version"]) != int(subject.get("profile_version") or 0):
        return "the credential was rotated after this request was raised"
    if str(row["auth_kind"]) in SSH_CREDENTIAL_KINDS:
        return "SSH credentials are shared with a credential grant, not for one Hunt"
    hunt_kind = str(run.get("target_kind") or "web")
    if not target_kinds_share_asset(str(row["target_kind"]), hunt_kind):
        return f"a {row['target_kind']} credential cannot be used on a {hunt_kind} target"
    try:
        from credential_api import grant_target_kind_error
    except ModuleNotFoundError:
        from ..credential_api import grant_target_kind_error
    return grant_target_kind_error(
        declared_kind=hunt_kind, auth_kind=str(row["auth_kind"]),
        http_origin=hunt_kind in {"web", "api"}, serves_http=True, services_observed=False,
        device=hunt_kind == "device",
    )


async def credential_use_refusal(conn: Any, run: Mapping[str, Any], refusal: HuntRefusal) -> HuntRefusal:
    """Turn ``credential_not_attached`` into a grantable request when another target's active
    credential could be used; an inactive, rotated or own credential stays a plain refusal."""
    profile_id = refusal.subject.get("profile_id")
    if refusal.reason_code != "credential_not_attached":
        return refusal
    plain = HuntRefusal("credential_not_attached", refusal.message, extra=refusal.extra)
    if not profile_id:
        return plain
    try:
        profile_uuid = uuid.UUID(str(profile_id))
    except ValueError:
        return plain
    row = await conn.fetchrow(
        """SELECT p.id, p.target_id, p.current_version, p.is_active, p.name, p.auth_kind,
                  (p.expires_at IS NULL OR p.expires_at > NOW()) AS unexpired, t.url AS home_url,
                  t.name AS home_name
           FROM credential_profiles p LEFT JOIN targets t ON t.id=p.target_id WHERE p.id=$1""",
        profile_uuid,
    )
    consuming = str(run.get("target_id") or run.get("device_target_id") or "")
    if row is None or not row["is_active"] or not row["unexpired"]:
        return HuntRefusal(
            "credential_inactive",
            "The credential selected for this slot is deactivated or expired; reactivate it or "
            "start a Hunt with another one.", extra=refusal.extra,
        )
    if str(row["target_id"]) == consuming:
        return HuntRefusal("credential_not_attached", refusal.message, extra=refusal.extra)
    subject = {
        "profile_id": str(row["id"]), "profile_version": int(row["current_version"]),
        "home_target_id": str(row["target_id"]),
        "home_host": (urllib.parse.urlsplit(str(row["home_url"] or "")).hostname or None),
        "slot": refusal.subject.get("slot"), "consuming_target_id": consuming,
    }
    if await credential_kind_error(conn, run, subject):
        return HuntRefusal("credential_not_attached", refusal.message, extra=refusal.extra)
    grantable = HuntRefusal("credential_not_attached", refusal.message, extra=refusal.extra, subject=subject)
    # D47: what the person reads names the credential and its target; names and kinds only,
    # outside the subject digest (a renamed profile is still the same request).
    grantable.display = {  # type: ignore[attr-defined]
        "profile_name": str(row["name"] or "")[:200], "auth_kind": str(row["auth_kind"] or "")[:80],
        "home_target_name": str(row["home_name"] or "")[:200],
    }
    return grantable


__all__ = [
    "approval_required_refusal", "preflight_reason_code",
    "capability_refusal", "complete_destination_subject", "credential_kind_error",
    "credential_use_refusal", "destination_refusal", "http_authority_refusal",
    "replay_authority_refusal", "resolve_destination_addresses",
]
