"""Hunt scanners and verifiers that run signed in, and verifiers that test a request body.

Admission (``scanner_admission``) and the worker (``resolve_scanner_identity``) apply the rules
``http.request`` already follows for a managed principal or a session: the Hunt's approval
receipt is checked at the credential tier, only a profile selected at start for that slot and
allowing that capability (or a session of this Hunt compatible with it) can supply the identity,
and the worker reloads the approval and the session's service authority immediately before it
decrypts anything. The identity reaches the fixed scanner adapters as the worker-resolved
``trusted_headers``, the same mechanism an authenticated Scan uses. Nothing is sent anonymously
in place of a requested identity: a capability that cannot carry one refuses it.

A body test (``xss.verify``/``sqli.verify`` with ``method``/``body_field_names``) sends
POST/PUT/PATCH requests and needs the Hunt's state-changing permission, at admission and again at
dispatch. Its requests stay in the verifier's own reservation (``http_requests``); the Hunt's
state-changing ceiling bounds the planner's own writes and is not charged for verifier traffic
sent under an active-testing grant.
"""
from __future__ import annotations

from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, Mapping
import urllib.parse

from .permission_reasons import HuntRefusal

try:
    from runtime.hunt_scanner_contract import (
        BODY_INPUT_VERIFIERS, SIGNED_IN_SCANNERS, hunt_body_input, signed_in_request,
    )
    from runtime.credential_refs import normalize_hunt_principal_slot
except ModuleNotFoundError:
    from ..runtime.hunt_scanner_contract import (
        BODY_INPUT_VERIFIERS, SIGNED_IN_SCANNERS, hunt_body_input, signed_in_request,
    )
    from ..runtime.credential_refs import normalize_hunt_principal_slot


def _browser_xss_route(name: str, values: Mapping[str, Any]) -> bool:
    """An ``xss.verify`` the worker hands to the pinned browser prover, which has no session."""
    return name == "xss.verify" and (
        values.get("deep_domxss") is True or "#" in str(values.get("path") or "")
    )


def scanner_identity_refusal(name: str, values: Mapping[str, Any]) -> str | None:
    """Why this scanner call cannot run as the identity it names, or None."""
    if not signed_in_request(values):
        return None
    if name not in SIGNED_IN_SCANNERS:
        return (
            f"{name} runs anonymously in a Hunt: it cannot carry a signed-in session yet. "
            "Omit as_principal and session_ref, or use web.crawl or http.request signed in."
        )
    if _browser_xss_route(name, values):
        return (
            "xss.verify proves a URL-fragment or deep_domxss parameter in the pinned browser, "
            "which runs without a session; verify it anonymously, or name a query or body input."
        )
    return None


def scanner_principal_slot(values: Mapping[str, Any]) -> str:
    """The managed principal slot an admitted scanner call names (``anonymous`` for none)."""
    return normalize_hunt_principal_slot(values.get("as_principal"))


def body_authority_refusal(name: str, values: Mapping[str, Any], policy: Mapping[str, Any]) -> HuntRefusal | None:
    """A grantable refusal for a body test the Hunt's policy does not allow."""
    if name not in BODY_INPUT_VERIFIERS or not hunt_body_input(values):
        return None
    if policy.get("active_testing") and policy.get("allow_state_changing_http"):
        return None
    method = str(values.get("method") or "POST").upper()
    return HuntRefusal(
        "state_changing_http_not_allowed",
        f"{name} on a {method} body sends {method} requests and needs this Hunt's active_testing "
        "and allow_state_changing_http permissions. A person can allow them for this Hunt (a "
        "permission request is raised). The verifier's requests count in its own hold, not in "
        "the state-changing request limit.",
        subject={"capability": name, "flag": "state-changing"},
    )


def scanner_admission(name: str, values: Mapping[str, Any], policy: Mapping[str, Any]) -> str:
    """Refuse what admission must refuse for a scanner call; return its principal slot."""
    refusal = scanner_identity_refusal(name, values)
    if refusal is not None:
        raise HuntRefusal("principal_anonymous_only", refusal)
    coded = body_authority_refusal(name, values, policy)
    if coded is not None:
        raise coded
    return scanner_principal_slot(values)


@dataclass(frozen=True)
class ScannerIdentity:
    """The worker-resolved identity of one scanner call. ``headers`` never leave the worker."""

    headers: Mapping[str, str]
    principal_slot: str
    session_ref: str | None

    @property
    def signed_in(self) -> bool:
        return bool(self.headers)

    def evidence_principals(self) -> tuple[str, ...]:
        return () if self.principal_slot == "anonymous" else (self.principal_slot,)


ANONYMOUS = ScannerIdentity(headers={}, principal_slot="anonymous", session_ref=None)


def _service_origin(url: str) -> str:
    return urllib.parse.urlunsplit((*urllib.parse.urlsplit(url)[:2], "", "", ""))


async def resolve_scanner_identity(
    conn: Any, *, context: Mapping[str, Any], target: Any, policy: Mapping[str, Any],
    approval_receipt_id: Any, hunt_id: Any, capability_name: str,
    values: Mapping[str, Any], execution_target: str, session_store: Any,
) -> ScannerIdentity:
    """The headers this scanner call sends, resolved under the Hunt's current authority.

    Raises ``HuntDispatchRejected`` (nothing sent, the hold is released) when the identity or
    the body authority admission accepted is no longer available.
    """
    from .dispatch_authority import HuntDispatchRejected

    if hunt_body_input(values) and not (
        policy.get("active_testing") and policy.get("allow_state_changing_http")
    ):
        raise HuntDispatchRejected(
            f"Hunt action authority rejected at dispatch: {capability_name} on a request body "
            "no longer has the Hunt's state-changing permission"
        )
    if not signed_in_request(values):
        return ANONYMOUS
    if (refusal := scanner_identity_refusal(capability_name, values)) is not None:
        raise HuntDispatchRejected(refusal)
    try:
        from runtime.credential_resolver import (
            CredentialResolutionError, validate_worker_credential_authority,
        )
        from runtime.auth_session_store import AuthSessionStoreError
        from runtime.credential_refs import CredentialReferenceError
    except ModuleNotFoundError:
        from ..runtime.credential_resolver import (
            CredentialResolutionError, validate_worker_credential_authority,
        )
        from ..runtime.auth_session_store import AuthSessionStoreError
        from ..runtime.credential_refs import CredentialReferenceError
    from .http_principal import resolve_http_principal

    origin = _service_origin(execution_target)
    try:
        authority = await validate_worker_credential_authority(
            conn, owner_kind="hunt", owner_id=str(hunt_id), target=target,
            approval_receipt_id=approval_receipt_id, scope_receipt_id=target.scope_receipt_id,
            action_name=f"hunt.capability:{capability_name}",
        )
        session_ref = str(values.get("session_ref") or "") or None
        if session_ref:
            session = await session_store.load_for_worker(
                conn, session_ref=session_ref, owner_kind="hunt", owner_id=hunt_id,
                target=target, capability=capability_name, selected_origins=(origin,),
            )
            return ScannerIdentity(
                headers=dict(session.headers()), principal_slot=session.metadata.principal_slot,
                session_ref=session_ref,
            )
        slot = scanner_principal_slot(values)
        # The resolver zeroes its decrypted material when the stack closes; the scanner keeps
        # only the rendered headers, as an authenticated Scan hands its scanners.
        async with AsyncExitStack() as stack:
            headers, session = await resolve_http_principal(
                conn, context=context, target=target, authority=authority, hunt_id=hunt_id,
                principal=slot, origin=origin, stack=stack, session_store=session_store,
                capability=capability_name,
            )
            rendered = dict(headers)
        if not rendered:
            raise CredentialResolutionError("the managed principal supplies no request headers")
        return ScannerIdentity(
            headers=rendered, principal_slot=slot,
            session_ref=str(session.metadata.session_ref) if session is not None else None,
        )
    except (CredentialResolutionError, AuthSessionStoreError, CredentialReferenceError) as exc:
        raise HuntDispatchRejected(
            f"Hunt action authority rejected at dispatch: {capability_name} cannot run signed "
            f"in: {exc}"
        ) from exc


__all__ = [
    "ANONYMOUS", "ScannerIdentity", "body_authority_refusal", "resolve_scanner_identity",
    "scanner_admission", "scanner_identity_refusal", "scanner_principal_slot",
]
