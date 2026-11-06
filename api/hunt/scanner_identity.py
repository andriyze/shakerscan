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
dispatch. Its requests are verifier writes: held and settled in the Hunt's verifier-write ceiling
(``verifier_write_requests``), beside the state-changing ceiling that bounds the planner's own
writes.
"""
from __future__ import annotations

from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, Mapping
import urllib.parse

from .permission_reasons import HuntRefusal

try:
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.hunt_scanner_contract import (
        BODY_INPUT_VERIFIERS, SIGNED_IN_SCANNERS, captured_login_request, header_marker_refusal,
        hunt_body_input, signed_in_request, xss_browser_parameter,
    )
    from runtime.credential_refs import normalize_hunt_principal_slot
except ModuleNotFoundError:
    from ..runtime.capability_registry import CAPABILITY_REGISTRY
    from ..runtime.hunt_scanner_contract import (
        BODY_INPUT_VERIFIERS, SIGNED_IN_SCANNERS, captured_login_request, header_marker_refusal,
        hunt_body_input, signed_in_request, xss_browser_parameter,
    )
    from ..runtime.credential_refs import normalize_hunt_principal_slot


def _browser_xss_route(name: str, values: Mapping[str, Any]) -> bool:
    """An ``xss.verify`` that runs in a headless browser, which has no session: the pinned
    browser prover, by the worker's own selection (``xss_browser_parameter``), or any
    ``deep_domxss`` call (headless Dalfox). An anchor after a server query
    (``/search?q=1#results``) is Dalfox's, which carries the session."""
    if name != "xss.verify":
        return False
    deep = values.get("deep_domxss") is True
    return deep or xss_browser_parameter(str(values.get("path") or ""), deep_domxss=deep) is not None


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
            "xss.verify proves a client-route fragment parameter in the pinned browser, and a "
            "deep_domxss call in a headless browser; both run without a session. Verify it "
            "anonymously, or name a query or body input."
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
        "permission request is raised). The verifier's requests count as verifier writes, a "
        "ceiling of their own beside the state-changing request limit.",
        subject={"capability": name, "flag": "state-changing"},
    )


# The evidence principal of a call that sent a session cookie the Hunt's own login captured.
CAPTURED_SESSION = "captured_session"


def scanner_admission(
    name: str, values: Mapping[str, Any], policy: Mapping[str, Any],
) -> tuple[str, bool]:
    """Refuse what admission must refuse for a scanner call; return ``(principal slot, sends a
    captured login)``. A captured login is a workflow binding: like ``http.request`` and
    ``artifact.inspect`` it needs active testing, the approval receipt, and is metered as an
    active action."""
    refusal = scanner_identity_refusal(name, values)
    if refusal is not None:
        raise HuntRefusal("principal_anonymous_only", refusal)
    coded = body_authority_refusal(name, values, policy)
    if coded is not None:
        raise coded
    captured = captured_login_request(values)
    if captured and policy.get("active_testing") is not True:
        raise HuntRefusal(
            "capability_requires_active_testing",
            f"{name} with a captured login (request_bindings) needs this Hunt's active testing "
            "permission. A person can allow it for this Hunt (a permission request is raised).",
            subject={"capability": name, "flag": "active-testing"},
        )
    return scanner_principal_slot(values), captured


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
    if captured_login_request(values):
        return await _captured_login_identity(
            conn, run_id=str(hunt_id), target=target, policy=policy,
            capability_name=capability_name, binding=values["request_bindings"][0],
            destination=execution_target,
        )
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


async def _captured_login_identity(
    conn: Any, *, run_id: str, target: Any, policy: Mapping[str, Any], capability_name: str,
    binding: Mapping[str, Any], destination: str,
) -> ScannerIdentity:
    """The ``Cookie`` header a login of this Hunt captured, under the rules ``artifact.inspect``
    applies to it: only a Set-Cookie capture of this Hunt and target, unexpired, whose every
    value is long enough to be withheld exactly wherever the target echoes it."""
    from .dispatch_authority import HuntDispatchRejected
    try:
        from runtime.hunt_http_exchange import MIN_SCRUBBED_COOKIE_CHARS, captured_binding, cookie_values
    except ModuleNotFoundError:
        from ..runtime.hunt_http_exchange import MIN_SCRUBBED_COOKIE_CHARS, captured_binding, cookie_values

    def rejected(reason: str) -> HuntDispatchRejected:
        return HuntDispatchRejected(
            f"Hunt action authority rejected at dispatch: {capability_name} cannot run with the "
            f"captured login: {reason}")

    if policy.get("active_testing") is not True:
        raise rejected("the Hunt no longer has active testing")
    if str(binding.get("header") or "") != "Cookie":
        raise rejected("a captured login is sent only as the Cookie header")
    try:
        value, is_cookie = await captured_binding(
            conn, run_id=run_id, target=target, binding=binding, destination=destination)
    except ValueError as exc:  # expired, another Hunt's or target's, or never captured
        raise rejected(str(exc)) from None
    text = str(value)
    secrets = cookie_values(text) if is_cookie else []
    if not secrets or any(len(item) < MIN_SCRUBBED_COOKIE_CHARS for item in secrets):
        raise rejected(
            "only a Set-Cookie capture whose values have at least "
            f"{MIN_SCRUBBED_COOKIE_CHARS} characters is sent")
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise rejected("the captured value is not a valid header value")
    tool = CAPABILITY_REGISTRY.require(capability_name).process_tool_name
    if (marker := header_marker_refusal(tool, text)) is not None:
        raise rejected(marker)
    return ScannerIdentity(headers={"Cookie": text}, principal_slot=CAPTURED_SESSION, session_ref=None)


__all__ = [
    "ANONYMOUS", "CAPTURED_SESSION", "ScannerIdentity", "body_authority_refusal", "resolve_scanner_identity",
    "scanner_admission", "scanner_identity_refusal", "scanner_principal_slot",
]
