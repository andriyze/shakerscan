"""The identity a Hunt's ``artifact.inspect`` reads as: anonymous, a session, a principal, or a
session cookie this Hunt's own login captured.

A signed-in page is often longer than one ``http.request`` shows; ``artifact.inspect`` reads a
larger window of it as the same identity. The read is a GET the planner could send with
``http.request``, so it takes that capability's identities under that capability's rules: a
managed principal or session resolved server side (``http.request`` credential allowance), or a
response capture bound to a request header (active testing). Every value bound from a capture is
withheld wherever the target echoes it; no value reaches the planner.
"""
from __future__ import annotations

from typing import Any, Mapping
import urllib.parse

try:
    from runtime.hunt_http_exchange import MIN_SCRUBBED_COOKIE_CHARS, captured_binding, cookie_values
    from runtime.hunt_http_exchange_contract import _FORBIDDEN_HEADERS
except ModuleNotFoundError:  # package import layout
    from api.runtime.hunt_http_exchange import MIN_SCRUBBED_COOKIE_CHARS, captured_binding, cookie_values
    from api.runtime.hunt_http_exchange_contract import _FORBIDDEN_HEADERS

_ANONYMOUS = {"", "anonymous", "anon", "none"}


def artifact_read_identity(values: Mapping[str, Any], policy: Mapping[str, Any]) -> tuple[str, bool, bool]:
    """Admission: ``(principal slot, uses a session, uses a capture binding)`` for one read; the
    router meters and approves each as it does for http.request."""
    from fastapi import HTTPException
    try:
        from agent_tools import normalize_principal_slot
    except ModuleNotFoundError:  # package import layout
        from api.agent_tools import normalize_principal_slot
    bindings = bool(values.get("request_bindings"))
    if bindings and policy.get("active_testing") is not True:
        raise HTTPException(status_code=403,
                            detail="HTTP workflow bindings require this Hunt's active_testing permission")
    return normalize_principal_slot(values.get("as_principal")), bool(values.get("session_ref")), bindings


def _origin(value: str) -> str:
    return urllib.parse.urlunsplit((*urllib.parse.urlsplit(value)[:2], "", "", ""))


async def resolve_artifact_identity(
    *, pool: Any, run: Mapping[str, Any], hunt_id: Any, context: Any, target: Any, policy: Any,
    hunt_policy: Mapping[str, Any], target_url: str, values: Mapping[str, Any], stack: Any,
    session_store: Any,
) -> tuple[dict[str, str], list[str], str]:
    """``(headers, bound values, principal slot)`` for one read; worker-private."""
    try:
        from runtime.credential_refs import CredentialReferenceError
        from runtime.credential_resolver import validate_worker_credential_authority
    except ModuleNotFoundError:  # package import layout
        from api.runtime.credential_refs import CredentialReferenceError
        from api.runtime.credential_resolver import validate_worker_credential_authority
    session_ref = values.get("session_ref")
    principal = str(values.get("as_principal") or "anonymous").strip().lower()
    bindings = list(values.get("request_bindings") or ())
    if sum(bool(item) for item in (session_ref, principal not in _ANONYMOUS, bindings)) > 1:
        raise CredentialReferenceError(
            "artifact.inspect reads as one identity: session_ref, as_principal or request_bindings")
    origin = _origin(str(values.get("origin") or target_url))
    if not session_ref and principal in _ANONYMOUS and not bindings:
        return {}, [], "anonymous"
    if bindings:
        if hunt_policy.get("active_testing") is not True:
            raise CredentialReferenceError(
                "request_bindings require this Hunt's active_testing permission")
        headers: dict[str, str] = {}
        bound: list[str] = []
        for binding in bindings:
            if str(binding["header"]).lower() in _FORBIDDEN_HEADERS or any(
                    ord(char) < 32 or ord(char) > 126 for char in str(binding.get("prefix") or "")):
                raise CredentialReferenceError("workflow bindings cannot change HTTP routing or framing headers")
        async with pool.acquire() as conn:
            for binding in bindings:
                try:
                    value, is_cookie = await captured_binding(
                        conn, run_id=str(run["id"]), target=target, binding=binding)
                except ValueError as exc:  # expired, another Hunt's, or never captured
                    raise CredentialReferenceError(str(exc)) from None
                text = str(value)
                secrets = cookie_values(text) if is_cookie else []
                if not secrets or any(len(item) < MIN_SCRUBBED_COOKIE_CHARS for item in secrets):
                    # A read shows the page, so only a value withheld exactly can be sent: a session
                    # cookie this Hunt's login set. A PIN or token capture stays http.request's.
                    raise CredentialReferenceError(
                        "artifact.inspect sends only a captured session cookie (Set-Cookie capture, "
                        "values of at least 8 characters); use http.request for other captures")
                if any(ord(char) < 32 or ord(char) == 127 for char in text):
                    raise CredentialReferenceError("HTTP workflow header value is invalid")
                name = str(binding["header"])
                if any(key.lower() == name.lower() for key in headers):
                    raise CredentialReferenceError("HTTP workflow header conflicts with another selected header")
                headers[name] = str(binding.get("prefix") or "") + text
                bound.extend([text, *secrets])
        return headers, bound, "workflow_binding"
    conn = await stack.enter_async_context(pool.acquire())
    authority = await validate_worker_credential_authority(
        conn, owner_kind="hunt", owner_id=str(hunt_id), target=target,
        approval_receipt_id=policy.approval_receipt_id, scope_receipt_id=target.scope_receipt_id,
        action_name="hunt.capability:artifact.inspect",
    )
    if session_ref:
        session = await session_store.load_for_worker(
            conn, session_ref=session_ref, owner_kind="hunt", owner_id=hunt_id, target=target,
            capability="http.request", selected_origins=(origin,))
        stack.callback(session.close)  # its headers leave worker memory with the action
        return session.headers(), [], session.metadata.principal_slot
    try:
        from hunt.http_principal import resolve_http_principal
    except ModuleNotFoundError:  # package import layout
        from api.hunt.http_principal import resolve_http_principal
    headers, _session = await resolve_http_principal(
        conn, context=context, target=target, authority=authority, hunt_id=hunt_id,
        principal=principal, stack=stack, session_store=session_store, origin=origin)
    if _session is not None:
        stack.callback(_session.close)
    return headers, [], principal


__all__ = ["artifact_read_identity", "resolve_artifact_identity"]
