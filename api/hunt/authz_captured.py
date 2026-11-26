"""Two logins a Hunt made itself as the two principals of ``authz.verify``.

A Hunt without attached credentials whose planner registered two accounts and signed in as each
holds two captured logins (a session cookie or a bearer token per account, by reference). The
authorization proof compares what two principals can reach, so it may run on those two logins,
but only when the engine itself can tell they are two different accounts. The planner's word is
not evidence: a single account signed in twice would make every "another user's object is
readable" comparison true.

Distinct means, from records the server holds and the planner cannot write:

* the two logins were captured from different actions of this Hunt, and
* the tokens name different subjects (a JWT's ``sub``/``id``/``email``/``username`` claim, read
  without trusting its signature), or, when a login is not a JWT, the two sign-in requests this
  Hunt sent carried different account names in their body.

Anything else is refused with what to do (sign in as two different accounts and capture each
session from its own sign-in request). The headers never leave the worker.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Mapping, Sequence
import uuid

try:
    from runtime.credential_refs import CredentialReferenceError
except ModuleNotFoundError:  # package import layout
    from api.runtime.credential_refs import CredentialReferenceError

from .artifact_identity import resolve_artifact_identity

CREDENTIAL_SOURCE = "captured_logins"
_SUBJECT_CLAIMS = ("sub", "id", "user_id", "userId", "uid", "email", "username", "preferred_username", "login")
_ACCOUNT_FIELDS = ("email", "username", "user", "login", "user_name", "userName", "account", "name")
_NOT_DISTINCT = (
    "authz.verify compares two different accounts, and these two captured logins could not be told "
    "apart: sign in as two different accounts and capture each session from its own sign-in request "
    "(a JWT with different subjects, or two sign-in requests with different account names)")


def _jwt_claims(value: str) -> dict[str, str]:
    """Identity claims of a JWT-shaped value (payload decoded, signature not trusted)."""
    parts = value.strip().split(".")
    if len(parts) != 3 or not all(parts[:2]):
        return {}
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError):
        return {}
    found: dict[str, str] = {}
    for holder in (payload, payload.get("data") if isinstance(payload, Mapping) else None,
                   payload.get("user") if isinstance(payload, Mapping) else None):
        if not isinstance(holder, Mapping):
            continue
        for name in _SUBJECT_CLAIMS:
            claim = holder.get(name)
            if isinstance(claim, (str, int)) and not isinstance(claim, bool) and str(claim).strip():
                found.setdefault(name, str(claim).strip().lower())
    return found


def token_subjects(values: Sequence[str]) -> dict[str, str]:
    """Identity claims of the JWTs among one login's bound values (a bearer token, a cookie value)."""
    found: dict[str, str] = {}
    for value in values:
        for name, claim in _jwt_claims(str(value)).items():
            found.setdefault(name, claim)
    return found


def account_name(login_input: Any) -> str | None:
    """The account name one sign-in request of this Hunt carried in its body, if it shows one."""
    if isinstance(login_input, str):
        try:
            login_input = json.loads(login_input)
        except ValueError:
            return None
    if not isinstance(login_input, Mapping) or str(login_input.get("method") or "").upper() != "POST":
        return None
    for key in ("json_body", "form_body"):
        body = login_input.get(key)
        if not isinstance(body, Mapping):
            continue
        for name in _ACCOUNT_FIELDS:
            value = body.get(name)
            if isinstance(value, str) and value.strip() and "[withheld" not in value and set(value) != {"*"}:
                return value.strip().lower()
    return None


def distinction(primary_subjects: Mapping[str, str], secondary_subjects: Mapping[str, str],
                primary_account: str | None, secondary_account: str | None) -> str | None:
    """Why the two logins are different accounts (``token_subject`` or ``sign_in_account``), or None."""
    shared = [name for name in primary_subjects if name in secondary_subjects]
    if shared:
        # Tokens that name their subject settle it either way: the same subject is one account.
        return "token_subject" if any(primary_subjects[n] != secondary_subjects[n] for n in shared) else None
    if primary_account and secondary_account and primary_account != secondary_account:
        return "sign_in_account"
    return None


async def resolve_captured_principals(
    *, pool: Any, run: Mapping[str, Any], hunt_id: Any, context: Any, target: Any, policy: Any,
    hunt_policy: Mapping[str, Any], target_url: str, values: Mapping[str, Any], stack: Any,
    session_store: Any,
) -> tuple[dict[str, str], dict[str, str], str]:
    """``(primary headers, secondary headers, distinction)`` for an authz.verify call that names
    two captured logins; ``CredentialReferenceError`` when they are not provably two accounts."""
    sides = {}
    for side in ("primary", "secondary"):
        bindings = [dict(item) for item in values.get(f"{side}_bindings") or () if isinstance(item, Mapping)]
        if not bindings:
            raise CredentialReferenceError("authz.verify needs primary_bindings and secondary_bindings")
        headers, bound, _slot = await resolve_artifact_identity(
            pool=pool, run=run, hunt_id=hunt_id, context=context, target=target, policy=policy,
            hunt_policy=hunt_policy, target_url=target_url,
            values={"request_bindings": bindings, **({"origin": values["origin"]} if values.get("origin") else {})},
            stack=stack, session_store=session_store, capability="authz.verify")
        sides[side] = (headers, bound, {str(item["source_action_id"]) for item in bindings})
    (primary_headers, primary_bound, primary_sources) = sides["primary"]
    (secondary_headers, secondary_bound, secondary_sources) = sides["secondary"]
    if primary_sources & secondary_sources or dict(primary_headers) == dict(secondary_headers):
        raise CredentialReferenceError(_NOT_DISTINCT)
    accounts: dict[str, str | None] = {}
    async with pool.acquire() as conn:
        for side, sources in (("primary", primary_sources), ("secondary", secondary_sources)):
            rows = await conn.fetch(
                """SELECT input_summary->'input' AS input FROM hunt_actions
                   WHERE hunt_run_id=$1 AND id = ANY($2::uuid[]) AND capability_name='http.request'""",
                uuid.UUID(str(hunt_id)), [uuid.UUID(item) for item in sorted(sources)])
            accounts[side] = next((name for name in (account_name(row["input"]) for row in rows) if name), None)
    reason = distinction(token_subjects(primary_bound), token_subjects(secondary_bound),
                         accounts["primary"], accounts["secondary"])
    if reason is None:
        raise CredentialReferenceError(_NOT_DISTINCT)
    return dict(primary_headers), dict(secondary_headers), reason


__all__ = ["CREDENTIAL_SOURCE", "account_name", "distinction", "resolve_captured_principals", "token_subjects"]
