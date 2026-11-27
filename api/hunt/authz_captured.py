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
# Identity claims in priority order: the first one both tokens carry decides (a per-session id that
# differs must never make one account look like two, so the account-level claims come first).
_SUBJECT_CLAIMS = ("sub", "user_id", "userId", "uid", "email", "username", "preferred_username", "login", "id")
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


def account_name(login_input: Any) -> tuple[str, str] | None:
    """``(field, account)`` one sign-in request of this Hunt names, when its body carries exactly one
    account field: the application must sign in by that field. A body with several (an email and a
    user name) is refused here, since the server cannot tell which one the application reads."""
    if isinstance(login_input, str):
        try:
            login_input = json.loads(login_input)
        except ValueError:
            return None
    if not isinstance(login_input, Mapping) or str(login_input.get("method") or "").upper() != "POST":
        return None
    found: list[tuple[str, str]] = []
    for key in ("json_body", "form_body"):
        body = login_input.get(key)
        if not isinstance(body, Mapping):
            continue
        for name in _ACCOUNT_FIELDS:
            value = body.get(name)
            if isinstance(value, str) and value.strip() and "[withheld" not in value and set(value) != {"*"}:
                found.append((name, value.strip().lower()))
    return found[0] if len(found) == 1 else None


def distinction(primary_subjects: Mapping[str, str], secondary_subjects: Mapping[str, str],
                primary_account: tuple[str, str] | None, secondary_account: tuple[str, str] | None) -> str | None:
    """Why the two logins are different accounts (``token_subject`` or ``sign_in_account``), or None."""
    shared = next((name for name in _SUBJECT_CLAIMS if name in primary_subjects and name in secondary_subjects), None)
    if shared is not None:
        # The highest-priority subject both tokens name settles it either way.
        return "token_subject" if primary_subjects[shared] != secondary_subjects[shared] else None
    if (primary_account and secondary_account and primary_account[0] == secondary_account[0]
            and primary_account[1] != secondary_account[1]):
        return "sign_in_account"
    return None


def _uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise CredentialReferenceError("a captured login names an action of this Hunt by its id") from None


def _source_action(binding: Mapping[str, Any]) -> str:
    """The action of this Hunt a binding's value came from (a capture, or a withheld value's)."""
    if binding.get("withheld_ref"):
        return str(binding["withheld_ref"]).split("/")[3]
    return str(binding["source_action_id"])


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
        sides[side] = (headers, bound, {_source_action(item) for item in bindings})
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
                uuid.UUID(str(hunt_id)), [_uuid(item) for item in sorted(sources)])
            # Every sign-in request behind this login must name the same one account.
            named = {account_name(row["input"]) for row in rows}
            accounts[side] = named.pop() if len(named) == 1 else None
    reason = distinction(token_subjects(primary_bound), token_subjects(secondary_bound),
                         accounts["primary"], accounts["secondary"])
    if reason is None:
        raise CredentialReferenceError(_NOT_DISTINCT)
    return dict(primary_headers), dict(secondary_headers), reason


__all__ = ["CREDENTIAL_SOURCE", "account_name", "distinction", "resolve_captured_principals", "token_subjects"]
