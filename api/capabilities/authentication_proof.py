"""Shared login verdicts and content-free deterministic authentication evidence."""
from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping


_FAILED_STATES = frozenset({
    "blocked", "challenge", "challenge_required", "denied", "error", "failed",
    "failure", "incomplete", "invalid", "invalid_credentials", "invalid_password",
    "login_required", "mfa", "mfa_pending", "mfa_required", "not_authenticated",
    "pending", "pending_verification", "rejected", "requires_action", "requires_mfa",
    "two_factor_required", "unauthenticated", "unverified", "verification_required",
})
_AUTH_FLAGS = frozenset({
    "authenticated", "is_authenticated", "logged_in", "is_logged_in",
    "authorized", "success", "ok",
})
_REQUIRED_FLAGS = frozenset({
    "requires_mfa", "mfa_required", "requires_2fa", "two_factor_required",
    "requires_two_factor", "requires_challenge", "challenge_required",
    "requires_captcha", "captcha_required", "requires_verification",
    "verification_required", "requires_authentication", "authentication_required",
    "requires_login", "login_required",
})
_AUTH_ENVELOPES = frozenset({"authentication", "auth", "session", "login"})
_CHALLENGE_ENVELOPES = frozenset({"challenge", "mfa", "captcha", "two_factor", "verification"})
# Failure and status fields describe the login only at the document root, inside an auth or
# challenge envelope, or inside a generic response wrapper. Elsewhere (user.email_verification,
# subscription.state) they describe some other object and must not veto a successful login.
_LOGIN_SCOPE = _AUTH_ENVELOPES | _CHALLENGE_ENVELOPES | frozenset({
    "data", "result", "response", "payload", "meta", "metadata", "[]",
})
_COMPLETED_CHALLENGE_STATES = frozenset({
    "complete", "completed", "passed", "verified", "satisfied", "not_required",
})
_ACCOUNT_METADATA = frozenset({
    "user", "profile", "account", "subscription", "billing", "preferences", "settings",
})


def _name(value: Any) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value)).lower().replace("-", "_")


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        if value.lower().strip() in {"false", "no", "0"}:
            return False
        if value.lower().strip() in {"true", "yes", "1"}:
            return True
    return None


def _unfinished_challenge(value: Any) -> bool:
    """An issued challenge is unfinished unless the response explicitly clears it.

    Provider/type/URL metadata and even an empty object describe no completed
    authentication. Explicit rejection fields still veto a cleared object below.
    """
    if not isinstance(value, Mapping):
        return bool(value) and _flag(value) is not False
    fields = {_name(k): v for k, v in value.items()}
    not_required = _flag(fields.get("required")) is False
    completed = any(_flag(fields.get(k)) is True for k in ("complete", "completed")) or any(
        isinstance(fields.get(k), str)
        and _name(fields[k].strip()).replace(" ", "_") in _COMPLETED_CHALLENGE_STATES
        for k in ("status", "state")
    )
    return not (not_required or completed)


def authentication_failed_or_incomplete(
    document: Any,
    *,
    token_paths: Iterable[tuple[str, ...]] = (),
    response_identity: bool = False,
) -> bool:
    """Recognize explicit failure, without requiring positive injection proof.

    The caller supplies its own accepted token locations. Every usable identity
    honors response verdicts, including unfamiliar login wrappers. Account and
    subscription metadata remains outside login scope unless it declares an
    explicit authentication verdict.
    """
    nodes: list[tuple[tuple[str, ...], dict]] = []
    scopes: set[tuple[str, ...]] = {()}
    for token_path in token_paths:
        parent = tuple(_name(component) for component in token_path[:-1])
        scopes.update(parent[:i] for i in range(len(parent) + 1))

    def collect(value: Any, path: tuple[str, ...] = ()) -> None:
        if len(path) > 8:
            return
        if isinstance(value, Mapping):
            fields = {_name(k): v for k, v in value.items()}
            nodes.append((path, fields))
            # All usable identities honor explicit response verdicts. Inspect
            # unfamiliar response wrappers too, while account metadata
            # remains separate unless it contains an explicit auth envelope below.
            explicit_login_verdict = bool(fields.keys() & (_REQUIRED_FLAGS | {
                "authenticated", "is_authenticated", "logged_in", "is_logged_in",
                "authentication_status", "authentication_state", "login_status",
            }))
            # A user's verification/challenge is account metadata. Only an
            # explicit auth envelope re-enters login scope beneath that object.
            auth_start = max((i for i, p in enumerate(path)
                              if p in _AUTH_ENVELOPES), default=-1)
            metadata_path = path[auth_start + 1:] if auth_start >= 0 else path
            if response_identity and (explicit_login_verdict or not any(p in _ACCOUNT_METADATA for p in metadata_path)):
                scopes.add(path)
            if path and path[-1] in _AUTH_ENVELOPES:
                scopes.add(path)  # also handles a header token with a nested auth verdict
            for name, child in fields.items():
                collect(child, (*path, name))
        elif isinstance(value, list):
            for child in value[:20]:
                collect(child, (*path, "[]"))

    collect(document)
    for path, fields in nodes:
        login_scoped = any(path[:i] in scopes and all(p in _LOGIN_SCOPE for p in path[i:])
                           for i in range(len(path) + 1))
        if not login_scoped:
            continue
        for name, child in fields.items():
            if (
                (name in _AUTH_FLAGS and _flag(child) is False)
                or (name in _REQUIRED_FLAGS and bool(child) and _flag(child) is not False)
                or (name in {"error", "errors", "error_description"} and bool(child))
                or (name in _CHALLENGE_ENVELOPES and _unfinished_challenge(child))
                or (name in {"status", "state", "code", "error_code", "authentication_status",
                             "authentication_state", "login_status", "token_type", "purpose"}
                    and isinstance(child, str) and _name(child.strip()).replace(" ", "_") in _FAILED_STATES)
                or (name == "required" and any(p in _CHALLENGE_ENVELOPES for p in path)
                    and _flag(child) is True)
            ):
                return True
    return False


def successful_token_signals(result: Any) -> tuple[str, ...]:
    """Return content-free token assertions, vetoed by their own login state.

    Candidate ancestors are login scope even when an API uses an unfamiliar
    wrapper name. Unrelated user/subscription metadata is not a login verdict.
    Cookies and ambiguous generic tokens remain candidates, not bypass proof.
    """
    if not isinstance(result.status_code, int) or not 200 <= result.status_code < 300:
        return ()
    signals = {
        str(name).lower() for name, value in result.response_headers.items()
        if str(name).lower() in {"authorization", "x-auth-token"}
        and isinstance(value, str) and value.strip()
    }
    content_type = next((str(v).lower() for k, v in result.response_headers.items()
                         if str(k).lower() == "content-type"), "")
    if "json" not in content_type or not result.response_body:
        return tuple(sorted(signals))
    try:
        document = json.loads(result.response_body[:2_000_000].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return tuple(sorted(signals))

    token_paths: list[tuple[str, ...]] = []
    token_names = {"token", "access_token", "id_token", "jwt"}

    def collect(value: Any, path: tuple[str, ...] = (), authenticated: bool = False) -> None:
        if len(path) > 8:
            return
        if isinstance(value, Mapping):
            fields = {_name(k): v for k, v in value.items()}
            authenticated = authenticated or any(
                _flag(fields.get(k)) is True
                for k in {"authenticated", "is_authenticated", "logged_in", "is_logged_in"}
            )
            for name, child in fields.items():
                child_path = (*path, name)
                # Retained challenge tokens are never session evidence. A cleared
                # challenge may coexist with an independent valid login token.
                if (name in token_names and isinstance(child, str) and child.strip()
                        and not any(p in _CHALLENGE_ENVELOPES for p in path)
                        and (name != "token" or authenticated or any(p in _AUTH_ENVELOPES for p in path))):
                    signals.add("json:" + ".".join(child_path))
                    token_paths.append(child_path)
                collect(child, child_path, authenticated)
        elif isinstance(value, list):
            for child in value[:20]:
                collect(child, (*path, "[]"), authenticated)

    collect(document)
    if authentication_failed_or_incomplete(
        document, token_paths=token_paths, response_identity=bool(signals),
    ):
        return ()
    return tuple(sorted(signals))
