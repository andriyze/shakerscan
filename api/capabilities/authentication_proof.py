"""Shared, content-free authentication evidence for deterministic injection proof."""
from __future__ import annotations

import json
import re
from typing import Any, Mapping


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
_LOGIN_SCOPE = _AUTH_ENVELOPES | _CHALLENGE_ENVELOPES | frozenset({"data", "result", "response", "payload", "[]"})


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


def successful_token_signals(result: Any) -> tuple[str, ...]:
    """Return token assertion names, never their values, on a successful response.

    A challenge, CSRF or preference cookie can be issued when login was rejected.
    Cookie creation and a status change alone cannot establish authenticated state.
    Explicit failure or an unfinished MFA/challenge overrides any token assertion.
    Cookie-only and generic token responses remain observations for a later
    authenticated resource check: a token value alone does not identify its purpose.
    """
    if not isinstance(result.status_code, int) or not 200 <= result.status_code < 300:
        return ()
    signals = {
        str(name).lower() for name, value in result.response_headers.items()
        if str(name).lower() in {"authorization", "x-auth-token"}
        and isinstance(value, str) and value.strip()
    }
    content_type = next((
        str(value).lower() for name, value in result.response_headers.items()
        if str(name).lower() == "content-type"
    ), "")
    if "json" not in content_type or not result.response_body:
        return tuple(sorted(signals))
    try:
        document = json.loads(result.response_body[:2_000_000].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return tuple(sorted(signals))

    incomplete = False

    def walk(value: Any, path: tuple[str, ...] = (), authenticated: bool = False) -> None:
        nonlocal incomplete
        if len(path) > 8:
            return
        if isinstance(value, Mapping):
            fields = {_name(raw_name): child for raw_name, child in value.items()}
            authenticated = authenticated or any(
                _flag(fields.get(name)) is True
                for name in {"authenticated", "is_authenticated", "logged_in", "is_logged_in"}
            )
            login_scoped = all(part in _LOGIN_SCOPE for part in path)
            for name, child in fields.items():
                child_path = (*path, name)
                if (
                    (login_scoped and name in _AUTH_FLAGS and _flag(child) is False)
                    or (login_scoped and name in _REQUIRED_FLAGS and bool(child) and _flag(child) is not False)
                    or (login_scoped and name in {"error", "errors", "error_description"} and bool(child))
                    # A challenge object is judged by its own fields (required, token, status);
                    # {"challenge": {"required": false}} is not an unfinished challenge.
                    or (login_scoped and name in {"challenge", "captcha"} and not isinstance(child, Mapping)
                        and bool(child) and _flag(child) is not False)
                    or (login_scoped and name in {"status", "state", "code", "error_code", "authentication_status",
                                                  "authentication_state", "login_status", "token_type", "purpose"}
                        and isinstance(child, str) and _name(child.strip()).replace(" ", "_") in _FAILED_STATES)
                    or (name == "required" and any(part in _CHALLENGE_ENVELOPES for part in path)
                        and _flag(child) is True)
                    or (name in {"token", "access_token", "id_token", "jwt"}
                        and any(part in _CHALLENGE_ENVELOPES for part in path) and bool(child))
                ):
                    incomplete = True
                if (
                    name in {"token", "access_token", "id_token", "jwt"}
                    and isinstance(child, str) and child.strip()
                    and (name != "token" or authenticated or any(part in _AUTH_ENVELOPES for part in path))
                ):
                    signals.add("json:" + ".".join(child_path))
                walk(child, child_path, authenticated)
        elif isinstance(value, list):
            for child in value[:20]:
                walk(child, (*path, "[]"), authenticated)

    walk(document)
    return () if incomplete else tuple(sorted(signals))
