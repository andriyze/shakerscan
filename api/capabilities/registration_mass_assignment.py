"""``request.verify`` check ``mass_assignment``: a sign-up that accepts a privileged field.

A driven VAmPI Hunt registered with ``"admin": true`` and got an admin account; no proof could
settle it, because the create-based mass-assignment proof needs the create answer to name an id it
can read back and delete, and a sign-up names neither.

Here the check signs up three fresh accounts on the planner's sign-up request (its fields, with
the engine's own random user name, e-mail and password filled in): a control without the field the
claim is about, then two with it (``parameter`` = ``privilege_value``). It signs in as each on
``login_path`` and reads that account's own profile (``profile_path``, ``{username}`` / ``{email}``
filled in). Verified only when the control's profile shows the field with another value and both
accounts that sent it show the sent value: the application stored a privilege its user chose.

The accounts stay on the target (a sign-up has no undo); the check needs the Hunt's
``allow_account_creation`` and names the accounts by user name in its observation.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
import json
import re
import secrets
from typing import Any
import urllib.parse

CONTRACT = "request_registration_privilege_readback/v1"
REQUESTS = 9
_LOGIN_FIELD = re.compile(r"^(?:user(?:_?name)?|login|name|handle|nick(?:name)?)$", re.I)
_EMAIL_FIELD = re.compile(r"e-?mail", re.I)
_SECRET_FIELD = re.compile(r"pass(?:word|wd)?|pwd", re.I)
_TOKEN_KEYS = re.compile(r"^(?:auth_?token|access_?token|token|jwt|id_?token|session_?token)$", re.I)


def _privilege(raw: Any) -> Any:
    if isinstance(raw, (bool, int, float)) or raw is None:
        return True if raw is None else raw
    text = str(raw).strip()
    try:
        return json.loads(text)
    except ValueError:
        return text


def _same(observed: Any, sent: Any) -> bool:
    if isinstance(sent, bool):
        return observed is sent or str(observed).strip().lower() == str(sent).lower()
    return str(observed).strip().lower() == str(sent).strip().lower()


def _walk(node: Any, key: str, depth: int = 0) -> list[Any]:
    found: list[Any] = []
    if depth > 5:
        return found
    if isinstance(node, Mapping):
        for name, child in node.items():
            if name == key and not isinstance(child, (Mapping, list)):
                found.append(child)
            found.extend(_walk(child, key, depth + 1))
    elif isinstance(node, list):
        for child in node[:20]:
            found.extend(_walk(child, key, depth + 1))
    return found


def _json(body: bytes) -> Any:
    try:
        return json.loads(bytes(body or b"").decode("utf-8", "replace"))
    except ValueError:
        return None


def _token(body: bytes) -> str | None:
    def walk(node: Any, depth: int = 0) -> str | None:
        if depth > 4:
            return None
        if isinstance(node, Mapping):
            for name, child in node.items():
                if _TOKEN_KEYS.match(str(name)) and isinstance(child, str) and len(child) >= 16:
                    return child
            for child in node.values():
                found = walk(child, depth + 1)
                if found:
                    return found
        return None
    return walk(_json(body))


def _cookies(headers: Mapping[str, Any]) -> str:
    pairs = []
    for name, value in headers.items():
        if str(name).lower() == "set-cookie":
            for part in str(value).split("\n"):
                cookie = part.split(";", 1)[0].strip()
                if "=" in cookie and not cookie.endswith("="):
                    pairs.append(cookie)
    return "; ".join(pairs)


def _body_kind(request: Any) -> str:
    for name, value in request.headers:
        if str(name).lower() == "content-type":
            return "form" if "urlencoded" in str(value) else "json"
    return "json"


def _encode(fields: Mapping[str, Any], kind: str) -> bytes:
    if kind == "form":
        return urllib.parse.urlencode({key: ("true" if value is True else "false" if value is False else value)
                                       for key, value in fields.items()}).encode()
    return json.dumps(dict(fields), separators=(",", ":")).encode()


async def prove(verifier: Any) -> dict[str, Any]:
    request, field = verifier.request, verifier.field
    login_path = str(verifier.options.get("login_path") or "")
    profile_path = str(verifier.options.get("profile_path") or "")
    sent_value = _privilege(verifier.options.get("privilege_value"))
    kind = _body_kind(request)
    if kind == "json":
        template = _json(request.body)
    else:
        template = dict(urllib.parse.parse_qsl(bytes(request.body or b"").decode("utf-8", "replace"),
                                               keep_blank_values=True))
    if not isinstance(template, Mapping) or not template:
        return verifier.observation(inconclusive_reason="sign_up_body_not_an_object")
    names = list(template)
    user_field = next((name for name in names if _LOGIN_FIELD.match(name)), None)
    email_field = next((name for name in names if _EMAIL_FIELD.search(name)), None)
    secret_fields = [name for name in names if _SECRET_FIELD.search(name)]
    login_name = user_field or email_field
    if not login_name or not secret_fields or field in {user_field, email_field, *secret_fields}:
        return verifier.observation(inconclusive_reason="sign_up_fields_not_recognised")
    if verifier.left() < REQUESTS:
        return verifier.observation(inconclusive_reason="budget")
    origin = request.origin()

    async def account(with_field: bool) -> tuple[Any, str | None]:
        tag = secrets.token_hex(5)
        username, email, password = f"ss{tag}", f"ss{tag}@example.invalid", "Ss-" + secrets.token_urlsafe(12) + "9!"
        fields = dict(template)
        if user_field:
            fields[user_field] = username
        if email_field:
            fields[email_field] = email
        for name in secret_fields:
            fields[name] = password
        fields.pop(field, None)
        if with_field:
            fields[field] = sent_value
        signed_up = await verifier.send(replace(request, body=_encode(fields, kind)))
        if not (200 <= int(signed_up.status_code or 0) < 400):
            return None, f"sign_up_refused_{signed_up.status_code}"
        login = {login_name: username if login_name == user_field else email, secret_fields[0]: password}
        answer = await verifier.send(replace(
            request, url=origin + login_path, method="POST", body=_encode(login, kind)))
        token = _token(answer.response_body)
        cookie = _cookies(answer.response_headers)
        if not (200 <= int(answer.status_code or 0) < 400) or not (token or cookie):
            return None, "sign_in_failed"
        session = (("Authorization", f"Bearer {token}"),) if token else (("Cookie", cookie),)
        path = profile_path.replace("{username}", urllib.parse.quote(username)).replace(
            "{email}", urllib.parse.quote(email))
        read = await verifier.send(replace(
            request, url=origin + path, method="GET", body=b"", body_mode="none",
            headers=tuple(item for item in request.headers if str(item[0]).lower() != "content-type") + session))
        if not 200 <= int(read.status_code or 0) < 300:
            return None, f"profile_read_{read.status_code}"
        values = _walk(_json(read.response_body), field)
        return (values[0] if len(set(map(str, values))) == 1 else None), (None if values else "field_not_in_profile")

    control, reason = await account(False)
    if reason:
        return verifier.observation(inconclusive_reason=f"control_{reason}")
    if _same(control, sent_value):
        return verifier.observation(not_proven_reason="control_already_holds_the_value")
    observed = []
    for _ in range(2):
        value, reason = await account(True)
        if reason:
            return verifier.observation(inconclusive_reason=f"overposted_{reason}")
        observed.append(value)
    if not all(_same(value, sent_value) for value in observed):
        return verifier.observation(not_proven_reason="field_not_stored")
    return verifier.observation(
        proof_contract=CONTRACT, technique="sign_up_overpost_profile_readback_repeated",
        field_path=field, control_value=str(control)[:80], sent_value=json.dumps(sent_value)[:80],
        repetitions=2, accounts_created=3,
    )
