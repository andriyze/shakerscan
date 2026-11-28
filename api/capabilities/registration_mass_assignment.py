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

Which field is a privilege is decided here, not by the planner: a sign-up that stores
``newsletter: true`` or ``theme: "dark"`` passes the same differential and is the application
working as designed. ``privilege_refusal`` holds the vocabulary (whole field names, never a
substring) and what value each kind must be sent with; admission and ``prove`` both ask it.

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

try:
    from capabilities.secret_material import keyed_body_digest
except ModuleNotFoundError:  # package import layout
    from api.capabilities.secret_material import keyed_body_digest

CONTRACT = "request_registration_privilege_readback/v1"
REQUESTS = 9
_LOGIN_FIELD = re.compile(r"^(?:user(?:_?name)?|login|name|handle|nick(?:name)?)$", re.I)
_EMAIL_FIELD = re.compile(r"e-?mail", re.I)
_SECRET_FIELD = re.compile(r"pass(?:word|wd)?|pwd", re.I)
_TOKEN_KEYS = re.compile(r"^(?:auth_?token|access_?token|token|jwt|id_?token|session_?token)$", re.I)


# -- what counts as a privilege --------------------------------------------------------------
# A field name is read as its words: snake_case, kebab-case, dotted and camelCase all split
# (``isAdmin`` -> is, admin). The whole name must then be one of the kinds below; a name that only
# contains such a word (``admin_notes``, ``role_description``, ``newsletter_active``) is not one.
_WORD = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
# Words that say whose attribute it is and nothing about what it is.
_LEADING_WORDS = frozenset({"is", "has", "user", "account"})
# The account may administer the application: the flag every framework's user model has
# (Django is_staff / is_superuser, the ubiquitous admin / isAdmin). Sent as true.
_ADMINISTRATOR_FLAGS = frozenset({"admin", "administrator", "superuser", "superadmin", "staff", "moderator"})
# What the account is allowed to do, by name or id: a role, or the permission set itself
# (Spring authorities, OAuth-style scopes). Sent as the role the control was not given.
_ROLE_FIELDS = frozenset({"role", "roles", "permission", "permissions", "privilege", "privileges",
                          "scope", "scopes", "authority", "authorities"})
# A gate the application itself is meant to open (e-mail confirmation, an operator's approval,
# activation): an account that opens it for itself skips that step. Sent as true.
_ACCOUNT_GATES = frozenset({"verified", "approved", "confirmed", "active", "enabled"})
_GATE_SUBJECTS = frozenset({"email", "phone", "mobile"})
# Value the application accounts for: nobody is meant to choose their own. Sent as a positive number.
_BALANCES = frozenset({"balance", "credit", "credits"})
# Left out on purpose: group(s), plan, tier, type and level. A sign-up form legitimately asks for
# them in many applications (a class group, the plan being bought), so storing the chosen value
# proves nothing by itself.
ACCEPTED_FIELDS = (
    "an administrator flag (admin, is_admin, isAdmin, is_staff, is_superuser, moderator), a role or "
    "permission set (role, roles, role_id, permissions, privileges, scopes, authorities), an account "
    "gate (verified, email_verified, approved, confirmed, active, enabled) or a balance (balance, credits)")


def name_words(name: Any) -> tuple[str, ...]:
    return tuple(word.lower() for word in _WORD.findall(str(name or "")))


def privilege_kind(name: Any) -> str | None:
    """``administrator_flag``, ``role``, ``account_gate`` or ``balance`` when the whole field name
    is one, else None."""
    words = list(name_words(name))
    while len(words) > 1 and words[0] in _LEADING_WORDS:
        words.pop(0)
    whole = "".join(words)  # super_user and superUser are superuser
    if whole in _ADMINISTRATOR_FLAGS:
        return "administrator_flag"
    if whole in _ROLE_FIELDS or (len(words) > 1 and words[-1] in {"id", "ids"} and "".join(words[:-1]) in _ROLE_FIELDS):
        return "role"
    if whole in _ACCOUNT_GATES or (len(words) > 1 and words[0] in _GATE_SUBJECTS and "".join(words[1:]) in _ACCOUNT_GATES):
        return "account_gate"
    if whole in _BALANCES:
        return "balance"
    return None


def privilege_refusal(name: Any, raw_value: Any) -> str | None:
    """Why this field and value cannot show a privilege (what is accepted), or None when they can."""
    kind = privilege_kind(name)
    if kind is None:
        return (f"mass_assignment proves a stored privilege, and {str(name)[:80]!r} is not named for one: "
                f"parameter must be {ACCEPTED_FIELDS}. A stored field with another name is a lead, not a "
                "verified finding")
    value = _privilege(raw_value)
    number = isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind in {"administrator_flag", "account_gate"} and not (
            value is True or value == 1 or str(value).strip().lower() in {"true", "yes"}):
        return f"mass_assignment: {name} is a flag, so privilege_value must be true"
    if kind == "balance" and not (number and value > 0):
        return f"mass_assignment: {name} is an amount, so privilege_value must be a positive number"
    if kind == "role" and not (number or (isinstance(value, str) and value.strip())):
        return f"mass_assignment: {name} names a role, so privilege_value must be the role name or id to claim"
    return None


def _value_digest(value: Any) -> str:
    """What the control's profile showed, without the value: it is a field of someone's profile."""
    return keyed_body_digest(str(value).encode("utf-8", "replace"))


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
    refused = privilege_refusal(field, verifier.options.get("privilege_value"))
    if refused:
        # Admission refuses this before anything is reserved; a caller that reaches the check
        # another way gets the same answer and nothing is sent.
        return verifier.observation(not_proven_reason="field_is_not_a_privilege", refusal=refused[:300])
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
        field_path=field, privilege_kind=privilege_kind(field),
        # The control's own value is a profile field: its type, length and a digest say it differed.
        control_value_type=type(control).__name__, control_value_chars=len(str(control)),
        control_value_sha256=_value_digest(control), sent_value=json.dumps(sent_value)[:80],
        repetitions=2, accounts_created=3,
    )
