"""Accounts the engine makes itself, and what it does with them.

Measured Hunts reached little of an application's signed-in surface: the planner made one account
or none, and an application's API shows its routes only when someone uses the features. A person
testing an application with self-registration signs up twice and uses it as each account. The
engine's sweep does the same, as ordinary capability calls of the Hunt (scope, pacing, budget,
records as for any other call), only with the Hunt's state-changing permission:

1. **Sign up** on each registration route the inventory names (a ``register``/``signup`` route, a
   POST collection of users or accounts, or a form with a password confirmation), up to two
   accounts, each with fresh random values. The values are the engine's own for an account it made
   on the target under test; no person's credential is involved.
2. **Sign in** as each account on the sign-in the sweep found, capturing the session (Set-Cookie)
   and reading the token the answer withholds, by reference. A sign-up answer that already holds a
   token is that account's login.
3. **Use the application as each login** (``Sweep``): read the mapped API routes as it, send the
   mapped non-destructive writes with plausible values (a basket item, a review, a profile field),
   and hand the two logins to ``authz.verify`` on the routes that name each account's own objects.
   Every request it sends as a login names the route and its inputs for the coverage report, so
   the sweep's checks run on them as that login.

Accepted default credentials join as a login too (chaining): the session the accepted attempt
captured is used like an account the engine made.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import re
import secrets
from typing import Any

MAX_ACCOUNTS = 2
MAX_SIGNUP_ROUTES = 4
MAX_LOGIN_READS = 150
MAX_FEATURE_WRITES = 40
MAX_OBJECT_ROUTES = 10

_SIGNUP = re.compile(r"(?:^|/)(?:register|registration|signup|sign-up|sign_up|join|create-?account|"
                     r"accounts?/new|users?/new|enrol+)(?:/|$|\.)", re.I)
_USER_COLLECTION = re.compile(r"^/(?:api|rest|v[0-9]{1,2})(?:/v[0-9]{1,2})?/(?:users|accounts|customers|members)/?$", re.I)
_CONFIRM_FIELD = re.compile(r"(?:confirm|repeat|again|retype|verify|password2|_2$)", re.I)
_SECRET_FIELD = re.compile(r"pass(?:word|wd)?|pwd", re.I)
_TOKEN_KEY = re.compile(
    r'"(?:token|access_?token|accessToken|id_?token|idToken|jwt|auth_?token|authToken|bearer|session_?token)"'
    r'\s*:\s*"(\[withheld:\d+\])"', re.I)
_ID_KEYS = re.compile(r'"((?:[A-Za-z]+_?)?[iI][dD])"\s*:\s*(\d{1,12})\b')
_DESTRUCTIVE = re.compile(
    r"(?:delete|remove|destroy|drop|purge|wipe|truncate|shutdown|restart|reboot|reset|restore|revoke|"
    r"cancel|withdraw|refund|transfer|pay(?:ment)?s?|purchase|checkout|approve|disable|deactivate|"
    r"unsubscribe|terminate|kill|stop|logout|signout|import|deploy|install|exec|run|build|password|"
    r"login|signin|sign-in|register|signup)", re.I)


def new_account() -> dict[str, str]:
    """Fresh values for one account the engine makes (never reused across Hunts)."""
    tag = secrets.token_hex(5)
    return {"email": f"shakerscan-{tag}@example.invalid", "username": f"shakerscan{tag}",
            "name": f"ShakerScan {tag}", "password": "Ss-" + secrets.token_urlsafe(14) + "9!"}


def signup_routes(items: Sequence[Mapping[str, Any]]) -> list[tuple[str, list[str]]]:
    """``(path, input names)`` of the registration routes the coverage report names, best first."""
    found: list[tuple[int, str, list[str]]] = []
    for item in items:
        method, _, route = str(item.get("endpoint") or "").partition(" ")
        if method != "POST" or not route.startswith("/") or "{" in route:
            continue
        params = [str(name) for name in item.get("params") or ()]
        confirm = sum(1 for name in params if _SECRET_FIELD.search(name)) >= 2 or any(
            _CONFIRM_FIELD.search(name) and _SECRET_FIELD.search(name) for name in params)
        if _SIGNUP.search(route) or confirm:
            found.append((0, route, params))
        elif _USER_COLLECTION.match(route):
            found.append((1, route, params))
    found.sort(key=lambda entry: entry[0])
    unique: list[tuple[str, list[str]]] = []
    for _rank, route, params in found:
        if route not in [path for path, _ in unique]:
            unique.append((route, params))
    return unique[:MAX_SIGNUP_ROUTES]


def signup_body(params: Sequence[str], account: Mapping[str, str]) -> dict[str, Any]:
    """A registration body: the route's own inputs filled by name, else the common fields."""
    names = [str(name) for name in params if str(name)] or [
        "email", "username", "name", "password", "passwordRepeat", "password_confirmation", "confirmPassword"]
    return {name: field_value(name, account) for name in names[:20]}


def field_value(name: str, account: Mapping[str, str], refs: Mapping[str, str] | None = None) -> Any:
    """A plausible value for one input, by its name (the account's own where the name asks for it)."""
    low = name.lower().split(".")[-1]
    if _SECRET_FIELD.search(low):
        return account.get("password", "Ss-value-9!")
    if "mail" in low:
        return account.get("email", "shakerscan@example.invalid")
    if low in {"username", "user", "login", "user_name", "nickname", "handle"}:
        return account.get("username", "shakerscan")
    if low in {"name", "fullname", "full_name", "displayname", "display_name", "firstname", "lastname"}:
        return account.get("name", "ShakerScan")
    if low.endswith("id") and len(low) > 2:
        # The account's own object where the field names its collection (BasketId -> bid, basket_id).
        collection = low[:-2].rstrip("_")
        wanted = {low, f"{collection}id", f"{collection}_id", f"{collection[:1]}id"}
        for key, value in (refs or {}).items():
            if key.lower() in wanted:
                return int(value)
        if collection in {"user", "account", "customer", "member"} and (refs or {}).get("id"):
            return int(refs["id"])
        return 1
    if low in {"quantity", "qty", "count", "amount", "rating", "stars", "score", "number", "page", "limit"}:
        return 1
    if low in {"price", "total", "cost"}:
        return 1
    if any(word in low for word in ("url", "uri", "link", "image", "avatar", "website")):
        return "https://example.invalid/shakerscan.png"
    if any(word in low for word in ("date", "time")):
        return "2026-01-01"
    if low.startswith(("is", "has", "enable", "accept", "agree")):
        return True
    return "shakerscan"


def token_ref(response: Mapping[str, Any]) -> str | None:
    """The withheld reference of the token a sign-in (or sign-up) answer carried, if any."""
    text = str(response.get("body_sample") or "")
    match = _TOKEN_KEY.search(text)
    if not match:
        return None
    marker = match.group(1)
    for entry in response.get("withheld_values") or ():
        if isinstance(entry, Mapping) and entry.get("marker") == marker and entry.get("ref"):
            return str(entry["ref"])
    return None


def own_refs(response: Mapping[str, Any]) -> dict[str, str]:
    """Integer ids an answer names by key (the account's own user, basket, cart ...)."""
    found: dict[str, str] = {}
    for key, value in _ID_KEYS.findall(str(response.get("body_sample") or ""))[:40]:
        found.setdefault(key, value)
    return found


def object_key(route: str) -> str | None:
    """The collection a templated route's id belongs to (``/rest/basket/{id}`` -> ``basket``)."""
    segments = [segment for segment in route.split("/") if segment]
    for index, segment in enumerate(segments):
        if segment.startswith("{") and index:
            return segments[index - 1].lower().rstrip("s")
    return None


def own_id(route: str, refs: Mapping[str, str]) -> str | None:
    """The account's own id for a templated route: a key naming its collection (``basketId``,
    ``basket_id``, ``bid``), or the account's ``id`` on a users route."""
    collection = object_key(route)
    if not collection:
        return None
    wanted = {f"{collection}id", f"{collection}_id", f"{collection[0]}id"}
    for key, value in refs.items():
        if key.lower() in wanted:
            return value
    if collection in {"user", "account", "customer", "member", "profile"}:
        return refs.get("id") or refs.get("userId") or refs.get("user_id")
    return None


def bindings_for(*, token: str | None, cookie_action: str | None) -> list[dict[str, str]] | None:
    """The request bindings that send one login: its token as a bearer, else its session cookie."""
    if token:
        return [{"withheld_ref": token, "header": "Authorization", "prefix": "Bearer "}]
    if cookie_action:
        return [{"source_action_id": cookie_action, "capture_name": "session", "header": "Cookie"}]
    return None


def feature_writes(items: Sequence[Mapping[str, Any]]) -> list[tuple[str, str, list[str]]]:
    """``(method, path, inputs)`` of mapped writes a user of the application would send: inputs known,
    the route not destructive, not a sign-in or a sign-up."""
    found: list[tuple[str, str, list[str]]] = []
    for item in items:
        method, _, route = str(item.get("endpoint") or "").partition(" ")
        params = [str(name) for name in item.get("params") or () if str(name)]
        if method not in {"POST", "PUT", "PATCH"} or not params or not route.startswith("/"):
            continue
        if _DESTRUCTIVE.search(route) or _SIGNUP.search(route) or _USER_COLLECTION.match(route):
            continue
        found.append((method, route, params))
    return found[:MAX_FEATURE_WRITES]


def concrete_for(route: str, refs: Mapping[str, str]) -> str:
    """A requestable path: the account's own id where the route names its collection, else 1."""
    own = own_id(route, refs)
    return re.sub(r"\{[^/{}]*\}", own or "1", route)


def body_json(text: Any) -> Any:
    try:
        return json.loads(str(text))
    except ValueError:
        return None


__all__ = ["MAX_ACCOUNTS", "MAX_FEATURE_WRITES", "MAX_LOGIN_READS", "MAX_OBJECT_ROUTES", "bindings_for",
           "concrete_for", "feature_writes", "field_value", "new_account", "object_key", "own_id", "own_refs",
           "signup_body", "signup_routes", "token_ref"]
