"""Saved logins a person attaches to a Hunt, used by reference (``login.use``).

A Hunt driven by a model never signs in on its own: it holds no credential, and a login is a
state-changing request a person must allow. A *saved login* is an existing form or JSON login
profile attached to the Hunt's target (``form_login``/``json_login`` with ``http.request``
allowed). A person attaches one to a Hunt:

* at start (``saved_logins`` on ``POST /hunts``, ``shakerscan hunt start --saved-login``), or
* later, through a ``login.use`` permission request the Hunt raises when the planner first binds
  the login (``shakerscan approve <id>``), which the person's launch bound
  ``login.use:<profile-id>`` grants as it arises.

**What the planner sees.** A reference and a description only: the profile id and version, its
principal label, its kind, the login URL (scheme, host, port and path of the profile's endpoint),
and how many logins are left. Never a username or secret value.

**What the attachment allows.** The login flow only, a bounded number of times, and nothing more:
an ``http.request`` POST to exactly that login URL whose body binds the profile's username and
secret by reference (``request_bindings: [{"saved_login": "<profile id>", "credential_field":
"secret", "body_pointer": "/password"}]``), optionally with a value this Hunt captured (a CSRF
token). It needs the Hunt's active testing, but not its state-changing permission, and it is not
charged to the state-changing budget: it is counted against the attachment's login count instead
(``DEFAULT_LOGINS``, at most ``MAX_LOGINS`` per decision). The worker re-checks the live grant,
the profile version and the login URL after decryption, and sends the values only there.

**What comes back.** The login's answer is reduced to its status and cookie names (the request
binds a credential), the session cookie it set is captured by reference as before and sent back
only to the origin that set it, and the secret is sealed into the Hunt's known values, so any
later echo of it in a response is withheld from the planner, receipts and findings.

Every login is recorded in ``hunt_credential_uses`` (slot ``login``, source ``live_grant:<grant>``
or ``preauthorized:<pre-authorization>``); that ledger is the count.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from typing import Any
import urllib.parse
import uuid

from .credential_uses import CredentialUse, hunt_consuming_target_id
from .permission_reasons import KIND_LOGIN_USE, HuntRefusal

SAVED_LOGIN_KINDS = frozenset({"form_login", "json_login"})
DEFAULT_LOGINS = 3
MAX_LOGINS = 10
MAX_SAVED_LOGINS = 4
LOGIN_SLOT = "login"
LOGIN_FIELDS = frozenset({"username", "secret"})
BINDING_KEY = "saved_login"
# Planner-facing guidance (fixed text, never target or credential content).
HOW_TO_USE = (
    "Sign in with a saved login by reference: http.request POST to its login_url (origin and path "
    "exactly; form_body or json_body with the form's field names) with request_bindings "
    "[{\"saved_login\": \"<profile_id>\", \"credential_field\": \"username\", \"body_pointer\": "
    "\"/<user field>\"}, {\"saved_login\": \"<profile_id>\", \"credential_field\": \"secret\", "
    "\"body_pointer\": \"/<password field>\"}] and \"capture\": [{\"name\": \"session\", \"header\": "
    "\"Set-Cookie\"}]. The worker fills the values; you never see them. The answer's captures entry "
    "is the request_bindings item that sends the session on later requests to the same origin. "
    "Each login counts against logins_left. An available (unattached) login is asked for by "
    "binding it: the first call raises a login.use permission request for a person."
)


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return default if value is None else value


def login_url(endpoint: Any) -> str | None:
    """``scheme://host:port/path`` of a profile endpoint (no user info, query or fragment)."""
    try:
        parts = urllib.parse.urlsplit(str(endpoint or ""))
        port = parts.port
    except ValueError:
        return None
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        return None
    netloc = f"[{host}]" if ":" in host else host
    port = port or (443 if scheme == "https" else 80)
    return f"{scheme}://{netloc}:{port}{parts.path or '/'}"


def profile_login_url(endpoint: Any, target_url: Any, target_host: Any) -> str | None:
    """A profile's login URL for this Hunt: its endpoint (a same-origin path is the Hunt target's),
    in ``login_url`` form, and only on the Hunt's own host. A login elsewhere (another host, a
    destination granted for this Hunt) is never a saved login: no credential goes off the target."""
    text = str(endpoint or "")
    url = login_url(urllib.parse.urljoin(str(target_url or ""), text) if text.startswith("/") else text)
    host = (urllib.parse.urlsplit(url).hostname or "") if url else ""
    wanted = str(target_host or "").lower().rstrip(".").strip("[]")
    return url if url and host and host == wanted else None


def request_login_url(values: Mapping[str, Any], default_origin: Any) -> str | None:
    """Where an ``http.request`` goes, in ``login_url`` form: its own origin, else the Hunt's."""
    origin = str(values.get("origin") or default_origin or "").strip()
    path = str(values.get("path") or "/").split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    try:
        parts = urllib.parse.urlsplit(origin)
    except ValueError:
        return None
    return login_url(urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", "")))


def saved_login_ids(values: Mapping[str, Any]) -> list[str]:
    """The saved-login profile ids an ``http.request`` binds, in order (syntax only)."""
    return [str(item[BINDING_KEY]) for item in values.get("request_bindings") or ()
            if isinstance(item, Mapping) and BINDING_KEY in item]


def is_saved_login_request(values: Mapping[str, Any]) -> bool:
    return bool(saved_login_ids(values))


def validate_login_request_shape(values: Mapping[str, Any]) -> str:
    """The one profile a login request binds; ``ValueError`` when the shape is not a login.

    A login request is a POST that binds fields of one saved login into its body, plus at most
    values this Hunt captured from the login page (``source_action_id``): no other credential,
    withheld value or discovered secret rides along with it."""
    ids = saved_login_ids(values)
    if not ids:
        raise ValueError("not a saved-login request")
    if len(set(ids)) != 1:
        raise ValueError("a login request binds one saved login")
    if str(values.get("method") or "") != "POST":
        raise ValueError("a saved login is sent only as the login's POST")
    if values.get("session_ref") or str(values.get("as_principal") or "anonymous").lower() not in {
            "anonymous", "anon", "none", ""}:
        raise ValueError("a login request carries no other identity (session_ref or as_principal)")
    for item in values.get("request_bindings") or ():
        if BINDING_KEY in item:
            if item.get("credential_field") not in LOGIN_FIELDS or "body_pointer" not in item:
                raise ValueError("a saved login binds its username or secret into the request body")
        elif "source_action_id" not in item:
            raise ValueError(
                "a login request carries only its saved login and values this Hunt captured "
                "(a CSRF token); no other credential, withheld value or secret")
    try:
        return str(uuid.UUID(ids[0]))
    except ValueError:
        raise ValueError("saved_login must be a credential profile id") from None


def _capabilities(value: Any) -> list[str]:
    value = _json(value, [])
    return [str(item) for item in value] if isinstance(value, (list, tuple)) else []


_ATTACHED_SQL = """
    SELECT p.id, p.current_version, p.auth_kind, p.principal_label, p.principal_slot, p.name,
           p.target_id AS home_target_id, b.allowed_capabilities
    FROM credential_profiles p
    JOIN credential_profile_bindings b
      ON b.profile_id=p.id AND b.binding_kind='target'
     AND b.binding_id=$2::text AND b.is_active=true AND b.revoked_at IS NULL
    WHERE p.is_active=true AND (p.expires_at IS NULL OR p.expires_at > NOW())
      AND p.auth_kind = ANY($3::text[])"""


def _usable(row: Mapping[str, Any]) -> bool:
    return "http.request" in _capabilities(row.get("allowed_capabilities"))


async def attached_profile(conn: Any, consuming_target_id: Any, profile_id: Any) -> dict[str, Any] | None:
    """The saved-login profile attached to the consuming target (usable by ``http.request``)."""
    row = await conn.fetchrow(_ATTACHED_SQL + " AND p.id=$1",
                              uuid.UUID(str(profile_id)), str(consuming_target_id or ""),
                              sorted(SAVED_LOGIN_KINDS))
    return dict(row) if row is not None and _usable(row) else None


def subject_of(run: Mapping[str, Any], profile: Mapping[str, Any]) -> dict[str, Any]:
    """The ``login.use`` subject: server-resolved ids only."""
    return {
        "profile_id": str(profile["id"]), "profile_version": int(profile["current_version"]),
        "auth_kind": str(profile["auth_kind"]),
        "consuming_target_id": str(hunt_consuming_target_id(run)),
    }


def display_of(profile: Mapping[str, Any]) -> dict[str, Any]:
    return {"principal_label": str(profile.get("principal_label") or "")[:120],
            "profile_name": str(profile.get("name") or "")[:120]}


async def live_login_grants(conn: Any, hunt_id: Any, profile_id: Any = None) -> list[dict[str, Any]]:
    """This Hunt's unrevoked ``login.use`` grants, oldest first (optionally for one profile)."""
    rows = await conn.fetch(
        """SELECT id, preauthorization_id, subject_json, effect_json, created_at, created_by
           FROM hunt_permission_grants
           WHERE hunt_run_id=$1 AND kind=$2 AND revoked_at IS NULL
             AND ($3::text IS NULL OR subject_json->>'profile_id'=$3)
           ORDER BY created_at, id""",
        uuid.UUID(str(hunt_id)), KIND_LOGIN_USE, str(profile_id) if profile_id else None,
    )
    result = []
    for row in rows:
        subject, effect = _json(row["subject_json"], {}), _json(row["effect_json"], {})
        try:
            version = int(subject.get("profile_version"))
            allowed = max(0, min(int(effect.get("max_logins") or 0), MAX_LOGINS))
        except (TypeError, ValueError):
            continue  # a malformed grant covers nothing
        if not effect.get("login_url"):
            continue
        result.append({
            "grant_id": str(row["id"]), "profile_id": str(subject.get("profile_id")),
            "profile_version": version, "login_url": str(effect["login_url"]),
            "max_logins": allowed,
            "source": (f"preauthorized:{row['preauthorization_id']}" if row["preauthorization_id"]
                       else f"live_grant:{row['id']}"),
            "granted_by": str(row["created_by"] or ""),
            "granted_at": row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else None,
        })
    return result


async def logins_used(conn: Any, hunt_id: Any, profile_id: Any) -> int:
    return int(await conn.fetchval(
        """SELECT count(*) FROM hunt_credential_uses
           WHERE hunt_run_id=$1 AND profile_id=$2 AND slot=$3""",
        uuid.UUID(str(hunt_id)), uuid.UUID(str(profile_id)), LOGIN_SLOT) or 0)


async def admit_saved_login(
    conn: Any, *, run: Mapping[str, Any], values: Mapping[str, Any], default_origin: Any,
) -> list[CredentialUse]:
    """At admission (Hunt row locked): the login this request may make, or a coded refusal.

    No grant for the profile raises ``saved_login_not_attached`` (a ``login.use`` request); every
    allowed login used raises ``saved_login_logins_exhausted`` (a request for more). The login is
    recorded with the action, so it is counted under the same lock that checks the count."""
    if not is_saved_login_request(values):
        return []
    try:
        profile_id = validate_login_request_shape(values)
    except ValueError as exc:
        raise HuntRefusal("saved_login_invalid", f"{exc}; nothing was sent.") from None
    consuming = hunt_consuming_target_id(run)
    profile = await attached_profile(conn, consuming, profile_id)
    if profile is None:
        raise HuntRefusal("saved_login_unavailable", (
            f"{profile_id} is not a saved login of this Hunt's target: an active form or JSON login "
            "profile attached to the target that allows http.request. Nothing was sent."))
    subject = subject_of(run, profile)
    grants = [item for item in await live_login_grants(conn, run["id"], profile_id)
              if item["profile_version"] == subject["profile_version"]]
    if not grants:
        refusal = HuntRefusal("saved_login_not_attached", (
            f"The saved login {profile_id} ({display_of(profile)['principal_label'] or 'no label'}) "
            "is not attached to this Hunt. A person attaches it for this login flow only (a login.use "
            "permission request is raised); nothing was sent."), subject=subject)
        refusal.display = display_of(profile)  # type: ignore[attr-defined]
        raise refusal
    wanted = request_login_url(values, default_origin)
    url = grants[0]["login_url"]
    if wanted != url:
        raise HuntRefusal("saved_login_destination", (
            f"This saved login signs in only at {url} (POST); the request goes to "
            f"{wanted or 'an origin that cannot be named'}. Nothing was sent."))
    used = await logins_used(conn, run["id"], profile_id)
    remaining = used
    for grant in grants:
        if remaining < grant["max_logins"]:
            return [CredentialUse(profile_id, subject["profile_version"], grant["source"], LOGIN_SLOT)]
        remaining -= grant["max_logins"]
    refusal = HuntRefusal("saved_login_logins_exhausted", (
        f"Every login a person allowed with saved login {profile_id} in this Hunt was used ({used}). "
        "Reuse the captured session; a person can allow more logins (a login.use permission request "
        "is raised)."), subject=subject)
    refusal.display = {**display_of(profile), "logins_used": used}  # type: ignore[attr-defined]
    raise refusal


async def resolve_login_url(conn: Any, run: Mapping[str, Any], profile_id: Any) -> str:
    """The profile's login URL, read under the Hunt's own credential authority (the same
    approval and scope checks the worker makes before decryption). Only the URL leaves."""
    try:
        from runtime.credential_resolver import (
            CredentialResolutionError, WorkerCredentialResolver, validate_worker_credential_authority,
        )
    except ModuleNotFoundError:
        from ..runtime.credential_resolver import (
            CredentialResolutionError, WorkerCredentialResolver, validate_worker_credential_authority,
        )
    from .target_binding import web_hunt_target
    context, policy = _json(run.get("context_pack"), {}), _json(run.get("policy_json"), {})
    try:
        target, target_url = web_hunt_target(run, context, policy)
        authority = await validate_worker_credential_authority(
            conn, owner_kind="hunt", owner_id=str(run["id"]), target=target,
            approval_receipt_id=policy.get("approval_receipt_id"),
            scope_receipt_id=target.scope_receipt_id, action_name="hunt.capability:http.request")
        async with WorkerCredentialResolver().resolve(
                conn, profile_id=profile_id, target=target, capability="http.request",
                authority=authority) as resolved:
            url = profile_login_url(resolved.interactive_http().endpoint_url, target_url, target.canonical_host)
    except (CredentialResolutionError, ValueError) as exc:
        raise ValueError(f"the saved login cannot be read under this Hunt's authorization ({exc})") from None
    if url is None:
        raise ValueError("the saved login's login URL is not an HTTP(S) URL on this Hunt's target host")
    return url


async def apply_login_use(conn: Any, run: Mapping[str, Any], request: Mapping[str, Any],
                          choice: Mapping[str, Any], *, refused: Any) -> dict[str, Any]:
    """The grant's effect: this profile version's login flow, ``max_logins`` times."""
    subject = _json(request["subject_json"], {})
    logins = choice.get("logins", DEFAULT_LOGINS)
    if isinstance(logins, bool) or not isinstance(logins, int) or not 1 <= logins <= MAX_LOGINS:
        raise refused(422, "saved_login_logins_invalid", f"logins must be 1 to {MAX_LOGINS}.")
    if str(subject.get("consuming_target_id")) != str(hunt_consuming_target_id(run)):
        raise refused(409, "permission_subject_changed", "The request names another target than this Hunt's.")
    profile = await attached_profile(conn, subject.get("consuming_target_id"), subject.get("profile_id"))
    if profile is None or int(profile["current_version"]) != int(subject.get("profile_version") or 0):
        raise refused(409, "saved_login_unavailable", (
            "The saved login is no longer attached to the target at this version (deactivated, "
            "expired, rotated or its binding revoked); nothing was granted."))
    try:
        url = await resolve_login_url(conn, run, subject["profile_id"])
    except ValueError as exc:
        raise refused(409, "saved_login_unavailable", f"{exc}; nothing was granted.") from None
    return {"profile_id": str(subject["profile_id"]), "profile_version": int(subject["profile_version"]),
            "login_url": url, "max_logins": logins}


def render_login_use(subject: Mapping[str, Any], display: Mapping[str, Any], label: Any) -> tuple[str, str, str]:
    """Title, explanation and effect a person reads; ids and labels only, never a value."""
    who = label(display.get("principal_label")) or label(display.get("profile_name")) or "a saved login"
    title = f"Let this Hunt sign in as {who} (saved login {subject.get('profile_id')})"
    if "logins_used" in display:  # raised because every allowed login was used
        explanation = (
            f"The Hunt used every login a person allowed with this saved login "
            f"({display.get('logins_used', '?')}) and asks to sign in again.")
    else:
        explanation = (
            f"The agent asks to sign in with the saved {subject.get('auth_kind')} login "
            f"{subject.get('profile_id')} (version {subject.get('profile_version')}), attached to this "
            "Hunt's target. The agent never sees its username or secret: the worker fills them in.")
    effect = (
        f"Allows up to {DEFAULT_LOGINS} logins (or the number you choose, 1-{MAX_LOGINS}) with this "
        "saved login, as POST requests to its own login URL only, in this Hunt only, even without "
        "state-changing permission. The session it gets is reused under the usual same-origin rules. "
        "It allows no other state-changing request and never widens the Hunt's scope.")
    return title, explanation, effect


async def start_attach_subjects(
    conn: Any, run: Mapping[str, Any], requested: Sequence[Mapping[str, Any]],
) -> list[tuple[dict[str, Any], dict[str, Any], int]]:
    """``(subject, display, logins)`` for each saved login a person attached at start; refuses
    (``ValueError``) a profile that is not a saved login of the target."""
    found = []
    for item in requested:
        profile = await attached_profile(conn, hunt_consuming_target_id(run), item["profile_id"])
        if profile is None:
            raise ValueError(
                f"saved login {item['profile_id']} is not an active form or JSON login profile "
                "attached to this target that allows http.request")
        found.append((subject_of(run, profile), display_of(profile), int(item["max_logins"])))
    return found


async def hunt_view(conn: Any, run: Mapping[str, Any]) -> dict[str, Any]:
    """What the planner, the client and the UI see: attached logins (reference, label, kind,
    login URL, logins left) and the target's other saved logins (reference and label only)."""
    hunt_id, consuming = run["id"], hunt_consuming_target_id(run)
    attached: list[dict[str, Any]] = []
    attached_ids: set[str] = set()
    by_profile: dict[str, list[dict[str, Any]]] = {}
    for grant in await live_login_grants(conn, hunt_id):
        by_profile.setdefault(grant["profile_id"], []).append(grant)
    for profile_id, grants in by_profile.items():
        profile = await attached_profile(conn, consuming, profile_id) if consuming else None
        current = [g for g in grants if profile is not None and g["profile_version"] == int(profile["current_version"])]
        allowed = sum(g["max_logins"] for g in current)
        used = await logins_used(conn, hunt_id, profile_id)
        attached_ids.add(profile_id)
        attached.append({
            "saved_login": profile_id, "profile_version": grants[-1]["profile_version"],
            "principal_label": (profile or {}).get("principal_label"),
            "auth_kind": (profile or {}).get("auth_kind"),
            "login_url": grants[-1]["login_url"],
            "logins_allowed": allowed, "logins_used": used, "logins_left": max(0, allowed - used),
            "usable": bool(current),
            "attached_by": grants[0]["granted_by"], "grant_ids": [g["grant_id"] for g in grants],
            "secret_values_visible": False,
        })
    available: list[dict[str, Any]] = []
    if consuming:
        rows = await conn.fetch(
            """SELECT p.id, p.current_version, p.auth_kind, p.principal_label, p.name,
                      b.allowed_capabilities
               FROM credential_profiles p
               JOIN credential_profile_bindings b
                 ON b.profile_id=p.id AND b.binding_kind='target'
                AND b.binding_id=$1::text AND b.is_active=true AND b.revoked_at IS NULL
               WHERE p.is_active=true AND (p.expires_at IS NULL OR p.expires_at > NOW())
                 AND p.auth_kind = ANY($2::text[])
               ORDER BY lower(p.name), p.id LIMIT 20""",
            str(consuming), sorted(SAVED_LOGIN_KINDS))
        for row in rows:
            if str(row["id"]) in attached_ids or not _usable(row):
                continue
            available.append({
                "saved_login": str(row["id"]), "profile_version": int(row["current_version"]),
                "principal_label": row["principal_label"], "auth_kind": row["auth_kind"],
                "attached": False, "secret_values_visible": False,
            })
    return {"attached": attached, "available": available[:10],
            "how_to_use": HOW_TO_USE if attached or available else None}


async def safe_hunt_view(conn: Any, run: Mapping[str, Any]) -> dict[str, Any]:
    """``hunt_view`` in its own savepoint; a view that cannot be read says so, never raises."""
    try:
        async with conn.transaction():
            return await hunt_view(conn, run)
    except Exception as exc:  # noqa: BLE001 - reported in the view, never raised into a read
        return {"attached": [], "available": [], "how_to_use": None,
                "available_state": {"available": False, "reason": type(exc).__name__}}


__all__ = [
    "BINDING_KEY", "DEFAULT_LOGINS", "HOW_TO_USE", "LOGIN_SLOT", "MAX_LOGINS", "MAX_SAVED_LOGINS",
    "SAVED_LOGIN_KINDS", "admit_saved_login", "apply_login_use", "attached_profile",
    "hunt_view", "is_saved_login_request", "live_login_grants", "login_url", "logins_used", "profile_login_url",
    "render_login_use", "request_login_url", "resolve_login_url", "safe_hunt_view", "saved_login_ids",
    "start_attach_subjects", "validate_login_request_shape",
]
