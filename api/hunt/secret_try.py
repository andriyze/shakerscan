"""Trying a secret discovered on another target on this Hunt's login, only after a person allows it.

A secret ShakerScan found on target S (``secret://<id>``) is usable by reference in Hunts of S. A
Hunt of another target T may send it only under an operator's grant of that secret to T
(``discovered_secret_grants``), or after a person allowed this exact try:

* **Never automatic.** The planner can only ask: an ``http.request`` that binds the reference to a
  login of T is refused at admission with ``secret_other_target``, which raises a ``secret.try``
  permission request (``shakerscan approve <id>``). No start bound covers it, it cannot be
  remembered for the target, and nothing is sent before the person's decision is recorded.
* **Scoped.** The grant names one secret, one login (scheme, host and port of T, path and method)
  and this Hunt. It never widens the Hunt's scope: the request still passes every admission check
  (target binding, standing authorization, approval receipt, budget) and the worker's own.
* **Rate limited, lockout-safe.** A grant allows ``max_attempts`` attempts (3 unless the person
  chooses 1..10); across all Hunts, a secret is tried at most ``WINDOW_MAX`` times per
  ``WINDOW`` on one host. Attempts are claimed under the grant's row lock in the transaction that
  records them, so concurrent actions cannot overrun either limit.
* **Audited.** Every attempt is a ``discovered_secret_uses`` row with the grant, action,
  destination host and the login's answer (``http_<status>``), shown on the Hunt record; the
  request, decision and use are ``hunt_permission_events``.
* **Hard limits.** Some logins never receive any discovered secret, whoever asks
  (``secret_try_denied_logins.txt`` plus ``SHAKERSCAN_SECRET_TRY_DENY``): shared demonstration logins whose
  accounts other people rely on.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import timedelta
import json
import os
import asyncio
import ipaddress
import posixpath
import re
import socket
import time
from typing import Any
import urllib.parse
import uuid

from .permission_reasons import KIND_SECRET_TRY, HuntRefusal

# discovered_secrets.SECRET_REF_PATTERN (kept here so the store and this module do not import each other).
_SECRET_REF_RE = re.compile(
    r"^secret://[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DEFAULT_ATTEMPTS = 3
MAX_ATTEMPTS = 10
WINDOW = timedelta(minutes=15)
WINDOW_MAX = 3
# The http.request path limit: a longer path cannot carry a discovered secret (never truncated).
MAX_PATH_CHARS = 4000
SECRET_TRY_DESTINATION_DENIED = "secret_try_destination_denied"
SECRET_TRY_RATE_LIMITED = "secret_try_rate_limited"
SECRET_TRY_EXHAUSTED = "secret_try_attempts_exhausted"
SECRET_TRY_UNRELATED = "secret_try_unrelated_target"
# Shipped logins that never receive a discovered secret (host/path prefix per line); the shared
# demonstration hub login of the project's public test site is one.
DENIED_LOGINS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret_try_denied_logins.txt")


def _shipped_rules() -> tuple[str, ...]:
    try:
        with open(DENIED_LOGINS_FILE, encoding="utf-8") as handle:
            return tuple(line.strip() for line in handle if line.strip() and not line.lstrip().startswith("#"))
    except OSError:
        return ()


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return default if value is None else value


def _canonical_host(value: Any) -> str:
    try:
        from action_scope import _canonical_host as canonical
    except ModuleNotFoundError:
        from ..action_scope import _canonical_host as canonical
    return canonical(value)


def _denied_rules() -> tuple[tuple[str, str], ...]:
    """The shipped rules plus ``SHAKERSCAN_SECRET_TRY_DENY`` (``host/path,host/path``)."""
    extra = []
    configured = str(os.environ.get("SHAKERSCAN_SECRET_TRY_DENY") or "").split(",")
    for item in (*_shipped_rules(), *configured):
        text = item.strip()
        if not text:
            continue
        host, _, path = text.partition("/")
        host = _canonical_host(host)
        if host:
            extra.append((host, _normal_path("/" + path)))
    return tuple(extra)


def _normal_path(path: Any) -> str:
    """A path as a server would route it, for the deny rules only: percent-decoded (twice, for a
    double-encoded spelling), ``;params`` dropped from every segment, dot segments and repeated
    slashes resolved, lowercase."""
    text = str(path or "/")
    for _ in range(2):
        text = urllib.parse.unquote(text)
    text = text.split("?", 1)[0].split("#", 1)[0].replace("\\", "/")
    text = "/".join(segment.split(";", 1)[0] for segment in text.split("/"))
    normal = posixpath.normpath("/" + text.lstrip("/"))
    return ("/" if normal in {"", "."} else normal.replace("//", "/")).lower()


def _rule_matches(prefix: str, normal: str) -> bool:
    return prefix in {"", "/"} or normal == prefix or normal.startswith(prefix.rstrip("/") + "/")


def denied_destination(host: Any, path: Any, addresses: Any = ()) -> bool:
    """Whether a login never receives a discovered secret (a hard limit, never a request): its
    host is a denied one, or (``addresses``: where the request is pinned) it reaches an address a
    denied host resolves to, under the denied path. Synchronous checks use only resolved
    addresses already known (``denied_addresses``); the worker resolves them before sending."""
    canonical = _canonical_host(host)
    normal = _normal_path(path)
    pinned = {_address(item) for item in addresses or ()} - {""}
    for denied_host, prefix in _denied_rules():
        if not _rule_matches(prefix, normal):
            continue
        if canonical == denied_host or (pinned and pinned & _RESOLVED.get(denied_host, (0.0, frozenset()))[1]):
            return True
    return False


def _address(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip().strip("[]")))
    except ValueError:
        return ""


# Denied host -> (resolved at, its addresses). Resolved off the event loop, bounded in time, and
# reused for RESOLVE_TTL; an unresolvable host keeps only the name rule.
_RESOLVED: dict[str, tuple[float, frozenset[str]]] = {}
RESOLVE_TTL = 600.0
RESOLVE_TIMEOUT = 2.0


def _resolve_host(host: str) -> frozenset[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return frozenset()
    return frozenset(_address(info[4][0]) for info in infos) - {""}


# Replaceable in tests (a labelled double): no DNS leaves a test.
resolve_denied_host: Callable[[str], frozenset[str]] = _resolve_host


async def denied_addresses() -> None:
    """Refresh the addresses of the denied hosts (cached; failures leave the name rule)."""
    now = time.monotonic()
    for denied_host, _prefix in _denied_rules():
        cached = _RESOLVED.get(denied_host)
        if cached is not None and now - cached[0] < RESOLVE_TTL:
            continue
        try:
            found = await asyncio.wait_for(asyncio.to_thread(resolve_denied_host, denied_host), RESOLVE_TIMEOUT)
        except (asyncio.TimeoutError, OSError):
            found = frozenset()
        _RESOLVED[denied_host] = (now, frozenset(found))


async def denied_destination_resolved(host: Any, path: Any, addresses: Any = ()) -> bool:
    """``denied_destination`` after the denied hosts' addresses were refreshed."""
    if addresses:
        await denied_addresses()
    return denied_destination(host, path, addresses)


def destination_of(values: Mapping[str, Any]) -> dict[str, Any] | None:
    """Where an ``http.request`` sends its bindings: canonical origin, host, path and method.
    None when it cannot be named exactly (no ``origin`` of its own, or a path over
    ``MAX_PATH_CHARS``): such a request never carries a discovered secret. The request's own
    ``origin`` is the only source, never a default of the target binding, so the grant, the deny
    check and the worker all key on where the request is actually sent."""
    text = str(values.get("origin") or "").strip()
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port
    except ValueError:
        return None
    host = _canonical_host(parsed.hostname) if parsed.hostname else ""
    if parsed.scheme not in {"http", "https"} or not host:
        return None
    port = port or (443 if parsed.scheme == "https" else 80)
    netloc = f"[{host}]" if ":" in host else host
    path = str(values.get("path") or "/")
    if len(path) > MAX_PATH_CHARS:
        return None
    return {
        "origin": f"{parsed.scheme}://{netloc}:{port}", "host": host,
        "path": path if path.startswith("/") else "/" + path,
        "method": str(values.get("method") or "GET").upper(),
    }


async def _live_grants(conn: Any, hunt_run_id: Any, secret_id: Any, destination: Mapping[str, Any],
                       *, lock: bool = False) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        """SELECT id, effect_json FROM hunt_permission_grants
           WHERE hunt_run_id=$1 AND kind=$2 AND revoked_at IS NULL
             AND subject_json->>'secret_id'=$3 AND subject_json->>'origin'=$4
             AND subject_json->>'path'=$5 AND subject_json->>'method'=$6
           ORDER BY created_at, id""" + (" FOR UPDATE" if lock else ""),
        uuid.UUID(str(hunt_run_id)), KIND_SECRET_TRY, str(secret_id), str(destination["origin"]),
        str(destination["path"]), str(destination["method"]),
    )
    return [dict(row) for row in rows]


def _allowed(grant: Mapping[str, Any]) -> int:
    effect = _json(grant.get("effect_json"), {})
    try:
        return max(0, min(int(effect.get("max_attempts") or 0), MAX_ATTEMPTS))
    except (TypeError, ValueError):
        return 0


async def _used(conn: Any, grant_id: Any) -> int:
    return int(await conn.fetchval(
        "SELECT count(*) FROM discovered_secret_uses WHERE permission_grant_id=$1", grant_id) or 0)


async def window_attempts(conn: Any, secret_id: Any, host: str) -> int:
    """Tries of this secret on this host in the last ``WINDOW``, across every Hunt."""
    return int(await conn.fetchval(
        """SELECT count(*) FROM discovered_secret_uses
           WHERE secret_id=$1 AND destination_host=$2 AND permission_grant_id IS NOT NULL
             AND used_at > NOW() - $3::interval""",
        uuid.UUID(str(secret_id)), str(host)[:255], WINDOW) or 0)


async def lock_window(conn: Any, secret_id: Any, host: str) -> None:
    """Until the caller's transaction ends: one secret on one host is counted and claimed one
    claim at a time, whichever Hunt or grant claims it."""
    await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", f"secret-try:{secret_id}:{host}")


async def remaining_grant(conn: Any, grants: list[dict[str, Any]]) -> Any:
    for grant in grants:
        if await _used(conn, grant["id"]) < _allowed(grant):
            return grant["id"]
    return None


class SecretTryError(ValueError):
    """A refused try; ``reason`` is one of the SECRET_TRY_* codes (or ``secret_target_mismatch``),
    safe to show. The store re-raises it as its own refusal."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _error(code: str, message: str) -> Exception:
    return SecretTryError(code, message)


async def has_live_grant(conn: Any, *, hunt_run_id: Any, secret_id: Any, destination: Mapping[str, Any] | None) -> bool:
    if destination is None:
        return False
    return bool(await _live_grants(conn, hunt_run_id, secret_id, destination))


async def claim_attempt(
    conn: Any, *, hunt_run_id: Any, secret_id: Any, destination: Mapping[str, Any],
    record: Callable[[Any], Any],
) -> Any:
    """In the worker, inside one transaction: lock the Hunt's grants for this secret and login,
    refuse past the rate limit or the allowed attempts, and record the attempt (``record(grant)``)
    before the lock is released. Returns what ``record`` returned."""
    async with conn.transaction():
        await lock_window(conn, secret_id, destination["host"])
        grants = await _live_grants(conn, hunt_run_id, secret_id, destination, lock=True)
        if not grants:
            raise _error("secret_target_mismatch", (
                "secret reference belongs to another target; a person must allow trying it on "
                "this login (a secret.try permission request) or grant it to this target"))
        if await window_attempts(conn, secret_id, destination["host"]) >= WINDOW_MAX:
            raise _error(SECRET_TRY_RATE_LIMITED, (
                f"this secret was tried {WINDOW_MAX} times on this host in the last "
                f"{int(WINDOW.total_seconds() // 60)} minutes; try again later"))
        grant_id = await remaining_grant(conn, grants)
        if grant_id is None:
            raise _error(SECRET_TRY_EXHAUSTED, "every attempt a person allowed on this login was used")
        return await record(grant_id)


def _pinned_addresses(run: Mapping[str, Any], destination: Mapping[str, Any]) -> list[str]:
    """The addresses an admitted request to ``destination`` is pinned to: the Hunt's authorized
    target addresses, and a destination a person authorized for this Hunt."""
    context, policy = _json(run.get("context_pack"), {}), _json(run.get("policy_json"), {})
    found = [str(item) for item in (context or {}).get("authorized_target_addresses") or ()]
    for granted in (policy or {}).get("granted_destinations") or ():
        if isinstance(granted, Mapping) and _canonical_host(granted.get("host")) == destination["host"]:
            found += [str(item) for item in granted.get("addresses") or ()]
    return found


async def admit_secret_references(conn: Any, *, run: Mapping[str, Any], values: Mapping[str, Any]) -> None:
    """At admission: refuse (and so ask a person about) every ``secret_ref`` binding the worker
    would refuse for want of a ``secret.try`` grant, before anything is reserved. A request that
    cannot name its destination exactly, or goes to a denied login, never carries a secret."""
    bindings = [item for item in values.get("request_bindings") or () if isinstance(item, Mapping)
                and item.get("secret_ref")]
    if not bindings:
        return
    destination = destination_of(values)
    if destination is None:
        raise HuntRefusal("scope_origin_invalid", (
            "A request carrying a discovered secret must name its own HTTP(S) origin "
            f"(scheme://host:port) and a path of at most {MAX_PATH_CHARS} characters; nothing was sent."))
    # The denied hosts' addresses are cached (RESOLVE_TTL); a refresh is bounded by RESOLVE_TIMEOUT.
    if await denied_destination_resolved(destination["host"], destination["path"], _pinned_addresses(run, destination)):
        raise HuntRefusal(SECRET_TRY_DESTINATION_DENIED, (
            f"{destination['origin']}{destination['path']} never receives a discovered secret: "
            "it is a shared login other people rely on. No permission can allow it."))
    consuming = run.get("target_id")
    for binding in bindings:
        text = str(binding["secret_ref"])
        if not _SECRET_REF_RE.fullmatch(text):
            continue  # the input schema and the worker refuse it with its code
        secret_id = uuid.UUID(text.removeprefix("secret://"))
        row = await conn.fetchrow(
            """SELECT s.target_id, s.kind, s.label, s.length, t.name AS found_on_name, t.url AS found_on_url
               FROM discovered_secrets s LEFT JOIN targets t ON t.id=s.target_id WHERE s.id=$1""",
            secret_id,
        )
        if row is None or consuming is None:
            continue  # the worker refuses it with its code
        if str(row["target_id"]) == str(consuming) or await conn.fetchval(
            "SELECT 1 FROM discovered_secret_grants WHERE secret_id=$1 AND target_id=$2",
            secret_id, uuid.UUID(str(consuming)),
        ):
            continue
        if not await is_related(conn, consuming, row["target_id"]):
            # Only a related target's secret (the ones secrets.inspect lists) is worth asking a
            # person about; any other stays refused without a request.
            raise HuntRefusal(SECRET_TRY_UNRELATED, (
                f"secret://{secret_id} was found on a target unrelated to this Hunt's (another root "
                "domain and host asset). An operator can grant it to this target "
                "(shakerscan secrets grant); a Hunt cannot ask for it."))
        subject = {
            "secret_id": str(secret_id), "found_on_target_id": str(row["target_id"]),
            "consuming_target_id": str(consuming), "origin": destination["origin"],
            "host": destination["host"], "path": destination["path"], "method": destination["method"],
        }
        display = {
            "secret_kind": str(row["kind"] or ""), "secret_label": str(row["label"] or "")[:120],
            "secret_length": int(row["length"] or 0),
            "found_on_name": str(row["found_on_name"] or row["found_on_url"] or "")[:200],
        }
        grants = await _live_grants(conn, run["id"], secret_id, destination)
        if not grants:
            refusal = HuntRefusal("secret_other_target", (
                f"secret://{secret_id} was found on another target. Sending it to "
                f"{destination['method']} {destination['origin']}{destination['path']} needs a "
                "person's permission for this login (a permission request is raised); nothing was sent."
            ), subject=subject)
            refusal.display = display  # type: ignore[attr-defined]
            raise refusal
        if await window_attempts(conn, secret_id, destination["host"]) >= WINDOW_MAX:
            raise HuntRefusal(SECRET_TRY_RATE_LIMITED, (
                f"secret://{secret_id} was tried {WINDOW_MAX} times on {destination['host']} in the "
                f"last {int(WINDOW.total_seconds() // 60)} minutes, the most ShakerScan sends so "
                "an account is not locked out. Continue other work and try again later."))
        if await remaining_grant(conn, grants) is None:
            refusal = HuntRefusal(SECRET_TRY_EXHAUSTED, (
                f"Every attempt a person allowed for secret://{secret_id} on this login was used. "
                "A person can allow more (a permission request is raised)."
            ), subject=subject)
            refusal.display = display  # type: ignore[attr-defined]
            raise refusal


# Targets related to one another: the same root domain, or the same host asset. One predicate for
# the planner's listing and for whether a try may be asked for at all.
_RELATED_SQL = """
    (me.root IS NOT NULL AND lower(t.root_domain) = me.root)
    OR COALESCE(to_jsonb(t)->>'asset_owner_id', t.id::text) = me.asset"""
_ME_SQL = """SELECT id, lower(root_domain) AS root,
                    COALESCE(to_jsonb(t)->>'asset_owner_id', id::text) AS asset
             FROM targets t WHERE id=$1"""


async def is_related(conn: Any, target_id: Any, other_id: Any) -> bool:
    return bool(await conn.fetchval(
        f"""WITH me AS ({_ME_SQL})
            SELECT 1 FROM targets t, me WHERE t.id=$2 AND t.id <> me.id AND ({_RELATED_SQL})""",
        uuid.UUID(str(target_id)), uuid.UUID(str(other_id))))


MAX_RELATED = 50


async def related_secrets(conn: Any, target_id: Any, *, limit: int = MAX_RELATED) -> list[dict[str, Any]]:
    """Metadata of usable secrets found on targets related to this one (the same root domain or
    the same host asset) and not granted to it: what a Hunt here may ask to try on its own login.
    Reference, kind, field name, length, where and when found; never a value."""
    rows = await conn.fetch(
        f"""WITH me AS ({_ME_SQL}),
           related AS (
               SELECT t.id, t.name, t.url FROM targets t, me
               WHERE t.id <> me.id AND t.is_active IS NOT FALSE AND ({_RELATED_SQL})
               LIMIT 200)
           SELECT s.id, s.target_id, s.kind, s.label, s.length, s.last_seen_at, r.name, r.url
           FROM related r JOIN discovered_secrets s ON s.target_id = r.id
           WHERE s.state='active' AND s.expires_at > NOW()
             AND NOT EXISTS (SELECT 1 FROM discovered_secret_grants g
                             WHERE g.secret_id=s.id AND g.target_id=$1)
           ORDER BY s.last_seen_at DESC, s.id LIMIT $2""",
        uuid.UUID(str(target_id)), max(1, min(int(limit), MAX_RELATED)),
    )
    return [{
        "ref": f"secret://{row['id']}", "kind": row["kind"], "label": row["label"],
        "length": row["length"], "found_on": str(row["target_id"]),
        "found_on_name": str(row["name"] or row["url"] or "")[:200],
        "last_seen_at": row["last_seen_at"].isoformat(),
        "use": ("bind it in http.request on this Hunt's login; the first call raises a secret.try "
                "permission request for a person, and it is sent only after they allow it"),
    } for row in rows]


def render_secret_try(subject: Mapping[str, Any], display: Mapping[str, Any], label: Callable[..., str]) -> tuple[str, str, str]:
    """Title, explanation and effect a person reads; names, kinds and ids only, never a value."""
    login = f"{subject.get('method')} {subject.get('origin')}{label(subject.get('path'), 300)}"
    found_on = label(display.get("found_on_name")) or str(subject.get("found_on_target_id"))
    secret = (f"the {label(display.get('secret_kind'), 40) or 'secret'} '{label(display.get('secret_label'))}'"
              f" ({display.get('secret_length') or '?'} characters, secret://{subject.get('secret_id')})")
    title = f"Try a secret found on '{found_on}' on the login {login}"
    explanation = (
        f"The agent asks to send {secret}, which ShakerScan found on target '{found_on}' "
        f"({subject.get('found_on_target_id')}), to the login {login} of this Hunt's target "
        f"({subject.get('consuming_target_id')}). The value is never shown: the worker sends it."
    )
    effect = (
        f"Allows up to {DEFAULT_ATTEMPTS} attempts (or the number you choose, 1-{MAX_ATTEMPTS}) with "
        "this secret on exactly this login, in this Hunt only, and at most "
        f"{WINDOW_MAX} per {int(WINDOW.total_seconds() // 60)} minutes on this host across Hunts. "
        "Every attempt and its answer is recorded. It never widens the Hunt's scope, and it cannot "
        "be remembered or pre-authorized."
    )
    return title, explanation, effect


async def apply_secret_try(conn: Any, run: Mapping[str, Any], request: Mapping[str, Any],
                           choice: Mapping[str, Any], *, refused: Callable[[int, str, str], Exception]) -> dict[str, Any]:
    """The grant's effect: this secret on this login, ``max_attempts`` times."""
    subject = _json(request["subject_json"], {})
    attempts = choice.get("attempts", DEFAULT_ATTEMPTS)
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= MAX_ATTEMPTS:
        raise refused(422, "secret_try_attempts_invalid", f"attempts must be 1 to {MAX_ATTEMPTS}.")
    if denied_destination(subject.get("host"), subject.get("path")):
        raise refused(422, SECRET_TRY_DESTINATION_DENIED, "This login never receives a discovered secret.")
    state = await conn.fetchval(
        "SELECT state FROM discovered_secrets WHERE id=$1 AND expires_at > NOW()",
        uuid.UUID(str(subject["secret_id"])))
    if state != "active":
        raise refused(409, "secret_not_active",
                      "The secret is no longer active (revoked, expired, promoted or purged); nothing was granted.")
    if not await is_related(conn, run.get("target_id"), subject.get("found_on_target_id")):
        raise refused(409, SECRET_TRY_UNRELATED, "The secret's target is not related to this Hunt's target.")
    if str(subject.get("consuming_target_id")) != str(run.get("target_id")):
        raise refused(409, "permission_subject_changed", "The request names another target than this Hunt's.")
    return {key: subject[key] for key in ("secret_id", "origin", "path", "method")} | {"max_attempts": attempts}


__all__ = [
    "DEFAULT_ATTEMPTS", "DENIED_LOGINS_FILE", "MAX_ATTEMPTS", "SECRET_TRY_DESTINATION_DENIED",
    "SECRET_TRY_EXHAUSTED", "SECRET_TRY_RATE_LIMITED", "SecretTryError", "WINDOW", "WINDOW_MAX",
    "MAX_RELATED", "SECRET_TRY_UNRELATED", "admit_secret_references",
    "denied_addresses", "denied_destination_resolved", "is_related", "lock_window", "apply_secret_try", "related_secrets", "claim_attempt", "denied_destination",
    "destination_of", "has_live_grant", "render_secret_try", "window_attempts",
]
