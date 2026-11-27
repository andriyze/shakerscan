"""A bounded vendor-default and common-password check on a login a Hunt found.

A Hunt that finds a sign-in form may try a small built-in list of well-known default and common
credential pairs against it, by reference, through ``http.request``: a request binding
``{"default_credential": "dc-NN", "credential_field": "username"|"secret", "body_pointer": ...}``
fills the pair's field into the login POST. Everything else about the request is the Hunt's own
(the login's field names, a CSRF token it captured), and every attempt is an ordinary
``http.request`` action: admitted against the Hunt's scope, policy and budget, sent by the worker,
archived as evidence and recorded here. A candidate cites the accepted attempt's action id.

It is never bulk guessing. The server enforces, whatever the planner asks:

* **Small and fixed.** Only the pairs in ``PAIRS`` (vendor defaults and the most common pairs);
  a Hunt cannot add its own list through this path.
* **Bounded per login.** At most ``MAX_ATTEMPTS_PER_LOGIN`` attempts on one login (method,
  origin and path) in a Hunt and ``MAX_LOGINS_PER_HUNT`` logins; across all Hunts at most
  ``WINDOW_MAX`` attempts on one login per ``WINDOW``. A pair is sent to a login once, unless it
  was accepted (signing in again with it is then allowed).
* **Paced.** Attempts on one login are at least ``PACE_SECONDS`` apart.
* **Stops at the first sign of a lockout or rate limit.** An answer of 429 or 423, a
  ``Retry-After`` header, or lockout or rate-limit wording ends the check on that login for this
  Hunt and, for ``WINDOW``, for every Hunt.
* **Own host only, never a shared login.** The login must be on the Hunt's own host, and the
  logins that never receive a discovered secret (``secret_try_denied_logins.txt`` and
  ``SHAKERSCAN_SECRET_TRY_DENY``) never receive a default credential either.
* **Active testing only, and switchable.** The Hunt needs active testing. The operator switches
  the check off for the whole instance with ``SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS=false``; it is
  on by default.

The pairs are public knowledge, so the values are not secrets; the briefing lists the user names
and products, not the passwords, so that every attempt goes through these bounds.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import json
import os
import re
from typing import Any
import uuid

from .permission_reasons import HuntRefusal

SETTING = "SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS"
BINDING_KEY = "default_credential"
PAIR_ID_PATTERN = r"^dc-[0-9]{2}$"
_PAIR_ID_RE = re.compile(PAIR_ID_PATTERN)
LOGIN_FIELDS = frozenset({"username", "secret"})
# HTTP Basic: the pair as one ``Authorization: Basic`` header on a GET of a route that asks for it.
BASIC_FIELD = "basic"
MAX_ATTEMPTS_PER_LOGIN = 20
# A work budget, not the safety bound: each login keeps its own attempt cap, pacing and lockout
# stop. Four was fewer than the distinct sign-ins of one measured target (owner, 2026-11-26).
MAX_LOGINS_PER_HUNT = 12
PACE_SECONDS = 2.0
WINDOW = timedelta(hours=1)
WINDOW_MAX = 20
SCHEMA = "hunt-default-credentials/v1"

# (reference, user name, password, where the pair comes from). Vendor defaults first, then the
# most common weak pairs. Never more than MAX_ATTEMPTS_PER_LOGIN entries.
PAIRS: tuple[tuple[str, str, str, str], ...] = (
    ("dc-01", "admin", "admin", "generic and many appliance defaults"),
    ("dc-02", "admin", "password", "generic default"),
    ("dc-03", "admin", "admin123", "common weak password"),
    ("dc-04", "admin", "123456", "common weak password"),
    ("dc-05", "admin", "changeme", "vendor default (several products)"),
    ("dc-06", "administrator", "administrator", "vendor default"),
    ("dc-07", "administrator", "password", "vendor default"),
    ("dc-08", "root", "root", "vendor default"),
    ("dc-09", "root", "toor", "vendor default"),
    ("dc-10", "user", "user", "common weak pair"),
    ("dc-11", "user", "password", "common weak pair"),
    ("dc-12", "test", "test", "common test account"),
    ("dc-13", "guest", "guest", "vendor default (guest accounts)"),
    ("dc-14", "demo", "demo", "common demo account"),
    ("dc-15", "tomcat", "tomcat", "Apache Tomcat manager default"),
    ("dc-16", "manager", "manager", "vendor default"),
    ("dc-17", "operator", "operator", "vendor default"),
    ("dc-18", "support", "support", "vendor default"),
    ("dc-19", "admin", "1234", "common weak password"),
    ("dc-20", "admin", "Password1", "common weak password"),
)
_BY_ID = {pair_id: (username, password, source) for pair_id, username, password, source in PAIRS}

VERDICTS = ("pending", "accepted", "rejected", "rate_limited", "locked", "unclear", "not_sent")
STOP_VERDICTS = frozenset({"rate_limited", "locked"})

HUNT_DEFAULT_CREDENTIALS_SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS hunt_default_credential_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    action_id UUID NOT NULL REFERENCES hunt_actions(id) ON DELETE CASCADE,
    login_key TEXT NOT NULL CHECK (login_key ~ '^[0-9a-f]{{64}}$'),
    login_host TEXT NOT NULL CHECK (length(login_host) BETWEEN 1 AND 260),
    pair_id TEXT NOT NULL CHECK (pair_id ~ '{PAIR_ID_PATTERN}'),
    verdict TEXT NOT NULL DEFAULT 'pending' CHECK (verdict IN ({", ".join(f"'{v}'" for v in VERDICTS)})),
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    settled_at TIMESTAMPTZ,
    request_shape JSONB NOT NULL DEFAULT '{{}}'::jsonb,
    CONSTRAINT hunt_default_credential_attempts_action_unique UNIQUE (action_id, pair_id)
);
CREATE INDEX IF NOT EXISTS idx_hunt_default_credential_attempts_login
    ON hunt_default_credential_attempts(login_key, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_default_credential_attempts_run
    ON hunt_default_credential_attempts(hunt_run_id, login_key);
"""

# Wording a login uses when it stops accepting attempts. Matched case-insensitively on the bounded
# answer only; any match stops the check on that login (erring towards stopping).
_LOCKOUT_RE = re.compile(
    r"account (?:has been |is |was )?(?:temporarily )?(?:locked|disabled|suspended|blocked)"
    r"|locked out|lockout|too many (?:[a-z-]+ ){0,2}(?:attempts|tries|requests)"
    r"|temporarily (?:locked|blocked|disabled)|try again (?:later|in \d+)",
    re.IGNORECASE,
)
_RATE_RE = re.compile(r"rate[ -]?limit|throttl|slow down|captcha", re.IGNORECASE)
_FAILURE_RE = re.compile(
    r"invalid (?:user ?name|username|password|credentials|login|email)|incorrect|wrong password"
    r"|login failed|authentication failed|sign[- ]in failed|bad credentials|unauthori[sz]ed"
    r"|not (?:recogni[sz]ed|found|correct|valid)|does not (?:match|exist)|do not match|doesn'?t exist",
    re.IGNORECASE,
)
_TOKEN_NAMES = frozenset({"token", "access_token", "id_token", "jwt", "auth_token", "session",
                          "session_id", "sessionid", "accesstoken", "authtoken"})
_SUCCESS_FLAGS = frozenset({"authenticated", "is_authenticated", "logged_in", "success", "ok"})
# An outcome field carrying a failure word: ``{"status": "fail"}`` (the JSend convention), ``"error"``.
_OUTCOME_FIELDS = frozenset({"status", "result", "outcome", "state"})
_OUTCOME_FAILURES = frozenset({"fail", "failed", "failure", "error", "denied", "unauthorized", "invalid"})
_LOGIN_PATH_RE = re.compile(r"(?:^|/)(?:log[-_]?in|sign[-_]?in|auth|session)s?(?:[/?#.]|$)", re.IGNORECASE)
# Query names of a redirect back to the sign-in's own path that mean "sign in (again)".
_SAME_PATH_RETRY_RE = re.compile(
    r"(?:^|&)(?:next|return\w*|redirect\w*|continue|back|goto|dest\w*|from|ref\w*|url|r|msg|message|"
    r"notice|alert|status|log[-_]?in|sign[-_]?in|auth\w*|logout|loggedout|expired|timeout|reason|code|e)=",
    re.IGNORECASE)
MAX_BODY_INSPECTED = 64 * 1024


def enabled() -> bool:
    """The operator's switch: on unless set to an off value."""
    value = str(os.environ.get("SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS", "true")).strip().lower()
    return value not in {"0", "false", "no", "off", "disabled"}


def pair(pair_id: Any) -> tuple[str, str, str] | None:
    return _BY_ID.get(str(pair_id or ""))


def value_of(pair_id: Any, field: Any) -> str:
    """A pair's user name or password, worker-side. ``ValueError`` for an unknown reference."""
    found = pair(pair_id)
    if found is None:
        raise ValueError("default_credential_unknown: not one of the built-in default credentials")
    if field == BASIC_FIELD:
        import base64
        return "Basic " + base64.b64encode(f"{found[0]}:{found[1]}".encode()).decode("ascii")
    if field == "username":
        return found[0]
    if field == "secret":
        return found[1]
    raise ValueError("a default credential binds its username or secret only")


def pair_ids(values: Mapping[str, Any]) -> list[str]:
    return [str(item[BINDING_KEY]) for item in values.get("request_bindings") or ()
            if isinstance(item, Mapping) and BINDING_KEY in item]


def is_default_credential_request(values: Mapping[str, Any]) -> bool:
    return bool(pair_ids(values))


def is_basic_request(values: Mapping[str, Any]) -> bool:
    """Whether a default-credential request sends its pair as HTTP Basic."""
    return any(isinstance(item, Mapping) and BINDING_KEY in item and item.get("credential_field") == BASIC_FIELD
               for item in values.get("request_bindings") or ())


def _validate_basic_shape(values: Mapping[str, Any]) -> None:
    bindings = [item for item in values.get("request_bindings") or () if isinstance(item, Mapping)]
    if len(bindings) != 1 or str(bindings[0].get("header") or "").lower() != "authorization" \
            or "body_pointer" in bindings[0]:
        raise ValueError("an HTTP Basic default-credential attempt binds one pair into the Authorization "
                         "header and nothing else")
    if str(values.get("method") or "") != "GET":
        raise ValueError("an HTTP Basic default credential is sent only in a GET of the route that asked for it")
    if any(values.get(key) for key in ("json_body", "form_body", "body", "headers")):
        raise ValueError("an HTTP Basic default-credential attempt carries no body and no other header")


def validate_request_shape(values: Mapping[str, Any]) -> str:
    """The one pair a default-credential request binds; ``ValueError`` when the shape is not a
    login POST that binds one pair's fields into its body, or a GET that sends one pair as HTTP
    Basic."""
    ids = pair_ids(values)
    if not ids:
        raise ValueError("not a default-credential request")
    if len(set(ids)) != 1:
        raise ValueError("a login attempt binds one default credential pair")
    if not _PAIR_ID_RE.fullmatch(ids[0]) or pair(ids[0]) is None:
        raise ValueError("default_credential must be one of the built-in references dc-01..dc-%02d" % len(PAIRS))
    basic = is_basic_request(values)
    if not basic and str(values.get("method") or "") != "POST":
        raise ValueError("a default credential is sent only in a login POST")
    if values.get("session_ref") or str(values.get("as_principal") or "anonymous").lower() not in {
            "anonymous", "anon", "none", ""}:
        raise ValueError("a default-credential attempt carries no other identity (session_ref or as_principal)")
    if basic:
        _validate_basic_shape(values)
        return ids[0]
    fields: set[str] = set()
    for item in values.get("request_bindings") or ():
        if BINDING_KEY in item:
            if item.get("credential_field") not in LOGIN_FIELDS or "body_pointer" not in item:
                raise ValueError("a default credential binds its username or secret into the request body")
            fields.add(str(item["credential_field"]))
        elif "source_action_id" not in item:
            raise ValueError("a default-credential attempt carries only its pair and values this Hunt "
                             "captured (a CSRF token); no other credential, withheld value or secret")
    if "secret" not in fields:
        raise ValueError("a default-credential attempt binds the pair's secret")
    return ids[0]


@dataclass(frozen=True)
class AttemptClaim:
    pair_id: str
    login_key: str
    login_host: str
    request_shape: Mapping[str, Any] | None = None


MAX_SHAPE_BYTES = 8_192


def request_shape(values: Mapping[str, Any], login_url: str) -> dict[str, Any]:
    """What a deterministic proof needs to send this login again: its URL, body kind, the body's
    literal fields and the two pointers the pair fills. Replayable only when nothing else was bound
    (a value captured from a page, such as a CSRF token, does not survive to a later request)."""
    bindings = [item for item in values.get("request_bindings") or () if isinstance(item, Mapping)]
    if is_basic_request(values):
        return {"login_url": login_url, "body_kind": BASIC_FIELD, "body": {}, "user_pointer": None,
                "secret_pointer": None, "replayable": True}
    pointers = {str(item.get("credential_field")): str(item.get("body_pointer") or "")
                for item in bindings if BINDING_KEY in item}
    body_kind = "json" if isinstance(values.get("json_body"), Mapping) else "form"
    body = values.get("json_body") if body_kind == "json" else values.get("form_body")
    shape = {
        "login_url": login_url, "body_kind": body_kind,
        "body": body if isinstance(body, Mapping) else {},
        "user_pointer": pointers.get("username") or None,
        "secret_pointer": pointers.get("secret") or None,
        "replayable": all(BINDING_KEY in item for item in bindings) and bool(pointers.get("secret")),
    }
    if values.get("form_prefetch") is True and body_kind == "form":
        # The page's hidden fields (a CSRF token) are read again on each replay (form_prefetch).
        shape["form_prefetch"] = True
        if isinstance(values.get("form_page"), str) and values["form_page"].startswith("/"):
            shape["form_page"] = values["form_page"][:2048]
    if len(json.dumps(shape, default=str)) > MAX_SHAPE_BYTES:
        shape = {**shape, "body": {}, "replayable": False}
    return shape


def _login_target(values: Mapping[str, Any], default_origin: Any) -> tuple[str, str] | None:
    from .saved_logins import request_login_url
    import urllib.parse
    url = request_login_url(values, default_origin)
    if url is None:
        return None
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    return url, host


def login_key(url: str) -> str:
    return hashlib.sha256(f"POST {url}".encode()).hexdigest()


def _refuse(code: str, message: str, **kwargs: Any) -> HuntRefusal:
    return HuntRefusal(code, message, **kwargs)


async def admit_default_credentials(
    conn: Any, *, run: Mapping[str, Any], values: Mapping[str, Any], policy: Mapping[str, Any],
    context: Mapping[str, Any],
) -> AttemptClaim | None:
    """At admission (Hunt row locked): the attempt this request may make, or a coded refusal.
    ``context`` is the Hunt's context pack: its target URL is the default origin and own host."""
    if not is_default_credential_request(values):
        return None
    import urllib.parse
    target_context = context.get("target") if isinstance(context.get("target"), Mapping) else {}
    default_origin = target_context.get("url") or target_context.get("locator")
    target_host = (urllib.parse.urlsplit(str(default_origin)).hostname
                   if "://" in str(default_origin or "") else None)
    if not enabled():
        raise _refuse("default_credentials_disabled", (
            "The operator switched the default-credential check off on this instance "
            f"({SETTING}=false). Nothing was sent; do not guess passwords another way."))
    if policy.get("active_testing") is not True:
        raise _refuse("default_credentials_invalid", (
            "A default-credential attempt needs this Hunt's active_testing permission. Nothing was sent."))
    try:
        pair_id = validate_request_shape(values)
    except ValueError as exc:
        raise _refuse("default_credentials_invalid", f"{exc}. Nothing was sent.") from None
    target = _login_target(values, default_origin)
    own_host = str(target_host or "").lower().rstrip(".").strip("[]")
    if target is None or not own_host or target[1].strip("[]") != own_host:
        raise _refuse("default_credentials_destination", (
            "Default credentials are tried only on a login on this Hunt's own host, named by origin "
            "and path. Nothing was sent."))
    url, host = target
    from .secret_try import _pinned_addresses, denied_destination_resolved
    import urllib.parse
    path = urllib.parse.urlsplit(url).path or "/"
    if await denied_destination_resolved(host, path, _pinned_addresses(run, {"host": host})):
        raise _refuse("default_credentials_destination", (
            "This login is a shared login other people rely on; it never receives default "
            "credentials. Nothing was sent."))
    key = login_key(url)
    hunt_id = uuid.UUID(str(run["id"]))
    # One login at a time across Hunts: the window and the stop are read and claimed together.
    await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 7243))", key)
    rows = await conn.fetch(
        """SELECT pair_id, verdict, attempted_at,
                  EXTRACT(EPOCH FROM (NOW() - attempted_at)) AS age
           FROM hunt_default_credential_attempts
           WHERE hunt_run_id=$1 AND login_key=$2 ORDER BY attempted_at DESC""",
        hunt_id, key,
    )
    stopped = [row for row in rows if row["verdict"] in STOP_VERDICTS]
    if stopped or await conn.fetchval(
            """SELECT 1 FROM hunt_default_credential_attempts
               WHERE login_key=$1 AND verdict = ANY($2::text[]) AND attempted_at > NOW() - $3::interval
               LIMIT 1""", key, sorted(STOP_VERDICTS), WINDOW):
        raise _refuse("default_credentials_stopped", (
            "This login answered a default-credential attempt with a lockout or rate-limit sign, so "
            "the check stopped on it. Record what was observed; do not try other passwords on it."))
    if len(rows) >= MAX_ATTEMPTS_PER_LOGIN:
        raise _refuse("default_credentials_exhausted", (
            f"The {MAX_ATTEMPTS_PER_LOGIN} default-credential attempts this Hunt may make on this login "
            "were made. Record the results; no further guessing is allowed."))
    tried = {str(row["pair_id"]): str(row["verdict"]) for row in rows}
    if pair_id in tried and tried[pair_id] != "accepted":
        raise _refuse("default_credentials_invalid", (
            f"{pair_id} was already tried on this login ({tried[pair_id]}); each pair is tried once. "
            "Nothing was sent."))
    if rows and rows[0]["age"] is not None and float(rows[0]["age"]) < PACE_SECONDS:
        wait = max(1, int(PACE_SECONDS - float(rows[0]["age"]) + 0.999))
        raise _refuse("default_credentials_paced", (
            f"Default-credential attempts on one login are at least {PACE_SECONDS:g} seconds apart; "
            f"send this one again in {wait} s. Nothing was sent."), headers={"Retry-After": str(wait)})
    if not rows:
        logins = int(await conn.fetchval(
            "SELECT count(DISTINCT login_key) FROM hunt_default_credential_attempts WHERE hunt_run_id=$1",
            hunt_id) or 0)
        if logins >= MAX_LOGINS_PER_HUNT:
            raise _refuse("default_credentials_exhausted", (
                f"Default credentials were tried on {MAX_LOGINS_PER_HUNT} logins in this Hunt, the most "
                "allowed. Nothing was sent."))
    window = int(await conn.fetchval(
        """SELECT count(*) FROM hunt_default_credential_attempts
           WHERE login_key=$1 AND attempted_at > NOW() - $2::interval""", key, WINDOW) or 0)
    if window >= WINDOW_MAX:
        raise _refuse("default_credentials_paced", (
            f"This login received {WINDOW_MAX} default-credential attempts in the last hour across "
            "Hunts, the most ShakerScan sends. Continue other work. Nothing was sent."),
            headers={"Retry-After": str(int(WINDOW.total_seconds()))})
    return AttemptClaim(pair_id=pair_id, login_key=key, login_host=host[:260],
                        request_shape=request_shape(values, url))


async def record_attempt(conn: Any, *, hunt_id: Any, action_id: Any, claim: AttemptClaim | None) -> None:
    """Record the admitted attempt with its action, under the admission transaction."""
    if claim is None:
        return
    await conn.execute(
        """INSERT INTO hunt_default_credential_attempts
               (hunt_run_id, action_id, login_key, login_host, pair_id, request_shape)
           VALUES ($1,$2,$3,$4,$5,$6::jsonb)
           ON CONFLICT ON CONSTRAINT hunt_default_credential_attempts_action_unique DO NOTHING""",
        uuid.UUID(str(hunt_id)), uuid.UUID(str(action_id)), claim.login_key, claim.login_host, claim.pair_id,
        json.dumps(dict(claim.request_shape or {}), default=str),
    )


async def require_admitted(conn: Any, *, hunt_id: Any, action_id: Any, pair_id: str) -> None:
    """Worker-side: the pair goes out only on the action admission recorded for it (admission
    applied the operator's switch and every bound)."""
    found = await conn.fetchval(
        """SELECT 1 FROM hunt_default_credential_attempts
           WHERE hunt_run_id=$1 AND action_id=$2 AND pair_id=$3 AND verdict='pending'""",
        uuid.UUID(str(hunt_id)), uuid.UUID(str(action_id)), pair_id,
    )
    if not found:
        raise ValueError("default_credential_not_admitted: this action was not admitted for that pair")


def _walk(value: Any, depth: int = 0) -> Sequence[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if depth > 6:
        return found
    if isinstance(value, Mapping):
        for key, child in list(value.items())[:200]:
            name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key)).lower().replace("-", "_")
            found.append((name, child))
            found.extend(_walk(child, depth + 1))
    elif isinstance(value, list):
        for child in value[:50]:
            found.extend(_walk(child, depth + 1))
    return found


def classify_response(*, status: Any, headers: Mapping[str, Any], cookie_names: Sequence[str],
                      body: bytes, location: Any, login_path: str, basic: bool = False) -> str:
    """The login's answer to one attempt: accepted, rejected, rate_limited, locked or unclear.

    A lockout or rate-limit sign wins over everything else (the check stops on it). ``accepted``
    needs a positive sign (a token in a JSON answer, a success flag, or a session cookie with a
    redirect away from the login) and no failure sign. The answer is target-controlled: it only
    ever decides this verdict and is never echoed into the verdict.
    """
    if not isinstance(status, int) or isinstance(status, bool):
        return "unclear"
    names = {str(key).lower() for key in headers}
    text = bytes(body[:MAX_BODY_INSPECTED]).decode("utf-8", "replace")
    if status == 423 or _LOCKOUT_RE.search(text):
        return "locked"
    if status == 429 or "retry-after" in names or (status in {403, 503} and _RATE_RE.search(text)):
        return "rate_limited"
    if basic:
        # HTTP Basic on a route that answered 401 without it: the challenge again (or a refusal) is
        # a rejection, the route's own answer an acceptance. The proof's control (a random password)
        # settles a route that stopped asking.
        if status in {401, 403, 407}:
            return "rejected"
        return "accepted" if 200 <= status < 400 else "unclear"
    document: Any = None
    if text.lstrip()[:1] in {"{", "["}:
        try:
            document = json.loads(text)
        except ValueError:
            document = None
    if status in {400, 401, 403, 404, 405, 409, 422} or status >= 500:
        return "rejected" if status in {400, 401, 403, 422} else "unclear"
    fields = _walk(document) if document is not None else []
    explicit_failure = bool(_FAILURE_RE.search(text)) or any(
        (name in _SUCCESS_FLAGS and child is False)
        or (name in {"error", "errors", "error_description"} and child not in (None, "", [], {}, False))
        or (name in _OUTCOME_FIELDS and isinstance(child, str) and child.strip().lower() in _OUTCOME_FAILURES)
        for name, child in fields)
    if document is not None:
        try:
            from capabilities.authentication_proof import authentication_failed_or_incomplete
        except ModuleNotFoundError:  # package import layout
            from ..capabilities.authentication_proof import authentication_failed_or_incomplete
        explicit_failure = explicit_failure or authentication_failed_or_incomplete(document, response_identity=True)
    if explicit_failure:
        return "rejected"
    token = any(name in _TOKEN_NAMES and isinstance(child, str) and len(child.strip()) >= 8
                for name, child in fields)
    flagged = any(name in _SUCCESS_FLAGS and child is True for name, child in fields)
    if 200 <= status < 300 and (token or flagged):
        return "accepted"
    target = str(location or "")
    if 300 <= status < 400 and cookie_names and target:
        import urllib.parse
        parts = urllib.parse.urlsplit(target)
        path = parts.path or "/"
        if re.search(r"error|fail|denied|invalid", target, re.IGNORECASE) or _LOGIN_PATH_RE.search(path):
            return "rejected"
        # A relative Location (``index.php?route=/``) names a sibling of the login's own path.
        same = (path.rstrip("/") == login_path.rstrip("/")
                or (not path.startswith("/") and path == login_path.rsplit("/", 1)[-1]))
        if not same:
            return "accepted"
        # A front controller signs in on its own path and redirects to itself with the page to
        # show (``/index.php?route=/``); a redirect back to the bare path, or one that carries
        # where to return to or a message, is the sign-in shown again. The proof's control (the
        # same user name, a random password) settles a login that redirects alike for any password.
        if parts.query and not _SAME_PATH_RETRY_RE.search(parts.query):
            return "accepted"
        return "rejected"
    if 200 <= status < 300 and re.search(r"type=[\"']?password", text, re.IGNORECASE):
        return "rejected"  # the sign-in form was shown again
    return "unclear"


async def settle_attempt(pool: Any, *, hunt_id: Any, action_id: Any, verdict: str) -> None:
    if verdict not in VERDICTS:
        verdict = "unclear"
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE hunt_default_credential_attempts SET verdict=$3, settled_at=NOW()
               WHERE hunt_run_id=$1 AND action_id=$2 AND verdict='pending'""",
            uuid.UUID(str(hunt_id)), uuid.UUID(str(action_id)), verdict,
        )


def public_verdict(pair_id: str, verdict: str) -> dict[str, Any]:
    username = (pair(pair_id) or ("", "", ""))[0]
    meaning = {
        "accepted": "The login accepted this pair: a default or weak credential. Record a candidate "
                    "citing this action; capture the session to see what the account reaches.",
        "rejected": "The login refused this pair.",
        "rate_limited": "The login signalled a rate limit: the check stopped on this login.",
        "locked": "The login signalled a lockout: the check stopped on this login.",
        "unclear": "The answer neither accepts nor refuses clearly; compare with a refused attempt.",
        "not_sent": "No answer was received.",
    }.get(verdict, "")
    return {"schema_version": SCHEMA, "pair": pair_id, "username": username, "verdict": verdict,
            "meaning": meaning, "stopped": verdict in STOP_VERDICTS}


async def briefing_section(conn: Any, run: Mapping[str, Any]) -> dict[str, Any]:
    """The live ``default_credentials`` section: on or off, references, limits and use so far."""
    policy = dict(run).get("policy_json")
    if isinstance(policy, (str, bytes, bytearray)):
        try:
            policy = json.loads(policy)
        except ValueError:
            policy = {}
    section: dict[str, Any] = {
        "schema_version": SCHEMA,
        "enabled": enabled(),
        "usable_in_this_hunt": enabled() and isinstance(policy, Mapping) and policy.get("active_testing") is True,
        "setting": SETTING,
    }
    if not section["enabled"]:
        section["note"] = ("The operator switched the default-credential check off on this instance. "
                           "Do not guess passwords.")
        return section
    attempts = await conn.fetch(
        """SELECT login_host, verdict, count(*) AS count FROM hunt_default_credential_attempts
           WHERE hunt_run_id=$1 GROUP BY login_host, verdict ORDER BY login_host, verdict""",
        uuid.UUID(str(dict(run)["id"])),
    ) if dict(run).get("id") else []
    section.update({
        "pair_count": len(PAIRS),
        "pairs": [{"ref": pair_id, "username": username, "source": source}
                  for pair_id, username, _password, source in PAIRS],
        "limits": {"attempts_per_login": MAX_ATTEMPTS_PER_LOGIN, "logins_per_hunt": MAX_LOGINS_PER_HUNT,
                   "seconds_between_attempts": PACE_SECONDS,
                   "stops_on": "429, 423, Retry-After, or lockout or rate-limit wording"},
        "used": [{"login_host": str(row["login_host"]), "verdict": str(row["verdict"]),
                  "count": int(row["count"])} for row in attempts][:16],
        "how_to_use": (
            "On a sign-in form you found on this target (active testing): http.request POST to the "
            "login (origin and path exactly; form_body or json_body with the form's own field names "
            "and any CSRF value) with request_bindings [{\"default_credential\": \"dc-01\", "
            "\"credential_field\": \"username\", \"body_pointer\": \"/<user field>\"}, "
            "{\"default_credential\": \"dc-01\", \"credential_field\": \"secret\", \"body_pointer\": "
            "\"/<password field>\"}]; to try a pair's password with a user name you found, bind only "
            "its secret and put the user name in the body. Add capture [{\"name\": \"session\", "
            "\"header\": \"Set-Cookie\"}] to keep an accepted session. The answer's login_attempt.verdict "
            "says accepted, rejected, unclear or stopped. Send one attempt at a time; each "
            "pair is tried once per login. Record an accepted pair as a candidate of family "
            "default_credentials citing its action, then candidate.verify it: the server sends the "
            "pair again and a random-password control on the same login. On a route that answers "
            "401 with a Basic challenge (response challenge_schemes lists basic): http.request GET of "
            "that route with request_bindings [{\"default_credential\": \"dc-15\", "
            "\"credential_field\": \"basic\", \"header\": \"Authorization\"}] and nothing else. "
            "Never guess passwords outside this list."),
    })
    return section


__all__ = [
    "AttemptClaim", "BINDING_KEY", "HUNT_DEFAULT_CREDENTIALS_SCHEMA_SQL", "MAX_ATTEMPTS_PER_LOGIN",
    "PAIRS", "PAIR_ID_PATTERN", "SETTING", "admit_default_credentials", "briefing_section",
    "BASIC_FIELD", "classify_response", "enabled", "is_basic_request", "is_default_credential_request",
    "public_verdict",
    "record_attempt", "require_admitted", "settle_attempt", "validate_request_shape", "value_of",
]
