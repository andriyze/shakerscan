"""Deterministic broken-function-level-authorization (BFLA) contract.

Function-level authorization is a rule the black box does not publish, so this
contract promotes only the sub-case it can prove without the app's intended
policy: an *established auth boundary* plus *identical anonymous access to an
authenticated data function*.

The boundary is proven when at least one probed route denies the anonymous
principal (401/403) while the authenticated principal succeeds — evidence the
app does gate function access. A finding is a route where the anonymous
principal receives a 2xx JSON body byte-identical to the authenticated
principal's, i.e. the authenticated data function serves the same content with
no auth check. A fully public app has no boundary and yields nothing; a static
page or an empty/short body is never promoted; the comparison is repeated.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Iterable, Mapping

try:
    from capabilities.secret_material import SELF_EVIDENT_SECRET_PATTERNS, normalized_key_name
except ModuleNotFoundError:  # package import layout
    from .secret_material import SELF_EVIDENT_SECRET_PATTERNS, normalized_key_name


AUTHZ_SURFACE_PARSER_VERSION = "authz-surface/v1"

_DENIED_STATUSES = frozenset({401, 403})
_MIN_BODY_BYTES = 32


@dataclass(frozen=True)
class PrincipalProbe:
    """One probed access result for one principal against one route."""

    status: int | None
    body_sha256: str
    body_len: int
    is_json: bool
    error: bool = False
    # Installation-keyed digests of the account password hashes the JSON body carried
    # (account_password_hashes), never the values, and the fields they were found under.
    hash_digests: tuple[str, ...] = ()
    hash_fields: tuple[str, ...] = ()


# --- Account password hashes in an API response ----------------------------------------------
# An API that returns stored password hashes hands every caller an offline cracking target
# (OWASP API3, excessive data exposure). Two shapes prove it without knowing the app: a hash
# whose format is self-evident (bcrypt, argon2) under any key, or a hash-shaped value (crypt,
# hex digest, LDAP scheme, pbkdf2/scrypt) under a key that names the account's password.
_SELF_EVIDENT_HASH = dict(SELF_EVIDENT_SECRET_PATTERNS)["password_hash"]
_PASSWORD_HASH_KEYS = frozenset({
    "password", "passwd", "pwd", "pass", "password_hash", "passwordhash", "hashed_password",
    "password_digest", "encrypted_password", "pass_hash", "pwd_hash", "user_password",
    "password_hashed", "hash_password",
})
_HASH_VALUE_RE = re.compile(
    r"^(?:\$[0-9a-z]{1,8}\$\S{8,}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128}"
    r"|\{[A-Z0-9-]{2,16}\}\S{8,}|pbkdf2[_:$]\S{8,}|scrypt[:$]\S{8,})$",
    re.IGNORECASE,
)
_MAX_HASH_BODY_BYTES = 1_000_000
_MAX_HASH_NODES = 5_000
_MAX_HASHES = 50


def account_password_hashes(body: bytes, *, is_json: bool) -> list[tuple[str, str]]:
    """``(field, hash)`` of every stored password hash a JSON response body carries."""
    if not is_json or not body or len(body) > _MAX_HASH_BODY_BYTES:
        return []
    try:
        document = json.loads(bytes(body).decode("utf-8", "replace"))
    except ValueError:
        return []
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    budget = [_MAX_HASH_NODES]

    def keep(field: str, value: str) -> None:
        if value not in seen and len(found) < _MAX_HASHES:
            seen.add(value)
            found.append((field[:120] or "value", value))

    def walk(value: Any, field: str, key: str, depth: int) -> None:
        budget[0] -= 1
        if budget[0] < 0 or depth > 8:
            return
        if isinstance(value, Mapping):
            for name, item in list(value.items())[:500]:
                walk(item, f"{field}.{name}" if field else str(name), normalized_key_name(str(name)), depth + 1)
        elif isinstance(value, list):
            for index, item in enumerate(value[:2_000]):
                walk(item, f"{field}[{index}]", key, depth + 1)
        elif isinstance(value, str) and 13 <= len(value) <= 512:
            text = value.strip()
            match = _SELF_EVIDENT_HASH.search(text)
            if match is not None and match.group(1) == text:
                keep(field, text)
            elif (
                key in _PASSWORD_HASH_KEYS and _HASH_VALUE_RE.match(text)
                # A run of one character is a placeholder, not a digest.
                and len(set(text.lower())) >= 8
            ):
                keep(field, text)

    walk(document, "", "", 0)
    return found


@dataclass(frozen=True)
class RouteComparison:
    """Anonymous vs authenticated access for one route, repeated."""

    route_id: str
    url: str
    anonymous: tuple[PrincipalProbe, ...]
    authenticated: tuple[PrincipalProbe, ...]


def _stable(probes: tuple[PrincipalProbe, ...]) -> PrincipalProbe | None:
    if len(probes) < 2 or any(item.error for item in probes):
        return None
    first = probes[0]
    for other in probes[1:]:
        if (other.status, other.body_sha256) != (first.status, first.body_sha256):
            return None
    return first


def _is_success(probe: PrincipalProbe | None) -> bool:
    return probe is not None and probe.status is not None and 200 <= probe.status < 300


def boundary_established(comparisons: Iterable[RouteComparison]) -> bool:
    """True when the app denies anonymous access somewhere it authenticates."""
    for comparison in comparisons:
        anon = _stable(comparison.anonymous)
        authed = _stable(comparison.authenticated)
        if (
            anon is not None and anon.status in _DENIED_STATUSES
            and _is_success(authed)
        ):
            return True
    return False


def bfla_finding(comparison: RouteComparison) -> Mapping[str, object] | None:
    """Return a verified BFLA observation for one route, or ``None``.

    Caller must first confirm :func:`boundary_established` over the batch.
    """
    anon = _stable(comparison.anonymous)
    authed = _stable(comparison.authenticated)
    if not (_is_success(anon) and _is_success(authed)):
        return None
    if anon.body_sha256 != authed.body_sha256:
        return None
    if not anon.is_json or anon.body_len < _MIN_BODY_BYTES:
        return None
    return {
        "kind": "authz_surface_proof",
        "proof_state": "verified",
        "finding_verdict": "verified",
        "proof_contract": "authz_surface_anonymous_access/v1",
        "technique": "anonymous_equals_authenticated_repeated",
        "route_id": comparison.route_id,
        "request_url": comparison.url,
        "anonymous_status": anon.status,
        "authenticated_status": authed.status,
        "response_body_sha256": anon.body_sha256,
        "response_body_len": anon.body_len,
        "boundary_established": True,
        "repetitions": len(comparison.anonymous),
        "secret_values_visible": False,
    }


def password_hash_disclosure_finding(
    comparison: RouteComparison, principal_hash_digests: Iterable[str],
) -> Mapping[str, object] | None:
    """A verified observation that ``comparison``'s route returns account password hashes.

    The authenticated principal received the same password-hash fields on both reads.
    ``principal_hash_digests`` are every hash the same principal received across the batch:
    one person has one password, so two distinct hashes prove the principal reads at least one
    other account's hash. A hash the anonymous principal also receives is exposed to anyone.
    """
    authed = _stable(comparison.authenticated)
    if not _is_success(authed) or not authed.is_json:
        return None
    digests = set(comparison.authenticated[0].hash_digests)
    if not digests or any(set(probe.hash_digests) != digests for probe in comparison.authenticated):
        return None
    anon = _stable(comparison.anonymous)
    anonymous_reads = bool(
        _is_success(anon)
        and all(set(probe.hash_digests) & digests for probe in comparison.anonymous)
    )
    other_accounts = len(set(principal_hash_digests) | digests) >= 2
    return {
        "kind": "authz_surface_proof",
        "proof_state": "verified",
        "finding_verdict": "verified",
        "proof_contract": "authz_surface_password_hash_disclosure/v1",
        "technique": "authenticated_response_password_hash_fields_repeated",
        "route_id": comparison.route_id,
        "request_url": comparison.url,
        "anonymous_status": anon.status if anon is not None else None,
        "authenticated_status": authed.status,
        "response_body_sha256": authed.body_sha256,
        "response_body_len": authed.body_len,
        "hash_count": len(digests),
        "hash_fields": [{"field": name} for name in comparison.authenticated[0].hash_fields[:10]],
        "other_accounts_hashes": other_accounts,
        "anonymous_reads_hashes": anonymous_reads,
        "repetitions": len(comparison.authenticated),
        "secret_values_visible": False,
    }


PASSWORD_HASH_DISCLOSURE_CONTRACT = "authz_surface_password_hash_disclosure/v1"  # the proof_contract above


__all__ = [
    "AUTHZ_SURFACE_PARSER_VERSION",
    "PASSWORD_HASH_DISCLOSURE_CONTRACT",
    "account_password_hashes",
    "password_hash_disclosure_finding",
    "PrincipalProbe",
    "RouteComparison",
    "boundary_established",
    "bfla_finding",
]
