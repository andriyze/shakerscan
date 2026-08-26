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
from typing import Iterable, Mapping


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


__all__ = [
    "AUTHZ_SURFACE_PARSER_VERSION",
    "PrincipalProbe",
    "RouteComparison",
    "boundary_established",
    "bfla_finding",
]
