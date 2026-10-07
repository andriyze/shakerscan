"""Deterministic preflight of a web candidate verification, before any budget or traffic.

``candidate.verify`` reserves the verifier's complete traffic envelope and settles it in full
whenever the verifier fails, because once the family-proof workflow is dispatched nobody can prove
how much traffic it sent. Some refusals, though, are decided from the stored candidate alone: an
unsupported proof family, a locus without a concrete route, or a mass-assignment claim that names
no POST. Raised inside the verifier they charged the whole reservation and consumed a
verification for zero traffic. They are now decided here, at admission and again inside the
verifier, so both paths refuse with exactly the same answer and the admission refusal is free.
"""
from __future__ import annotations

import json
import urllib.parse
from collections.abc import Mapping
from typing import Any

try:
    import family_proof
except ModuleNotFoundError:  # package import in host-side tests
    from .. import family_proof

# Families the server-owned family-proof bridge can re-execute.
VERIFIABLE_FAMILIES: frozenset[str] = frozenset({
    "bola", "auth_bypass", "data_exposure", "mass_assignment", "access_control",
    "field_constraint", "workflow",
})
# Locus keys a verification route is resolved from, in precedence order.
ROUTE_LOCUS_KEYS: tuple[str, ...] = ("route", "url")


class CandidateVerificationRefused(ValueError):
    """The stored candidate alone shows that the verifier cannot run."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except ValueError:
            return {}
        return dict(decoded) if isinstance(decoded, Mapping) else {}
    return {}


def unsupported_family_detail(family: str) -> str:
    return f"verification bridge supports {sorted(VERIFIABLE_FAMILIES)}, not '{family or 'unknown'}'"


def verification_route(locus: Mapping[str, Any], context: Mapping[str, Any]) -> str | None:
    """The concrete route a verifier re-executes, or None when the candidate names none."""
    sources = [locus.get(key) for key in ROUTE_LOCUS_KEYS] + [context.get("route")]
    raw = next((str(value).strip() for value in sources if value), "")
    if raw.startswith("http://") or raw.startswith("https://"):
        raw = urllib.parse.urlsplit(raw).path or "/"
    return raw if raw and raw != "/" else None


def web_candidate_preflight(candidate: Mapping[str, Any]) -> tuple[str, str, str]:
    """Return ``(family, route, method_hint)`` or raise ``CandidateVerificationRefused``."""
    if str(candidate.get("status") or "") == "verified":
        raise CandidateVerificationRefused(409, "Candidate is already verified")
    locus = _mapping(candidate.get("canonical_locus"))
    context = _mapping(candidate.get("verification_context"))
    family = family_proof.canonical_family(candidate.get("family"))
    if family not in VERIFIABLE_FAMILIES:
        raise CandidateVerificationRefused(422, unsupported_family_detail(family))
    route = verification_route(locus, context)
    if route is None:
        raise CandidateVerificationRefused(422, "verification_route_unresolved")
    method_hint = str(locus.get("method") or context.get("method") or "GET")
    if family == "mass_assignment" and method_hint.upper() != "POST":
        raise CandidateVerificationRefused(
            422,
            "mass_assignment verification requires an explicitly evidenced POST create operation",
        )
    return family, route, method_hint
