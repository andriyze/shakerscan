"""The canonical set of deterministic proof contracts.

A finding reaches "exploited" only by naming a contract the scanner re-executed and
satisfied. Historically nothing validated that name: `_has_satisfied_proof_contract`
accepted any non-empty string, so an untrusted or legacy evidence record carrying an
invented contract could cross the deterministic-only proof boundary.

The names live here rather than beside each emitter so that the check and the emitters
cannot disagree: `tests/test_proof_contract_registry.py` asserts this set is exactly
what the capability modules emit.
"""

from __future__ import annotations

CANONICAL_PROOF_CONTRACTS: frozenset[str] = frozenset({
    "authz_surface_anonymous_access/v1",
    "nosqli_operator_differential/v1",
    "sqli_authentication_bypass/v1",
    "sqli_boolean_differential/v1",
    "sqli_error_differential/v1",
    "sqli_error_differential/v2",
    "sqli_time_differential/v1",
    "xss_reflection_differential/v1",
})


def is_canonical_proof_contract(name: object) -> bool:
    """True only for a contract this scanner can actually re-execute."""
    return str(name or "").strip() in CANONICAL_PROOF_CONTRACTS


__all__ = ["CANONICAL_PROOF_CONTRACTS", "is_canonical_proof_contract"]
