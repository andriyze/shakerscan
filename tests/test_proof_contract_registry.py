"""The proof-contract registry must match what the scanner can actually re-execute.

`_has_satisfied_proof_contract` used to accept any non-empty `proof_contract` string.
Evidence is operator-supplied on the manual-finding path, so a made-up contract name
paired with `proof_state: verified` promoted a finding to "exploited" without any
deterministic re-execution -- straight through the boundary that promotion exists to
defend.

A hard-coded allowlist is only as good as its agreement with the emitters, so this
also asserts the registry is exactly the set the capability modules emit.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from proof_contracts import CANONICAL_PROOF_CONTRACTS, is_canonical_proof_contract  # noqa: E402
from scan_verification_state import _has_satisfied_proof_contract  # noqa: E402

CONTRACT_LITERAL = re.compile(r'"([a-z_]+/v\d+)"')
# Emitters live in the capability modules; these are the families that produce proof.
EMITTERS = (
    "capabilities/authz_surface.py",
    "capabilities/nosqli_verify.py",
    "capabilities/request_mutation.py",
    "capabilities/sqli_proof.py",
)


def _verified_evidence(contract: str) -> dict:
    return {
        "proof_contract": contract,
        "proof_state": "verified",
        "triage": {"verified": True},
    }


def test_a_real_contract_is_accepted():
    for contract in sorted(CANONICAL_PROOF_CONTRACTS):
        assert _has_satisfied_proof_contract(_verified_evidence(contract)), contract


def test_an_invented_contract_is_rejected():
    for contract in (
        "made-up/nonexistent",
        "sqli_error_differential/v99",
        "totally_real_proof/v1",
        "",
        "   ",
    ):
        assert not _has_satisfied_proof_contract(_verified_evidence(contract)), contract


def test_the_other_two_markers_are_still_required():
    real = sorted(CANONICAL_PROOF_CONTRACTS)[0]
    assert not _has_satisfied_proof_contract({"proof_contract": real})
    assert not _has_satisfied_proof_contract(
        {"proof_contract": real, "proof_state": "verified"}
    )
    assert not _has_satisfied_proof_contract(
        {"proof_contract": real, "proof_state": "suspected", "triage": {"verified": True}}
    )


def test_the_registry_matches_what_the_capabilities_emit():
    emitted = set()
    for relative in EMITTERS:
        path = ROOT / "api" / relative
        assert path.exists(), relative
        source = path.read_text(encoding="utf-8")
        for line in source.splitlines():
            if "proof_contract" not in line and "_differential/v" not in line and "_access/v" not in line and "_bypass/v" not in line:
                continue
            emitted.update(CONTRACT_LITERAL.findall(line))
    unregistered = emitted - CANONICAL_PROOF_CONTRACTS
    assert not unregistered, (
        "capabilities emit proof contracts the registry does not list, so a real proof "
        f"would be rejected: {sorted(unregistered)}"
    )
    stale = CANONICAL_PROOF_CONTRACTS - emitted
    assert not stale, (
        "the registry lists contracts nothing emits any more; remove them rather than "
        f"leaving an accepted name with no producer: {sorted(stale)}"
    )


def test_is_canonical_rejects_non_strings():
    for value in (None, 1, [], {}, True):
        assert not is_canonical_proof_contract(value)
