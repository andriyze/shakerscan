"""A resolved address is admitted before it is frozen, not because it was frozen.

Review finding R1. Admission resolves the target's hostname and freezes the answers into
`allowed_addresses`; execution then accepts any address in that frozen set without the
destination-class check, because membership is treated as stronger authority than the generic
predicate. Pinning does stop later drift -- a changed answer is still refused -- but nothing
established that the *first* answer was acceptable. A name resolving to 169.254.169.254, the
cloud metadata address, was frozen and then allowed.

The fix is not to refuse every private hostname: an internal name resolving into the operator's
own network is exactly what a self-hosted scanner is for. It is to classify each answer under
the deployment's destination policy and freeze only what that policy admits.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

import action_scope  # noqa: E402

RESTRICTED = ("169.254.169.254", "224.0.0.1", "0.0.0.0", "255.255.255.255")
OPERATOR_OWN = ("192.168.1.50", "10.0.0.7", "172.16.3.4", "127.0.0.1")


def _admit(addresses, environment="production", allow_private=None):
    """The addresses an admission step may freeze, given what DNS returned."""
    return [
        address for address in addresses
        if action_scope._ip_scope_block_reason(
            address, environment, allow_private_networks=allow_private,
        ) is None
    ]


@pytest.mark.parametrize("address", RESTRICTED)
@pytest.mark.parametrize("environment", ["production", "lab"])
def test_a_restricted_answer_is_never_admitted(address, environment):
    assert _admit([address], environment) == []


@pytest.mark.parametrize("address", OPERATOR_OWN)
def test_the_operators_own_network_is_admitted_by_the_self_hosted_default(address):
    assert _admit([address]) == [address]


@pytest.mark.parametrize("address", OPERATOR_OWN)
def test_a_refusing_deployment_admits_none_of_them(address):
    assert _admit([address], allow_private=False) == []


def test_a_mixed_answer_keeps_only_what_policy_admits():
    """DNS can return several addresses; the restricted ones are dropped, not the whole set."""
    answers = ["93.184.216.34", "169.254.169.254", "192.168.1.50", "224.0.0.1"]
    assert _admit(answers) == ["93.184.216.34", "192.168.1.50"]


def test_an_answer_that_is_entirely_restricted_leaves_nothing_to_freeze():
    """With nothing admissible the caller must refuse, not freeze an empty set and continue."""
    assert _admit(["169.254.169.254", "224.0.0.1"]) == []


def test_the_resolver_applies_the_policy_before_returning():
    """The admission resolver itself, not just a helper a caller might forget to use."""
    source = (ROOT / "api" / "fleet_routes" / "router.py").read_text(encoding="utf-8")
    start = source.index("async def _resolve_runtime_target_addresses(")
    body = source[start:start + 3000]
    assert "_ip_scope_block_reason" in body or "admit_runtime_address" in body, (
        "_resolve_runtime_target_addresses returns DNS answers without classifying them, so a "
        "restricted address is frozen into allowed_addresses and then trusted at execution"
    )
