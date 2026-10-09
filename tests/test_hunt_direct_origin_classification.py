"""Hunt direct-origin addresses use the web scope guard's classification, at start and at connect.

S3 of the #358 review: ``normalize_hunt_start_payload`` kept a list of forbidden networks of its
own. With private networks refused it accepted 198.18.0.1 (benchmarking), 192.0.0.8 and
192.0.0.192 (IETF protocol assignments; 192.0.0.192 is Oracle Cloud Classic metadata), 192.0.2.1
(documentation) and ``64:ff9b::c612:1`` (198.18.0.1 through NAT64). At connect the HTTP
capability only checked that ``via_address`` was in the confirmed list. Both now apply
``action_scope.direct_origin_refusal``.
"""
from __future__ import annotations

import asyncio

import pytest

from api.capabilities.http import execute_bound_http_request
from api.hunt.start_contract import HuntStartContractError, normalize_hunt_start_payload
from api.runtime.models import TargetBinding

APPROVAL = "11111111-1111-4111-8111-111111111111"
AUTHORIZED = {
    "allow_direct_origin": True, "active_testing": True, "authorization_confirmed": True,
    "approval_receipt_id": APPROVAL,
}
ENV = "SHAKERSCAN_PRIVATE_NETWORK_TARGETS"

# Refused whatever the deployment admits.
ALWAYS_REFUSED = (
    "192.0.0.192", "::ffff:192.0.0.192", "64:ff9b::c000:c0",  # Oracle Cloud Classic metadata
    "169.254.170.23", "fd00:ec2::23",  # EKS Pod Identity
    "0.0.0.1", "240.0.0.1", "255.255.255.255", "::ffff:240.0.0.1",
)
# Refused when the deployment refuses private-network targets, as target admission refuses them.
PRIVATE_CLASS = (
    "198.18.0.1", "192.0.0.8", "192.0.2.1", "203.0.113.9", "64:ff9b::c612:1", "::ffff:0:c612:1",
    "2002:c612:1::", "100.64.0.1", "10.0.0.5", "fd12::7",
    # The NAT64 well-known prefix is reserved space (::/8) to the web scope guard too.
    "64:ff9b::808:808",
)
PUBLIC = ("8.8.8.8", "2606:4700:4700::1111", "93.184.216.34")


def _start(addresses):
    return normalize_hunt_start_payload({
        "target_id": "t1", "target_kind": "web", "goal": "g",
        "direct_origin_addresses": list(addresses), "policy": AUTHORIZED,
    })


@pytest.mark.parametrize("policy", ["refuse", "allow"])
@pytest.mark.parametrize("address", ALWAYS_REFUSED)
def test_cloud_service_and_non_routable_origins_are_refused_under_every_policy(monkeypatch, policy, address):
    monkeypatch.setenv(ENV, policy)
    with pytest.raises(HuntStartContractError, match="private, local, or non-routable"):
        _start([address])


@pytest.mark.parametrize("address", PRIVATE_CLASS)
def test_private_class_origins_follow_the_deployment_policy(monkeypatch, address):
    monkeypatch.setenv(ENV, "refuse")
    with pytest.raises(HuntStartContractError, match="private, local, or non-routable"):
        _start([address])
    monkeypatch.setenv(ENV, "allow")
    assert _start([address]).direct_origin_addresses


@pytest.mark.parametrize("policy", ["refuse", "allow"])
@pytest.mark.parametrize("address", PUBLIC)
def test_public_origins_are_admitted(monkeypatch, policy, address):
    monkeypatch.setenv(ENV, policy)
    assert _start([address]).direct_origin_addresses


def _connect_via(address):
    return asyncio.run(execute_bound_http_request(
        "https://app.example.test", {"method": "GET", "path": "/", "via_address": address},
        target=TargetBinding(
            target_id="t1", target_kind="web", canonical_host="app.example.test",
            allowed_origins=("https://app.example.test",), allowed_addresses=("198.51.100.5",),
        ),
        timeout_seconds=1, direct_origin_addresses=(address,),
    ))


@pytest.mark.parametrize("address", [*PRIVATE_CLASS, *ALWAYS_REFUSED])
def test_a_confirmed_address_is_classified_again_at_connect(monkeypatch, address):
    """A confirmed list persisted under ``allow`` (or before a cloud-service address was listed)
    is not a connect authority under ``refuse``: no socket is opened."""
    monkeypatch.setenv(ENV, "refuse")
    result = _connect_via(address)
    assert result["ok"] is False
    assert result["error"].startswith("scope: via_address is refused as a direct origin")
