"""Shared address space (100.64.0.0/10, RFC 6598) is private-network space.

``ipaddress`` calls 100.64.0.0/10 neither private nor reserved, so a production deployment that
refuses private-network targets admitted it as public: a registered target or a connected device
on a carrier-grade NAT or a Tailscale address (Tailscale numbers its nodes from this block, and the
platform supports it as a transport) needed no private-network permission. It is now judged as
private, in every spelling: refused unless a Lab environment or
``SHAKERSCAN_PRIVATE_NETWORK_TARGETS=allow`` admits it, and never a Hunt-authorized destination.
This is a deliberate tightening (docs/functionality-reference.md, safety model).
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import sys

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import action_scope  # noqa: E402
from hunt.dispatch_authority import destination_hard_limit, public_address  # noqa: E402
from scanner_tools import device_posture  # noqa: E402

SHARED = ("100.64.0.1", "100.100.1.10", "100.127.255.254")
SPELLINGS = {
    "plain": lambda v: v,
    "mapped": lambda v: f"::ffff:{v}",
    "siit": lambda v: str(ipaddress.IPv6Address((0xFFFF0000 << 32) | int(ipaddress.IPv4Address(v)))),
    "nat64": lambda v: str(ipaddress.IPv6Address((0x64FF9B << 96) | int(ipaddress.IPv4Address(v)))),
    "6to4": lambda v: str(ipaddress.IPv6Address((0x2002 << 112) | (int(ipaddress.IPv4Address(v)) << 80) | 1)),
}


@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
@pytest.mark.parametrize("address", SHARED)
def test_shared_address_space_needs_the_private_network_setting(spelling, address):
    spelled = SPELLINGS[spelling](address)
    assert action_scope._ip_scope_block_reason(
        spelled, "production", allow_private_networks=False,
    ) == "loopback_or_private_range", spelled


@pytest.mark.parametrize("address", SHARED)
def test_private_network_permission_and_lab_still_admit_it(address):
    assert action_scope._ip_scope_block_reason(address, "production", allow_private_networks=True) is None
    assert action_scope._ip_scope_block_reason(address, "lab", allow_private_networks=False) is None


@pytest.mark.parametrize("address", SHARED)
def test_a_hunt_never_authorizes_it(address):
    assert not public_address(address)
    granted = {"scheme": "https", "host": "dest.example.net", "port": 443, "addresses": [address]}
    assert destination_hard_limit(granted, "production")


def test_the_refusal_names_the_shared_address_space():
    text = action_scope.destination_refusal_explanation("100.64.0.1", "production")
    assert "100.64.0.0/10" in text and "SHAKERSCAN_PRIVATE_NETWORK_TARGETS=allow" in text


def test_the_alibaba_metadata_address_inside_it_stays_always_refused():
    assert action_scope._ip_scope_block_reason("100.100.100.200", "lab", allow_private_networks=True)


@pytest.mark.parametrize("address", SHARED)
def test_device_plane_refuses_it_under_a_refusing_deployment(monkeypatch, address):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")
    reason = device_posture.device_private_destination_refusal(address, "production", "refuse")
    assert reason and "100.64.0.0/10" in reason
    with pytest.raises(ValueError, match="loopback_or_private_range"):
        device_posture.validate_device_destination(address, environment="production", policy="refuse")
    from devices import destination_policy

    with pytest.raises(HTTPException) as caught:
        asyncio.run(destination_policy.admit_device_destination(address, "production", policy="refuse"))
    assert caught.value.status_code == 422


@pytest.mark.parametrize("address", SHARED)
def test_device_plane_admits_it_where_private_networks_are_allowed(monkeypatch, address):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    assert device_posture.device_private_destination_refusal(address, "production", "allow") is None
    assert device_posture.validate_device_destination(address, environment="production", policy="allow") == address
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")
    assert device_posture.validate_device_destination(address, environment="lab", policy="refuse") == address
