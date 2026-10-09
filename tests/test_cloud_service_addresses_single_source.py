"""One cloud-service list for every destination check, and the device plane refuses broadcast.

S4 of the #358 review: the EKS Pod Identity agent (169.254.170.23, ``fd00:ec2::23``) and Oracle
Cloud Classic metadata (192.0.0.192) were missing. On the device plane the APIPA allowance
admitted 169.254.170.23, and with private networks allowed ``fd00:ec2::23`` and 192.0.0.192 were
admitted everywhere. The limited broadcast address 255.255.255.255 was a device destination.
``device_posture.DEFAULT_DENIED_DEVICE_DESTINATIONS`` is now derived from
``address_classes.CLOUD_SERVICE_ADDRESSES``.
"""
from __future__ import annotations

import ipaddress
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import action_scope
from scanner_tools import address_classes, device_posture

ADDED = ("169.254.170.23", "fd00:ec2::23", "192.0.0.192")
SPELLINGS = {
    "169.254.170.23": ("169.254.170.23", "::ffff:169.254.170.23", "64:ff9b::a9fe:aa17"),
    "fd00:ec2::23": ("fd00:ec2::23", "fd00:ec2::23%eth0"),
    "192.0.0.192": ("192.0.0.192", "::ffff:192.0.0.192", "64:ff9b::c000:c0", "::ffff:0:c000:c0"),
}
EVERY_SPELLING = [item for values in SPELLINGS.values() for item in values]


def test_the_device_deny_list_is_the_cloud_service_list():
    assert {
        ipaddress.ip_network(raw) for raw in device_posture.DEFAULT_DENIED_DEVICE_DESTINATIONS
    } == {ipaddress.ip_network(address) for address in address_classes.CLOUD_SERVICE_ADDRESSES}
    assert {ipaddress.ip_address(raw) for raw in ADDED} <= address_classes.CLOUD_SERVICE_ADDRESSES


@pytest.mark.parametrize("address", EVERY_SPELLING)
@pytest.mark.parametrize("environment, allow", [("production", True), ("production", False), ("lab", False)])
def test_the_scope_guard_refuses_the_added_cloud_services(address, environment, allow):
    assert action_scope._ip_scope_block_reason(
        address, environment, allow_private_networks=allow,
    ) == "loopback_or_private_range"
    assert not action_scope.public_unicast_address(address)
    explanation = action_scope.destination_refusal_explanation(address, environment)
    assert "cloud metadata or platform-service" in explanation


@pytest.mark.parametrize("address", EVERY_SPELLING)
@pytest.mark.parametrize("environment, policy", [("production", "allow"), ("lab", "allow"), ("lab", "refuse")])
def test_the_device_plane_refuses_the_added_cloud_services(monkeypatch, address, environment, policy):
    monkeypatch.delenv("SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS", raising=False)
    with pytest.raises(ValueError, match="metadata|link-local"):
        device_posture.validate_device_destination(address, environment=environment, policy=policy)


def test_the_apipa_allowance_still_admits_other_link_local_devices(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS", raising=False)
    for address in ("169.254.10.20", "169.254.170.22", "169.254.170.24"):
        assert device_posture.validate_device_destination(
            address, environment="production", policy="refuse",
        ) == address


@pytest.mark.parametrize("address", ["255.255.255.255", "::ffff:255.255.255.255", "64:ff9b::ffff:ffff"])
@pytest.mark.parametrize("environment, policy", [("production", "allow"), ("lab", "allow"), ("production", "refuse")])
def test_the_device_plane_refuses_limited_broadcast(monkeypatch, address, environment, policy):
    monkeypatch.setenv("SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS", "true")
    with pytest.raises(ValueError, match="unicast"):
        device_posture.validate_device_destination(address, environment=environment, policy=policy)


def test_growing_the_list_never_widens_a_refusing_deployment_under_the_metadata_opt_in(monkeypatch):
    """The opt-in keeps admitting what it always admitted; an added private-class cloud-service
    address still needs the private-network setting."""
    monkeypatch.setenv("SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS", "true")
    for address in ("fd00:ec2::23", "192.0.0.192"):
        with pytest.raises(ValueError, match="loopback_or_private_range"):
            device_posture.validate_device_destination(address, environment="production", policy="refuse")
        assert device_posture.validate_device_destination(address, environment="production", policy="allow")
    assert device_posture.validate_device_destination(
        "fd00:ec2::254", environment="production", policy="refuse",
    ) == "fd00:ec2::254"
