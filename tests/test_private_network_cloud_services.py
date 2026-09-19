"""Intranet permission never grants access to special cloud-service endpoints."""

import pytest

import action_scope


CLOUD_SERVICES = (
    "169.254.169.254", "169.254.170.2", "100.100.100.200",
    "168.63.129.16", "fd00:ec2::254", "FD00:EC2::254",
    "::ffff:100.100.100.200", "::ffff:168.63.129.16",
)


@pytest.mark.parametrize("environment", ["production", "lab"])
@pytest.mark.parametrize("address", CLOUD_SERVICES)
def test_special_cloud_destination_never_inherits_private_permission(monkeypatch, environment, address):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    assert action_scope._ip_scope_block_reason(address, environment) is not None
    assert action_scope._ip_scope_block_reason(address, environment, allow_private_networks=True) is not None


@pytest.mark.parametrize("address", ["192.168.1.50", "10.0.0.2", "127.0.0.1", "::1", "fd00:1234::1"])
def test_private_permission_still_admits_ordinary_intranet_targets(monkeypatch, address):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    assert action_scope._ip_scope_block_reason(address, "production") is None
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")
    assert action_scope._ip_scope_block_reason(address, "production") is not None
