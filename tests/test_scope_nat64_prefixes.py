"""A deployment can name its network-specific NAT64 prefixes (``SHAKERSCAN_NAT64_PREFIXES``).

Only the well-known 64:ff9b::/96 and the local-use 64:ff9b:1::/48 can be recognised from the
address alone. A NAT64 gateway on a network-specific prefix (RFC 6052, for example a provider's
2600:1f00:64::/96) makes ``<prefix>::a9fe:a9fe`` the metadata service, and the address reads as
global. An operator whose network runs such a gateway lists the prefix; every address under it is
then judged as the IPv4 address it carries. The setting is empty by default.
"""
from __future__ import annotations

import ipaddress
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import action_scope  # noqa: E402
from hunt.dispatch_authority import public_address  # noqa: E402
from scanner_tools import address_classes  # noqa: E402

ENV = "SHAKERSCAN_NAT64_PREFIXES"
PREFIX_96 = "2600:1f00:64::/96"
PREFIX_64 = "2600:1f00:64:1::/64"


def embed(prefix: str, ipv4: str) -> str:
    """RFC 6052 embedding (the u octet, bits 64-71, stays zero)."""
    network = ipaddress.IPv6Network(prefix)
    head = list(network.network_address.packed[:network.prefixlen // 8])
    body = head + list(ipaddress.IPv4Address(ipv4).packed)
    if len(head) <= 8 < len(body):
        body.insert(8, 0)
    body += [0] * (16 - len(body))
    return str(ipaddress.IPv6Address(bytes(body[:16])))


def test_the_setting_is_empty_by_default(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    assert address_classes.nat64_prefixes() == ()
    spelled = embed(PREFIX_96, "169.254.169.254")
    assert action_scope.embedded_ipv4_addresses(ipaddress.ip_address(spelled)) == ()


@pytest.mark.parametrize("prefix", [PREFIX_96, PREFIX_64])
@pytest.mark.parametrize("ipv4", ["169.254.169.254", "168.63.129.16", "224.0.0.1"])
@pytest.mark.parametrize("environment", ["production", "lab"])
def test_a_declared_prefix_is_decoded_everywhere(monkeypatch, prefix, ipv4, environment):
    monkeypatch.setenv(ENV, f"{PREFIX_96}, {PREFIX_64}")
    spelled = embed(prefix, ipv4)
    assert ipaddress.IPv4Address(ipv4) in action_scope.embedded_ipv4_addresses(ipaddress.ip_address(spelled))
    assert action_scope._ip_scope_block_reason(spelled, environment, allow_private_networks=True), spelled
    assert not public_address(spelled)


def test_a_declared_prefix_carrying_a_private_address_needs_the_private_setting(monkeypatch):
    monkeypatch.setenv(ENV, PREFIX_96)
    spelled = embed(PREFIX_96, "10.0.0.1")
    assert action_scope._ip_scope_block_reason(spelled, "production", allow_private_networks=False)
    assert not public_address(spelled)


def test_a_declared_prefix_carrying_a_public_address_stays_public(monkeypatch):
    monkeypatch.setenv(ENV, PREFIX_96)
    spelled = embed(PREFIX_96, "93.184.216.34")
    assert action_scope._ip_scope_block_reason(spelled, "production", allow_private_networks=False) is None
    assert public_address(spelled)


@pytest.mark.parametrize("value", ["not-a-prefix", "10.0.0.0/8", "2600:1f00:64::/80", "2600:1f00:64::1/96"])
def test_an_invalid_entry_fails_closed_naming_the_setting(monkeypatch, value):
    monkeypatch.setenv(ENV, value)
    with pytest.raises(ValueError, match=ENV):
        address_classes.nat64_prefixes()
    with pytest.raises(ValueError, match=ENV):
        action_scope._ip_scope_block_reason("2001:4860::8888", "production")
