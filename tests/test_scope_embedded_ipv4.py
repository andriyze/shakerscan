"""IPv6 spellings of an IPv4 address are judged as the address they reach.

``ipaddress.is_global`` accepts ``64:ff9b::a9fe:a9fe`` (169.254.169.254 through NAT64) and
``64:ff9b::a00:1`` (10.0.0.1), and calls 168.63.129.16 (Azure WireServer) global. The scope guard
(``_ip_scope_block_reason``, registered targets) and the Hunt's authorized-destination hard limit
(D39: ``public_address`` at the permission request and at dispatch) now share one classifier that
decodes NAT64 (64:ff9b::/96 and 64:ff9b:1::/48), IPv4-mapped, IPv4-compatible, 6to4 and Teredo
addresses and applies the private, metadata and cloud-service blocks to what they carry.
"""
from __future__ import annotations

import asyncio
import ipaddress

import pytest

import action_scope
from hunt import permission_subjects
from hunt.dispatch_authority import destination_hard_limit, public_address
from hunt.permission_reasons import HuntRefusal


def _int(value: str) -> int:
    return int(ipaddress.IPv4Address(value))


def nat64(ipv4: str) -> str:
    return str(ipaddress.IPv6Address((0x64FF9B << 96) | _int(ipv4)))


def nat64_local(ipv4: str, prefix_bytes: int) -> str:
    """RFC 6052 embedding under the local-use prefix 64:ff9b:1::/48 (u octet left zero)."""
    head = list(ipaddress.IPv6Address("64:ff9b:1::").packed[:prefix_bytes])
    body = head + list(ipaddress.IPv4Address(ipv4).packed)
    if prefix_bytes <= 8 < len(body):
        body.insert(8, 0)
    body += [0] * (16 - len(body))
    return str(ipaddress.IPv6Address(bytes(body[:16])))


def mapped(ipv4: str) -> str:
    return f"::ffff:{ipv4}"


def siit(ipv4: str) -> str:
    """SIIT IPv4-translated (RFC 7915, ::ffff:0:0:0/96): not IPv4-mapped, so not ``ipv4_mapped``."""
    return str(ipaddress.IPv6Address((0xFFFF0000 << 32) | _int(ipv4)))


def compatible(ipv4: str) -> str:
    return str(ipaddress.IPv6Address(_int(ipv4)))


def sixtofour(ipv4: str) -> str:
    return str(ipaddress.IPv6Address((0x2002 << 112) | (_int(ipv4) << 80) | 1))


def teredo_server(ipv4: str) -> str:
    return str(ipaddress.IPv6Address((0x20010000 << 96) | (_int(ipv4) << 64) | _int("192.0.2.1") ^ 0xFFFFFFFF))


def teredo_client(ipv4: str) -> str:
    return str(ipaddress.IPv6Address((0x20010000 << 96) | (_int("65.54.227.120") << 64) | (_int(ipv4) ^ 0xFFFFFFFF)))


FORMS = {
    "nat64": nat64, "nat64_local_48": lambda v: nat64_local(v, 6), "nat64_local_56": lambda v: nat64_local(v, 7),
    "nat64_local_64": lambda v: nat64_local(v, 8), "nat64_local_96": lambda v: nat64_local(v, 12),
    "mapped": mapped, "siit": siit, "compatible": compatible, "6to4": sixtofour,
    "teredo_server": teredo_server, "teredo_client": teredo_client,
}
METADATA = ("169.254.169.254", "168.63.129.16", "100.100.100.200", "169.254.170.2")
PRIVATE = ("10.0.0.1", "192.168.1.50", "127.0.0.1")


@pytest.mark.parametrize("form", sorted(FORMS))
def test_each_form_decodes_to_the_address_it_carries(form):
    spelled = ipaddress.ip_address(FORMS[form]("169.254.169.254"))
    assert ipaddress.IPv4Address("169.254.169.254") in action_scope.embedded_ipv4_addresses(spelled), spelled


def test_is_global_alone_accepted_the_reviewed_spellings():
    """The premise: the standard library calls these global."""
    assert ipaddress.ip_address("64:ff9b::a9fe:a9fe").is_global
    assert ipaddress.ip_address("64:ff9b::a00:1").is_global
    assert ipaddress.ip_address("168.63.129.16").is_global


@pytest.mark.parametrize("form", sorted(FORMS))
@pytest.mark.parametrize("address", METADATA)
@pytest.mark.parametrize("environment", ["production", "lab"])
def test_a_metadata_address_in_any_spelling_is_never_a_target(form, address, environment):
    spelled = FORMS[form](address)
    assert action_scope._ip_scope_block_reason(spelled, environment, allow_private_networks=True), spelled
    assert not public_address(spelled), spelled


@pytest.mark.parametrize("form", sorted(FORMS))
@pytest.mark.parametrize("address", ("224.0.0.1", "239.255.255.250"))
@pytest.mark.parametrize("environment", ["production", "lab"])
def test_a_multicast_address_in_any_spelling_is_never_a_target(form, address, environment):
    spelled = FORMS[form](address)
    assert action_scope._ip_scope_block_reason(spelled, environment, allow_private_networks=True), spelled
    assert not public_address(spelled), spelled


def test_siit_is_decoded_and_is_not_mapped():
    spelled = ipaddress.ip_address(siit("168.63.129.16"))
    assert spelled.ipv4_mapped is None
    assert action_scope.embedded_ipv4_addresses(spelled) == (ipaddress.IPv4Address("168.63.129.16"),)
    assert "cloud metadata" in action_scope.destination_refusal_explanation(str(spelled), "production")


@pytest.mark.parametrize("form", sorted(FORMS))
@pytest.mark.parametrize("address", PRIVATE)
def test_a_private_address_in_any_spelling_needs_the_private_network_setting(form, address):
    spelled = FORMS[form](address)
    assert action_scope._ip_scope_block_reason(spelled, "production", allow_private_networks=False), spelled
    assert not public_address(spelled), spelled


@pytest.mark.parametrize("address", ["64:ff9b::a9fe:a9fe", "64:ff9b::a00:1", "168.63.129.16", "100.64.0.1",
                                     "::ffff:10.0.0.1", "10.0.0.1", "::1", "ff02::1", "not-an-address"])
def test_a_granted_destination_never_uses_them(address):
    granted = {"scheme": "http", "host": "dest.example.net", "port": 80, "addresses": ["93.184.216.34", address]}
    assert destination_hard_limit(granted, "production"), address


@pytest.mark.parametrize("address", ["93.184.216.34", "2606:4700:4700::1111", "8.8.8.8"])
def test_public_addresses_are_still_public(address):
    assert public_address(address)
    assert action_scope._ip_scope_block_reason(address, "production", allow_private_networks=False) is None


def test_the_permission_request_refuses_a_destination_resolving_through_nat64(monkeypatch):
    """D39 at the request: a host whose DNS64 answer carries the metadata address is a hard limit."""
    async def resolver(_url, _environment):  # labelled double: DNS answers a NAT64 address
        return ["64:ff9b::a9fe:a9fe"]

    monkeypatch.setattr(permission_subjects, "resolve_destination_addresses", resolver)
    refusal = HuntRefusal("scope_other_host", "other host", subject={
        "target_id": "t", "host": "dest.example.net", "port": 80, "scheme": "http",
        "origin": "http://dest.example.net:80", "same_host": False, "addresses": [],
    })
    completed = asyncio.run(permission_subjects.complete_destination_subject({"context_pack": {}}, refusal))
    assert completed.reason_code == "scope_destination_blocked"


def test_the_refusal_names_the_address_a_translator_reaches():
    assert "cloud metadata" in action_scope.destination_refusal_explanation("64:ff9b::a9fe:a9fe", "production")
    assert "private-network" in action_scope.destination_refusal_explanation("64:ff9b::a00:1", "production")
