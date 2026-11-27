"""Device, network and SSH destinations share the web scope guard's address decoder.

``validate_device_destination`` compared the metadata networks by IP version and decoded only an
IPv4-mapped address, and only for the private-network test. ``::ffff:169.254.169.254``,
``64:ff9b::a9fe:a9fe``, ``::ffff:168.63.129.16`` and ``2002:a9fe:a9fe::`` were admitted, and over
a dual-stack socket ``::ffff:169.254.169.254`` reaches the metadata service; the locator kept
that spelling. Network (``host://``) targets are scanned by the same device posture scan, and its
SSH review connects to the address that scan pins. Every embedded spelling is now judged as the
IPv4 address it carries (``address_classes.embedded_ipv4_addresses``), an IPv4-mapped locator is
stored as its IPv4 address, and the device plane's link-local allowance covers a link-local
address itself only, never one carried inside a translator or tunnel form.

Resolvers and connections are labelled test doubles; nothing touches the network.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import sys

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_posture, device_probe  # noqa: E402


def _int(value: str) -> int:
    return int(ipaddress.IPv4Address(value))


FORMS = {
    "mapped": lambda v: f"::ffff:{v}",
    "siit": lambda v: str(ipaddress.IPv6Address((0xFFFF0000 << 32) | _int(v))),
    "compatible": lambda v: str(ipaddress.IPv6Address(_int(v))),
    "nat64": lambda v: str(ipaddress.IPv6Address((0x64FF9B << 96) | _int(v))),
    "nat64_local_48": lambda v: str(ipaddress.IPv6Address(
        bytes(list(ipaddress.IPv6Address("64:ff9b:1::").packed[:6]) + list(ipaddress.IPv4Address(v).packed) + [0] * 6)
    )),
    "6to4": lambda v: str(ipaddress.IPv6Address((0x2002 << 112) | (_int(v) << 80))),
    "teredo_client": lambda v: str(ipaddress.IPv6Address(
        (0x20010000 << 96) | (_int("65.54.227.120") << 64) | (_int(v) ^ 0xFFFFFFFF)
    )),
}
METADATA = ("169.254.169.254", "169.254.170.2", "168.63.129.16", "100.100.100.200")
REVIEWED = ("::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "::ffff:168.63.129.16", "2002:a9fe:a9fe::")


@pytest.mark.parametrize("policy", ["allow", "refuse"])
@pytest.mark.parametrize("environment", ["production", "lab"])
@pytest.mark.parametrize("address", REVIEWED)
def test_the_reviewed_spellings_are_refused(monkeypatch, policy, environment, address):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", policy)
    with pytest.raises(ValueError, match="denied|refused"):
        device_posture.validate_device_destination(address, environment=environment, policy=policy)
    assert not device_posture.device_destination_admitted(address, environment=environment, policy=policy)


@pytest.mark.parametrize("form", sorted(FORMS))
@pytest.mark.parametrize("address", METADATA)
def test_every_embedded_metadata_spelling_is_refused(monkeypatch, form, address):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    spelled = FORMS[form](address)
    with pytest.raises(ValueError):
        device_posture.validate_device_destination(spelled, environment="lab", policy="allow")


@pytest.mark.parametrize("form", sorted(FORMS))
def test_embedded_multicast_is_not_a_unicast_device(monkeypatch, form):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    with pytest.raises(ValueError, match="unicast"):
        device_posture.validate_device_destination(FORMS[form]("239.255.255.250"), policy="allow")


@pytest.mark.parametrize("form", sorted(set(FORMS) - {"mapped"}))
def test_a_private_address_carried_by_a_translator_needs_the_private_setting(monkeypatch, form):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")
    spelled = FORMS[form]("10.0.0.5")
    assert device_posture.device_private_destination_refusal(spelled, "production", "refuse")
    # A local-use NAT64 address is decoded at every RFC 6052 length, so another decoding may
    # refuse it first; it is refused either way.
    with pytest.raises(ValueError, match="loopback_or_private_range|unicast"):
        device_posture.validate_device_destination(spelled, environment="production", policy="refuse")


@pytest.mark.parametrize("form", sorted(set(FORMS) - {"mapped"}))
def test_a_link_local_address_carried_by_a_translator_is_refused(monkeypatch, form):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    with pytest.raises(ValueError, match="link-local|unicast"):
        device_posture.validate_device_destination(FORMS[form]("169.254.10.20"), policy="allow")


@pytest.mark.parametrize("address", ["fe80::1", "fe80::1%eth0", "169.254.10.20", "::ffff:169.254.10.20"])
def test_genuine_link_local_devices_stay_admitted(monkeypatch, address):
    """The plane's intended allowance: an APIPA or IPv6 link-local device on the LAN."""
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")
    admitted = device_posture.validate_device_destination(address, environment="production", policy="refuse")
    assert admitted == device_posture.canonical_device_address(address)


def test_a_zoned_metadata_address_is_refused(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    with pytest.raises(ValueError, match="metadata"):
        device_posture.validate_device_destination("fd00:ec2::254%eth0", policy="allow")


@pytest.mark.parametrize("raw, canonical", [
    ("::ffff:169.254.169.254", "169.254.169.254"),
    ("[::ffff:10.0.0.5]", "10.0.0.5"),
    ("::FFFF:A9FE:A9FE", "169.254.169.254"),
    ("64:ff9b::a9fe:a9fe", "64:ff9b::a9fe:a9fe"),
])
def test_device_locators_are_stored_canonically(raw, canonical):
    assert device_posture.normalize_device_locator(raw) == canonical


def test_a_configured_deny_cidr_matches_an_embedded_spelling(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    monkeypatch.setenv("SHAKERSCAN_DEVICE_DENY_CIDRS", "203.0.113.0/24")
    with pytest.raises(ValueError, match="control-plane"):
        device_posture.validate_device_destination("64:ff9b::cb00:710a", policy="allow")


def _resolve_with(answers, locator, admit):
    async def run():
        loop = asyncio.get_running_loop()

        async def getaddrinfo(*_args, **_kwargs):  # labelled double: the DNS answer
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (item, 0)) for item in answers]

        loop.getaddrinfo = getaddrinfo  # type: ignore[method-assign]
        return await device_posture.resolve_device_address(locator, admit=admit)

    return asyncio.run(run())


def test_a_mapped_dns_answer_pins_its_ipv4_address_and_a_refused_answer_is_skipped(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")

    def admit(address):
        return device_posture.device_destination_admitted(address, environment="production", policy="allow")

    pinned = _resolve_with(["::ffff:169.254.169.254", "::ffff:203.0.113.10"], "dual.test", admit)
    assert pinned == "203.0.113.10"
    assert _resolve_with(["::ffff:203.0.113.10"], "dual.test", None) == "203.0.113.10"


def _no_traffic(monkeypatch, module):
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("no connection may be attempted to a refused destination")

    for name in ("check_device_health", "probe_device_reachability", "full_ssh_scan"):
        if hasattr(module, name):
            monkeypatch.setattr(module, name, forbidden)


@pytest.mark.parametrize("locator", REVIEWED)
def test_a_network_or_device_posture_scan_and_its_ssh_review_never_start(monkeypatch, locator):
    """Network (host://) targets and devices share this scan; SSH review uses its pinned address."""
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    _no_traffic(monkeypatch, device_posture)
    with pytest.raises((ValueError, AssertionError)) as caught:
        asyncio.run(device_posture.run_device_posture_scan(locator, {
            "device_profile": "inventory", "confirm_authorized": True,
            "private_network_targets": "allow", "device_environment": "production",
        }))
    assert caught.type is ValueError, caught.value


@pytest.mark.parametrize("locator", REVIEWED)
def test_a_device_service_probe_never_starts(monkeypatch, locator):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    _no_traffic(monkeypatch, device_probe)
    with pytest.raises((ValueError, AssertionError)) as caught:
        asyncio.run(device_probe.run_device_service_probe(locator, {
            "probe_transport": "tcp", "probe_port": 22, "expected_state": "open",
            "confirm_authorized": True, "private_network_targets": "allow",
        }))
    assert caught.type is ValueError, caught.value


@pytest.mark.parametrize("address", REVIEWED + ("::ffff:0:a9fe:a9fe",))
def test_a_hunt_network_or_ssh_binding_refuses_the_embedded_literal(monkeypatch, address):
    """Hunt ``ssh.connect`` and SSH commands connect to the frozen binding address, which the
    runtime resolution admits through the shared classifier."""
    from fleet_routes import router as fleet

    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    with pytest.raises(HTTPException) as caught:
        asyncio.run(fleet._resolve_runtime_target_addresses(
            f"host://[{address}]", subject="Hunt target", environment="production",
        ))
    assert caught.value.status_code == 422


def test_an_api_side_device_request_is_pinned_and_checked(monkeypatch):
    """Device Hunt ``device_http_request`` and the control replay connect from the API process."""
    from devices import destination_policy

    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")

    async def resolve(_host):  # labelled double: the device name's DNS answer
        return ["::ffff:169.254.169.254", "203.0.113.10"]

    pinned = asyncio.run(destination_policy.pin_device_connect_address(
        "tv.test", "production", policy="allow", resolve=resolve,
    ))
    assert pinned == "203.0.113.10"
    for stored in REVIEWED:
        with pytest.raises(HTTPException) as caught:
            asyncio.run(destination_policy.pin_device_connect_address(stored, "production", policy="allow"))
        assert caught.value.status_code == 422
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")
    with pytest.raises(HTTPException):
        asyncio.run(destination_policy.pin_device_connect_address("10.0.0.5", "production", policy="refuse"))
