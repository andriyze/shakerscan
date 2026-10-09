"""Differential check: the shared address classifier against the classifiers it replaced.

``LEGACY`` below is a frozen copy of the decisions before this change: the web scope guard as
#357 left it (``_ip_scope_block_reason`` and ``public_unicast_address``), the device plane's
``validate_device_destination`` (with its ``SHAKERSCAN_DEVICE_DENY_CIDRS`` and
``SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS`` handling) and the Hunt direct-origin list as #358
left it. Every comparison also runs with ``SHAKERSCAN_NAT64_PREFIXES``,
``SHAKERSCAN_DEVICE_DENY_CIDRS`` and ``SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS`` set, alone and
together. Over a large address set (every special-purpose boundary, a
seeded sample of the IPv4 space, and every IPv6 spelling that carries one of them), in production
with private networks refused, production with them allowed, and Lab, the new classifier must
refuse everything the old one refused. Where it refuses more, the address must belong to one of
the deliberate tightenings of this change, and nothing else:

- shared address space 100.64.0.0/10 (CGNAT, Tailscale) is private-class;
- SIIT ``::ffff:0:a.b.c.d`` is decoded;
- an IPv6 zone id no longer hides a cloud-service address;
- device plane: every embedded spelling is judged as the IPv4 address it carries, and a link-local
  IPv4 address carried inside a translator or tunnel form is refused;
- a Hunt direct origin is judged by the web scope guard (``action_scope.direct_origin_refusal``):
  reserved and special-purpose space the old list did not name follows the private setting;
- an address under a declared ``SHAKERSCAN_NAT64_PREFIXES`` prefix is judged as the address it
  carries;
- the cloud-service list gains the EKS Pod Identity agent (169.254.170.23, fd00:ec2::23) and
  Oracle Cloud Classic metadata (192.0.0.192), refused everywhere, and the device plane refuses
  the limited broadcast address 255.255.255.255 in every spelling.
"""
from __future__ import annotations

import ipaddress
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import action_scope  # noqa: E402
from scanner_tools import device_posture  # noqa: E402
from scanner_tools.address_classes import (  # noqa: E402
    embedded_ipv4_addresses as new_embedded,
    judged_addresses as new_judged,
)


# --------------------------------------------------------------------------------------------
# Frozen legacy decisions (origin/main before this change). Do not edit to match new behaviour.

_LEGACY_CLOUD = frozenset({"169.254.169.254", "169.254.170.2", "100.100.100.200", "168.63.129.16", "fd00:ec2::254"})
_LEGACY_LAB = {"development", "dev", "preview", "staging", "lab", "test"}
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.ip_network("64:ff9b:1::/48")


def _legacy_rfc6052(address, prefix_bytes):
    packed = [byte for index, byte in enumerate(address.packed) if index != 8]
    start = prefix_bytes if prefix_bytes <= 8 else prefix_bytes - 1
    return ipaddress.IPv4Address(bytes(packed[start:start + 4]))


def legacy_embedded(address):
    if address.version != 6:
        return ()
    found = []
    if address.ipv4_mapped is not None:
        found.append(address.ipv4_mapped)
    elif int(address) >> 32 == 0 and int(address) > 1:
        found.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    if address in _NAT64_WELL_KNOWN:
        found.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    if address in _NAT64_LOCAL_USE:
        found.extend(_legacy_rfc6052(address, size) for size in (6, 7, 8, 12))
    if address.sixtofour is not None:
        found.append(address.sixtofour)
    if address.teredo is not None:
        found.extend(address.teredo)
    return tuple(dict.fromkeys(found))


def _legacy_always_refused(address):
    return (str(address) in _LEGACY_CLOUD or address.is_link_local or address.is_multicast
            or address.is_unspecified or str(address) == "255.255.255.255")


def legacy_scope_block(host, environment, allow_private):
    lowered = host.lower().strip("[]")
    try:
        ip_obj = ipaddress.ip_address(lowered)
    except ValueError:
        return None
    embedded = legacy_embedded(ip_obj)
    candidates = embedded if ip_obj.version == 6 and ip_obj.ipv4_mapped is not None else (ip_obj, *embedded)
    if any(_legacy_always_refused(item) for item in candidates):
        return "loopback_or_private_range"
    if environment in _LEGACY_LAB:
        return None
    if any(item.is_loopback or item.is_private or item.is_reserved for item in candidates):
        return None if allow_private else "loopback_or_private_range"
    return None


def legacy_public_unicast(value):
    try:
        address = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return False
    if legacy_scope_block(str(address), "production", False) is not None:
        return False
    return all(item.is_global and not item.is_multicast for item in (address, *legacy_embedded(address)))


_LEGACY_DEVICE_DENIED = tuple(ipaddress.ip_network(raw) for raw in (
    "169.254.169.254/32", "169.254.170.2/32", "100.100.100.200/32", "168.63.129.16/32", "fd00:ec2::254/128",
))


def legacy_device_admits(address, environment, policy, *, metadata_allowed=False, deny_cidrs=()):
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if parsed.is_unspecified or parsed.is_multicast:
        return False
    judged = parsed.ipv4_mapped if parsed.version == 6 and parsed.ipv4_mapped is not None else parsed
    if not (environment in _LEGACY_LAB or policy == "allow"):
        metadata = any(judged.version == net.version and judged in net for net in _LEGACY_DEVICE_DENIED)
        if not (judged.is_link_local or metadata) and (judged.is_loopback or judged.is_private or judged.is_reserved):
            return False
    if metadata_allowed:
        return True
    networks = (*_LEGACY_DEVICE_DENIED, *(ipaddress.ip_network(raw, strict=False) for raw in deny_cidrs))
    return not any(parsed.version == net.version and parsed in net for net in networks)


_LEGACY_ORIGIN_NEVER = tuple(ipaddress.ip_network(raw) for raw in (
    "0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::/128", "fe80::/10", "ff00::/8",
))
_LEGACY_ORIGIN_PRIVATE = tuple(ipaddress.ip_network(raw) for raw in (
    "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7",
))


def legacy_direct_origin_refused(address, allow_private):
    """``start_contract._ip_addresses`` as #358 left it (its decoding was already the shared one)."""
    parsed = ipaddress.ip_address(address)
    networks = _LEGACY_ORIGIN_NEVER + (() if allow_private else _LEGACY_ORIGIN_PRIVATE)
    candidates = new_judged(parsed)
    return any(str(item) in _LEGACY_CLOUD for item in candidates) or any(
        item.version == net.version and item in net for item in candidates for net in networks
    )


# --------------------------------------------------------------------------------------------
# The address set.

SPECIAL_V4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)
POINTS_V4 = (
    "169.254.169.254", "169.254.170.2", "100.100.100.200", "168.63.129.16", "255.255.255.255",
    "169.254.170.23", "192.0.0.192", "192.0.0.8", "198.18.0.1", "192.0.2.1",
    "8.8.8.8", "93.184.216.34", "1.1.1.1", "100.63.255.255", "100.128.0.0", "169.254.10.20",
)
SPECIAL_V6 = (
    "::1", "::", "fe80::1", "fe80::1%eth0", "fc00::1", "fd12::7", "fd00:ec2::254", "fd00:ec2::254%eth0",
    "fd00:ec2::254%25", "fd00:ec2::23", "fd00:ec2::23%eth0", "ff02::1", "2001:db8::1", "2606:4700:4700::1111", "2001:4860:4860::8888",
    "100::1", "2001:10::1", "2001:20::1", "64:ff9b::", "2002::", "2001::",
)


def _forms(ipv4):
    value = int(ipaddress.IPv4Address(ipv4))
    local = list(ipaddress.IPv6Address("64:ff9b:1::").packed[:6]) + list(ipaddress.IPv4Address(ipv4).packed)
    return (
        f"::ffff:{ipv4}",
        str(ipaddress.IPv6Address((0xFFFF0000 << 32) | value)),  # SIIT
        str(ipaddress.IPv6Address(value)) if value > 1 else "::2",  # IPv4-compatible
        str(ipaddress.IPv6Address((0x64FF9B << 96) | value)),  # NAT64
        str(ipaddress.IPv6Address(bytes(local + [0] * 6))),  # local-use NAT64 /48
        str(ipaddress.IPv6Address((0x2002 << 112) | (value << 80) | 1)),  # 6to4
        str(ipaddress.IPv6Address((0x20010000 << 96) | (value << 64) | 0xFFFFFFFE)),  # Teredo server
        str(ipaddress.IPv6Address((0x20010000 << 96) | (0x4136E378 << 64) | (value ^ 0xFFFFFFFF))),  # client
    )


def _address_set():
    rng = random.Random(20261008)
    v4 = set(POINTS_V4)
    for raw in SPECIAL_V4:
        network = ipaddress.ip_network(raw)
        v4.update(str(network[index]) for index in (0, 1, network.num_addresses // 2, -2, -1))
        v4.update(str(network[rng.randrange(network.num_addresses)]) for _ in range(8))
    v4.update(str(ipaddress.IPv4Address(rng.getrandbits(32))) for _ in range(4000))
    addresses = set(v4) | set(SPECIAL_V6)
    for ipv4 in sorted(v4):
        addresses.update(_forms(ipv4))
    addresses.update(str(ipaddress.IPv6Address(rng.getrandbits(128))) for _ in range(2000))
    return sorted(addresses)


# Deployment settings every comparison also runs under.
DECLARED_NAT64 = ("2001:db8:64::/96", "2001:db8:100::/40")
DENY_CIDRS = ("203.0.113.0/24", "2001:db8:dead::/48")
SETTINGS = {
    "defaults": {},
    "nat64_prefixes": {"SHAKERSCAN_NAT64_PREFIXES": ",".join(DECLARED_NAT64)},
    "deny_cidrs": {"SHAKERSCAN_DEVICE_DENY_CIDRS": ",".join(DENY_CIDRS)},
    "allow_metadata": {"SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS": "true"},
    "all": {
        "SHAKERSCAN_NAT64_PREFIXES": ",".join(DECLARED_NAT64),
        "SHAKERSCAN_DEVICE_DENY_CIDRS": ",".join(DENY_CIDRS),
        "SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS": "true",
    },
}
_SETTING_NAMES = (
    "SHAKERSCAN_NAT64_PREFIXES", "SHAKERSCAN_DEVICE_DENY_CIDRS", "SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS",
)


def _rfc6052(prefix, ipv4):
    network = ipaddress.IPv6Network(prefix)
    body = list(network.network_address.packed[:network.prefixlen // 8]) + list(ipaddress.IPv4Address(ipv4).packed)
    if network.prefixlen // 8 <= 8 < len(body):
        body.insert(8, 0)
    return str(ipaddress.IPv6Address(bytes((body + [0] * 16)[:16])))


def _declared_nat64_forms():
    v4 = set(POINTS_V4)
    for raw in SPECIAL_V4:
        network = ipaddress.ip_network(raw)
        v4.update(str(network[index]) for index in (0, 1, network.num_addresses // 2, -2, -1))
    return {_rfc6052(prefix, item) for prefix in DECLARED_NAT64 for item in v4}


ADDRESSES = sorted({*_address_set(), *_declared_nat64_forms(), "2001:db8:dead::1", "::ffff:203.0.113.7"})


def _apply(monkeypatch, settings):
    for name in _SETTING_NAMES:
        monkeypatch.delenv(name, raising=False)
    for name, value in SETTINGS[settings].items():
        monkeypatch.setenv(name, value)


def _under_declared_nat64(text, settings):
    if "SHAKERSCAN_NAT64_PREFIXES" not in SETTINGS[settings]:
        return False
    address = _plain(text)
    return any(address in ipaddress.ip_network(prefix) for prefix in DECLARED_NAT64)
MODES = (("production", False), ("production", True), ("lab", False))


def _plain(text):
    return ipaddress.ip_address(text.split("%", 1)[0])


def _carried(text):
    address = _plain(text)
    return (address, *new_embedded(address))


# Cloud-service addresses added by this change (S4 of the #358 review), and the limited broadcast
# address the device plane now refuses.
_NEW_CLOUD = frozenset(ipaddress.ip_address(raw) for raw in ("169.254.170.23", "192.0.0.192", "fd00:ec2::23"))
_BROADCAST = ipaddress.ip_address("255.255.255.255")


def _carries_new_cloud(text):
    return any(item in _NEW_CLOUD for item in _carried(text))


def _deliberate_scope_tightening(text):
    address = _plain(text)
    carried = _carried(text)
    if _carries_new_cloud(text):
        return True
    shared = any(item.version == 4 and item in ipaddress.ip_network("100.64.0.0/10") for item in carried)
    siit = address.version == 6 and address in ipaddress.ip_network("::ffff:0:0:0/96")
    zoned_cloud = "%" in text and str(address) in _LEGACY_CLOUD
    return shared or siit or zoned_cloud


def test_the_address_set_is_large_and_covers_every_form():
    assert len(ADDRESSES) > 30_000
    assert "::ffff:0:a9fe:a9fe" in ADDRESSES and "64:ff9b::a9fe:a9fe" in ADDRESSES


@pytest.mark.parametrize("settings", SETTINGS)
@pytest.mark.parametrize("environment, allow_private", MODES)
def test_the_scope_guard_is_never_more_permissive(monkeypatch, environment, allow_private, settings):
    _apply(monkeypatch, settings)
    loosened, tightened, unexplained = [], [], []
    for text in ADDRESSES:
        old = legacy_scope_block(text, environment, allow_private)
        new = action_scope._ip_scope_block_reason(text, environment, allow_private_networks=allow_private)
        if old is not None and new is None:
            loosened.append(text)
        elif old is None and new is not None:
            tightened.append(text)
            if not (_deliberate_scope_tightening(text) or _under_declared_nat64(text, settings)):
                unexplained.append(text)
    assert not loosened, loosened[:20]
    assert not unexplained, unexplained[:20]
    assert tightened, "the deliberate tightenings are exercised"


@pytest.mark.parametrize("settings", SETTINGS)
def test_a_hunt_destination_is_never_more_permissive(monkeypatch, settings):
    _apply(monkeypatch, settings)
    loosened = [text for text in ADDRESSES
                if action_scope.public_unicast_address(text) and not legacy_public_unicast(text)]
    assert not loosened, loosened[:20]


def _deliberate_device_tightening(text, environment, policy):
    address = _plain(text)
    carried = new_embedded(address)
    if _carries_new_cloud(text) or _BROADCAST in _carried(text):
        return True
    if address.version == 6 and address.ipv4_mapped is None and carried:
        return True  # judged as the IPv4 address it carries
    if address.version == 6 and address.ipv4_mapped is not None:
        return True  # the mapped IPv4 address is deny-listed as itself
    if "%" in text:
        return True  # a zone id no longer hides a deny-listed address
    return any(item.version == 4 and item in ipaddress.ip_network("100.64.0.0/10") for item in (address,))


@pytest.mark.parametrize("settings", SETTINGS)
@pytest.mark.parametrize("environment, policy", [("production", "refuse"), ("production", "allow"), ("lab", "refuse")])
def test_the_device_plane_is_never_more_permissive(monkeypatch, environment, policy, settings):
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", policy)
    _apply(monkeypatch, settings)
    configured = SETTINGS[settings]
    loosened, unexplained = [], []
    for text in ADDRESSES:
        old = legacy_device_admits(
            text, environment, policy,
            metadata_allowed="SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS" in configured,
            deny_cidrs=DENY_CIDRS if "SHAKERSCAN_DEVICE_DENY_CIDRS" in configured else (),
        )
        new = device_posture.device_destination_admitted(text, environment=environment, policy=policy)
        if new and not old:
            loosened.append(text)
        elif old and not new and not _deliberate_device_tightening(text, environment, policy):
            unexplained.append(text)
    assert not loosened, loosened[:20]
    assert not unexplained, unexplained[:20]


@pytest.mark.parametrize("settings", SETTINGS)
@pytest.mark.parametrize("allow_private", [False, True])
def test_a_hunt_direct_origin_is_never_more_permissive(monkeypatch, allow_private, settings):
    """S3 of the #358 review: the direct-origin list now follows the web scope guard. Every
    address it newly refuses is one that guard refuses under the same private setting."""
    _apply(monkeypatch, settings)
    loosened, tightened, unexplained = [], [], []
    for text in ADDRESSES:
        old = legacy_direct_origin_refused(text, allow_private)
        new = action_scope.direct_origin_refusal(text, allow_private_networks=allow_private) is not None
        if old and not new:
            loosened.append(text)
        elif new and not old:
            tightened.append(text)
            if action_scope._ip_scope_block_reason(
                text, "production", allow_private_networks=allow_private,
            ) is None:
                unexplained.append(text)
    assert not loosened, loosened[:20]
    assert not unexplained, unexplained[:20]
    assert tightened, "the deliberate tightenings are exercised"
    for address in ("198.18.0.1", "192.0.0.8", "192.0.2.1", "64:ff9b::c612:1"):
        assert (address in tightened) is (not allow_private)
    assert "192.0.0.192" in tightened
