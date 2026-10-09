"""The address classes every destination check shares (web scope guard, device, network, SSH).

``embedded_ipv4_addresses`` decodes an IPv6 address into every IPv4 address it carries, so a
destination check can apply its deny tests to the address a translator or tunnel would reach
rather than to the spelling it was given.

This module has no dependency outside the standard library, so the scanner package (which does
not import the API package) and the API share it.
"""
from __future__ import annotations

from functools import lru_cache
import ipaddress
import os

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

NAT64_PREFIXES_ENV = "SHAKERSCAN_NAT64_PREFIXES"
# Special cloud-service destinations. They are not all link-local, so private-network permission
# must not admit them.
CLOUD_SERVICE_ADDRESSES = frozenset({
    ipaddress.ip_address(raw) for raw in (
        "169.254.169.254", "169.254.170.2", "100.100.100.200", "168.63.129.16", "fd00:ec2::254",
    )
})

# RFC 6598 shared address space (carrier-grade NAT). Neither ``is_private`` nor ``is_reserved``,
# yet never a public destination: Tailscale and other overlay networks number their nodes from it.
SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")

_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.ip_network("64:ff9b:1::/48")
# SIIT (RFC 7915) IPv4-translated addresses, ::ffff:0:a.b.c.d.
_IPV4_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")
# RFC 6052 prefix lengths, in bytes, a local-use NAT64 prefix inside 64:ff9b:1::/48 may use.
_NAT64_LOCAL_PREFIX_BYTES = (6, 7, 8, 12)
# RFC 6052 prefix lengths, in bits, any NAT64 prefix may use.
_RFC6052_PREFIX_BITS = (32, 40, 48, 56, 64, 96)


def without_scope(address: IPAddress) -> IPAddress:
    """``address`` without an IPv6 zone id (``fd00:ec2::254%eth0`` is ``fd00:ec2::254``)."""
    if address.version == 6 and getattr(address, "scope_id", None):
        return ipaddress.IPv6Address(int(address))
    return address


def _rfc6052_ipv4(address: ipaddress.IPv6Address, prefix_bytes: int) -> ipaddress.IPv4Address:
    """The IPv4 address RFC 6052 embeds after a prefix of ``prefix_bytes``; bits 64-71 (the
    "u" octet) never carry address bits."""
    packed = [byte for index, byte in enumerate(address.packed) if index != 8]
    start = prefix_bytes if prefix_bytes <= 8 else prefix_bytes - 1
    return ipaddress.IPv4Address(bytes(packed[start:start + 4]))


@lru_cache(maxsize=16)
def _parse_nat64_prefixes(raw: str) -> tuple[ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv6Network] = []
    for item in (part.strip() for part in raw.split(",")):
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as exc:
            raise ValueError(f"invalid {NAT64_PREFIXES_ENV} entry: {item}") from exc
        if not isinstance(network, ipaddress.IPv6Network) or network.prefixlen not in _RFC6052_PREFIX_BITS:
            raise ValueError(
                f"invalid {NAT64_PREFIXES_ENV} entry: {item} (an IPv6 prefix of length "
                "32, 40, 48, 56, 64 or 96)"
            )
        networks.append(network)
    return tuple(networks)


def nat64_prefixes(raw: str | None = None) -> tuple[ipaddress.IPv6Network, ...]:
    """The deployment's network-specific NAT64 prefixes (``SHAKERSCAN_NAT64_PREFIXES``).

    A comma-separated list of RFC 6052 prefixes (for example ``2001:db8:64::/96``), empty by
    default. A NAT64 gateway on a network-specific prefix cannot be recognised from the address
    alone, so an operator whose network runs one names it here and every address under it is
    judged as the IPv4 address it carries. An invalid entry raises ``ValueError``: destination
    checks then fail closed instead of ignoring a prefix the operator meant to declare.
    """
    return _parse_nat64_prefixes(
        os.environ.get("SHAKERSCAN_NAT64_PREFIXES", "") if raw is None else raw
    )


def validate_nat64_prefixes_setting(raw: str | None = None) -> tuple[ipaddress.IPv6Network, ...]:
    """Parse ``SHAKERSCAN_NAT64_PREFIXES`` once, for process startup and readiness.

    An invalid value used to surface only when an IPv6 address was first classified, as an
    uncaught ``ValueError`` (a 500 from the API). The API and the workers call this before they
    serve or claim work, so a malformed setting stops the process with an error naming it.
    """
    value = os.environ.get(NAT64_PREFIXES_ENV, "") if raw is None else raw
    try:
        return _parse_nat64_prefixes(value)
    except ValueError as exc:
        raise ValueError(f"{NAT64_PREFIXES_ENV} is invalid: {exc}") from None


def embedded_ipv4_addresses(address: IPAddress) -> tuple[ipaddress.IPv4Address, ...]:
    """Every IPv4 address an IPv6 address carries and a translator or tunnel would reach.

    IPv4-mapped (::ffff:a.b.c.d), SIIT IPv4-translated (::ffff:0:a.b.c.d) and IPv4-compatible
    (::a.b.c.d), NAT64 (64:ff9b::/96, the local-use 64:ff9b:1::/48 at each RFC 6052 prefix
    length and the deployment's ``SHAKERSCAN_NAT64_PREFIXES``), 6to4 (2002::/16) and Teredo (both the server and the de-obfuscated client).
    ``64:ff9b::a9fe:a9fe`` is 169.254.169.254 to a NAT64 gateway, and ``ipaddress.is_global``
    calls it global.
    """
    if address.version != 6:
        return ()
    assert isinstance(address, ipaddress.IPv6Address)
    found: list[ipaddress.IPv4Address] = []
    if address.ipv4_mapped is not None:
        found.append(address.ipv4_mapped)
    elif int(address) >> 32 == 0 and int(address) > 1:
        found.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    if address in _IPV4_TRANSLATED or address in _NAT64_WELL_KNOWN:
        found.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    if address in _NAT64_LOCAL_USE:
        found.extend(_rfc6052_ipv4(address, size) for size in _NAT64_LOCAL_PREFIX_BYTES)
    for network in nat64_prefixes():
        if address in network:
            found.append(_rfc6052_ipv4(address, network.prefixlen // 8))
    if address.sixtofour is not None:
        found.append(address.sixtofour)
    if address.teredo is not None:
        found.extend(address.teredo)
    return tuple(dict.fromkeys(found))


def judged_addresses(address: IPAddress) -> tuple[IPAddress, ...]:
    """The addresses a destination check judges ``address`` as: itself (without a zone id) and
    every IPv4 address it carries. An IPv4-mapped address is only its IPv4 address (the
    ::ffff:0:0/96 block itself reads private)."""
    plain = without_scope(address)
    embedded = embedded_ipv4_addresses(plain)
    if getattr(plain, "ipv4_mapped", None) is not None:
        return embedded
    return (plain, *embedded)


def cloud_service_address(address: IPAddress) -> bool:
    """A cloud metadata or platform-service address, whatever zone id it carries."""
    return without_scope(address) in CLOUD_SERVICE_ADDRESSES



def shared_address_space(address: IPAddress) -> bool:
    """RFC 6598 shared address space (100.64.0.0/10, CGNAT and Tailscale)."""
    return address.version == 4 and address in SHARED_ADDRESS_SPACE


def private_class(address: IPAddress) -> bool:
    """Loopback, private, reserved or shared (CGNAT) space: admitted only where a Lab environment
    or the deployment's private-network setting admits private-network targets."""
    return (address.is_loopback or address.is_private or address.is_reserved
            or shared_address_space(address))


__all__ = [
    "CLOUD_SERVICE_ADDRESSES", "IPAddress", "NAT64_PREFIXES_ENV", "SHARED_ADDRESS_SPACE",
    "cloud_service_address", "embedded_ipv4_addresses", "judged_addresses", "nat64_prefixes",
    "private_class", "shared_address_space", "validate_nat64_prefixes_setting", "without_scope",
]
