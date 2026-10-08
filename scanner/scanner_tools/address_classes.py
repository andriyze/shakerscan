"""The address classes every destination check shares (web scope guard, device, network, SSH).

``embedded_ipv4_addresses`` decodes an IPv6 address into every IPv4 address it carries, so a
destination check can apply its deny tests to the address a translator or tunnel would reach
rather than to the spelling it was given.

This module has no dependency outside the standard library, so the scanner package (which does
not import the API package) and the API share it.
"""
from __future__ import annotations

import ipaddress

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

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


def embedded_ipv4_addresses(address: IPAddress) -> tuple[ipaddress.IPv4Address, ...]:
    """Every IPv4 address an IPv6 address carries and a translator or tunnel would reach.

    IPv4-mapped (::ffff:a.b.c.d), SIIT IPv4-translated (::ffff:0:a.b.c.d) and IPv4-compatible
    (::a.b.c.d), NAT64 (64:ff9b::/96 and the local-use 64:ff9b:1::/48 at each RFC 6052 prefix
    length), 6to4 (2002::/16) and Teredo (both the server and the de-obfuscated client).
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
    "CLOUD_SERVICE_ADDRESSES", "IPAddress", "SHARED_ADDRESS_SPACE", "cloud_service_address",
    "embedded_ipv4_addresses", "judged_addresses", "private_class", "shared_address_space",
    "without_scope",
]
