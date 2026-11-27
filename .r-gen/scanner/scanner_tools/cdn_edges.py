"""Shared CDN edges are not the application's origin network.

When a hostname resolves to a shared CDN edge (Cloudflare, for example), a port sweep of that
address examines the CDN provider's infrastructure, not the operator's server: whatever answers
there is the edge. The application is assessed through the CDN; the origin network is not
assessed at all, and saying otherwise would present the edge's listeners as the origin's.

An edge is recognised from the provider's published address ranges (Cloudflare publishes its
ranges at https://www.cloudflare.com/ips/) or, after an HTTP exchange, from the provider's
response headers. An origin address the operator authorized explicitly is scanned as its own
target, with the application's name as Host/SNI.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Mapping

EDGE_NOTE = "application assessed through the CDN; origin network not assessed"

# https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6 (published ranges).
CLOUDFLARE_RANGES = tuple(ipaddress.ip_network(item) for item in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
))
PUBLISHED_EDGE_RANGES: Mapping[str, tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]] = {
    "Cloudflare": CLOUDFLARE_RANGES,
}
# The web ports a Cloudflare edge proxies for a zone. An edge address is examined only on these:
# the rest of its ports belong to the provider, not to the application.
CLOUDFLARE_PROXIED_TCP_PORTS = (80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880)
EDGE_TCP_PORTS = {"Cloudflare": CLOUDFLARE_PROXIED_TCP_PORTS}


def edge_provider(address: Any) -> str | None:
    """The CDN whose published range contains ``address``, or None."""
    try:
        parsed = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return None
    mapped = getattr(parsed, "ipv4_mapped", None)
    parsed = mapped or parsed
    for provider, ranges in PUBLISHED_EDGE_RANGES.items():
        if any(parsed.version == network.version and parsed in network for network in ranges):
            return provider
    return None


def edge_from_headers(headers: Mapping[str, Any]) -> str | None:
    """A CDN named by the response headers it adds (after an HTTP exchange through it)."""
    lowered = {str(key).lower(): str(value).lower() for key, value in (headers or {}).items()}
    server = lowered.get("server", "")
    if server == "cloudflare" or "cf-ray" in lowered:
        return "Cloudflare"
    if server.startswith("akamaighost") or "x-akamai-transformed" in lowered:
        return "Akamai"
    if "x-amz-cf-id" in lowered or "cloudfront" in lowered.get("via", ""):
        return "Amazon CloudFront"
    if "x-fastly-request-id" in lowered or lowered.get("x-served-by", "").startswith("cache-"):
        return "Fastly"
    return None


def network_role(address: Any) -> dict[str, Any] | None:
    """The coverage label for an address on a shared CDN edge, or None for anything else."""
    provider = edge_provider(address)
    if provider is None:
        return None
    return {
        "role": "cdn_edge",
        "provider": provider,
        "basis": "published_range",
        "note": EDGE_NOTE,
        "tcp_ports_examined": list(EDGE_TCP_PORTS.get(provider, (80, 443))),
        "origin_assessed": False,
    }


def header_network_role(provider: str) -> dict[str, Any]:
    """The coverage label for an address whose HTTP answers named a CDN in their headers."""
    return {
        "role": "cdn_edge",
        "provider": provider,
        "basis": "response_header",
        "note": EDGE_NOTE,
        "origin_assessed": False,
    }


__all__ = [
    "CLOUDFLARE_PROXIED_TCP_PORTS", "EDGE_NOTE", "edge_from_headers", "edge_provider",
    "header_network_role", "network_role",
]
