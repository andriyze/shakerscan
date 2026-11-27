"""One deterministic policy for frozen target-address selection and fallback."""

from __future__ import annotations

import ipaddress
from typing import Iterable


ADDRESS_POLICY_SCHEMA = "frozen-target-address-policy/v1"
DEFAULT_ADDRESS_FAMILY_PREFERENCE = "ipv4_first"
MAX_FROZEN_ADDRESSES = 64
MAX_FALLBACK_ATTEMPTS = 8
_PREFERENCES = frozenset({"ipv4_first", "ipv6_first"})


def normalize_frozen_addresses(
    values: Iterable[str],
    *,
    preference: str = DEFAULT_ADDRESS_FAMILY_PREFERENCE,
) -> tuple[str, ...]:
    """Normalize, deduplicate, and stably order an admitted numeric address set."""
    selected_preference = str(preference or "").strip().lower()
    if selected_preference not in _PREFERENCES:
        raise ValueError("target address family preference is invalid")
    parsed: dict[str, ipaddress.IPv4Address | ipaddress.IPv6Address] = {}
    for raw in values:
        address = ipaddress.ip_address(str(raw or "").strip())
        parsed[str(address)] = address
    if not parsed:
        raise ValueError("at least one frozen address is required")
    if len(parsed) > MAX_FROZEN_ADDRESSES:
        raise ValueError("frozen address set exceeds the deterministic policy bound")
    preferred_version = 4 if selected_preference == "ipv4_first" else 6
    return tuple(
        str(address)
        for address in sorted(
            parsed.values(),
            key=lambda address: (
                0 if address.version == preferred_version else 1,
                int(address),
            ),
        )
    )


def bounded_fallback_addresses(
    values: Iterable[str],
    *,
    preference: str = DEFAULT_ADDRESS_FAMILY_PREFERENCE,
    max_attempts: int = MAX_FALLBACK_ATTEMPTS,
) -> tuple[str, ...]:
    if isinstance(max_attempts, bool):
        raise ValueError("target fallback attempt bound must be an integer")
    try:
        limit = int(max_attempts)
    except (TypeError, ValueError) as exc:
        raise ValueError("target fallback attempt bound must be an integer") from exc
    if not 1 <= limit <= MAX_FROZEN_ADDRESSES:
        raise ValueError("target fallback attempt bound is invalid")
    return normalize_frozen_addresses(values, preference=preference)[:limit]


def primary_frozen_address(
    values: Iterable[str],
    *,
    preference: str = DEFAULT_ADDRESS_FAMILY_PREFERENCE,
) -> str:
    """Return the stable primary address selected by the canonical policy."""
    return normalize_frozen_addresses(values, preference=preference)[0]


def address_policy_receipt(
    values: Iterable[str],
    *,
    preference: str = DEFAULT_ADDRESS_FAMILY_PREFERENCE,
    max_attempts: int = MAX_FALLBACK_ATTEMPTS,
) -> dict[str, object]:
    ordered = normalize_frozen_addresses(values, preference=preference)
    bounded = bounded_fallback_addresses(
        ordered, preference=preference, max_attempts=max_attempts,
    )
    return {
        "schema_version": ADDRESS_POLICY_SCHEMA,
        "family_preference": preference,
        "admitted_address_count": len(ordered),
        "fallback_attempt_limit": len(bounded),
        "no_runtime_resolution": True,
    }
