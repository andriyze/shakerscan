"""Shared bounded inputs for canonical target-bound network adapters."""

from __future__ import annotations

import ipaddress
from typing import Any

from runtime.models import ScanPolicy, TargetBinding


class CapabilityInputError(ValueError):
    pass


def _ports(values: Any, *, maximum: int) -> tuple[int, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise CapabilityInputError("ports must be a non-empty array")
    result: list[int] = []
    for value in values:
        if isinstance(value, bool):
            raise CapabilityInputError("ports must contain integers")
        try:
            port = int(value)
        except (TypeError, ValueError) as exc:
            raise CapabilityInputError("ports must contain integers") from exc
        if not 1 <= port <= 65_535:
            raise CapabilityInputError("ports must be between 1 and 65535")
        if port not in result:
            result.append(port)
        if len(result) > maximum:
            raise CapabilityInputError(f"at most {maximum} ports are allowed")
    return tuple(sorted(result))


def _port_range(value: Any, *, maximum: int) -> tuple[int, int]:
    text = str(value or "").strip()
    parts = text.split("-")
    if len(parts) != 2:
        raise CapabilityInputError("port_range must be START-END")
    try:
        start, end = int(parts[0]), int(parts[1])
    except (TypeError, ValueError) as exc:
        raise CapabilityInputError("port_range must be two integers") from exc
    if not (1 <= start <= end <= 65_535):
        raise CapabilityInputError("port_range must be within 1-65535 with start <= end")
    if end - start + 1 > maximum:
        raise CapabilityInputError(f"port_range spans more than {maximum} ports; scan it in chunks")
    return start, end


def _require_network_policy(policy: ScanPolicy) -> None:
    if not policy.network_discovery:
        raise CapabilityInputError("network discovery policy is not enabled")
    if not policy.active_testing or not policy.approval_receipt_id:
        raise CapabilityInputError("network discovery requires active approval")


def _addresses(target: TargetBinding) -> tuple[str, ...]:
    if not target.allowed_addresses:
        raise CapabilityInputError("target binding has no approved runtime addresses")
    return tuple(str(ipaddress.ip_address(value)) for value in target.allowed_addresses)
