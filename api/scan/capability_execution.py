"""Canonical contracts for executable capabilities owned by one Scan."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from typing import Any, Mapping

try:
    from runtime.models import PreparedExecution, TargetBinding
except ModuleNotFoundError:  # package imports in host-side tests
    from ..runtime.models import PreparedExecution, TargetBinding


class ScanCapabilityContractError(ValueError):
    """A capability cannot execute within its immutable Scan authority."""


# Stable, deliberately small TCP service set used by deterministic Scan. Hunt can
# request broader registry profiles, but Scan divides its exact port ceiling
# between discovery and follow-up fingerprinting instead of hiding an unbounded
# second pass inside the scanner subprocess.
CANONICAL_SCAN_NETWORK_PORTS: tuple[int, ...] = (
    21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
    1433, 1521, 1883, 3000, 3306, 5432, 6379, 8080, 8443, 8883, 9200,
)


def _budget_integer(
    budget: Mapping[str, Any], name: str, *, allow_zero: bool = False,
) -> int:
    value = budget.get(name)
    if isinstance(value, bool):
        raise ScanCapabilityContractError(f"Scan {name} must be an integer")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ScanCapabilityContractError(f"Scan {name} must be an integer") from exc
    if normalized < (0 if allow_zero else 1):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ScanCapabilityContractError(
            f"Scan {name} must be a {qualifier} integer"
        )
    return normalized


def scan_network_capability_allocation(
    budget: Mapping[str, Any],
    *,
    available_address_count: int,
) -> dict[str, Any]:
    """Partition exact Scan ceilings across port discovery and fingerprinting."""
    addresses = int(available_address_count)
    if addresses <= 0:
        raise ScanCapabilityContractError(
            "network discovery requires at least one bound address"
        )
    endpoints = _budget_integer(budget, "max_endpoints")
    ports = _budget_integer(budget, "max_tcp_ports")
    wall = _budget_integer(budget, "max_tool_wall_seconds")
    can_fingerprint = endpoints >= 2 and ports >= 2 and wall >= 2
    passes = 2 if can_fingerprint else 1
    address_count = min(
        addresses,
        max(1, endpoints // passes),
        max(1, ports // passes),
    )
    port_capacity = max(1, ports // passes)
    ports_per_address = max(1, port_capacity // address_count)
    selected_ports = CANONICAL_SCAN_NETWORK_PORTS[
        :min(len(CANONICAL_SCAN_NETWORK_PORTS), ports_per_address)
    ]
    attempt_count = len(selected_ports) * address_count
    first_wall = max(1, wall // passes)
    result: dict[str, Any] = {
        "address_count": address_count,
        "ports": selected_ports,
        "port_discovery_limits": {
            "hosts_attempted": address_count,
            "tcp_ports_attempted": attempt_count,
            "tool_wall_seconds": first_wall,
        },
        "fingerprint_limits": None,
    }
    if can_fingerprint:
        result["fingerprint_limits"] = {
            "hosts_attempted": address_count,
            "tcp_ports_attempted": attempt_count,
            "tool_wall_seconds": wall - first_wall,
        }
    return result


def scan_budget_ledger_limits(
    budget: Mapping[str, Any], *, allow_zero: bool = False,
) -> dict[str, int]:
    """Map one canonical Scan budget to the shared reservation dimensions."""
    http = _budget_integer(
        budget, "max_http_requests", allow_zero=allow_zero,
    )
    endpoints = _budget_integer(
        budget, "max_endpoints", allow_zero=allow_zero,
    )
    return {
        "http_requests": http,
        # Scan has no independent mutation ceiling yet. Permission is enforced by
        # policy, while this prevents writes from exceeding total HTTP authority.
        "state_changing_requests": http,
        "browser_actions": _budget_integer(
            budget, "max_browser_actions", allow_zero=allow_zero,
        ),
        "tcp_ports_attempted": _budget_integer(
            budget, "max_tcp_ports", allow_zero=allow_zero,
        ),
        # A root-bound discovery action consumes one host attempt. The endpoint
        # ceiling is the existing Scan-level bound until max_hosts becomes a
        # separately configurable public Scan field.
        "hosts_attempted": endpoints,
        "tool_wall_seconds": _budget_integer(
            budget, "max_tool_wall_seconds", allow_zero=allow_zero,
        ),
    }


def fit_prepared_scan_capability(
    prepared: PreparedExecution,
    *,
    ledger_limits: Mapping[str, int],
) -> PreparedExecution:
    """Clamp an adapter estimate to exact Scan ceilings before reservation."""
    requested: dict[str, int] = {}
    for raw_name, raw_amount in dict(prepared.estimated_budget).items():
        name = str(raw_name or "").strip()
        if name not in ledger_limits:
            raise ScanCapabilityContractError(
                f"capability requires undeclared Scan budget dimension: {name}"
            )
        amount = int(raw_amount)
        ceiling = int(ledger_limits[name])
        if amount <= 0 or ceiling <= 0:
            raise ScanCapabilityContractError(
                f"Scan budget leaves no capacity for capability dimension: {name}"
            )
        requested[name] = min(amount, ceiling)
    if not requested:
        raise ScanCapabilityContractError("capability did not declare a budget")
    return replace(prepared, estimated_budget=requested)


def scan_capability_action_digest(
    *,
    scan_id: str,
    execution_plan_digest: str,
    target: TargetBinding,
    prepared: PreparedExecution,
) -> str:
    """Bind idempotency to the exact Scan plan, target, input, and hold."""
    payload = {
        "schema_version": "scan-capability-action/v1",
        "scan_id": str(scan_id),
        "execution_plan_digest": str(execution_plan_digest).lower(),
        "target_binding": target.canonical_dict(),
        "target_binding_digest": target.digest,
        "capability_name": prepared.capability_name,
        "adapter_name": prepared.adapter_name,
        "adapter_version": prepared.adapter_version,
        "input_digest": prepared.input_digest,
        "requested_budget": {
            str(name): int(amount)
            for name, amount in sorted(dict(prepared.estimated_budget).items())
        },
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
