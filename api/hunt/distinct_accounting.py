"""Hosts and ports a Hunt attempted are charged once: admission, worker bound and settlement.

Combines ``host_accounting`` (distinct hosts) and ``port_accounting`` (distinct TCP ports) so a
network action is admitted, bounded and recorded through one call at each stage.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .host_accounting import bound_distinct_hosts, distinct_host_charge, record_attempted_hosts
from .port_accounting import (
    action_pairs, bound_distinct_ports, distinct_port_charge, measured_pairs, observed_open_pairs,
    record_attempted_pairs,
)


@dataclass(frozen=True)
class Attempted:
    hosts: frozenset[str] = frozenset()
    pairs: frozenset[tuple[str, int]] = frozenset()


def distinct_charge(context: Any, prepared: Any, charges: Mapping[str, int]) -> dict[str, int]:
    """Admission: reserve only the hosts and ports this Hunt has not attempted."""
    return distinct_port_charge(context, action_pairs(prepared), distinct_host_charge(context, prepared, charges))


def bound_distinct_usage(requested_budget: Mapping[str, int], prepared: Any, reserved: Mapping[str, int],
                         context: Any) -> tuple[dict[str, int], Any, Attempted]:
    """Worker: adopt the admitted host and port holds and bound measurement to them."""
    budget, prepared, hosts = bound_distinct_hosts(requested_budget, prepared, reserved, context)
    budget, prepared, pairs = bound_distinct_ports(budget, prepared, reserved, context)
    return budget, prepared, Attempted(hosts=hosts, pairs=pairs)


async def record_attempted_usage(conn: Any, *, hunt_id: Any, run: Mapping[str, Any], attempted: Attempted,
                                 reserved: Mapping[str, int], actual: Mapping[str, int],
                                 observations: Iterable[Any] = ()) -> None:
    """Settlement: remember the hosts and ports measured as attempted, and observed open ports."""
    await record_attempted_hosts(conn, hunt_id=hunt_id, run=run, hosts=attempted.hosts,
                                 reserved=reserved, actual=actual)
    pairs = measured_pairs(attempted.pairs, reserved, actual) | observed_open_pairs(observations)
    if pairs:
        await record_attempted_pairs(conn, hunt_id=hunt_id, run=run, pairs=pairs)


__all__ = ["Attempted", "bound_distinct_usage", "distinct_charge", "record_attempted_usage"]
