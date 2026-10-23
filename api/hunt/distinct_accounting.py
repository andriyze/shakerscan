"""Hosts and ports a Hunt attempted are charged once: admission, worker bound and settlement.

Combines ``host_accounting`` (distinct hosts) and ``port_accounting`` (distinct TCP ports) so a
network action is admitted, bounded and recorded through one call at each stage.

The worker also states what each of the action's commands uses once it starts
(``command_usage``), so the network adapter charges a run stopped part way what the commands
that started attempted rather than spreading the hold evenly over every command, and so device
fragility counts every connection a command makes, however few of its ports are new.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .host_accounting import (
    DIMENSION as HOSTS, action_hosts, bound_distinct_hosts, charged_hosts, distinct_host_charge,
    record_attempted_hosts,
)
from .port_accounting import (
    DIMENSION as PORTS, FRAGILITY, action_pairs, attempted_pairs, bound_distinct_ports, command_pairs,
    distinct_port_charge, measured_pairs, observed_open_pairs, record_attempted_pairs,
)


@dataclass(frozen=True)
class Attempted:
    hosts: frozenset[str] = frozenset()
    pairs: frozenset[tuple[str, int]] = frozenset()
    # Per prepared command, what it uses once it starts (``command_usage``); None: not named.
    command_usage: tuple[Mapping[str, int], ...] | None = None


def distinct_charge(context: Any, prepared: Any, charges: Mapping[str, int]) -> dict[str, int]:
    """Admission: reserve only the hosts and ports this Hunt has not attempted."""
    return distinct_port_charge(context, action_pairs(prepared), distinct_host_charge(context, prepared, charges))


def _first_takes_the_rest(usage: list[dict[str, int]], dimension: str, held: int) -> None:
    """What the hold reserved beyond the commands' own new items (items another action recorded
    after admission) goes on the first command, so a completed run settles exactly the hold."""
    rest = held - sum(item.get(dimension, 0) for item in usage)
    if usage and rest > 0:
        usage[0][dimension] = usage[0].get(dimension, 0) + rest


def command_usage(prepared: Any, budget: Mapping[str, int], context: Any) -> tuple[dict[str, int], ...] | None:
    """What each command of an (unbounded) prepared network action uses once it starts.

    - ``hosts_attempted``: one for a command whose address this Hunt has not attempted;
    - ``tcp_ports_attempted``: the command's pairs this Hunt has not attempted;
    - ``device_fragility_points`` (when held and the action has no estimate of its own): every
      port the command is sent, attempted before or not, since each is a connection to the device.

    Only dimensions ``budget`` holds are listed, and only when the commands name them (one
    address each, an explicit ``-p``); otherwise the adapter keeps its even split. None when no
    dimension is named.
    """
    commands = tuple(getattr(prepared, "commands", ()) or ())
    usage: list[dict[str, int]] = [{} for _ in commands]
    if HOSTS in budget and action_hosts(prepared):
        known, seen = set(charged_hosts(context)), set()
        for item, command in zip(usage, commands):
            address = str(command.destination_address)
            item[HOSTS] = int(address not in known and address not in seen)
            seen.add(address)
        _first_takes_the_rest(usage, HOSTS, int(budget[HOSTS]))
    if action_pairs(prepared):
        known, seen = set(attempted_pairs(context)), set()
        connections = FRAGILITY in budget and FRAGILITY not in dict(prepared.estimated_budget)
        for item, command in zip(usage, commands):
            pairs = command_pairs(command) or frozenset()
            if PORTS in budget:
                item[PORTS] = len(pairs - known - seen)
            if connections:
                item[FRAGILITY] = len(pairs)
            seen |= pairs
        if PORTS in budget:
            _first_takes_the_rest(usage, PORTS, int(budget[PORTS]))
        if connections:
            _first_takes_the_rest(usage, FRAGILITY, int(budget[FRAGILITY]))
    return tuple(usage) if any(usage) else None


def bound_distinct_usage(requested_budget: Mapping[str, int], prepared: Any, reserved: Mapping[str, int],
                         context: Any) -> tuple[dict[str, int], Any, Attempted]:
    """Worker: adopt the admitted host and port holds, bound measurement to them, and state what
    each command uses (``command_usage``) for the adapter to settle."""
    budget, bounded, hosts = bound_distinct_hosts(requested_budget, prepared, reserved, context)
    budget, bounded, pairs = bound_distinct_ports(budget, bounded, reserved, context)
    return budget, bounded, Attempted(hosts=hosts, pairs=pairs,
                                      command_usage=command_usage(prepared, budget, context))


async def record_attempted_usage(conn: Any, *, hunt_id: Any, run: Mapping[str, Any], attempted: Attempted,
                                 reserved: Mapping[str, int], actual: Mapping[str, int],
                                 observations: Iterable[Any] = ()) -> None:
    """Settlement: remember the hosts and ports measured as attempted, and observed open ports."""
    await record_attempted_hosts(conn, hunt_id=hunt_id, run=run, hosts=attempted.hosts,
                                 reserved=reserved, actual=actual)
    pairs = measured_pairs(attempted.pairs, reserved, actual) | observed_open_pairs(observations)
    if pairs:
        await record_attempted_pairs(conn, hunt_id=hunt_id, run=run, pairs=pairs)


__all__ = ["Attempted", "bound_distinct_usage", "command_usage", "distinct_charge", "record_attempted_usage"]
