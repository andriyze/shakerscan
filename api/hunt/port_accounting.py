"""``tcp_ports_attempted`` counts distinct ports a Hunt attempted, not connections or actions.

The TCP port ceiling bounds how many of a host's ports a Hunt touches. A ``tls.inspect`` was
charged its ten handshakes and a ``service.fingerprint`` of ports that ``ports.discover`` had
just swept was charged them again, so on ``balanced`` one 1,200-port sweep used up the ceiling and
the next inspection of a port it had found was refused. A port is now charged once per Hunt, the
way ``host_accounting`` charges a host once:

- Admission reserves only the (address, port) pairs this Hunt has not attempted. An action names
  its pairs when each of its commands carries an explicit ``-p`` list or range for one address
  (``ports.discover`` with ports, a range or a listed profile, ``service.fingerprint``,
  ``service.nse_check``) and the pairs add up to its estimate; ``tls.inspect`` names the one
  pair its handshakes use. An action whose pairs are unknown (a ``top_100`` / ``top_1000``
  sweep) keeps its full charge.
- The worker adopts that reservation and bounds its measurement to it, exactly as for hosts, so
  no new port runs uncharged.
- Settlement records the pairs whose whole hold was measured as attempted in
  ``context_pack.tcp_ports_attempted_by_address`` (one compact range list per address), and the
  open ports a sweep observed, which it certainly attempted, whatever the sweep's charge.

Charging stays conservative where identity is unknown: a pair is recorded only after a
settlement that measured it, so a failed or concurrent action can over-count but never
under-count. The record is bounded; a pair it cannot hold is simply charged again.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Any

CONTEXT_KEY = "tcp_ports_attempted_by_address"
DIMENSION = "tcp_ports_attempted"
MAX_TRACKED_ADDRESSES = 256
# Each address's ranges as stored ("1-1024,3306"); a record past this is not extended.
MAX_RANGES_TEXT = 16_384

Pair = tuple[str, int]


def _context(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except ValueError:
            return {}
        return dict(decoded) if isinstance(decoded, Mapping) else {}
    return {}


def _ports(text: Any) -> set[int] | None:
    """The ports of a ``-p`` value (``22,80,8000-8010``), or None when it is not one."""
    ports: set[int] = set()
    for item in str(text or "").split(","):
        low, _, high = item.strip().partition("-")
        if not low.isdigit() or (high and not high.isdigit()):
            return None
        start, end = int(low), int(high or low)
        if not 1 <= start <= end <= 65_535:
            return None
        ports.update(range(start, end + 1))
    return ports or None


def _ranges(ports: Iterable[int]) -> str:
    ordered, spans = sorted(set(ports)), []
    for port in ordered:
        if spans and port == spans[-1][1] + 1:
            spans[-1][1] = port
        else:
            spans.append([port, port])
    return ",".join(f"{low}" if low == high else f"{low}-{high}" for low, high in spans)


def attempted_pairs(context: Any) -> frozenset[Pair]:
    record = _context(context).get(CONTEXT_KEY)
    if not isinstance(record, Mapping):
        return frozenset()
    return frozenset(
        (str(address), port) for address, text in record.items() if isinstance(text, str)
        for port in (_ports(text) or ())
    )


def action_pairs(prepared: Any) -> frozenset[Pair]:
    """(address, port) pairs a prepared network action attempts, when each charged pair is named."""
    pairs: set[Pair] = set()
    for command in getattr(prepared, "commands", ()) or ():
        argv = tuple(getattr(command, "argv", ()) or ())
        address = getattr(command, "destination_address", None)
        if not address or "-p" not in argv or argv.index("-p") + 1 >= len(argv):
            return frozenset()
        ports = _ports(argv[argv.index("-p") + 1])
        if ports is None:
            return frozenset()
        pairs.update((str(address), port) for port in ports)
    estimated = int(dict(getattr(prepared, "estimated_budget", {}) or {}).get(DIMENSION) or 0)
    return frozenset(pairs) if pairs and len(pairs) == estimated else frozenset()


def distinct_port_charge(context: Any, pairs: frozenset[Pair], charges: Mapping[str, int]) -> dict[str, int]:
    """Admission: reserve only the pairs this Hunt has not already attempted."""
    result = dict(charges)
    if DIMENSION not in result or not pairs:
        return result
    held = min(int(result[DIMENSION]), len(pairs - attempted_pairs(context)))
    if held > 0:
        result[DIMENSION] = held
    else:
        # Durable reservations omit zero grants; digest the shape that is persisted.
        result.pop(DIMENSION)
    return result


def bound_distinct_ports(
    requested_budget: Mapping[str, int], prepared: Any, reserved: Mapping[str, int], context: Any,
) -> tuple[dict[str, int], Any, frozenset[Pair]]:
    """Worker: adopt the admitted port hold (never above the estimate) and bound measurement to it.

    As ``host_accounting.bound_distinct_hosts``: a hold the stored reservation omits is zero, and a
    hold below the pairs this Hunt has not attempted is not adopted, so no new port runs
    uncharged. Also returns the action's pairs, identified before bounding.
    """
    budget = dict(requested_budget)
    pairs = action_pairs(prepared)
    if DIMENSION not in budget or not pairs:
        return budget, prepared, pairs
    held = int(dict(reserved).get(DIMENSION) or 0)
    unattempted = len(pairs - attempted_pairs(context))
    if not unattempted <= held <= int(budget[DIMENSION]):
        return budget, prepared, pairs
    estimate = dict(prepared.estimated_budget)
    if held:
        budget[DIMENSION] = estimate[DIMENSION] = held
    else:
        budget.pop(DIMENSION)
        estimate.pop(DIMENSION, None)
    return budget, replace(prepared, estimated_budget=estimate), pairs


def observed_open_pairs(observations: Iterable[Any]) -> frozenset[Pair]:
    """Open TCP ports a sweep reported: each was attempted, whatever the sweep was charged."""
    pairs: set[Pair] = set()
    for item in observations or ():
        if not isinstance(item, Mapping) or item.get("kind") != "open_port":
            continue
        port = item.get("port")
        if str(item.get("transport") or "tcp") == "tcp" and isinstance(port, int) and 1 <= port <= 65_535 \
                and isinstance(item.get("address"), str):
            pairs.add((item["address"], port))
    return frozenset(pairs)


def measured_pairs(pairs: frozenset[Pair], reserved: Mapping[str, int], actual: Mapping[str, int]) -> frozenset[Pair]:
    """The pairs whose whole admitted hold was measured as attempted (a zero hold: all known)."""
    held = int(reserved.get(DIMENSION) or 0)
    if not pairs or (held > 0 and int(actual.get(DIMENSION) or 0) < held):
        return frozenset()
    return pairs


async def record_attempted_pairs(conn: Any, *, hunt_id: Any, run: Mapping[str, Any], pairs: Iterable[Pair]) -> None:
    """Remember attempted pairs in the Hunt's context (one compact range list per address)."""
    record = _context(run.get("context_pack")).get(CONTEXT_KEY)
    record = {str(key): str(value) for key, value in record.items()} if isinstance(record, Mapping) else {}
    by_address: dict[str, set[int]] = {}
    for address, port in pairs:
        by_address.setdefault(str(address), set()).add(int(port))
    changed = False
    for address, ports in sorted(by_address.items()):
        known = _ports(record[address]) if address in record else set()
        if address not in record and len(record) >= MAX_TRACKED_ADDRESSES:
            continue
        merged = (known or set()) | ports
        text = _ranges(merged)
        if merged != known and len(text) <= MAX_RANGES_TEXT:
            record[address], changed = text, True
    if not changed:
        return
    await conn.execute(
        """UPDATE hunt_runs
           SET context_pack=jsonb_set(COALESCE(context_pack,'{}'::jsonb), $2::text[], $3::jsonb)
           WHERE id=$1""",
        hunt_id, [CONTEXT_KEY], json.dumps(record),
    )


def tls_pair(target: Any, origin: str) -> Pair | None:
    """The (address, port) a ``tls.inspect`` handshakes with: the origin's port on the target's
    primary frozen address, or None when it cannot be named."""
    import urllib.parse
    try:
        from runtime.target_bound_socket import FrozenTargetSocketFactory
    except ModuleNotFoundError:  # package import in host-side tests
        from ..runtime.target_bound_socket import FrozenTargetSocketFactory
    try:
        parsed = urllib.parse.urlsplit(str(origin or ""))
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return None
        port = parsed.port or 443
        factory = FrozenTargetSocketFactory(
            hostname=parsed.hostname, port=port, frozen_addresses=target.allowed_addresses,
        )
        return str(factory.primary_address), port
    except (ValueError, TypeError, AttributeError):
        return None


def tls_port_usage(result: Mapping[str, Any], reserved: Mapping[str, int]) -> dict[str, Any]:
    """A ``tls.inspect`` result with its handshakes counted as the one port they attempted.

    The handshakes all go to one (address, port) pair, so the port dimension is one when any was
    attempted, and is left out when admission reserved none (the port was already attempted).
    Whether a handshake was attempted is kept explicitly, since the port no longer shows it.
    """
    measured = result.get("budget_consumed")
    if not isinstance(measured, Mapping):
        return dict(result)
    attempts = max(0, int(measured.get(DIMENSION) or 0))
    usage = {key: value for key, value in measured.items() if key != DIMENSION}
    if DIMENSION in reserved:
        usage[DIMENSION] = min(int(reserved[DIMENSION]), 1 if attempts else 0)
    return {**result, "budget_consumed": usage, "execution_started": attempts > 0}


__all__ = [
    "CONTEXT_KEY", "DIMENSION", "action_pairs", "attempted_pairs", "bound_distinct_ports",
    "distinct_port_charge", "measured_pairs", "observed_open_pairs", "record_attempted_pairs",
    "tls_pair", "tls_port_usage",
]
