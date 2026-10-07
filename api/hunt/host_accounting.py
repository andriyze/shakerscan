"""``hosts_attempted`` counts distinct hosts, not network actions.

Every network capability of a Hunt runs against the Hunt's frozen authorized address set. The
ledger used to add each action's host count, so on a single-host target with ``max_hosts=1`` one
``ports.discover`` consumed the whole dimension and the next action on that same host (for example
``service.fingerprint``) was refused and terminated the Hunt as ``budget_exhausted:hosts_attempted``
(soak Hunt 8fe2f65d). A host is now charged once: admission reserves only hosts this Hunt has not
already attempted, the worker adopts that reservation and bounds its measurement to it, and a
settled action records the hosts it attempted in ``context_pack.hosts_attempted_addresses``.

Charging stays conservative where identity is unknown: an action whose commands do not name one
address per charged host keeps its full charge, and hosts are recorded only after a settlement
that measured them, so a failed or concurrent action can over-count but never under-count.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

CONTEXT_KEY = "hosts_attempted_addresses"
MAX_TRACKED_HOSTS = 256
DIMENSION = "hosts_attempted"


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


def action_hosts(prepared: Any) -> frozenset[str]:
    """Hosts named by the action's prepared commands, when each charged host is named."""
    hosts = frozenset(
        str(command.destination_address)
        for command in getattr(prepared, "commands", ()) or ()
        if getattr(command, "destination_address", None)
    )
    estimated = int(dict(getattr(prepared, "estimated_budget", {}) or {}).get(DIMENSION) or 0)
    return hosts if hosts and len(hosts) == estimated else frozenset()


def charged_hosts(context: Any) -> frozenset[str]:
    values = _context(context).get(CONTEXT_KEY)
    return frozenset(str(item) for item in values if isinstance(item, str)) if isinstance(values, list) else frozenset()


def distinct_host_charge(
    context: Any, prepared: Any, charges: Mapping[str, int],
) -> dict[str, int]:
    """Admission: reserve only hosts this Hunt has not already attempted."""
    result = dict(charges)
    hosts = action_hosts(prepared)
    if DIMENSION not in result or not hosts:
        return result
    result[DIMENSION] = min(int(result[DIMENSION]), len(hosts - charged_hosts(context)))
    return result


def bound_distinct_hosts(
    requested_budget: Mapping[str, int], prepared: Any, reserved: Mapping[str, int],
) -> tuple[dict[str, int], Any]:
    """Worker: adopt the admitted host hold (never above the estimate) and bound measurement to it.

    The admission and queue digests cover the reduced hold, so the recomputed request must use it;
    the adapter measures hosts against its prepared estimate, so the estimate is bounded too.
    """
    budget = dict(requested_budget)
    if DIMENSION not in budget or DIMENSION not in reserved:
        return budget, prepared
    held = int(reserved[DIMENSION])
    if not 0 <= held <= int(budget[DIMENSION]) or not action_hosts(prepared):
        return budget, prepared
    budget[DIMENSION] = held
    estimate = {**dict(prepared.estimated_budget), DIMENSION: held}
    return budget, replace(prepared, estimated_budget=estimate)


async def record_attempted_hosts(
    conn: Any, *, hunt_id: Any, run: Mapping[str, Any], prepared: Any,
    reserved: Mapping[str, int], actual: Mapping[str, int],
) -> None:
    """Settlement: remember hosts whose whole admitted hold was measured as attempted."""
    hosts = action_hosts(prepared)
    held = int(reserved.get(DIMENSION) or 0)
    if not hosts or held <= 0 or int(actual.get(DIMENSION) or 0) < held:
        return
    known = charged_hosts(run.get("context_pack"))
    merged = sorted(known | hosts)[:MAX_TRACKED_HOSTS]
    if set(merged) == set(known):
        return
    await conn.execute(
        """UPDATE hunt_runs
           SET context_pack=jsonb_set(COALESCE(context_pack,'{}'::jsonb), $2::text[], $3::jsonb)
           WHERE id=$1""",
        hunt_id, [CONTEXT_KEY], json.dumps(merged),
    )
