"""Bring a target's lead board up to date when a Hunt starts.

Runs the server's lead producers for the Hunt's target: the existing graph and inventory routes,
the leads verified findings open (``followup_leads``) and advisories matched to observed services
(``advisory_leads``). Leads only: nothing here runs traffic, grants authority or marks proof.
"""
from __future__ import annotations

import asyncio
import sys
from typing import Any, Awaitable, Callable, Sequence
import uuid

from .advisory_leads import produce as produce_advisory_leads
from .followup_leads import produce as produce_followup_leads

SEED_TIMEOUT_SECONDS = 10.0

_pool: Callable[[], Any] | None = None
_seeds: tuple[Callable[[str], Awaitable[Any]], ...] = ()


def configure_lead_seeding(*, pool: Callable[[], Any],
                           seeds: Sequence[Callable[[str], Awaitable[Any]]] = ()) -> None:
    """Wire the pool and the target lead producers run when a Hunt starts (composition root)."""
    global _pool, _seeds
    _pool, _seeds = pool, tuple(seeds)


async def seed_started_hunt(hunt_id: Any) -> None:
    """Bring a started Hunt's target lead board up to date: graph, inventory, proof follow-ups, advisories.

    The graph and inventory producers are the existing target routes. Each runs only when its
    records gained a row since the leads it last wrote, so starting Hunts does not re-endorse an
    unchanged board. Bounded, and never the reason a Hunt fails to start.
    """
    if _pool is None:
        return
    try:
        await asyncio.wait_for(_seed(uuid.UUID(str(hunt_id))), SEED_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 - a start never depends on lead seeding
        print(f"[hunt] lead seeding skipped: {type(exc).__name__}", file=sys.stderr, flush=True)


#: For each seed, in configured order: the endorsement source it writes and when the records it
#: reads last gained a row. Re-observing known routes moves ``last_seen_at`` on every Scan and Hunt;
#: seeding on that would re-endorse every lead at every start.
SEED_FRESHNESS = (
    ("app_graph", """SELECT GREATEST(
                         (SELECT max(first_seen_at) FROM application_graph_nodes WHERE target_id=$1),
                         (SELECT max(first_seen_at) FROM application_graph_edges WHERE target_id=$1))"""),
    ("endpoint_inventory", "SELECT max(first_seen_at) FROM target_endpoints WHERE target_id=$1"),
)


async def _seed(hunt_id: uuid.UUID) -> None:
    assert _pool is not None
    async with _pool().acquire() as conn:
        run = await conn.fetchrow("SELECT device_target_id, target_id FROM hunt_runs WHERE id=$1", hunt_id)
        target = (run["device_target_id"] or run["target_id"]) if run else None
        if target is None:
            return
        device = bool(run["device_target_id"])
        stale = []
        for seed, (source, newest_sql) in zip(_seeds, SEED_FRESHNESS):
            newest = await conn.fetchval(newest_sql, target)
            written = await conn.fetchval(
                """SELECT max(GREATEST(h.updated_at, (e->>'recorded_at')::timestamptz))
                   FROM hypotheses h, jsonb_array_elements(h.endorsements) e
                   WHERE h.target_id=$1 AND e->>'source'=$2""", target, source)
            if newest is not None and (written is None or newest > written):
                stale.append(seed)
    # The producers take their own connections.
    for seed in stale:
        await seed(str(target))
    async with _pool().acquire() as conn:
        await produce_followup_leads(conn, target)
        # Advisories that match the target's observed services (known exploited first).
        await produce_advisory_leads(conn, target, device=device)


__all__ = ["SEED_FRESHNESS", "configure_lead_seeding", "seed_started_hunt"]
