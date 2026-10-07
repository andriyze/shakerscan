"""Rebuild an idempotent replay's result from what the original execution persisted.

Worker-placed actions (scanner, network, browser) persist only a content-safe count in
``hunt_actions.result_summary``; their observations live in the action's immutable capability
receipt on the durable budget reservation. A client whose HTTP wait ends before a long action
finishes (content discovery runs about a minute) settles the unknown outcome by replaying the same
idempotency key. The replay used to read observations only from the summary, so every such caller
received ``observations: []`` and ``execution_started: false`` for an action that had run and found
hits. The replay now returns the receipt's observations and derives ``execution_started`` from the
settled budget, exactly as the first response does.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

NON_TRAFFIC_DIMENSIONS = frozenset({"agent_actions", "active_actions"})
RECEIPT_QUERY = """SELECT receipt_json FROM budget_reservations
   WHERE owner_kind='hunt' AND owner_id=$1 AND action_id=$2"""


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except ValueError:
            return {}
        return dict(decoded) if isinstance(decoded, Mapping) else {}
    return {}


def execution_started_from_budget(consumed: Any) -> bool:
    """Traffic dimensions with a positive settled charge mean execution started."""
    if not isinstance(consumed, Mapping):
        return False
    started = False
    for dimension, amount in consumed.items():
        if dimension in NON_TRAFFIC_DIMENSIONS:
            continue
        try:
            started = started or int(amount or 0) > 0
        except (TypeError, ValueError):
            continue
    return started


async def replay_observations(
    conn: Any, *, hunt_id: Any, action_id: Any, receipt_id: Any, summary: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    """Observations of a settled action: its summary's, else its own capability receipt's."""
    stored = summary.get("observations")
    if isinstance(stored, list):
        return tuple(dict(item) for item in stored if isinstance(item, Mapping))
    if not receipt_id:
        return ()
    row = await conn.fetchrow(RECEIPT_QUERY, str(hunt_id), str(action_id))
    receipt = _mapping(row["receipt_json"]) if row is not None else {}
    # Only the receipt the action itself settled with; never another attempt's.
    if str(receipt.get("receipt_id") or "") != str(receipt_id):
        return ()
    return tuple(
        dict(item) for item in receipt.get("observations") or () if isinstance(item, Mapping)
    )
