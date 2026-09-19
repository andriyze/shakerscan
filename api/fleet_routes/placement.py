"""Placement-preserving broker retries; transport hints never widen execution policy."""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

try:
    from job_queue import placement_from_payload, worker_matches_placement
except ModuleNotFoundError:
    from ..job_queue import placement_from_payload, worker_matches_placement


def private_input_retry_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Unpinned legacy inputs may stay local; pinned work waits for a capable worker.

    A missing ephemeral sealing key is not authorization to change region, node,
    network or residency. Retry only the original secret-free queue envelope.
    """
    retry = deepcopy(dict(payload))
    retry["placement"] = placement_from_payload(retry) or {"node_scope": "local"}
    return retry


def matches_broker_placement(labels: Mapping[str, Any], payload: Mapping[str, Any]) -> bool:
    placement = placement_from_payload(dict(payload))
    return not placement or worker_matches_placement(dict(labels), placement)
