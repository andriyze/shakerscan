"""Pure budget policy for keyless Deep Hunt sessions."""

from __future__ import annotations


MIN_USEFUL_WIRE_REQUEST_BUDGET = 900
MAX_WIRE_REQUEST_BUDGET = 3600
WIRE_REQUESTS_PER_TURN = 90


def keyless_hunt_wire_budget(max_iterations: int) -> int:
    """Keep short hunts able to compose recon with one bounded attack scanner."""
    turns = max(1, int(max_iterations))
    return min(
        MAX_WIRE_REQUEST_BUDGET,
        max(MIN_USEFUL_WIRE_REQUEST_BUDGET, turns * WIRE_REQUESTS_PER_TURN),
    )
